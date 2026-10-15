//! Public-fixture failures through actual OS processes, TLS, disk custody and proofs.
//! The easy work profile below is explicitly a test contract, never production security.
use compact_query::PlainRow;
use peer_runtime::{
    Bootstrap, Connector, Endpoint, Identity, RemoteError, RemotePeer, Request, Response,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use std::{
    fs::OpenOptions,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage_client::{Participant, Session, VerifiedResult};
use version_journal::{Header, ProtocolProfile, Target};

fn identity() -> Identity {
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
fn test_contract() -> ProtocolProfile {
    ProtocolProfile {
        initial_target: Target([0x0f; 32]),
        pow_limit: Target([0x0f; 32]),
        block_spacing_secs: 1,
        retarget_interval: 1024,
        max_future_secs: 30,
        confirmation_depth: 1,
        max_headers: 4096,
        max_shards: 16,
        max_updates: 16,
        max_body_bytes: 32 * 1024 * 1024,
        max_request_bytes: 32 * 1024 * 1024,
        max_proof_bytes: 32 * 1024 * 1024,
        max_journal_bytes: 256 * 1024 * 1024,
    }
}
struct Process {
    child: Child,
    endpoint: Endpoint,
    directory: PathBuf,
}
impl Process {
    fn start(owner: [u8; 32], id: u64) -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.local/network-tests")
            .join(format!(
                "faults-{}-{id}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        command
            .args(["--state-dir", directory.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", "2");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let bootstrap = Bootstrap {
            identity: identity(),
            authority: vec![],
            owner,
            node_id: id,
            quota_bytes: 256 * 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let secret = zeroize::Zeroizing::new(serde_json::to_vec(&bootstrap).unwrap());
        peer_transport::write_frame(&mut child.stdin.take().unwrap(), &secret, 64 * 1024).unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(result);
        });
        let endpoint = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => serde_json::from_str(&line).unwrap(),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Peer startup failed: {other:?}");
            }
        };
        assert_ne!(child.id(), std::process::id());
        Self {
            child,
            endpoint,
            directory,
        }
    }
    fn participant(&self, id: u64, connector: &Connector) -> Participant {
        Participant {
            id,
            remote: RemotePeer::new(self.endpoint.clone(), connector.clone()),
        }
    }
    fn corrupt_public_fixture_bundle(&self, object: [u8; 32]) {
        let mut name = String::new();
        for byte in object {
            use std::fmt::Write as _;
            write!(name, "{byte:02x}").unwrap();
        }
        name.push_str(".bundle");
        let path = self.directory.join(name);
        // Only this test's explicitly public ciphertext fixture is changed. Preserve
        // the filename and length so availability must detect content corruption.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let length = file.metadata().unwrap().len();
        assert!(length > 0);
        file.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert_eq!(file.metadata().unwrap().len(), length);
    }
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.kill();
    }
}

fn selected(result: VerifiedResult) -> Vec<Vec<u32>> {
    let VerifiedResult::Selected { rows, .. } = result else {
        panic!("SELECT result required");
    };
    rows
}
fn is_busy(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RemoteError>())
        .is_some_and(|source| matches!(source, RemoteError::Busy))
}
fn call_when_ready(remote: &RemotePeer, make: impl Fn() -> Request) -> io::Result<Response> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match remote.call(make()) {
            Err(error) if is_busy(&error) && Instant::now() < deadline => {
                // Bounded polling of the actual peer's occupied work permit.
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}
fn assert_unauthorized(error: io::Error) {
    assert!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RemoteError>())
            .is_some_and(|source| matches!(source, RemoteError::Unauthorized)),
        "wrong-operator request must fail authorization: {error}"
    );
}

#[test]
fn corrupted_physical_copy_falls_back_to_a_real_replica_but_losing_both_copies_never_uses_cached_rows()
 {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1);
    let second = Process::start(owner.fingerprint(), 2);
    let a = first.participant(1, &connector);
    let b = second.participant(2, &connector);
    let mut session = Session::create(
        "corruption".into(),
        &[
            PlainRow {
                age: 18,
                amount: 255,
            },
            PlainRow {
                age: 42,
                amount: 256,
            },
        ],
        vec![a.clone(), b.clone()],
        test_contract(),
    )
    .unwrap();
    let expected = vec![vec![18, 255], vec![42, 256]];
    assert_eq!(
        selected(session.execute("SELECT * FROM records").unwrap()),
        expected
    );
    let source = session.shards();
    let object = source[0].object;
    let version = session.version();
    assert!(source[0].holders.contains(&1) && source[0].holders.contains(&2));
    first.corrupt_public_fixture_bundle(object);

    let recovered = selected(session.execute("SELECT * FROM records").unwrap());

    assert_eq!(
        recovered, expected,
        "only the healthy process can supply authenticated input and a real proof"
    );
    assert_eq!(session.version().state_root, version.state_root);
    assert!(
        a.remote
            .status()
            .unwrap()
            .objects
            .iter()
            .any(|info| info.id == object && !info.available)
    );
    assert!(
        b.remote
            .status()
            .unwrap()
            .objects
            .iter()
            .any(|info| info.id == object && info.available)
    );
    second.corrupt_public_fixture_bundle(object);
    let error = session.execute("SELECT * FROM records").unwrap_err();
    assert!(
        matches!(error, storage_client::Error::UnavailableShard(_)),
        "all physical copies are invalid although journals remain reachable: {error}"
    );
    assert!(
        session
            .execute("UPDATE records SET amount=amount+1")
            .is_err()
    );
    assert!(
        session
            .execute("INSERT INTO records VALUES (21, 7)")
            .is_err()
    );
    assert_eq!(session.rows(), 2);
    assert_eq!(session.version(), version);
    for (old, current) in source.iter().zip(session.shards()) {
        assert_eq!(old.data_head, current.data_head);
        assert_eq!(old.index_head, current.index_head);
    }
    assert!(a.remote.status().unwrap().journal_bytes > 0);
    assert!(b.remote.status().unwrap().journal_bytes > 0);
}

#[test]
fn all_processes_offline_prevent_proved_reads_and_writes_after_a_successful_read() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let mut first = Process::start(owner.fingerprint(), 1);
    let mut second = Process::start(owner.fingerprint(), 2);
    let a = first.participant(1, &connector);
    let b = second.participant(2, &connector);
    let mut session = Session::create(
        "offline".into(),
        &[
            PlainRow {
                age: 18,
                amount: 20,
            },
            PlainRow {
                age: 42,
                amount: 30,
            },
        ],
        vec![a.clone(), b.clone()],
        test_contract(),
    )
    .unwrap();
    assert_eq!(
        selected(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 20], vec![42, 30]]
    );
    let version = session.version();
    let heads = session.shards();
    first.kill();
    second.kill();

    let read = session.execute("SELECT * FROM records");

    assert!(
        read.is_err(),
        "a previous proved result is not a fresh network answer"
    );
    assert!(
        session
            .execute("UPDATE records SET amount=amount+1")
            .is_err()
    );
    assert!(
        session
            .execute("INSERT INTO records VALUES (7, 1)")
            .is_err()
    );
    assert_eq!(session.version(), version);
    for (old, current) in heads.iter().zip(session.shards()) {
        assert_eq!(old.data_head, current.data_head);
        assert_eq!(old.index_head, current.index_head);
    }
    assert!(a.remote.status().is_err());
    assert!(b.remote.status().is_err());
}

#[test]
fn permissionless_identity_cannot_reconfigure_another_operator_or_publish_a_forged_state_with_valid_work()
 {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1);
    let participant = process.participant(1, &connector);
    let session = Session::create(
        "authority".into(),
        &[PlainRow {
            age: 18,
            amount: 20,
        }],
        vec![participant.clone()],
        test_contract(),
    )
    .unwrap();
    let outsider = Connector::permissionless(&identity()).unwrap();
    let remote = RemotePeer::new(process.endpoint.clone(), outsider);
    let status = remote.status().unwrap();
    let network = session.version().genesis;
    let genesis = session.genesis().encode().unwrap();
    assert_unauthorized(
        remote
            .call(Request::Quota(status.quota_bytes + 1))
            .err()
            .expect("another operator must not change the quota"),
    );
    // A genuine network genesis is used; the unauthorized caller is rejected before
    // any setup lookup, rather than being accidentally denied by an unknown setup.
    assert_unauthorized(
        remote
            .call(Request::InitJournal {
                genesis,
                setup: [0; 32],
            })
            .err()
            .expect("another operator must not initialize a journal"),
    );
    assert_eq!(
        participant.remote.status().unwrap().quota_bytes,
        status.quota_bytes
    );
    assert_eq!(
        participant.remote.status().unwrap().journal_bytes,
        status.journal_bytes
    );
    let Response::JournalBlocks(blocks) = remote
        .call(Request::JournalBlocks {
            network,
            known: vec![network],
        })
        .unwrap()
    else {
        panic!("actual stored block required");
    };
    assert_eq!(blocks.len(), 1);
    let block = &blocks[0];
    let original = Header::decode(&block.header).unwrap();
    let mut forged = original.clone();
    forged.state_root[0] ^= 1;
    forged.nonce = 0;
    forged.mine(100_000).unwrap();
    assert!(
        forged.target.permits(forged.id()),
        "the forged state must pass the actual work test"
    );
    assert_ne!(forged.id(), original.id());
    let disk_before = participant.remote.status().unwrap().journal_bytes;

    let rejected = call_when_ready(&remote, || Request::PublishBlock {
        network,
        header: forged.encode().to_vec(),
        body: block.body.clone(),
    });

    let error = rejected
        .err()
        .expect("work cannot authorize a different database state");
    assert!(error.get_ref().and_then(|source|source.downcast_ref::<RemoteError>()).is_some_and(|source|matches!(source,RemoteError::Cryptography(reason)if reason.contains("InvalidTransition"))),"forged state must fail consensus validation: {error}");
    assert_eq!(
        participant.remote.status().unwrap().journal_bytes,
        disk_before
    );
    // Replay is idempotent, never a rollback or an extra confirmed version.
    assert!(
        matches!(call_when_ready(&remote,||Request::PublishBlock { network,header:block.header.clone(),body:block.body.clone() }).unwrap(),Response::JournalAccepted(id)if id==original.id())
    );
    assert_eq!(
        participant.remote.status().unwrap().journal_bytes,
        disk_before
    );
    let Response::JournalBlocks(remaining) = remote
        .call(Request::JournalBlocks {
            network,
            known: vec![network, original.id()],
        })
        .unwrap()
    else {
        panic!("journal response required");
    };
    assert!(
        remaining.is_empty(),
        "the rejected state cannot enter durable history"
    );
    assert_eq!(
        session.version().state_root,
        version_journal::state_root(&session.genesis().initial_shards)
    );
}
