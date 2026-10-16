//! Public-fixture, actual OS-process/TLS/FHE tests; no simulated transport or GUI.
use compact_query::{AgeRange, PlainRow, bfv as backend};
use compact_store::Limits;
use peer_runtime::{
    Bootstrap, Bundle, Connector, Endpoint, Identity, Operation, RemotePeer, Request, Response,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Authority {
    der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}
impl Authority {
    fn new() -> Self {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        Self {
            der: certificate.der().to_vec(),
            issuer: Issuer::new(params, key),
        }
    }
    fn identity(&self) -> Identity {
        let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        Identity {
            certificate: certificate.der().to_vec(),
            private_key_pkcs8: key.serialize_der(),
        }
    }
}
struct Process {
    child: Child,
    endpoint: Endpoint,
    directory: PathBuf,
}
impl Process {
    fn start(authority: &Authority, owner: [u8; 32], id: u64, directory: Option<PathBuf>) -> Self {
        Self::start_with_supervision(authority, owner, id, directory, false)
    }
    fn start_with_supervision(
        authority: &Authority,
        owner: [u8; 32],
        id: u64,
        directory: Option<PathBuf>,
        supervised: bool,
    ) -> Self {
        let directory = directory.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.local/network-tests")
                .join(format!(
                    "{}-{id}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        command
            .args(["--state-dir", directory.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", "2");
        if supervised {
            command.arg("--exit-on-stdin-close");
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let config = Bootstrap {
            identity: authority.identity(),
            authority: authority.der.clone(),
            owner,
            node_id: id,
            quota_bytes: 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let secret = zeroize::Zeroizing::new(serde_json::to_vec(&config).unwrap());
        peer_transport::write_frame(child.stdin.as_mut().unwrap(), &secret, 64 * 1024).unwrap();
        if !supervised {
            drop(child.stdin.take());
        }
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(result);
        });
        let endpoint = match rx
            .recv_timeout(Duration::from_secs(10))
            .and_then(|result| result.map_err(|_| mpsc::RecvTimeoutError::Disconnected))
        {
            Ok(line) => serde_json::from_str(&line).unwrap(),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Peer startup failed: {error}");
            }
        };
        assert_ne!(child.id(), std::process::id());
        Self {
            child,
            endpoint,
            directory,
        }
    }
    fn remote(&self, connector: &Connector) -> RemotePeer {
        RemotePeer::new(self.endpoint.clone(), connector.clone())
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
#[test]
fn authenticated_shutdown_wakes_the_listener_and_releases_the_process_directory() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let outsider = Connector::new(&authority.identity(), &authority.der).unwrap();
    assert!(process.remote(&outsider).call(Request::Shutdown).is_err());
    assert_eq!(remote.status().unwrap().pid, process.child.id());

    assert!(matches!(
        remote.call(Request::Shutdown).unwrap(),
        Response::Done
    ));

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Shutdown did not wake the listener"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(remote.status().is_err());
    let reopened = Process::start(
        &authority,
        owner.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    assert_eq!(
        reopened.remote(&connector).status().unwrap().pid,
        reopened.child.id()
    );
}

#[test]
fn supervised_peer_exits_on_owner_pipe_eof_and_releases_its_directory() {
    // Arrange: a real daemon remains reachable while its owner holds the pipe.
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process =
        Process::start_with_supervision(&authority, owner.fingerprint(), 1, None, true);
    assert_eq!(
        process.remote(&connector).status().unwrap().pid,
        process.child.id()
    );

    // Act: EOF is the same OS notification produced by a forcibly killed owner.
    drop(process.child.stdin.take());

    // Assert: the complete daemon exits, not just its listener/watchdog thread.
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "Supervised peer outlived its owner pipe"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    assert!(process.remote(&connector).status().is_err());
    let reopened = Process::start(
        &authority,
        owner.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    assert_eq!(
        reopened.remote(&connector).status().unwrap().pid,
        reopened.child.id()
    );
}

#[test]
fn independent_peer_remains_reachable_after_its_bootstrap_pipe_closes() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();

    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);

    assert!(process.child.stdin.is_none());
    assert!(process.child.try_wait().unwrap().is_none());
    assert_eq!(
        process.remote(&connector).status().unwrap().pid,
        process.child.id()
    );
}

#[test]
fn frame_activity_reports_real_io_before_completion_and_nothing_for_an_unreachable_peer() {
    use peer_runtime::ActivityPhase;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicBool::new(false));
    let sink = observed.clone();
    let before_completion = completed.clone();
    let on_completion = completed.clone();
    let remote = process
        .remote(&connector)
        .with_activity(Arc::new(move |activity| {
            assert!(
                !before_completion.load(Ordering::Acquire),
                "I/O observation must precede completed-RPC telemetry"
            );
            sink.lock().unwrap().push(activity);
        }))
        .with_trace(Arc::new(move |_| {
            on_completion.store(true, Ordering::Release);
        }));

    let status = remote.status().unwrap();

    assert_eq!(status.node_id, 1);
    assert!(completed.load(Ordering::Acquire));
    let activity = observed.lock().unwrap();
    assert_eq!(activity.len(), 2);
    assert_eq!(activity[0].phase, ActivityPhase::RequestSent);
    assert_eq!(activity[1].phase, ActivityPhase::ReplyReceived);
    assert_eq!(activity[0].request_id, activity[1].request_id);
    assert!(activity.iter().all(|event| event.bytes > 0
        && event.operation == "status"
        && event.peer == process.endpoint.identity));
    drop(activity);

    process.kill();
    observed.lock().unwrap().clear();
    completed.store(false, Ordering::Release);
    assert!(remote.status().is_err());
    assert!(
        observed.lock().unwrap().is_empty(),
        "A failed connect must not invent sent frames"
    );
}

fn fixture(owner: &backend::Owner) -> (Bundle, compact_query::TableId) {
    let table = owner
        .seal(
            &[
                PlainRow {
                    age: 17,
                    amount: 10,
                },
                PlainRow {
                    age: 18,
                    amount: 20,
                },
                PlainRow {
                    age: 42,
                    amount: 30,
                },
            ],
            256,
            Limits::default(),
        )
        .unwrap();
    let bundle = Bundle {
        data_head: table.commitment().encode().to_vec(),
        index_head: table.index_commitment().encode().to_vec(),
        data: table.snapshot().encode(),
        index: table.encrypted_index().encode(),
    };
    (bundle, *table.table_id())
}
#[test]
fn separate_processes_execute_real_fhe_and_copy_ciphertext_without_owner_keys() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let mut first = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let second = Process::start(&authority, owner_tls.fingerprint(), 2, None);
    assert_ne!(first.child.id(), second.child.id());
    let a = first.remote(&connector);
    let b = second.remote(&connector);
    let (owner, public) = backend::Owner::generate(*b"NETWORK-TEST-001").unwrap();
    let setup = public.encode_public_setup_for_experiment().unwrap();
    drop(public);
    let Response::Setup(setup_id) = a.call(Request::InstallSetup(setup)).unwrap() else {
        panic!("public setup expected")
    };
    let (bundle, table_id) = fixture(&owner);
    let object = bundle.id();
    let table = owner
        .restore_table_for_experiment(
            &bundle.data,
            &bundle.index,
            &table_id,
            &compact_store::Commitment::decode(&bundle.data_head, Limits::default()).unwrap(),
            &compact_store::Commitment::decode(&bundle.index_head, Limits::default()).unwrap(),
            Limits::default(),
        )
        .unwrap();
    assert!(matches!(
        a.call(Request::Store(bundle.clone())).unwrap(),
        Response::Stored(_)
    ));
    let prepared = owner
        .prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange {
                lower: 18,
                upper: 255,
            },
            256,
            Limits::default(),
        )
        .unwrap();
    let Response::UnverifiedCiphertext(output) = a
        .call(Request::Evaluate {
            object,
            setup: setup_id,
            operation: Operation::Aggregate,
            ciphertext: prepared.request().to_vec(),
        })
        .unwrap()
    else {
        panic!("encrypted output expected")
    };
    let actual = owner
        .complete_exact_aggregate_unverified_for_experiment(&table, prepared, &output)
        .unwrap();
    assert_eq!((actual.count, actual.sum), (2, 50));
    let prepared = owner
        .prepare_exact_select_for_experiment(
            &table,
            AgeRange {
                lower: 0,
                upper: 255,
            },
            backend::RowProjection::AgeAmount,
            256,
            Limits::default(),
        )
        .unwrap();
    let Response::UnverifiedCiphertext(output) = a
        .call(Request::Evaluate {
            object,
            setup: setup_id,
            operation: Operation::Select,
            ciphertext: prepared.request().to_vec(),
        })
        .unwrap()
    else {
        panic!("encrypted output expected")
    };
    let actual = owner
        .complete_exact_select_unverified_for_experiment(&table, prepared, &output)
        .unwrap();
    assert_eq!(
        actual
            .rows
            .iter()
            .map(|r| (r.age.unwrap(), r.amount.unwrap()))
            .collect::<Vec<_>>(),
        vec![(17, 10), (18, 20), (42, 30)]
    );
    assert!(matches!(
        b.call(Request::Copy {
            source: first.endpoint.clone(),
            object
        })
        .unwrap(),
        Response::Stored(_)
    ));
    assert_eq!(b.status().unwrap().objects.len(), 1);
    assert!(
        a.status()
            .unwrap()
            .recent
            .iter()
            .any(|e| e.operation == "fetch" && e.remote == second.endpoint.identity)
    );
    first.kill();
    assert!(a.status().is_err());
    let Response::Bundle(surviving) = b.call(Request::Fetch { object }).unwrap() else {
        panic!("physical replica expected")
    };
    assert_eq!(surviving, bundle);
    let restarted = Process::start(
        &authority,
        owner_tls.fingerprint(),
        1,
        Some(first.directory.clone()),
    );
    assert!(
        matches!(restarted.remote(&connector).call(Request::Fetch{object}).unwrap(),Response::Bundle(value) if value==bundle)
    );
}
#[test]
fn unauthenticated_foreign_and_wrong_identity_connections_cannot_access_the_peer() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let process = Process::start(&authority, owner.fingerprint(), 1, None);
    let foreign = Authority::new();
    let outsider = foreign.identity();
    let outsider = Connector::new(&outsider, &foreign.der).unwrap();
    assert!(process.remote(&outsider).status().is_err());
    let mut wrong = process.endpoint.clone();
    wrong.identity[0] ^= 1;
    assert!(RemotePeer::new(wrong, connector.clone()).status().is_err());
    let member = authority.identity();
    let member = Connector::new(&member, &authority.der).unwrap();
    assert!(
        process
            .remote(&member)
            .call(Request::Quota(2_000_000))
            .is_err()
    );
    assert_eq!(
        process.remote(&connector).status().unwrap().quota_bytes,
        1_048_576
    );
}
#[test]
fn missing_proof_rejects_real_network_results_and_never_commits_insert_or_update() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    let database = storage_client::Database::create(
        "network".into(),
        &[PlainRow {
            age: 18,
            amount: 20,
        }],
        vec![storage_client::Participant {
            id: 1,
            remote: peer.clone(),
        }],
    )
    .unwrap();
    let original = peer.status().unwrap().objects;
    for sql in [
        "SELECT * FROM records",
        "SELECT COUNT(*),SUM(amount) FROM records",
        "INSERT INTO records VALUES (42,30)",
        "UPDATE records SET amount=amount+5",
    ] {
        assert!(
            matches!(
                database.execute(sql),
                Err(storage_client::Error::MissingComputationProof)
            ),
            "{sql}"
        );
    }
    let status = peer.status().unwrap();
    assert_eq!(status.objects.len(), original.len());
    assert_eq!(status.objects[0].id, original[0].id);
    assert_eq!(
        status
            .recent
            .iter()
            .filter(|event| event.operation == "fhe" && event.succeeded)
            .count(),
        4
    );
    process.kill();
    assert!(matches!(
        database.execute("SELECT * FROM records"),
        Err(storage_client::Error::UnavailableShard(1))
    ));
}
#[test]
fn real_disk_tampering_and_quota_failures_never_return_cached_owner_data() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    let (data_owner, _) = backend::Owner::generate(*b"NETWORK-TEST-002").unwrap();
    let (bundle, _) = fixture(&data_owner);
    let object = bundle.id();
    assert!(matches!(
        peer.call(Request::Store(bundle.clone())).unwrap(),
        Response::Stored(_)
    ));
    assert!(peer.call(Request::Quota(1)).is_err());
    let file = fs::read_dir(&process.directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("bundle"))
        .unwrap();
    let mut bytes = fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(file, bytes).unwrap();
    assert!(peer.call(Request::Fetch { object }).is_err());
    assert!(!peer.status().unwrap().objects[0].available);
    assert!(
        peer.call(Request::Store(bundle)).is_err(),
        "An existing corrupt immutable file must never receive a false store acknowledgement"
    );
}
