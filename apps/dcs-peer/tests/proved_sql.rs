//! Actual independently identified OS processes, ciphertext custody, STARK and work journal.
//! The explicitly easy work target is a public test contract, never a production default.
use compact_query::PlainRow;
use peer_runtime::{Bootstrap, Connector, Endpoint, Identity, RemotePeer, Request, Response};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage_client::{Participant, Session, VerifiedResult};
use version_journal::{ProtocolProfile, Target};

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
    fn start(owner: [u8; 32], id: u64, directory: Option<PathBuf>) -> Self {
        let directory = directory.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.local/network-tests")
                .join(format!(
                    "proved-{}-{id}-{}",
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
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let config = Bootstrap {
            identity: identity(),
            authority: vec![],
            owner,
            node_id: id,
            quota_bytes: 256 * 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let secret = zeroize::Zeroizing::new(serde_json::to_vec(&config).unwrap());
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
fn execute(session: &mut Session, sql: &str) -> VerifiedResult {
    let started = Instant::now();
    let result = session
        .execute(sql)
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    eprintln!(
        "accepted_sql_ms={:.3} sql={sql}",
        started.elapsed().as_secs_f64() * 1000.
    );
    result
}
fn rows(result: VerifiedResult) -> Vec<Vec<u32>> {
    let VerifiedResult::Selected { rows, .. } = result else {
        panic!("SELECT result required");
    };
    rows
}

#[test]
fn proved_select_insert_update_survive_a_process_loss_and_journal_restart() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let mut a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let pa = a.participant(1, &connector);
    let pb = b.participant(2, &connector);
    let started = Instant::now();
    let mut database = Session::create(
        "proved".into(),
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
            PlainRow { age: 7, amount: 40 },
        ],
        vec![pa.clone(), pb.clone()],
        test_contract(),
    )
    .unwrap();
    eprintln!(
        "session_create_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.
    );
    let initial = database.version();
    assert_eq!(
        rows(execute(&mut database, "SELECT * FROM records")),
        vec![vec![17, 10], vec![18, 20], vec![42, 30], vec![7, 40]]
    );
    assert_eq!(
        rows(execute(
            &mut database,
            "SELECT amount, age FROM records WHERE age >= 18 LIMIT 1"
        )),
        vec![vec![20, 18]]
    );
    let original = database.shards();
    assert!(matches!(
        execute(&mut database, "INSERT INTO records VALUES (21, 255)"),
        VerifiedResult::Inserted { count: 1, .. }
    ));
    assert_ne!(database.version().state_root, initial.state_root);
    assert_eq!(database.rows(), 5);
    let inserted = database.shards();
    assert_ne!(original[0].data_head, inserted[0].data_head);
    assert_eq!(original[1].data_head, inserted[1].data_head);
    assert!(matches!(
        execute(
            &mut database,
            "UPDATE records SET amount = amount + 1 WHERE age >= 18"
        ),
        VerifiedResult::Updated {
            changed_rows: 3,
            ..
        }
    ));
    assert_eq!(
        rows(execute(
            &mut database,
            "SELECT * FROM records WHERE age >= 18"
        )),
        vec![vec![18, 21], vec![42, 31], vec![21, 256]]
    );
    let agreed = database.version();
    let outsider = Connector::permissionless(&identity()).unwrap();
    assert!(
        RemotePeer::new(b.endpoint.clone(), outsider)
            .status()
            .is_ok(),
        "Free identity admission must work without a CA"
    );
    a.kill();
    assert_eq!(
        rows(execute(
            &mut database,
            "SELECT amount FROM records WHERE age = 21"
        )),
        vec![vec![256]]
    );
    let restarted = Process::start(owner.fingerprint(), 1, Some(a.directory.clone()));
    database
        .replace_participant(restarted.participant(1, &connector))
        .unwrap();
    assert_eq!(database.version().state_root, agreed.state_root);
    assert_eq!(
        rows(execute(
            &mut database,
            "SELECT age FROM records WHERE age > 255"
        )),
        Vec::<Vec<u32>>::new()
    );
    assert!(pa.remote.status().is_err());
    assert!(pb.remote.status().unwrap().journal_bytes > 0);
    assert!(
        database.execute("SELECT COUNT(*) FROM records").is_err(),
        "An unsupported proof circuit must fail closed"
    );
}

#[test]
fn later_shard_overflow_never_publishes_any_earlier_staged_update() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let pa = a.participant(1, &connector);
    let pb = b.participant(2, &connector);
    let mut database = Session::create(
        "overflow".into(),
        &[
            PlainRow {
                age: 18,
                amount: 255,
            },
            PlainRow {
                age: 42,
                amount: 65535,
            },
        ],
        vec![pa.clone(), pb.clone()],
        test_contract(),
    )
    .unwrap();
    let initial = database.version();
    let heads = database.shards();
    let before_a = pa.remote.status().unwrap().objects.len();
    let before_b = pb.remote.status().unwrap().objects.len();
    let error = database
        .execute("UPDATE records SET amount=amount+1")
        .unwrap_err();
    assert!(error.to_string().contains("overflow"), "{error}");
    assert_eq!(database.version().state_root, initial.state_root);
    for (old, new) in heads.iter().zip(database.shards()) {
        assert_eq!(old.data_head, new.data_head);
        assert_eq!(old.index_head, new.index_head);
    }
    assert_eq!(pa.remote.status().unwrap().objects.len(), before_a);
    assert_eq!(pb.remote.status().unwrap().objects.len(), before_b);
    assert_eq!(
        rows(execute(&mut database, "SELECT * FROM records")),
        vec![vec![18, 255], vec![42, 65535]]
    );
    assert!(matches!(
        pa.remote
            .call(Request::CollectJournal {
                network: database.version().genesis
            })
            .unwrap(),
        Response::Done
    ));
}

#[test]
fn interrupted_confirmation_resumes_the_original_write_without_applying_it_twice() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let control = process.participant(1, &connector).remote;
    let armed = Arc::new(AtomicBool::new(false));
    let gate = armed.clone();
    let administrator = control.clone();
    let remote = control.clone().with_trace(Arc::new(move |trace| {
        if trace.operation == "journal-publish"
            && trace.succeeded
            && gate.swap(false, Ordering::SeqCst)
        {
            // Actual peer quota permits the just-fsynced transition but prevents
            // its next confirmation append. No transport or proof is simulated.
            let status = administrator.status().unwrap();
            let used = status.journal_bytes
                + status
                    .objects
                    .iter()
                    .map(|object| object.stored_bytes)
                    .sum::<u64>();
            assert!(matches!(
                administrator.call(Request::Quota(used)).unwrap(),
                Response::Done
            ));
        }
    }));
    let mut database = Session::create(
        "pending".into(),
        &[PlainRow {
            age: 18,
            amount: 20,
        }],
        vec![Participant { id: 1, remote }],
        test_contract(),
    )
    .unwrap();
    for (index, sql) in [
        "INSERT INTO records VALUES (42,30)",
        "UPDATE records SET amount=amount+1",
    ]
    .into_iter()
    .enumerate()
    {
        let before = database.version();
        armed.store(true, Ordering::SeqCst);
        let error = database.execute(sql).unwrap_err();
        assert!(
            matches!(error, storage_client::Error::PendingMutation { .. }),
            "{error}"
        );
        assert_eq!(database.version().state_root, before.state_root);
        assert!(
            matches!(
                database.execute("SELECT * FROM records"),
                Err(storage_client::Error::PendingMutation { .. })
            ),
            "Another statement must not hide an ambiguous write"
        );
        control.call(Request::Quota(256 * 1024 * 1024)).unwrap();
        let result = if index == 0 {
            database
                .resume_pending()
                .unwrap()
                .expect("Original INSERT outcome")
        } else {
            database.execute(sql).unwrap()
        };
        if index == 0 {
            assert!(matches!(result, VerifiedResult::Inserted { count: 1, .. }));
        } else {
            assert!(matches!(
                result,
                VerifiedResult::Updated {
                    changed_rows: 2,
                    ..
                }
            ));
        }
        assert!(database.resume_pending().unwrap().is_none());
        assert_eq!(database.rows(), 2);
        assert_eq!(database.shards()[0].data_head.revision(), index as u64 + 1);
    }
    assert_eq!(
        rows(execute(&mut database, "SELECT * FROM records")),
        vec![vec![18, 21], vec![42, 31]]
    );
}
