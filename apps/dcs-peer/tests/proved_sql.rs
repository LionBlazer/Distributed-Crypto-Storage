//! Actual independently identified OS processes, ciphertext custody, STARK and work journal.
//! The explicitly easy work target is a public test contract, never a production default.
#[path = "../../../experiments/combined-sql/aggregate_fixture.rs"]
mod aggregate_measurement;
#[path = "support/boolean_predicates.rs"]
mod boolean_predicates;
#[path = "support/mutation_cancellation.rs"]
mod mutation_cancellation;
#[path = "support/rpc_observation.rs"]
mod rpc_observation;
#[path = "support/static_aggregate.rs"]
mod static_aggregate;
#[path = "support/static_update.rs"]
mod static_update;
#[path = "support/typed_sql.rs"]
mod typed_sql;

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

#[test]
fn zero_delta_update_counts_matched_rows_after_real_proofs_without_publishing_new_images() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let proofs = Arc::new(AtomicUsize::new(0));
    let participants: Vec<_> = [&a, &b]
        .into_iter()
        .enumerate()
        .map(|(slot, process)| {
            let mut participant = process.participant(slot as u64 + 1, &connector);
            let proofs = proofs.clone();
            participant.remote = participant.remote.with_activity(Arc::new(move |event| {
                if event.operation == "fhe-proof"
                    && event.phase == peer_runtime::ActivityPhase::ReplyReceived
                {
                    proofs.fetch_add(1, Ordering::SeqCst);
                }
            }));
            participant
        })
        .collect();
    let mut session = Session::create(
        "update-count".into(),
        &[
            PlainRow {
                age: 42,
                amount: 65535,
            },
            PlainRow { age: 18, amount: 0 },
            PlainRow {
                age: 7,
                amount: 255,
            },
        ],
        participants.clone(),
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    let initial_heads: Vec<_> = session
        .shards()
        .into_iter()
        .map(|s| (s.data_head, s.index_head))
        .collect();
    let initial_objects: Vec<_> = participants
        .iter()
        .map(|p| p.remote.status().unwrap().objects.len())
        .collect();

    for (sql, expected) in [
        ("UPDATE records SET amount = amount + 0 WHERE age >= 18", 2),
        ("UPDATE records SET amount = amount + 0 WHERE age > 255", 0),
        ("UPDATE records SET amount = amount + 1 WHERE age > 255", 0),
    ] {
        proofs.store(0, Ordering::SeqCst);
        let VerifiedResult::Updated {
            affected_rows,
            version,
        } = session.execute(sql).unwrap()
        else {
            panic!("Expected accepted UPDATE count");
        };

        assert_eq!(affected_rows, expected, "{sql}");
        assert_eq!(
            proofs.load(Ordering::SeqCst),
            2,
            "Each shard returns a real checked proof, including an empty selection"
        );
        assert_eq!(version, initial);
        assert!(session.resume_pending().unwrap().is_none());
        assert_eq!(
            session
                .shards()
                .into_iter()
                .map(|s| (s.data_head, s.index_head))
                .collect::<Vec<_>>(),
            initial_heads
        );
        assert_eq!(
            participants
                .iter()
                .map(|p| p.remote.status().unwrap().objects.len())
                .collect::<Vec<_>>(),
            initial_objects
        );
    }
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![42, 65535], vec![18, 0], vec![7, 255]]
    );
}

#[test]
fn one_batch_fills_a254_row_shard_once_and_a255_row_shard_rejects_without_store() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let peer = Process::start(owner.fingerprint(), 1, None);
    let participant = peer.participant(1, &connector);
    for existing in [255usize, 254] {
        let mut session = Session::create(
            format!("batch-{existing}"),
            &vec![
                PlainRow {
                    age: 18,
                    amount: 255
                };
                existing
            ],
            vec![participant.clone()],
            test_contract(),
        )
        .unwrap();
        let initial = session.version();
        let old = session.shards().remove(0);
        let objects = participant.remote.status().unwrap().objects.len();
        let result = session.execute("INSERT INTO records(age,amount) VALUES(42,256),(7,65535)");
        if existing == 255 {
            assert!(result.is_err());
            assert_eq!(session.version(), initial);
            assert_eq!(session.rows(), 255);
            assert_eq!(participant.remote.status().unwrap().objects.len(), objects);
            assert_eq!(session.shards()[0].data_head, old.data_head);
            assert!(session.resume_pending().unwrap().is_none());
        } else {
            let VerifiedResult::Inserted { count, version } = result.unwrap() else {
                panic!("Missing batch result")
            };
            assert_eq!(count, 2);
            assert_eq!(
                version.height,
                initial.height + 1 + u64::from(test_contract().confirmation_depth),
                "One VALUES statement publishes one transition"
            );
            assert_eq!(
                session.shards()[0].data_head.revision(),
                old.data_head.revision() + 1
            );
            assert_eq!(session.rows(), 256);
            let actual = rows(session.execute("SELECT * FROM records").unwrap());
            assert_eq!(&actual[254..], &[vec![42, 256], vec![7, 65535]]);
        }
    }
}

#[test]
fn a_cancelled_later_batch_proof_leaves_all_shards_unpublished_and_retry_is_one_commit() {
    use peer_runtime::{ActivityPhase, RpcActivity};
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let control = peer_transport::RequestControl::default();
    let observed = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let first_gate = observed.clone();
    let first_armed = armed.clone();
    let activity_a: Arc<dyn Fn(RpcActivity) + Send + Sync> = Arc::new(move |event| {
        if first_armed.load(Ordering::SeqCst)
            && event.operation == "fhe-proof"
            && event.phase == ActivityPhase::ReplyReceived
        {
            first_gate.0.lock().unwrap().0 = true;
            first_gate.1.notify_all();
        }
    });
    let second_gate = observed.clone();
    let second_armed = armed.clone();
    let requests = control.clone();
    let activity_b: Arc<dyn Fn(RpcActivity) + Send + Sync> = Arc::new(move |event| {
        if second_armed.load(Ordering::SeqCst)
            && event.operation == "fhe-proof"
            && event.phase == ActivityPhase::RequestSent
        {
            let state = second_gate.0.lock().unwrap();
            let (mut state, timeout) = second_gate
                .1
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.0)
                .unwrap();
            state.1 |= timeout.timed_out() && !state.0;
            requests.cancel();
            second_armed.store(false, Ordering::SeqCst);
        }
    });
    let raw_a = a.participant(1, &connector);
    let raw_b = b.participant(2, &connector);
    let mut pa = raw_a.clone();
    let mut pb = raw_b.clone();
    pa.remote = pa
        .remote
        .with_activity(activity_a)
        .with_control(control.clone());
    pb.remote = pb
        .remote
        .with_activity(activity_b)
        .with_control(control.clone());
    let mut session = Session::create(
        "batch-cancel".into(),
        &vec![
            PlainRow {
                age: 18,
                amount: 20
            };
            510
        ],
        vec![pa, pb],
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    let before_a = raw_a.remote.status().unwrap().objects.len();
    let before_b = raw_b.remote.status().unwrap().objects.len();
    let scope = control.begin().unwrap();
    armed.store(true, Ordering::SeqCst);
    let result = session.execute("INSERT INTO records VALUES(42,256),(7,65535)");
    assert!(
        matches!(result, Err(storage_client::Error::Transport(error)) if error.kind() == std::io::ErrorKind::Interrupted)
    );
    assert_eq!(*observed.0.lock().unwrap(), (true, false));
    assert_eq!(session.version(), initial);
    assert_eq!(session.rows(), 510);
    assert_eq!(raw_a.remote.status().unwrap().objects.len(), before_a);
    assert_eq!(raw_b.remote.status().unwrap().objects.len(), before_b);
    drop(scope);
    assert!(session.resume_pending().unwrap().is_none());
    let result = session
        .execute("INSERT INTO records VALUES(42,256),(7,65535)")
        .unwrap();
    assert!(
        matches!(result, VerifiedResult::Inserted { count:2, version } if version.height == initial.height + 1 + u64::from(test_contract().confirmation_depth))
    );
    assert!(
        session
            .shards()
            .iter()
            .all(|shard| shard.data_head.revision() == 1)
    );
    let actual = rows(session.execute("SELECT * FROM records").unwrap());
    assert_eq!(actual.len(), 512);
    assert_eq!(actual[510], vec![42, 256]);
    assert_eq!(actual[511], vec![7, 65535]);
}

#[test]
fn immutable_mutation_profile_rejection_never_stores_or_creates_a_sticky_pending_batch() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    for limit in 0..4 {
        let a = Process::start(owner.fingerprint(), 1, None);
        let b = Process::start(owner.fingerprint(), 2, None);
        let pa = a.participant(1, &connector);
        let pb = b.participant(2, &connector);
        let mut profile = test_contract();
        match limit {
            0 => profile.max_updates = 1,
            1 => profile.max_request_bytes = 1,
            2 => profile.max_proof_bytes = 1,
            3 => {
                profile.max_body_bytes = 1024;
                profile.max_request_bytes = 1024;
                profile.max_proof_bytes = 1024;
            }
            _ => unreachable!(),
        }
        let source = if limit == 0 {
            vec![
                PlainRow {
                    age: 18,
                    amount: 20
                };
                510
            ]
        } else {
            vec![]
        };
        let mut session = Session::create(
            format!("batch-profile-{limit}"),
            &source,
            vec![pa.clone(), pb.clone()],
            profile,
        )
        .unwrap();
        let initial = session.version();
        let before_a = pa.remote.status().unwrap().objects.len();
        let before_b = pb.remote.status().unwrap().objects.len();
        let error = session
            .execute("INSERT INTO records VALUES(18,20),(42,30)")
            .unwrap_err();
        assert!(!matches!(
            error,
            storage_client::Error::PendingMutation { .. }
        ));
        assert_eq!(session.version(), initial);
        assert_eq!(pa.remote.status().unwrap().objects.len(), before_a);
        assert_eq!(pb.remote.status().unwrap().objects.len(), before_b);
        assert!(session.resume_pending().unwrap().is_none());
        assert_eq!(
            rows(session.execute("SELECT * FROM records").unwrap()).len(),
            source.len()
        );
    }
}

#[test]
fn a_real_peer_rejects_initializing_an_old_application_policy_with_the_q2_aggregate_contract() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let participant = process.participant(1, &connector);
    let session = Session::create(
        "policy-version".into(),
        &[],
        vec![participant.clone()],
        test_contract(),
    )
    .unwrap();
    let (_, setup) = bfv_query_core::Owner::generate(bfv_query_core::Geometry::Rows256).unwrap();
    let descriptor = setup.update_parameters().unwrap();
    let descriptor_bytes = descriptor.to_bytes().unwrap();
    let mut previous = b"dcs/peer-runtime/proved-job-application/v2".to_vec();
    previous.extend_from_slice(&(descriptor_bytes.len() as u64).to_le_bytes());
    previous.extend_from_slice(&descriptor_bytes);
    previous.extend_from_slice(&bfv_query_proof::PROOF_PROFILE_ID);
    let Response::Setup(setup_id) = participant
        .remote
        .call(Request::InstallSetup(setup.to_bytes().unwrap()))
        .unwrap()
    else {
        panic!("Missing setup acknowledgement")
    };
    let mut genesis = session.genesis().clone();
    genesis.network_id[0] ^= 1;
    genesis.application_commitment = version_journal::hash(&previous);
    let before = participant.remote.status().unwrap().journal_bytes;
    let rejected = participant
        .remote
        .call(Request::InitJournal {
            genesis: genesis.encode().unwrap(),
            setup: setup_id,
        })
        .err()
        .expect("An old policy must be rejected before journal creation");
    assert!(matches!(
        rejected
            .get_ref()
            .and_then(|error| error.downcast_ref::<peer_runtime::RemoteError>()),
        Some(peer_runtime::RemoteError::Integrity)
    ));
    assert_eq!(participant.remote.status().unwrap().journal_bytes, before);
    genesis.application_commitment = peer_runtime::evidence::JobVerifier::new(descriptor)
        .unwrap()
        .application_commitment();
    assert!(
        matches!(participant.remote.call(Request::InitJournal { genesis:genesis.encode().unwrap(),setup:setup_id }).unwrap(), Response::JournalReady(id) if id == genesis.id().unwrap())
    );
}

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
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.local/network-tests")
                .join(format!(
                    "proved-{}-{id}-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ))
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        let threads = std::env::var("DCS_TEST_PEER_THREADS").unwrap_or_else(|_| "2".into());
        assert!(
            threads
                .parse::<usize>()
                .is_ok_and(|count| (1..=8).contains(&count)),
            "DCS_TEST_PEER_THREADS must be 1..8"
        );
        command
            .args(["--state-dir", directory.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", threads);
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
            Ok(Ok(line)) => match serde_json::from_str(&line) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = child.kill();
                    let status = child.wait();
                    panic!(
                        "Peer startup failed for {}: {error}; child={status:?}",
                        directory.display()
                    );
                }
            },
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
    let observation = rpc_observation::RpcRecorder::optional("two_shard_update");
    let mut pa = a.participant(1, &connector);
    let mut pb = b.participant(2, &connector);
    if let Some(observation) = &observation {
        pa = observation.attach(pa);
        pb = observation.attach(pb);
    }
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
    if let Some(observation) = &observation {
        observation.start();
    }
    assert!(matches!(
        execute(
            &mut database,
            "UPDATE records SET amount = amount + 1 WHERE age >= 18"
        ),
        VerifiedResult::Updated {
            affected_rows: 3,
            ..
        }
    ));
    if let Some(observation) = &observation {
        observation.finish();
    }
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
        database.execute("SELECT AVG(amount) FROM records").is_err(),
        "An unsupported proof circuit must fail closed"
    );
}

#[test]
fn later_shard_overflow_never_publishes_any_earlier_staged_update() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = completed.clone();
    let activity = std::sync::Arc::new(move |event: peer_runtime::RpcActivity| {
        if event.operation == "fhe-proof"
            && event.phase == peer_runtime::ActivityPhase::ReplyReceived
        {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let mut pa = a.participant(1, &connector);
    let mut pb = b.participant(2, &connector);
    pa.remote = pa.remote.with_activity(activity.clone());
    pb.remote = pb.remote.with_activity(activity);
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
    assert_eq!(
        completed.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "Both admitted workers must finish their proof RPC before returning overflow"
    );
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
            let used = status.disk_bytes();
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
        "INSERT INTO records VALUES (42,30),(7,65534)",
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
        let storage_client::Error::PendingMutation { query_binding, .. } = &error else {
            unreachable!()
        };
        // The retained object includes the complete encrypted ID tail. Retry must
        // reuse its exact bytes rather than allocate another private row identity.
        let stored_images = || {
            control
                .status()
                .unwrap()
                .objects
                .into_iter()
                .map(|object| {
                    let Response::RawBundle(bundle) =
                        control.call(Request::Fetch { object: object.id }).unwrap()
                    else {
                        panic!("stored bundle");
                    };
                    (object.id, bundle)
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let retained = stored_images();
        let again = database.execute(sql).unwrap_err();
        assert!(
            stored_images() == retained,
            "ambiguous retry changed retained encrypted objects"
        );
        assert!(
            matches!(again, storage_client::Error::PendingMutation { query_binding: same, .. } if same == *query_binding)
        );
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
            assert!(matches!(result, VerifiedResult::Inserted { count: 2, .. }));
        } else {
            assert!(matches!(
                result,
                VerifiedResult::Updated {
                    affected_rows: 3,
                    ..
                }
            ));
        }
        assert!(database.resume_pending().unwrap().is_none());
        let confirmed = stored_images();
        // Confirmation may collect obsolete versions; it cannot replace the
        // retained committed ciphertext or create another allocated ID tail.
        assert!(
            confirmed
                .iter()
                .all(|(id, bundle)| retained.get(id) == Some(bundle)),
            "confirmation created or changed an encrypted object"
        );
        let committed = database.shards()[0].object;
        assert!(retained.contains_key(&committed));
        assert!(
            confirmed.get(&committed) == retained.get(&committed),
            "committed identity image changed during retry"
        );
        assert_eq!(database.rows(), 3);
        assert_eq!(database.shards()[0].data_head.revision(), index as u64 + 1);
    }
    assert_eq!(
        rows(execute(&mut database, "SELECT * FROM records")),
        vec![vec![18, 21], vec![42, 31], vec![7, 65535]]
    );
}

#[test]
fn real_peers_prove_count_sum_and_empty_sql_null_over_complete_shards() {
    use storage_client::AggregateProjection;
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    // Round-robin partitioning gives different input and a different partial sum
    // to each real peer; age filters also leave exactly one shard empty.
    let source: Vec<_> = (0..512)
        .map(|ordinal| {
            if ordinal % 2 == 0 {
                PlainRow {
                    age: 18,
                    amount: 65535,
                }
            } else {
                PlainRow { age: 7, amount: 1 }
            }
        })
        .collect();
    let mut session = Session::create(
        "aggregate".into(),
        &source,
        vec![
            first.participant(1, &connector),
            second.participant(2, &connector),
        ],
        test_contract(),
    )
    .unwrap();
    let expected_version = session.version();
    for (sql, expected_projection, expected_count, expected_sum) in [
        (
            "SELECT COUNT(*), SUM(amount) FROM records",
            AggregateProjection::CountSum,
            512,
            Some(16_777_216),
        ),
        (
            "SELECT COUNT(*) FROM records WHERE age >= 18",
            AggregateProjection::Count,
            256,
            Some(16_776_960),
        ),
        (
            "SELECT SUM(amount) FROM records WHERE age = 7",
            AggregateProjection::Sum,
            256,
            Some(256),
        ),
        (
            "SELECT COUNT(*) FROM records WHERE age > 255",
            AggregateProjection::Count,
            0,
            None,
        ),
        (
            "SELECT SUM(amount) FROM records WHERE age < 7",
            AggregateProjection::Sum,
            0,
            None,
        ),
    ] {
        let VerifiedResult::Aggregated {
            projection,
            count,
            sum,
            version,
        } = execute(&mut session, sql)
        else {
            panic!("verified aggregate")
        };
        assert_eq!(
            (projection, count, sum),
            (expected_projection, expected_count, expected_sum)
        );
        assert_eq!(version.state_root, expected_version.state_root);
    }
}

#[test]
fn q2_real_peers_aggregate_5119_and_5120_asymmetric_rows_with_partial_and_empty_bands() {
    use storage_client::AggregateProjection;
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    for total in [5119usize, 5120] {
        eprintln!("aggregate_fixture_rows={total}");
        let source: Vec<_> = (0..total)
            .map(|ordinal| {
                let shard = ordinal % 2;
                let slot = ordinal / 2;
                let band = slot / 256;
                if shard == 0 && slot == 257 {
                    PlainRow { age: 42, amount: 0 }
                } else {
                    PlainRow {
                        age: if shard == 0 { 18 } else { 7 },
                        amount: if shard == 0 {
                            65535 - band as u16 * 257
                        } else {
                            band as u16 * 256 + (slot % 256) as u16
                        },
                    }
                }
            })
            .collect();
        let mut session = Session::create(
            format!("aggregate-q2-{total}"),
            &source,
            vec![
                first.participant(1, &connector),
                second.participant(2, &connector),
            ],
            test_contract(),
        )
        .unwrap();
        let initial = session.version();
        for (sql, projection, age) in [
            (
                "SELECT COUNT(*), SUM(amount) FROM records",
                AggregateProjection::CountSum,
                None,
            ),
            (
                "SELECT COUNT(*) FROM records WHERE age = 18",
                AggregateProjection::Count,
                Some(18),
            ),
            (
                "SELECT SUM(amount) FROM records WHERE age = 7",
                AggregateProjection::Sum,
                Some(7),
            ),
            (
                "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42",
                AggregateProjection::CountSum,
                Some(42),
            ),
            (
                "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255",
                AggregateProjection::CountSum,
                Some(255),
            ),
        ] {
            // Fixture expectations exist only in this public test; the SQL path
            // encrypts every original selected value and accepts the peer proof.
            let expected: Vec<_> = source
                .iter()
                .filter(|row| age.is_none_or(|age| row.age == age))
                .collect();
            let expected_sum = (!expected.is_empty()).then(|| {
                expected
                    .iter()
                    .map(|row| u64::from(row.amount))
                    .sum::<u64>()
            });
            let VerifiedResult::Aggregated {
                projection: actual,
                count,
                sum,
                version,
            } = execute(&mut session, sql)
            else {
                panic!("verified Q2 aggregate")
            };
            assert_eq!(
                (actual, count, sum),
                (projection, expected.len() as u64, expected_sum),
                "{total}: {sql}"
            );
            assert_eq!(version.state_root, initial.state_root);
        }
    }
}

#[test]
fn aggregate_capacity_failure_on_one_shard_returns_no_prefix_and_publishes_nothing() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    let participants = vec![
        first.participant(1, &connector),
        second.participant(2, &connector),
    ];
    let mut session = Session::create(
        "aggregate-overflow".into(),
        &vec![
            PlainRow {
                age: 18,
                amount: 65535
            };
            5121
        ],
        participants.clone(),
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    let heads = || {
        session
            .shards()
            .into_iter()
            .map(|shard| (shard.object, shard.data_head, shard.index_head))
            .collect::<Vec<_>>()
    };
    let original = heads();
    let before: Vec<_> = participants
        .iter()
        .map(|peer| {
            peer.remote
                .status()
                .unwrap()
                .objects
                .into_iter()
                .map(|object| (object.id, object.stored_bytes))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        session
            .execute("SELECT COUNT(*), SUM(amount) FROM records")
            .is_err()
    );
    assert_eq!(session.version(), initial);
    assert_eq!(
        session
            .shards()
            .into_iter()
            .map(|shard| (shard.object, shard.data_head, shard.index_head))
            .collect::<Vec<_>>(),
        original
    );
    for (peer, objects) in participants.iter().zip(before) {
        assert_eq!(
            peer.remote
                .status()
                .unwrap()
                .objects
                .into_iter()
                .map(|object| (object.id, object.stored_bytes))
                .collect::<Vec<_>>(),
            objects
        );
    }
    assert!(session.resume_pending().unwrap().is_none());
}

#[test]
fn select_sends_proof_work_to_two_real_peers_before_reading_either_reply() {
    use peer_runtime::{ActivityPhase, RpcActivity};
    use std::{
        collections::BTreeSet,
        sync::{Arc, Condvar, Mutex},
    };

    #[derive(Default)]
    struct Observed {
        sent: BTreeSet<[u8; 32]>,
        timed_out: bool,
        early_reply: bool,
    }
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    let observed = Arc::new((Mutex::new(Observed::default()), Condvar::new()));
    let gate = observed.clone();
    let activity: Arc<dyn Fn(RpcActivity) + Send + Sync> = Arc::new(move |event| {
        if event.operation != "fhe-proof" {
            return;
        }
        let (state, ready) = &*gate;
        let mut state = state.lock().unwrap();
        match event.phase {
            ActivityPhase::RequestSent => {
                state.sent.insert(event.peer);
                ready.notify_all();
                let (mut state, timeout) = ready
                    .wait_timeout_while(state, Duration::from_secs(5), |state| state.sent.len() < 2)
                    .unwrap();
                state.timed_out |= timeout.timed_out() && state.sent.len() < 2;
            }
            ActivityPhase::ReplyReceived => state.early_reply |= state.sent.len() < 2,
        }
    });
    let mut a = first.participant(1, &connector);
    let mut b = second.participant(2, &connector);
    a.remote = a.remote.with_activity(activity.clone());
    b.remote = b.remote.with_activity(activity);
    let mut session = Session::create(
        "concurrent-select".into(),
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
        vec![a, b],
        test_contract(),
    )
    .unwrap();

    let result = session
        .execute("SELECT amount,age FROM records LIMIT 1")
        .unwrap();

    assert_eq!(rows(result), vec![vec![20, 18]]);
    let state = observed.0.lock().unwrap();
    assert_eq!(state.sent.len(), 2);
    assert!(!state.timed_out, "proof requests ran sequentially");
    assert!(
        !state.early_reply,
        "a reply was read before both proof requests were sent"
    );
}

#[test]
fn cancelling_both_select_workers_preserves_the_next_query() {
    use peer_runtime::{ActivityPhase, RpcActivity};
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    let control = peer_transport::RequestControl::default();
    let observed = Arc::new((Mutex::new((0usize, false)), Condvar::new()));
    let gate = observed.clone();
    let armed = Arc::new(AtomicBool::new(true));
    let requests = control.clone();
    let activity: Arc<dyn Fn(RpcActivity) + Send + Sync> = Arc::new(move |event| {
        if event.operation != "fhe-proof"
            || event.phase != ActivityPhase::RequestSent
            || !armed.load(Ordering::SeqCst)
        {
            return;
        }
        let (state, ready) = &*gate;
        let mut state = state.lock().unwrap();
        state.0 += 1;
        if state.0 == 2 {
            armed.store(false, Ordering::SeqCst);
            requests.cancel();
            ready.notify_all();
        } else {
            let (mut state, timeout) = ready
                .wait_timeout_while(state, Duration::from_secs(5), |state| state.0 < 2)
                .unwrap();
            state.1 |= timeout.timed_out() && state.0 < 2;
        }
    });
    let mut a = first.participant(1, &connector);
    let mut b = second.participant(2, &connector);
    a.remote = a
        .remote
        .with_control(control.clone())
        .with_activity(activity.clone());
    b.remote = b
        .remote
        .with_control(control.clone())
        .with_activity(activity);
    let mut session = Session::create(
        "cancel-concurrent-select".into(),
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
        vec![a, b],
        test_contract(),
    )
    .unwrap();
    let scope = control.begin().unwrap();

    let result = session.execute("SELECT * FROM records");

    assert!(
        matches!(result, Err(storage_client::Error::Transport(error)) if error.kind() == std::io::ErrorKind::Interrupted)
    );
    assert!(scope.cancellation().is_cancelled());
    let (sent, timed_out) = *observed.0.lock().unwrap();
    assert_eq!(sent, 2);
    assert!(!timed_out);
    drop(scope);
    let _next = control.begin().unwrap();
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 20], vec![42, 30]]
    );
}

#[test]
fn update_proves_both_shards_concurrently_before_storing_any_new_copy() {
    use peer_runtime::{ActivityPhase, RpcActivity};
    use std::{
        collections::BTreeSet,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    #[derive(Default)]
    struct Observed {
        sent: BTreeSet<[u8; 32]>,
        received: usize,
        timed_out: bool,
        early_store: bool,
    }
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let observed = Arc::new((Mutex::new(Observed::default()), Condvar::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let gate = observed.clone();
    let active = armed.clone();
    let activity: Arc<dyn Fn(RpcActivity) + Send + Sync> = Arc::new(move |event| {
        if !active.load(Ordering::SeqCst) {
            return;
        }
        let (state, ready) = &*gate;
        let mut state = state.lock().unwrap();
        match (event.operation.as_str(), event.phase) {
            ("fhe-proof", ActivityPhase::RequestSent) => {
                state.sent.insert(event.peer);
                ready.notify_all();
                let (mut state, timeout) = ready
                    .wait_timeout_while(state, Duration::from_secs(5), |state| state.sent.len() < 2)
                    .unwrap();
                state.timed_out |= timeout.timed_out() && state.sent.len() < 2;
            }
            ("fhe-proof", ActivityPhase::ReplyReceived) => state.received += 1,
            ("store", ActivityPhase::RequestSent) => state.early_store |= state.received < 2,
            _ => {}
        }
    });
    let mut pa = a.participant(1, &connector);
    let mut pb = b.participant(2, &connector);
    pa.remote = pa.remote.with_activity(activity.clone());
    pb.remote = pb.remote.with_activity(activity);
    let mut session = Session::create(
        "concurrent-update".into(),
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
        vec![pa, pb],
        test_contract(),
    )
    .unwrap();
    let before = session.version();

    armed.store(true, Ordering::SeqCst);
    let result = session
        .execute("UPDATE records SET amount=amount+1")
        .unwrap();
    armed.store(false, Ordering::SeqCst);

    assert!(matches!(
        result,
        VerifiedResult::Updated {
            affected_rows: 2,
            ..
        }
    ));
    assert_ne!(before.state_root, session.version().state_root);
    let state = observed.0.lock().unwrap();
    assert_eq!(state.sent.len(), 2);
    assert_eq!(state.received, 2);
    assert!(!state.timed_out, "UPDATE proof requests ran sequentially");
    assert!(
        !state.early_store,
        "A copy was stored before both proof replies completed"
    );
    drop(state);
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 21], vec![42, 31]]
    );
}

#[test]
fn concurrent_update_workers_queue_proofs_on_the_same_surviving_peer() {
    use peer_runtime::{ActivityPhase, RpcActivity};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Observed {
        active: usize,
        maximum: usize,
        completed: usize,
    }
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let mut a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let observed = Arc::new(Mutex::new(Observed::default()));
    let state = observed.clone();
    let activity: Arc<dyn Fn(RpcActivity) + Send + Sync> = Arc::new(move |event| {
        if event.operation != "fhe-proof" {
            return;
        }
        let mut state = state.lock().unwrap();
        match event.phase {
            ActivityPhase::RequestSent => {
                state.active += 1;
                state.maximum = state.maximum.max(state.active);
            }
            ActivityPhase::ReplyReceived => {
                state.active -= 1;
                state.completed += 1;
            }
        }
    });
    let pa = a.participant(1, &connector);
    let mut pb = b.participant(2, &connector);
    pb.remote = pb.remote.with_activity(activity);
    let mut session = Session::create(
        "update-replica-failover".into(),
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
        vec![pa, pb],
        test_contract(),
    )
    .unwrap();
    a.kill();

    let result = session
        .execute("UPDATE records SET amount=amount+1")
        .unwrap();

    assert!(matches!(
        result,
        VerifiedResult::Updated {
            affected_rows: 2,
            ..
        }
    ));
    let state = observed.lock().unwrap();
    assert_eq!(state.active, 0);
    assert_eq!(
        state.completed, 2,
        "Both logical shards need genuine proofs"
    );
    assert_eq!(
        state.maximum, 1,
        "Our RPCs must preserve the surviving peer's heavy-work admission"
    );
    drop(state);
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 21], vec![42, 31]]
    );
}

#[test]
fn million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    if std::env::var_os("DCS_TEST_FIXED_PIDS").is_some() {
        for (role, pid) in [
            ("owner", std::process::id()),
            ("peer-1", process.child.id()),
        ] {
            println!(
                "owned_fixed_process={}",
                serde_json::json!({"role": role, "pid": pid})
            );
        }
    }
    let observation = rpc_observation::RpcRecorder::optional("million_row_update");
    let mut participant = process.participant(1, &connector);
    if let Some(observation) = &observation {
        participant = observation.attach(participant);
    }
    let remote = participant.remote.clone();
    let mut source = vec![PlainRow { age: 7, amount: 1 }; compact_query::MAX_TABLE_ROWS];
    source[999_999].age = 42;
    let mut database = Session::create(
        "identity-resource-bound".into(),
        &source,
        vec![participant],
        test_contract(),
    )
    .unwrap();
    drop(source);
    let original = database.shards();
    assert_eq!(original[0].index_head.layout().row_count, 34_017_824);
    assert!(original[0].index_head.layout().row_count > compact_store::Limits::default().max_rows);
    let status = remote.status().unwrap();
    let object = status
        .objects
        .iter()
        .find(|object| object.id == original[0].object)
        .unwrap();
    assert_eq!(object.index_bytes, 34_416_624);
    assert_eq!(object.data_bytes, 3_187_648);
    assert!(object.stored_bytes < peer_transport::MAX_FRAME_BYTES as u64);

    if let Some(observation) = &observation {
        observation.start();
    }
    let result = execute(
        &mut database,
        "UPDATE records SET amount = amount + 1 WHERE age = 42",
    );
    if let Some(observation) = &observation {
        observation.finish();
    }

    assert!(matches!(
        result,
        VerifiedResult::Updated {
            affected_rows: 1,
            ..
        }
    ));
    assert_eq!(database.rows(), compact_query::MAX_TABLE_ROWS);
    let updated = database.shards();
    assert_eq!(
        updated[0].index_head.layout(),
        original[0].index_head.layout()
    );
    assert_eq!(
        updated[0].index_head.revision(),
        original[0].index_head.revision() + 1
    );
    assert_ne!(updated[0].object, original[0].object);
    assert_eq!(
        rows(execute(
            &mut database,
            "SELECT * FROM records WHERE age = 42"
        )),
        vec![vec![42, 2]]
    );
}

#[test]
fn proved_update_keeps_frozen_delta_roles_on_quota_failure_and_preplans_full_for_new_replicas() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let processes: Vec<_> = (1..=3)
        .map(|id| Process::start(owner.fingerprint(), id, None))
        .collect();
    let controls: Vec<_> = processes
        .iter()
        .enumerate()
        .map(|(slot, process)| process.participant(slot as u64 + 1, &connector))
        .collect();
    let events = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let restore = Arc::new(AtomicBool::new(false));
    let participants: Vec<_> = controls
        .iter()
        .map(|participant| {
            let id = participant.id;
            let mut participant = participant.clone();
            let sink = events.clone();
            let armed = armed.clone();
            participant.remote = participant.remote.with_trace(Arc::new(move |trace| {
                if armed.load(Ordering::SeqCst)
                    && matches!(trace.operation.as_str(), "store" | "store-delta")
                {
                    sink.lock().unwrap().push((id, trace));
                }
            }));
            if id == 3 {
                let restore = restore.clone();
                let peers = controls[..2].to_vec();
                participant.remote = participant.remote.with_activity(Arc::new(move |event| {
                    if event.operation == "store"
                        && event.phase == peer_runtime::ActivityPhase::ReplyReceived
                        && restore.swap(false, Ordering::SeqCst)
                    {
                        // A deterministic actual-I/O gate: only after the preplanned
                        // new replica has replied can journal publication use quota again.
                        for peer in &peers {
                            peer.remote.call(Request::Quota(256 * 1024 * 1024)).unwrap();
                        }
                    }
                }));
            }
            participant
        })
        .collect();
    let mut input = vec![PlainRow { age: 7, amount: 3 }; 100_000];
    input[0] = PlainRow {
        age: 42,
        amount: 100,
    };
    let mut session = Session::create(
        "delta-placement".into(),
        &input,
        participants[..2].to_vec(),
        test_contract(),
    )
    .unwrap();
    let original = session.shards();
    let initial = session.version();
    let plan =
        peer_runtime::StoreDeltaPlan::for_heads(&original[0].data_head, &original[0].index_head)
            .unwrap();
    let delta_bytes = plan
        .padded_request_bytes()
        .expect("Fixture must use geometry-padded delta");
    let initial_objects: Vec<_> = controls[..2]
        .iter()
        .map(|p| p.remote.status().unwrap().objects)
        .collect();
    for peer in &controls[..2] {
        let status = peer.remote.status().unwrap();
        let used = status.disk_bytes();
        peer.remote.call(Request::Quota(used)).unwrap();
    }
    armed.store(true, Ordering::SeqCst);

    assert!(
        session
            .execute("UPDATE records SET amount=amount+1 WHERE age=42")
            .is_err()
    );

    assert_eq!(session.version(), initial);
    assert!(session.resume_pending().unwrap().is_none());
    assert_eq!(session.shards()[0].object, original[0].object);
    for (peer, before) in controls[..2].iter().zip(initial_objects) {
        assert_eq!(
            peer.remote
                .status()
                .unwrap()
                .objects
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            before.iter().map(|o| o.id).collect::<Vec<_>>()
        );
    }
    let failed = std::mem::take(&mut *events.lock().unwrap());
    assert_eq!(failed.len(), 2);
    assert!(failed.iter().all(|(id, e)| *id <= 2
        && e.operation == "store-delta"
        && e.request_bytes == delta_bytes as u64
        && !e.succeeded));

    // The third peer holds another shard, making it a known participant but a
    // genuinely new replica of the changed shard. Its Full role is fixed in advance.
    armed.store(false, Ordering::SeqCst);
    session
        .copy_shard(original[1].id, participants[2].clone())
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    restore.store(true, Ordering::SeqCst);
    let VerifiedResult::Updated {
        affected_rows,
        version,
    } = session
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap()
    else {
        panic!("Expected proved UPDATE");
    };
    assert_eq!(affected_rows, 1);
    assert!(version.height > initial.height);
    let first = std::mem::take(&mut *events.lock().unwrap());
    assert_eq!(first.len(), 3);
    for (id, event) in &first {
        assert_eq!(
            event.operation,
            if *id == 3 { "store" } else { "store-delta" }
        );
        assert_eq!(
            event.request_bytes,
            if *id == 3 {
                plan.full_request_bytes() as u64
            } else {
                delta_bytes as u64
            }
        );
        assert_eq!(event.succeeded, *id == 3);
    }
    assert_eq!(
        rows(
            session
                .execute("SELECT amount FROM records WHERE age=42")
                .unwrap()
        ),
        vec![vec![101]]
    );
    events.lock().unwrap().clear();

    // The previously new replica is now committed placement: its next upload
    // uses exactly the same padded delta, followed by a preplanned new Full copy.
    let VerifiedResult::Updated { affected_rows, .. } = session
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap()
    else {
        panic!("Expected proved UPDATE");
    };
    assert_eq!(affected_rows, 1);
    let second = events.lock().unwrap();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].0, 3);
    assert_eq!(second[0].1.operation, "store-delta");
    assert_eq!(second[0].1.request_bytes, delta_bytes as u64);
    assert!(second[0].1.succeeded);
    assert_eq!(second[1].0, 1);
    assert_eq!(second[1].1.operation, "store");
    assert!(second[1].1.succeeded);
    drop(second);
    assert_eq!(
        rows(
            session
                .execute("SELECT amount FROM records WHERE age=42")
                .unwrap()
        ),
        vec![vec![102]]
    );
}

#[test]
fn a_known_holder_endpoint_alias_is_rejected_before_proof_or_full_store() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let processes: Vec<_> = (1..=2)
        .map(|id| Process::start(owner.fingerprint(), id, None))
        .collect();
    let armed = Arc::new(AtomicBool::new(false));
    let work = Arc::new(AtomicUsize::new(0));
    let participants: Vec<_> = processes
        .iter()
        .enumerate()
        .map(|(slot, process)| {
            let mut participant = process.participant(slot as u64 + 1, &connector);
            let armed = armed.clone();
            let work = work.clone();
            participant.remote = participant.remote.with_trace(Arc::new(move |event| {
                if armed.load(Ordering::SeqCst)
                    && matches!(
                        event.operation.as_str(),
                        "fhe-proof" | "store" | "store-delta"
                    )
                {
                    work.fetch_add(1, Ordering::SeqCst);
                }
            }));
            participant
        })
        .collect();
    let mut source = vec![PlainRow { age: 7, amount: 1 }; 100_000];
    source[0].age = 42;
    let mut session = Session::create(
        "delta-alias".into(),
        &source,
        participants.clone(),
        test_contract(),
    )
    .unwrap();
    let old = session.shards();
    assert!(
        peer_runtime::StoreDeltaPlan::for_heads(&old[0].data_head, &old[0].index_head)
            .unwrap()
            .padded_request_bytes()
            .is_some()
    );
    // Register a new routing ID on another shard while reusing the known first
    // holder's actual authenticated process. It must never receive new-Full.
    session
        .copy_shard(
            old[1].id,
            Participant {
                id: 3,
                remote: participants[0].remote.clone(),
            },
        )
        .unwrap();
    let version = session.version();
    let objects: Vec<_> = participants
        .iter()
        .map(|p| {
            p.remote
                .status()
                .unwrap()
                .objects
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>()
        })
        .collect();
    armed.store(true, Ordering::SeqCst);

    assert!(matches!(
        session.execute("UPDATE records SET amount=amount+1 WHERE age=42"),
        Err(storage_client::Error::InvalidInput(_))
    ));

    assert_eq!(work.load(Ordering::SeqCst), 0);
    assert_eq!(session.version(), version);
    assert!(session.resume_pending().unwrap().is_none());
    assert_eq!(
        session
            .shards()
            .iter()
            .map(|s| s.object)
            .collect::<Vec<_>>(),
        old.iter().map(|s| s.object).collect::<Vec<_>>()
    );
    assert_eq!(
        participants
            .iter()
            .map(|p| p
                .remote
                .status()
                .unwrap()
                .objects
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        objects
    );
}

#[test]
fn million_matching_rows_with_explicit_limit_use_real_proofs_and_the_same_static_source_frames() {
    use std::sync::{Arc, Mutex};
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::<peer_runtime::Trace>::new()));
    let observed = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        if matches!(
            event.operation.as_str(),
            "read-image" | "fhe-proof" | "fetch" | "fetch-version" | "fetch-pages"
        ) {
            let mut events = observed.lock().unwrap();
            assert!(events.len() < 16);
            events.push(event);
        }
    }));
    let source: Vec<_> = (0..1_000_000)
        .map(|i| PlainRow {
            age: if i % 2 == 0 { 42 } else { 18 },
            amount: (i % 65536) as u16,
        })
        .collect();
    let mut session = Session::create(
        "million-limited-select".into(),
        &source,
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    let mut source_shape = None;
    for (sql, expected) in [
        (
            "SELECT amount FROM records WHERE age >= 18 LIMIT 100",
            (0..100).map(|i| vec![i]).collect::<Vec<_>>(),
        ),
        (
            "SELECT age, amount FROM records WHERE age >= 18 LIMIT 0",
            vec![],
        ),
    ] {
        events.lock().unwrap().clear();
        assert_eq!(rows(execute(&mut session, sql)), expected, "{sql}");
        assert_eq!(session.version(), initial);
        let events = events.lock().unwrap();
        let reads: Vec<_> = events
            .iter()
            .filter(|e| e.operation == "read-image")
            .collect();
        let proofs: Vec<_> = events
            .iter()
            .filter(|e| e.operation == "fhe-proof")
            .collect();
        assert_eq!(reads.len(), 1);
        assert_eq!(
            proofs.len(),
            1,
            "LIMIT0 still executes genuine encrypted projection"
        );
        assert!(reads[0].succeeded && proofs[0].succeeded);
        assert!(!events.iter().any(|e| matches!(
            e.operation.as_str(),
            "fetch" | "fetch-version" | "fetch-pages"
        )));
        let shape = (reads[0].request_bytes, reads[0].response_bytes);
        if let Some(expected) = source_shape {
            assert_eq!(shape, expected);
        } else {
            source_shape = Some(shape);
        }
    }
    for sql in [
        "SELECT * FROM records WHERE age >= 18",
        "SELECT * FROM records WHERE age >= 18 LIMIT 257",
    ] {
        events.lock().unwrap().clear();
        let error = session.execute(sql).unwrap_err();
        assert!(
            matches!(error, storage_client::Error::Cryptography(ref message) if message.contains("SelectionBudget")),
            "{sql}: {error}"
        );
        let events = events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.operation == "read-image")
                .count(),
            1
        );
        assert!(!events.iter().any(|e| e.operation == "fhe-proof"));
    }
}

#[test]
fn limited_shard_prefixes_merge_by_global_ordinal_with_uneven_matching_counts() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let source: Vec<_> = (0..1101)
        .map(|i| PlainRow {
            age: if i % 2 == 0 || i % 5 == 1 { 42 } else { 7 },
            amount: i,
        })
        .collect();
    let mut session = Session::create(
        "uneven-limited-select".into(),
        &source,
        vec![a.participant(1, &connector), b.participant(2, &connector)],
        test_contract(),
    )
    .unwrap();
    for limit in [0, 1, 100, 256] {
        let expected: Vec<_> = source
            .iter()
            .filter(|row| row.age == 42)
            .take(limit)
            .map(|row| vec![42, u32::from(row.amount)])
            .collect();
        assert_eq!(
            rows(
                session
                    .execute(&format!(
                        "SELECT * FROM records WHERE age = 42 LIMIT {limit}"
                    ))
                    .unwrap()
            ),
            expected
        );
    }
    assert!(
        session
            .execute("SELECT * FROM records WHERE age = 42 LIMIT 257")
            .is_err()
    );
    // LIMIT applies after filtering, and its literal itself is not a hard geometry cap.
    assert!(
        rows(
            session
                .execute("SELECT * FROM records WHERE age = 255 LIMIT 1000")
                .unwrap()
        )
        .is_empty()
    );
}

#[test]
fn fixed_select_fetches_identical_static_images_for_projections_limits_absent_and_false_predicates()
{
    use std::sync::{Arc, Mutex};
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::<peer_runtime::Trace>::new()));
    let observed = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        if matches!(
            event.operation.as_str(),
            "read-image" | "fetch" | "fetch-version" | "fetch-pages" | "fhe-proof"
        ) {
            let mut events = observed.lock().unwrap();
            assert!(events.len() < 64, "Bounded metadata recorder overflow");
            events.push(event);
        }
    }));
    let source: Vec<_> = (0..6040)
        .map(|i| PlainRow {
            age: if i % 25 == 0 { 18 } else { 7 },
            amount: i as u16,
        })
        .collect();
    let mut session = Session::create(
        "static-read-shape".into(),
        &source,
        vec![participant.clone()],
        test_contract(),
    )
    .unwrap();
    let shard = &session.shards()[0];
    // Geometry comes from independently agreed heads, without a predicate or match count.
    // The logical table ID is irrelevant to this public byte-bound calculation.
    let heads = compact_query::ReadHeads::new(
        compact_query::TableId::from_bytes([96; 32]).unwrap(),
        &shard.data_head,
        &shard.index_head,
        compact_store::Limits::default(),
    )
    .unwrap();
    let required = heads.read_requirements().unwrap();
    let request = peer_runtime::ReadImageRequest::new(
        shard.object,
        heads.data(),
        heads.index(),
        required.index_prefix_pages,
    )
    .unwrap();
    assert!(
        u64::from(required.index_prefix_pages)
            < heads.index().layout().page_count().unwrap() as u64
    );
    let mut frame_shape = None;
    for (sql, expected) in [
        (
            "SELECT * FROM records WHERE age = 18",
            (0..6040)
                .step_by(25)
                .map(|amount| vec![18, amount])
                .collect::<Vec<_>>(),
        ),
        (
            "SELECT amount FROM records WHERE age = 18",
            (0..6040).step_by(25).map(|amount| vec![amount]).collect(),
        ),
        (
            "SELECT age, amount FROM records WHERE age = 18 LIMIT 1",
            vec![vec![18, 0]],
        ),
        (
            "SELECT amount, age FROM records WHERE age = 18 LIMIT 0",
            vec![],
        ),
        ("SELECT age FROM records WHERE age = 99", vec![]),
        ("SELECT * FROM records WHERE age > 255", vec![]),
    ] {
        events.lock().unwrap().clear();
        assert_eq!(rows(session.execute(sql).unwrap()), expected, "{sql}");
        let events = events.lock().unwrap();
        assert!(
            events.iter().all(|event| !matches!(
                event.operation.as_str(),
                "fetch" | "fetch-version" | "fetch-pages"
            )),
            "No whole-object or adaptive-page fallback: {sql}"
        );
        let reads: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "read-image")
            .collect();
        let proofs: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "fhe-proof")
            .collect();
        assert_eq!(reads.len(), 1, "{sql}");
        assert_eq!(
            proofs.len(),
            1,
            "Even LIMIT0/absent/false requires genuine proof: {sql}"
        );
        assert!(reads[0].succeeded && proofs[0].succeeded);
        assert_eq!(
            reads[0].response_bytes,
            request.encoded_response_bytes().unwrap() as u64
        );
        let actual_shape = (
            reads[0].request_bytes,
            reads[0].response_bytes,
            proofs[0].request_bytes,
        );
        if let Some(expected) = frame_shape {
            assert_eq!(actual_shape, expected, "{sql}");
        } else {
            frame_shape = Some(actual_shape);
        }
    }
    events.lock().unwrap().clear();
    assert!(
        session
            .execute("SELECT * FROM records WHERE age = 7")
            .is_err(),
        "Complete over-budget selections cannot become a result prefix"
    );
    let observed = events.lock().unwrap();
    let reads: Vec<_> = observed
        .iter()
        .filter(|event| event.operation == "read-image")
        .collect();
    assert_eq!(reads.len(), 1);
    assert_eq!(
        (reads[0].request_bytes, reads[0].response_bytes),
        (frame_shape.unwrap().0, frame_shape.unwrap().1)
    );
    assert!(!observed.iter().any(|event| event.operation == "fhe-proof"));
    drop(observed);
    let mut empty = Session::create(
        "empty-static-read".into(),
        &[],
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let mut empty_frame_shape = None;
    for sql in [
        "SELECT * FROM records",
        "SELECT amount FROM records WHERE age > 255 LIMIT 0",
    ] {
        events.lock().unwrap().clear();
        assert!(rows(empty.execute(sql).unwrap()).is_empty());
        let events = events.lock().unwrap();
        let reads: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "read-image")
            .collect();
        let proofs: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "fhe-proof")
            .collect();
        assert_eq!(reads.len(), 1);
        assert_eq!(proofs.len(), 1);
        let actual = (
            reads[0].request_bytes,
            reads[0].response_bytes,
            proofs[0].request_bytes,
        );
        if let Some(expected) = empty_frame_shape {
            assert_eq!(actual, expected);
        } else {
            empty_frame_shape = Some(actual);
        }
        assert!(!events.iter().any(|event| matches!(
            event.operation.as_str(),
            "fetch" | "fetch-version" | "fetch-pages"
        )));
    }
}

#[test]
fn interrupted_static_image_does_not_retry_an_uncancelled_replica_and_next_query_recovers() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let requests = peer_transport::RequestControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let active = armed.clone();
    let control = requests.clone();
    let mut first = a.participant(1, &connector);
    first.remote = first
        .remote
        .with_control(requests.clone())
        .with_activity(Arc::new(move |event| {
            if event.operation == "read-image"
                && event.phase == peer_runtime::ActivityPhase::RequestSent
                && active.swap(false, Ordering::SeqCst)
            {
                control.cancel();
            }
        }));
    let fallback_reads = Arc::new(AtomicUsize::new(0));
    let fallback_count = fallback_reads.clone();
    let mut second = b.participant(2, &connector);
    second.remote = second.remote.with_activity(Arc::new(move |event| {
        if matches!(event.operation.as_str(), "read-image" | "fhe-proof")
            && event.phase == peer_runtime::ActivityPhase::RequestSent
        {
            fallback_count.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let mut session = Session::create(
        "cancel-static-read".into(),
        &[PlainRow { age: 42, amount: 1 }],
        vec![first],
        test_contract(),
    )
    .unwrap();
    session.copy_shard(session.shards()[0].id, second).unwrap();
    let before = session.version();
    let scope = requests.begin().unwrap();
    armed.store(true, Ordering::SeqCst);
    let error = session.execute("SELECT * FROM records").unwrap_err();
    assert!(
        matches!(error, storage_client::Error::Transport(ref e) if e.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert!(scope.cancellation().is_cancelled());
    assert_eq!(fallback_reads.load(Ordering::SeqCst), 0);
    assert_eq!(session.version(), before);
    drop(scope);
    let _next = requests.begin().unwrap();
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![42, 1]]
    );
}

#[test]
fn cancellation_after_the_real_proof_reply_refuses_static_select_before_final_freshness_completion()
{
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let requests = peer_transport::RequestControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let active = armed.clone();
    let checked_replies = Arc::new(AtomicUsize::new(0));
    let replies = checked_replies.clone();
    let control = requests.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant
        .remote
        .with_control(requests.clone())
        .with_trace(Arc::new(move |event| {
            // Trace runs after RemotePeer's cancellation check. This successful real
            // reply therefore reaches the genuine proof verifier, then the cancelled
            // final journal check refuses completion. No peer response is fabricated.
            if event.operation == "fhe-proof"
                && event.succeeded
                && active.swap(false, Ordering::SeqCst)
            {
                replies.fetch_add(1, Ordering::SeqCst);
                control.cancel();
            }
        }));
    let mut session = Session::create(
        "cancel-final-static-read".into(),
        &[PlainRow { age: 42, amount: 1 }],
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let before = session.version();
    let scope = requests.begin().unwrap();
    armed.store(true, Ordering::SeqCst);
    let error = session.execute("SELECT * FROM records").unwrap_err();
    assert!(
        matches!(error, storage_client::Error::Transport(ref e) if e.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert_eq!(checked_replies.load(Ordering::SeqCst), 1);
    assert_eq!(session.version(), before);
    drop(scope);
    let _next = requests.begin().unwrap();
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![42, 1]]
    );
}

#[test]
fn one_staged_nonce_survives_genuine_update_replication_copy_and_reopen() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let mut c = Process::start(owner.fingerprint(), 3, None);
    let pa = a.participant(1, &connector);
    let pb = b.participant(2, &connector);
    let pc = c.participant(3, &connector);
    let mut session = Session::create(
        "salted-custody".into(),
        &[
            PlainRow {
                age: 18,
                amount: 10,
            },
            PlainRow {
                age: 42,
                amount: 20,
            },
        ],
        vec![pa.clone(), pb.clone()],
        test_contract(),
    )
    .unwrap();
    let fetch = |peer: &Participant, object| {
        let Response::RawBundle(raw) = peer.remote.call(Request::Fetch { object }).unwrap() else {
            panic!("raw object required")
        };
        let checked = peer_runtime::CheckedObject::audit(raw.clone()).unwrap();
        assert_eq!(checked.version().object(), &object);
        raw
    };
    let initial = session
        .shards()
        .into_iter()
        .map(|shard| (shard.id, fetch(&pa, shard.object)))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(matches!(
        session
            .execute("UPDATE records SET amount = amount + 1 WHERE age >= 18")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 2,
            ..
        }
    ));
    for shard in session.shards() {
        let one = fetch(&pa, shard.object);
        let two = fetch(&pb, shard.object);
        assert_eq!(one, two, "replicas must share the exact nonce/envelope");
        assert_ne!(one.nonce, initial[&shard.id].nonce);
        session.copy_shard(shard.id, pc.clone()).unwrap();
        assert_eq!(fetch(&pc, shard.object), one);
    }
    c.kill();
    let reopened = Process::start(owner.fingerprint(), 3, Some(c.directory.clone()));
    let pc = reopened.participant(3, &connector);
    for shard in session.shards() {
        assert_eq!(fetch(&pc, shard.object), fetch(&pb, shard.object));
    }
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 11], vec![42, 21]]
    );
}
