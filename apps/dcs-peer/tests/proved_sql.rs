//! Actual independently identified OS processes, ciphertext custody, STARK and work journal.
//! The explicitly easy work target is a public test contract, never a production default.
#[path = "support/rpc_observation.rs"]
mod rpc_observation;
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
fn a_real_peer_rejects_initializing_an_old_application_policy_with_the_new_insert_contract() {
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
    let mut previous = b"dcs/peer-runtime/proved-job-application/v1".to_vec();
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
                    let Response::Bundle(bundle) =
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
