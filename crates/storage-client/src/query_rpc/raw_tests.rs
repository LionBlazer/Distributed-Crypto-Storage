//! Real TLS custody and arithmetic scheduling, without SQL selection or freshness claims.
use super::*;
use bfv_query_core::{Geometry, Owner, PreparedByteSelect, QueryContext};
use compact_store::{Layout, Limits};
use peer_runtime::{
    ActivityPhase, Bootstrap, Connector, Identity, JobVerifier, PeerServer, RawBundle,
    RequestControl, RunningServer, Trace,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::{
        Condvar,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn identity() -> Identity {
    let mut parameters = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = parameters.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}

struct OwnedDirectory {
    parent: PathBuf,
    name: OsString,
    path: PathBuf,
}
impl OwnedDirectory {
    fn new() -> Self {
        let parent =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.local/raw-scheduler-tests");
        fs::create_dir_all(&parent).unwrap();
        let parent = parent.canonicalize().unwrap();
        let name = OsString::from(format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = parent.join(&name);
        fs::create_dir(&path).unwrap();
        let path = path.canonicalize().unwrap();
        assert_eq!(path.parent(), Some(parent.as_path()));
        assert_eq!(path.file_name(), Some(name.as_os_str()));
        Self { parent, name, path }
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if let Ok(path) = self.path.canonicalize()
            && path == self.path
            && path.parent() == Some(self.parent.as_path())
            && path.file_name() == Some(self.name.as_os_str())
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct Network {
    directory: OwnedDirectory,
    servers: Vec<RunningServer>,
    peers: Vec<Participant>,
    events: Arc<Mutex<Vec<(u64, Trace)>>>,
    owner: Owner,
    verifier: JobVerifier,
    bundle: RawBundle,
    object: [u8; 32],
    setup: [u8; 32],
}
impl Network {
    fn new() -> Self {
        // Generated keys and these tiny encrypted images are non-secret test fixtures.
        // The byte projection below is an independent raw arithmetic job, not SQL.
        let directory = OwnedDirectory::new();
        let tls_owner = identity();
        let connector = Connector::permissionless(&tls_owner).unwrap();
        let storage_owner = compact_store::Owner::generate([71; 16]).unwrap();
        let data = storage_owner
            .seal(
                Layout {
                    schema: [72; 16],
                    row_width: 3,
                    rows_per_page: 16,
                    row_count: 1,
                },
                &[18, 20, 0],
                Limits::default(),
            )
            .unwrap();
        let index = storage_owner
            .seal(
                Layout {
                    schema: [73; 16],
                    row_width: 1,
                    rows_per_page: 16,
                    row_count: 1,
                },
                &[0],
                Limits::default(),
            )
            .unwrap();
        let bundle = RawBundle::from_snapshots(&data, &index).unwrap();
        let object = *bundle.target_version().unwrap().object();
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let verifier = JobVerifier::new(setup.update_parameters().unwrap()).unwrap();
        let setup_bytes = setup.to_bytes().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut servers = Vec::new();
        let mut peers = Vec::new();
        let mut setup_id = None;
        for id in 1..=2 {
            let server = PeerServer::bind(
                Bootstrap {
                    identity: identity(),
                    authority: vec![],
                    owner: tls_owner.fingerprint(),
                    node_id: id,
                    quota_bytes: 32 * 1024 * 1024,
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                &directory.path.join(format!("peer-{id}")),
            )
            .unwrap()
            .spawn()
            .unwrap();
            let observed = Arc::clone(&events);
            let remote = RemotePeer::new(server.endpoint.clone(), connector.clone()).with_trace(
                Arc::new(move |event| observed.lock().unwrap().push((id, event))),
            );
            assert!(
                matches!(remote.call(Request::Store(bundle.clone())).unwrap(), Response::Stored(info) if info.id == object)
            );
            let Response::Setup(installed) = remote
                .call(Request::InstallSetup(setup_bytes.clone()))
                .unwrap()
            else {
                panic!("the genuine public setup must be installed");
            };
            if let Some(expected) = setup_id {
                assert_eq!(installed, expected);
            }
            setup_id = Some(installed);
            peers.push(Participant { id, remote });
            servers.push(server);
        }
        Self {
            directory,
            servers,
            peers,
            events,
            owner,
            verifier,
            bundle,
            object,
            setup: setup_id.unwrap(),
        }
    }

    fn prepare(&self, id: u8) -> PreparedByteSelect {
        self.owner
            .prepare_byte_select(
                QueryContext::new(
                    [id; 16],
                    self.bundle.data_head.as_slice().try_into().unwrap(),
                    self.bundle.index_head.as_slice().try_into().unwrap(),
                ),
                [id; 32],
                b"raw",
                &[true, false, true],
            )
            .unwrap()
    }

    fn job<'a>(&self, object: [u8; 32], ciphertext: &'a [u8]) -> ProofJob<'a> {
        ProofJob {
            object,
            setup: self.setup,
            operation: Operation::ByteSelect,
            ciphertext,
        }
    }

    fn proof_events(&self) -> Vec<(u64, bool)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| event.operation == "fhe-proof")
            .map(|(id, event)| (*id, event.succeeded))
            .collect()
    }

    fn damage(&self, id: u64) {
        let name: String = self
            .object
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = self
            .directory
            .path
            .join(format!("peer-{id}/{name}.object2"));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        // Release every peer's owned directory lock before OwnedDirectory cleanup.
        for server in &mut self.servers {
            server.stop();
        }
        self.servers.clear();
    }
}

fn remote_failure(error: &Error) -> Option<&RemoteError> {
    match error {
        Error::Transport(error) => error.get_ref().and_then(|source| source.downcast_ref()),
        _ => None,
    }
}

#[test]
fn interrupted_raw_reply_does_not_try_another_holder_and_fresh_scope_completes() {
    let network = Network::new();
    let prepared = network.prepare(74);
    let control = RequestControl::default();
    let scope = control.begin().unwrap();
    let cancellation = scope.cancellation();
    let interrupted = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&interrupted);
    let preferred = network.peers[0]
        .remote
        .clone()
        .with_control(control.clone())
        .with_activity(Arc::new(move |event| {
            // The actual proof reply has arrived. Interrupt this operation before
            // Requests can accept it; no abandoned peer prover needs a timing guess.
            if event.operation == "fhe-proof" && event.phase == ActivityPhase::ReplyReceived {
                observed.store(true, Ordering::Release);
                cancellation.cancel();
            }
        }));

    let failed = Requests::read_query()
        .request(
            &preferred,
            &network.peers,
            network.job(network.object, &prepared.request),
            |_| -> Result<()> { panic!("an interrupted response must not reach proof acceptance") },
        )
        .expect_err("the caller interrupted this exact raw operation");

    assert!(
        matches!(failed, Error::Transport(ref error) if error.kind() == io::ErrorKind::Interrupted)
    );
    assert!(interrupted.load(Ordering::Acquire));
    assert_eq!(network.proof_events(), vec![(1, false)]);
    drop(scope);
    let _fresh_scope = control.begin().unwrap();
    let preferred = network.peers[0].remote.clone().with_control(control);
    let (reply, checked) = Requests::read_query()
        .request(
            &preferred,
            &network.peers,
            network.job(network.object, &prepared.request),
            |reply| {
                network
                    .verifier
                    .check_job(Operation::ByteSelect, &prepared.request, reply)
                    .map_err(|error| Error::Cryptography(error.to_string()))
            },
        )
        .unwrap();
    let selected = compact_query::byte_select::complete_checked(
        &network.owner,
        &network.verifier.evaluator(),
        prepared,
        &reply.output,
        checked,
    )
    .unwrap();
    assert_eq!(selected.bytes(), b"r\0w");
    assert_eq!(network.proof_events(), vec![(1, false), (1, true)]);
}

#[test]
fn damaged_preferred_holder_falls_back_but_loss_of_both_cannot_reuse_a_checked_reply() {
    let network = Network::new();
    let prepared = network.prepare(75);
    let original_request = prepared.request.clone();
    network.damage(1);
    let requests = Requests::read_query();

    let (reply, checked) = requests
        .request(
            &network.peers[0].remote,
            &network.peers,
            network.job(network.object, &prepared.request),
            |reply| {
                network
                    .verifier
                    .check_job(Operation::ByteSelect, &prepared.request, reply)
                    .map_err(|error| Error::Cryptography(error.to_string()))
            },
        )
        .unwrap();

    let selected = compact_query::byte_select::complete_checked(
        &network.owner,
        &network.verifier.evaluator(),
        prepared,
        &reply.output,
        checked,
    )
    .unwrap();
    assert_eq!(selected.bytes(), b"r\0w");
    assert_eq!(network.proof_events(), vec![(1, false), (2, true)]);
    // Keep the previous reply and verifier cache alive while losing its last holder.
    assert!(!reply.proof.is_empty());
    network.damage(2);
    let lost = requests
        .request(
            &network.peers[0].remote,
            &network.peers,
            network.job(network.object, &original_request),
            |_| -> Result<()> {
                panic!("the scheduler must obtain a new reply, not a cached result")
            },
        )
        .expect_err("both ciphertext holders are damaged");
    assert!(matches!(
        remote_failure(&lost),
        Some(RemoteError::Integrity)
    ));
    assert_eq!(
        network.proof_events(),
        vec![(1, false), (2, true), (2, false)]
    );
    let fresh = Requests::read_query()
        .request(
            &network.peers[0].remote,
            &network.peers,
            network.job(network.object, &original_request),
            |_| -> Result<()> { panic!("a fresh query also requires a new actual reply") },
        )
        .expect_err("a fresh query cannot revive damaged ciphertext");
    assert!(matches!(
        remote_failure(&fresh),
        Some(RemoteError::Integrity)
    ));
    assert_eq!(
        network.proof_events(),
        vec![(1, false), (2, true), (2, false), (1, false), (2, false)]
    );
}

#[derive(Default)]
struct Progress {
    first_verified: bool,
    missing_finished: bool,
    first_finished: bool,
}

#[test]
fn required_raw_job_loss_returns_no_prefix_and_joins_the_successful_worker() {
    let network = Network::new();
    let mut absent = network.bundle.clone();
    absent.nonce[0] ^= 1;
    let absent_object = *absent.target_version().unwrap().object();
    assert_ne!(absent_object, network.object);
    let progress = (Mutex::new(Progress::default()), Condvar::new());
    let requests = Requests::read_query();
    let tasks = [
        (network.object, network.prepare(76)),
        (absent_object, network.prepare(77)),
    ];

    let failed = crate::jobs::run(tasks, |(object, prepared)| {
        if object == absent_object {
            let (state, timeout) = progress
                .1
                .wait_timeout_while(
                    progress.0.lock().unwrap(),
                    Duration::from_secs(30),
                    |state| !state.first_verified,
                )
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "the first actual proof must finish before the missing job"
            );
            drop(state);
            let error = requests
                .request(
                    &network.peers[0].remote,
                    &network.peers,
                    network.job(object, &prepared.request),
                    |_| -> Result<()> { panic!("an unserved exact object cannot produce a reply") },
                )
                .expect_err("neither real peer holds the required second object");
            assert!(matches!(
                remote_failure(&error),
                Some(RemoteError::NotFound)
            ));
            progress.0.lock().unwrap().missing_finished = true;
            progress.1.notify_all();
            return Err(error);
        }
        let (reply, checked) = requests.request(
            &network.peers[0].remote,
            &network.peers,
            network.job(object, &prepared.request),
            |reply| {
                network
                    .verifier
                    .check_job(Operation::ByteSelect, &prepared.request, reply)
                    .map_err(|error| Error::Cryptography(error.to_string()))
            },
        )?;
        let selected = compact_query::byte_select::complete_checked(
            &network.owner,
            &network.verifier.evaluator(),
            prepared,
            &reply.output,
            checked,
        )?;
        assert_eq!(selected.bytes(), b"r\0w");
        let mut state = progress.0.lock().unwrap();
        state.first_verified = true;
        progress.1.notify_all();
        let (mut state, timeout) = progress
            .1
            .wait_timeout_while(state, Duration::from_secs(30), |state| {
                !state.missing_finished
            })
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "the second actual RPC must report object loss"
        );
        state.first_finished = true;
        Ok(selected.into_bytes())
    })
    .expect_err("a successful prefix cannot satisfy two required raw jobs");

    assert!(matches!(
        remote_failure(&failed),
        Some(RemoteError::NotFound)
    ));
    let state = progress.0.lock().unwrap();
    assert!(state.first_verified && state.missing_finished && state.first_finished);
    assert_eq!(
        network.proof_events(),
        vec![(1, true), (1, false), (2, false)]
    );
}
