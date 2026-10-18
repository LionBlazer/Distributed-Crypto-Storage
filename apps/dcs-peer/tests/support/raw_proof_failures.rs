//! Raw arithmetic/custody only: no Session SQL, automatic failover or head agreement.
use super::*;
use bfv_query_core::{
    Geometry, PendingIndexedUpdate, PublicUpdateEvaluator, QueryContext, SelectedField,
    UnverifiedUpdateOutcome,
};
use peer_runtime::{ActivityPhase, ProofReply, RemoteError, evidence::JobVerifier};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

struct RawAddition {
    owner: bfv_query_core::Owner,
    pending: Option<PendingIndexedUpdate>,
    evaluator: Arc<PublicUpdateEvaluator>,
    verifier: JobVerifier,
    setup: Vec<u8>,
    bundle: RawBundle,
    object: [u8; 32],
    request: Vec<u8>,
}
impl RawAddition {
    fn new() -> Self {
        // Explicitly public fixture operands. No predicate is evaluated and no
        // source-to-FHE-input or SQL authority is claimed for this raw job.
        let storage = compact_store::Owner::generate([121; 16]).unwrap();
        let data = storage
            .seal(
                compact_store::Layout {
                    schema: [122; 16],
                    row_width: 3,
                    rows_per_page: 16,
                    row_count: 2,
                },
                &[42, 255, 0, 18, 254, 255],
                Limits::default(),
            )
            .unwrap();
        let index = storage
            .seal(
                compact_store::Layout {
                    schema: [123; 16],
                    row_width: 1,
                    rows_per_page: 16,
                    row_count: 2,
                },
                &[0, 1],
                Limits::default(),
            )
            .unwrap();
        let bundle = RawBundle::from_snapshots(&data, &index).unwrap();
        let version = bundle.target_version().unwrap();
        let object = *version.object();
        let (owner, public) = bfv_query_core::Owner::generate(Geometry::Rows16).unwrap();
        let verifier = JobVerifier::new(public.update_parameters().unwrap()).unwrap();
        let evaluator = verifier.evaluator();
        let prepared = owner
            .prepare_indexed_update_for_experiment(
                QueryContext::new(
                    [124; 16],
                    version.data_head().encode(),
                    version.index_head().encode(),
                ),
                &[
                    SelectedField {
                        age: 42,
                        amount: 255,
                        active: true,
                    },
                    SelectedField {
                        age: 18,
                        amount: 65534,
                        active: true,
                    },
                ],
                1,
            )
            .unwrap();
        Self {
            owner,
            pending: Some(prepared.pending),
            evaluator,
            verifier,
            setup: public.to_bytes().unwrap(),
            bundle,
            object,
            request: prepared.request,
        }
    }

    fn install(&self, remote: &RemotePeer) -> [u8; 32] {
        let Response::Setup(setup) = remote
            .call(Request::InstallSetup(self.setup.clone()))
            .unwrap()
        else {
            panic!("Actual public setup installation required");
        };
        setup
    }

    fn store(&self, remote: &RemotePeer) {
        assert!(
            matches!(remote.call(Request::Store(self.bundle.clone())).unwrap(),
            Response::Stored(info) if info.id == self.object)
        );
    }

    fn request(&self, setup: [u8; 32]) -> Request {
        Request::Prove {
            object: self.object,
            setup,
            operation: Operation::Update,
            ciphertext: self.request.clone(),
        }
    }

    fn prove(&self, remote: &RemotePeer, setup: [u8; 32]) -> io::Result<ProofReply> {
        // Cancelled server work may still hold its heavy permit. Retry only that
        // explicit response; this deadline is test liveness, not a speed claim.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            match remote.call(self.request(setup)) {
                Ok(Response::Proved(reply)) => return Ok(reply),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Raw Prove reply required",
                    ));
                }
                Err(error) if is_busy(&error) && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn check(&self, reply: &ProofReply) {
        self.verifier
            .check_job(Operation::Update, &self.request, reply)
            .unwrap();
    }

    fn check_and_decode_public_arithmetic(&mut self, reply: &ProofReply) {
        self.check(reply);
        let response = self
            .evaluator
            .restore_circuit_output(&self.request, &reply.output)
            .unwrap();
        let decoded = self
            .owner
            .decrypt_indexed_update_unverified_for_experiment(
                self.pending.take().expect("One-use arithmetic completion"),
                &response,
            )
            .unwrap();
        let UnverifiedUpdateOutcome::Values(values) = decoded else {
            panic!("No overflow in this public fixture")
        };
        assert_eq!(
            values
                .rows
                .iter()
                .map(|row| (row.slot, row.amount))
                .collect::<Vec<_>>(),
            vec![(0, 256), (1, 65535)]
        );
        // The codec deliberately keeps its unverified label. The independent
        // check above proves arithmetic only, never SQL input formation/writes.
        assert_eq!(values.proof, bfv_query_core::ProofStatus::Unavailable);
    }
}

fn is_busy(error: &io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RemoteError>()),
        Some(RemoteError::Busy)
    )
}

fn assert_integrity(error: io::Error) {
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<RemoteError>()),
            Some(RemoteError::Integrity)
        ),
        "Damaged real custody must fail before proof work: {error}"
    );
}

fn corrupt_last_byte(process: &Process, object: &[u8; 32]) -> u64 {
    let path = bundle_path(process, object);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
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
    length
}

#[test]
fn raw_prove_cancellation_interrupts_receipt_and_fresh_scope_verifies_the_next_proof() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let process = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let mut job = RawAddition::new();
    job.store(&remote);
    let setup = job.install(&remote);
    let baseline = job.prove(&remote, setup).unwrap();
    job.check(&baseline);
    let expected_output = version_journal::hash(&baseline.output);
    let minimum_proof_frame = baseline.output.len() as u64;
    drop(baseline);
    let initial_status = remote.status().unwrap();
    let original_custody = fs::read(bundle_path(&process, &job.object)).unwrap();
    let original_request = job.request.clone();
    let control = peer_transport::RequestControl::default();
    let mut final_reply = None;

    for phase in [ActivityPhase::RequestSent, ActivityPhase::ReplyReceived] {
        let activity = Arc::new(Mutex::new(Vec::new()));
        let traces = Arc::new(Mutex::new(Vec::new()));
        let armed = Arc::new(AtomicBool::new(true));
        let observed_activity = activity.clone();
        let observed_traces = traces.clone();
        let cancel_once = armed.clone();
        let cancel = control.clone();
        let controlled = remote
            .clone()
            .with_control(control.clone())
            .with_activity(Arc::new(move |event| {
                if event.operation == "fhe-proof" {
                    let selected = event.phase == phase;
                    observed_activity.lock().unwrap().push(event);
                    if selected && cancel_once.swap(false, Ordering::SeqCst) {
                        assert!(cancel.cancel());
                    }
                }
            }))
            .with_trace(Arc::new(move |trace| {
                observed_traces.lock().unwrap().push(trace)
            }));
        let scope = control.begin().unwrap();
        let old_token = scope.cancellation();

        let error = controlled
            .call(job.request(setup))
            .err()
            .expect("Cancellation must refuse this RPC result");

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(old_token.is_cancelled());
        assert!(!armed.load(Ordering::SeqCst));
        assert!(
            activity
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.phase == phase && event.bytes > 0)
        );
        if phase == ActivityPhase::ReplyReceived {
            assert!(
                activity
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|event| event.phase == phase && event.bytes > minimum_proof_frame),
                "Cancellation occurs after a real full proof-sized frame, not a Busy/error reply"
            );
        }
        assert_eq!(traces.lock().unwrap().len(), 1);
        assert!(!traces.lock().unwrap()[0].succeeded);
        drop(scope);
        assert!(control.current().is_none());
        let fresh_scope = control.begin().unwrap();
        old_token.cancel();
        assert!(!fresh_scope.cancellation().is_cancelled());

        let reply = job.prove(&controlled, setup).unwrap();
        job.check(&reply);
        assert_eq!(version_journal::hash(&reply.output), expected_output);
        assert!(traces.lock().unwrap().last().unwrap().succeeded);
        assert!(
            traces
                .lock()
                .unwrap()
                .iter()
                .all(|trace| trace.operation == "fhe-proof")
        );
        final_reply = Some(reply);
        drop(fresh_scope);
    }
    job.check_and_decode_public_arithmetic(&final_reply.unwrap());
    assert_eq!(job.request, original_request);
    assert_eq!(
        fs::read(bundle_path(&process, &job.object)).unwrap(),
        original_custody
    );
    let final_status = remote.status().unwrap();
    assert_eq!(final_status.journal_bytes, initial_status.journal_bytes);
    assert_eq!(final_status.objects.len(), initial_status.objects.len());
    assert_eq!(final_status.disk_bytes(), initial_status.disk_bytes());
}

#[test]
fn raw_prove_explicit_holder_resubmission_uses_healthy_replica_and_all_corrupt_copies_fail() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let first = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let second = Process::start(&authority, owner_tls.fingerprint(), 2, None);
    assert_ne!(first.child.id(), second.child.id());
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let remotes: Vec<_> = [&first, &second]
        .into_iter()
        .enumerate()
        .map(|(index, process)| {
            let observed = attempts.clone();
            process
                .remote(&connector)
                .with_activity(Arc::new(move |event| {
                    if event.operation == "fhe-proof" && event.phase == ActivityPhase::RequestSent {
                        observed.lock().unwrap().push(index + 1);
                    }
                }))
        })
        .collect();
    let mut job = RawAddition::new();
    job.store(&remotes[0]);
    assert!(
        matches!(remotes[1].call(Request::Copy { source: first.endpoint.clone(), object: job.object }).unwrap(),
        Response::Stored(info) if info.id == job.object)
    );
    let setup = job.install(&remotes[0]);
    assert_eq!(job.install(&remotes[1]), setup);
    let baseline = job.prove(&remotes[0], setup).unwrap();
    job.check(&baseline);
    let expected_output = version_journal::hash(&baseline.output);
    drop(baseline);
    let original_request = job.request.clone();
    let before: Vec<_> = remotes
        .iter()
        .map(|remote| remote.status().unwrap())
        .collect();
    let lengths = [
        fs::metadata(bundle_path(&first, &job.object))
            .unwrap()
            .len(),
        fs::metadata(bundle_path(&second, &job.object))
            .unwrap()
            .len(),
    ];
    assert_eq!(corrupt_last_byte(&first, &job.object), lengths[0]);
    attempts.lock().unwrap().clear();

    // This is an explicit raw client resubmission, not Session automatic failover.
    assert_integrity(job.prove(&remotes[0], setup).unwrap_err());
    let healthy = job.prove(&remotes[1], setup).unwrap();
    job.check_and_decode_public_arithmetic(&healthy);
    assert_eq!(version_journal::hash(&healthy.output), expected_output);
    assert_eq!(*attempts.lock().unwrap(), vec![1, 2]);
    drop(healthy);
    assert!(
        !remotes[0]
            .status()
            .unwrap()
            .objects
            .iter()
            .find(|info| info.id == job.object)
            .unwrap()
            .available
    );
    assert!(
        remotes[1]
            .status()
            .unwrap()
            .objects
            .iter()
            .find(|info| info.id == job.object)
            .unwrap()
            .available
    );
    assert_eq!(corrupt_last_byte(&second, &job.object), lengths[1]);
    attempts.lock().unwrap().clear();

    for remote in &remotes {
        // Earlier successful proof verification/cache entries cannot answer a
        // new raw request when every physical holder now fails its custody audit.
        assert_integrity(job.prove(remote, setup).unwrap_err());
    }
    assert_eq!(*attempts.lock().unwrap(), vec![1, 2]);
    assert_eq!(job.request, original_request);
    for (index, remote) in remotes.iter().enumerate() {
        let status = remote.status().unwrap();
        assert_eq!(status.objects.len(), before[index].objects.len());
        assert_eq!(status.journal_bytes, before[index].journal_bytes);
        assert_eq!(status.disk_bytes(), before[index].disk_bytes());
        let object = status
            .objects
            .iter()
            .find(|info| info.id == job.object)
            .unwrap();
        assert!(!object.available);
        assert_eq!(
            object.stored_bytes,
            before[index]
                .objects
                .iter()
                .find(|info| info.id == job.object)
                .unwrap()
                .stored_bytes
        );
    }
}
