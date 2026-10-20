//! PUBLIC NONSECRET Work keys. These test actual QC checking/scheduling, NOT SQL admission.
use super::*;
use ed25519_dalek::SigningKey;
use registry200_finality::joint::{CANDIDATE_BYTES, JointCandidate};
use sha2::{Digest, Sha256};
use work_finality::{
    Genesis, Limits, NetworkSeed, QuorumCertificate, SignedVote, Step, VoteContext, WorkTicket,
    consensus::{MAX_RECORD_BYTES, Rules},
};

fn fixture() -> (Context, Vec<SigningKey>, JointCandidate) {
    let mut keys: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let rules = Rules::multi_slot(
        [7; 32],
        CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    let seed = NetworkSeed::new(
        rules.seed_domain([3; 32]),
        [4; 32],
        [255; 32],
        Limits::new(16, 4).unwrap(),
    )
    .unwrap();
    let tickets = keys
        .iter()
        .map(|key| WorkTicket::sign(&seed.bootstrap_election(), key, 0).unwrap())
        .collect();
    let work = Genesis::from_bootstrap(seed, tickets).unwrap();
    let context = Context::new(rules, [3; 32], &work, [5; 32], 1, [6; 32]).unwrap();
    // Candidate metadata has deliberately NO Source/application authority. The
    // production caller constructs it from its own real binding/Header; this
    // owning unit checks only the advertised weighted-QC selection boundary.
    let header = version_journal::Header {
        genesis: [5; 32],
        parent: [8; 32],
        height: 1,
        timestamp: 1001,
        target: version_journal::Target([255; 32]),
        body_hash: [9; 32],
        state_root: [10; 32],
        nonce: 0,
    };
    let mut bytes = [0; CANDIDATE_BYTES];
    bytes[..8].copy_from_slice(b"DCSJCV01");
    bytes[8..40].copy_from_slice(&[11; 32]);
    bytes[40..48].copy_from_slice(&1u64.to_le_bytes());
    bytes[48..80].copy_from_slice(&context.previous_decision());
    bytes[80..].copy_from_slice(&header.encode());
    (context, keys, JointCandidate::decode(&bytes).unwrap())
}
fn qc(context: &Context, keys: &[SigningKey], candidate: JointCandidate) -> JointCheckpoint {
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/consensus-vote-instance/v1");
    h.update(work_finality::profile_digest());
    h.update(context.id());
    let vote = VoteContext::new(
        context.set(),
        h.finalize().into(),
        context.slot(),
        0,
        Step::Precommit,
        Some(context.value_id(&candidate.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = keys[..3]
        .iter()
        .map(|key| SignedVote::sign(vote, key).unwrap())
        .collect();
    let certificate = QuorumCertificate::assemble(context.set(), &vote, &votes)
        .unwrap()
        .encode()
        .unwrap();
    JointCheckpoint::new(candidate, 0, certificate).unwrap()
}
fn progress() -> PeerProgress {
    PeerProgress {
        busy: AtomicBool::new(false),
        stage: AtomicU8::new(2),
        ordinal: AtomicUsize::new(0),
        original_attempted: AtomicBool::new(false),
    }
}
fn checked(
    context: &Context,
    expected: &JointCandidate,
    checkpoint: JointCheckpoint,
) -> PeerResult<Option<JointCheckpoint>> {
    require_expected(context, expected, &checkpoint).map_err(|e| {
        PeerFailure::Remote(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    })?;
    Ok(Some(checkpoint))
}

#[test]
fn bad_fast_genuine_foreign_qc_cannot_abort_later_valid_weighted_qc() {
    let (context, keys, expected) = fixture();
    let mut foreign = expected.encode();
    foreign[80 + version_journal::HEADER_BYTES - 1] ^= 1;
    let foreign = JointCandidate::decode(&foreign).unwrap();
    let wrong = qc(&context, &keys, foreign);
    let good = qc(&context, &keys, expected.clone());
    // Both are genuine >2/3 weighted certificates, including the wrong value.
    context
        .verify_commit(&wrong.candidate().encode(), 0, wrong.certificate())
        .unwrap();
    context
        .verify_commit(&good.candidate().encode(), 0, good.certificate())
        .unwrap();
    let first = progress();
    let later = progress();
    let (ready, wait) = mpsc::sync_channel(0);
    let (sent, received) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        wait.recv().unwrap();
        sent.send(good).unwrap();
    });
    let bad = observe_peer(&first, checked(&context, &expected, wrong)).unwrap();
    assert!(bad.is_none());
    assert_eq!(first.stage.load(Ordering::Acquire), 3);
    ready.send(()).unwrap();
    let good = received.recv().unwrap();
    worker.join().unwrap();
    let selected = observe_peer(&later, checked(&context, &expected, good))
        .unwrap()
        .unwrap();
    assert_eq!(selected.candidate(), &expected);
    assert_eq!(later.stage.load(Ordering::Acquire), 2);
    let mut corrupt = selected.certificate().to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let corrupt = JointCheckpoint::new(expected.clone(), 0, corrupt).unwrap();
    assert!(
        observe_peer(&progress(), checked(&context, &expected, corrupt))
            .unwrap()
            .is_none()
    );
    let local_error = local::<_, registry200_joint::Error>(Manifest::decode(&[])).map(|_| None);
    assert!(
        observe_peer(&progress(), local_error).is_err(),
        "local canonical/depot corruption remains hard failure"
    );
}

#[test]
fn three_inflight_or_disqualified_peers_do_not_exclude_the_fourth_same_operation() {
    let scheduler = Scheduler {
        next: AtomicUsize::new(0),
        stopped: AtomicBool::new(false),
        peers: (0..4).map(|_| progress()).collect(),
    };
    let (a, held_a) = scheduler.claim().unwrap();
    let (b, held_b) = scheduler.claim().unwrap();
    let (c, held_c) = scheduler.claim().unwrap();
    assert_eq!([a, b, c], [0, 1, 2]);
    let (d, held_d) = scheduler.claim().unwrap();
    assert_eq!(d, 3);
    drop(held_d);
    for peer in &scheduler.peers[..3] {
        peer.stage.store(3, Ordering::Release);
    }
    drop((held_a, held_b, held_c));
    for _ in 0..3 {
        assert!(scheduler.claim().is_none());
    }
    let (next, held) = scheduler.claim().unwrap();
    assert_eq!(next, 3);
    drop(held);
    assert!(!scheduler.stopped.load(Ordering::Acquire));
}

// The following tests exercise PRIVATE ordinary-I/O step scheduling over real
// bounded framed TCP calls. ACK/BUSY/record bytes are UNTRUSTED test responses,
// not a Joint server, application proof, TLS authorization or SQL success.
const STEP_WAIT: Duration = Duration::from_secs(3);
enum StepResponse {
    Ack,
    Busy,
    Reject,
    Disconnect,
    PausedCheckpoint {
        bytes: Vec<u8>,
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    },
}
struct StepServer {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Vec<(usize, PeerAction)>>>,
}
impl StepServer {
    fn new(responses: Vec<StepResponse>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            let mut observed = Vec::new();
            for response in responses {
                let (mut socket, _) = listener.accept().unwrap();
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                socket.set_read_timeout(Some(STEP_WAIT)).unwrap();
                socket.set_write_timeout(Some(STEP_WAIT)).unwrap();
                let frame = peer_transport::read_frame(&mut socket, 17).unwrap();
                assert_eq!(frame.len(), 17);
                let peer =
                    usize::try_from(u64::from_le_bytes(frame[1..9].try_into().unwrap())).unwrap();
                let ordinal =
                    usize::try_from(u64::from_le_bytes(frame[9..].try_into().unwrap())).unwrap();
                let action = match frame[0] {
                    0 if ordinal == 0 => PeerAction::Original,
                    1 => PeerAction::Blob(ordinal),
                    2 if ordinal == 0 => PeerAction::Submit,
                    3 if ordinal == 0 => PeerAction::Checkpoint,
                    _ => panic!("Unexpected ordinary-I/O test action"),
                };
                observed.push((peer, action));
                let reply = match response {
                    StepResponse::Ack => vec![0],
                    StepResponse::Busy => vec![1],
                    StepResponse::Reject => vec![2],
                    StepResponse::Disconnect => {
                        socket.shutdown(std::net::Shutdown::Both).unwrap();
                        continue;
                    }
                    StepResponse::PausedCheckpoint {
                        bytes,
                        ready,
                        release,
                    } => {
                        ready.send(()).unwrap();
                        release.recv_timeout(STEP_WAIT).unwrap();
                        let mut reply = vec![3];
                        reply.extend(bytes);
                        reply
                    }
                };
                peer_transport::write_frame(&mut socket, &reply, 64 * 1024).unwrap();
            }
            observed
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> Vec<(usize, PeerAction)> {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for StepServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, Ordering::Release);
            // Wake an accept after an assertion failure; in-flight frame/channel
            // waits retain their own finite bounds. Every test worker is joined.
            let _ = std::net::TcpStream::connect_timeout(&self.address, STEP_WAIT);
            let _ = worker.join();
        }
    }
}
fn step_rpc(
    address: std::net::SocketAddr,
    peer: usize,
    action: PeerAction,
) -> PeerResult<StepReply> {
    let result = (|| -> io::Result<StepReply> {
        let mut socket = std::net::TcpStream::connect_timeout(&address, STEP_WAIT)?;
        socket.set_read_timeout(Some(STEP_WAIT))?;
        socket.set_write_timeout(Some(STEP_WAIT))?;
        let (tag, ordinal) = match action {
            PeerAction::Original => (0, 0),
            PeerAction::Blob(n) => (1, n),
            PeerAction::Submit => (2, 0),
            PeerAction::Checkpoint => (3, 0),
        };
        let mut frame = vec![tag];
        frame.extend(u64::try_from(peer).unwrap().to_le_bytes());
        frame.extend(u64::try_from(ordinal).unwrap().to_le_bytes());
        peer_transport::write_frame(&mut socket, &frame, 17)?;
        let reply = peer_transport::read_frame(&mut socket, 64 * 1024)?;
        match reply.as_slice() {
            [0] => Ok(StepReply::Completed(None)),
            [1] => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Untrusted test BUSY",
            )),
            [2] => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Untrusted test REJECT",
            )),
            [3, bytes @ ..] => JointCheckpoint::decode(bytes)
                .map(|checkpoint| StepReply::Completed(Some(Box::new(checkpoint))))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Test reply shape",
            )),
        }
    })();
    result.map_err(PeerFailure::Remote)
}
fn uploading() -> PeerProgress {
    PeerProgress {
        busy: AtomicBool::new(false),
        stage: AtomicU8::new(0),
        ordinal: AtomicUsize::new(0),
        original_attempted: AtomicBool::new(false),
    }
}

#[test]
fn late_busy_retries_only_the_current_blob_and_original_submit_is_observed_once() {
    let server = StepServer::new(vec![
        StepResponse::Reject,
        StepResponse::Ack,
        StepResponse::Busy,
        StepResponse::Ack,
        StepResponse::Ack,
        StepResponse::Ack,
        StepResponse::Ack,
    ]);
    let peer = uploading();
    for _ in 0..3 {
        let result = peer.perform(
            &SubmissionOrder::SavedOriginal,
            3,
            || true,
            |action| step_rpc(server.address, 0, action),
        );
        assert!(observe_peer(&peer, result).unwrap().is_none());
    }
    assert_eq!(peer.position(), (0, 1, true));
    for _ in 0..4 {
        let result = peer.perform(
            &SubmissionOrder::SavedOriginal,
            3,
            || true,
            |action| step_rpc(server.address, 0, action),
        );
        assert!(observe_peer(&peer, result).unwrap().is_none());
    }
    assert_eq!(peer.position(), (2, 3, true));
    assert_eq!(
        server.finish(),
        vec![
            (0, PeerAction::Original),
            (0, PeerAction::Blob(0)),
            (0, PeerAction::Blob(1)),
            (0, PeerAction::Blob(1)),
            (0, PeerAction::Blob(2)),
            (0, PeerAction::Submit),
            (0, PeerAction::Checkpoint),
        ]
    );
}

#[test]
fn fourth_peer_receives_io_before_the_first_peers_large_upload_finishes() {
    let server = StepServer::new(vec![StepResponse::Ack, StepResponse::Ack]);
    let scheduler = Scheduler {
        next: AtomicUsize::new(0),
        stopped: AtomicBool::new(false),
        peers: (0..4).map(|_| uploading()).collect(),
    };
    let (a, held_a) = scheduler.claim().unwrap();
    let (b, held_b) = scheduler.claim().unwrap();
    let (c, held_c) = scheduler.claim().unwrap();
    assert_eq!([a, b, c], [0, 1, 2]);
    let first = &scheduler.peers[a];
    let result = first.perform(
        &SubmissionOrder::Fresh,
        256,
        || true,
        |action| step_rpc(server.address, a, action),
    );
    assert!(observe_peer(first, result).unwrap().is_none());
    assert_eq!(first.position(), (0, 1, false));
    drop(held_a);
    let (fourth, held_fourth) = scheduler.claim().unwrap();
    assert_eq!(fourth, 3);
    let result = scheduler.peers[fourth].perform(
        &SubmissionOrder::Fresh,
        256,
        || true,
        |action| step_rpc(server.address, fourth, action),
    );
    assert!(
        observe_peer(&scheduler.peers[fourth], result)
            .unwrap()
            .is_none()
    );
    drop((held_b, held_c, held_fourth));
    assert_eq!(
        server.finish(),
        vec![(0, PeerAction::Blob(0)), (3, PeerAction::Blob(0))]
    );
}

#[test]
fn lost_ack_never_advances_the_blob_and_keeps_existing_remote_failure_classification() {
    let server = StepServer::new(vec![StepResponse::Ack, StepResponse::Disconnect]);
    let peer = uploading();
    let first = peer.perform(
        &SubmissionOrder::Fresh,
        3,
        || true,
        |action| step_rpc(server.address, 0, action),
    );
    assert!(observe_peer(&peer, first).unwrap().is_none());
    let lost = peer.perform(
        &SubmissionOrder::Fresh,
        3,
        || true,
        |action| step_rpc(server.address, 0, action),
    );
    assert!(observe_peer(&peer, lost).unwrap().is_none());
    assert_eq!(peer.position(), (3, 1, false));
    assert!(
        peer.perform(
            &SubmissionOrder::Fresh,
            3,
            || true,
            |_| { panic!("A disqualified peer must make no new RPC") }
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        server.finish(),
        vec![(0, PeerAction::Blob(0)), (0, PeerAction::Blob(1))]
    );
}

#[test]
fn cancellation_during_actual_checkpoint_io_discards_even_a_genuine_qc_and_stops_new_calls() {
    let (context, keys, candidate) = fixture();
    let checkpoint = qc(&context, &keys, candidate);
    context
        .verify_commit(
            checkpoint.candidate().encode().as_slice(),
            0,
            checkpoint.certificate(),
        )
        .unwrap();
    let (ready, observed) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let server = StepServer::new(vec![StepResponse::PausedCheckpoint {
        bytes: checkpoint.encode(),
        ready,
        release: wait,
    }]);
    let address = server.address;
    let active = Arc::new(AtomicBool::new(true));
    let running = active.clone();
    let (peer, result) = thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let peer = progress();
            let result = peer.perform(
                &SubmissionOrder::Fresh,
                0,
                || running.load(Ordering::Acquire),
                |action| step_rpc(address, 0, action),
            );
            (peer, result)
        });
        observed.recv_timeout(STEP_WAIT).unwrap();
        active.store(false, Ordering::Release);
        release.send(()).unwrap();
        worker.join().unwrap()
    });
    assert!(result.unwrap().is_none());
    assert!(
        peer.perform(
            &SubmissionOrder::Fresh,
            0,
            || active.load(Ordering::Acquire),
            |_| { panic!("A cancelled operation must start no new RPC") }
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(server.finish(), vec![(0, PeerAction::Checkpoint)]);
}
