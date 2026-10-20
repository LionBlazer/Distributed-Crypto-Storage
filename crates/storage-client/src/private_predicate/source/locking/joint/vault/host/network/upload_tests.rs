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
