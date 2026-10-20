//! PUBLIC NONSECRET inputs. Metadata is exercised against actual Work QCs.
use super::*;

fn accept_empty(
    history: &mut JointHistory,
    header: version_journal::Header,
) -> VerifiedJointParent {
    let block = CandidateBlock::new(
        header,
        Body::Empty
            .encode(&history.binding().journal_genesis().profile)
            .unwrap(),
    )
    .unwrap();
    let context = history.context().unwrap();
    let candidate =
        JointCandidate::for_context(history.binding(), context, block.header().clone()).unwrap();
    let checkpoint =
        JointCheckpoint::new(candidate.clone(), 0, certificate(context, &candidate, 0, 0)).unwrap();
    history.apply(&checkpoint, &block).unwrap()
}

#[test]
fn metadata_uses_owned_branch_retarget_and_rejects_stale_parent_time_or_owner_without_mutation() {
    let f = fixture();
    let directory = Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.root(), f.descriptor.id(), 10_000_000_000).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let setup = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let mut g = genesis(&f.descriptor);
    g.profile.retarget_interval = 2;
    let b = binding(g.clone(), setup);
    let mut history = JointHistory::new(b, depot).unwrap();
    let first = empty(&Journal::new(g.clone()).unwrap());
    let p1 = accept_empty(&mut history, first.header().clone());
    let before = HistorySnapshot::read(&history);
    let mut second = history
        .candidate_header(&p1, &Body::Empty, 1002, 1002)
        .unwrap();
    assert_eq!(
        second,
        history
            .journal
            .candidate(p1.head().block, &Body::Empty, 1002)
            .unwrap()
    );
    assert_eq!(HistorySnapshot::read(&history), before);
    second.mine(1).unwrap();
    let p2 = accept_empty(&mut history, second);
    let before = HistorySnapshot::read(&history);
    let third = history
        .candidate_header(&p2, &Body::Empty, 1003, 1003)
        .unwrap();
    assert_eq!(
        third.target,
        history.journal.next_target(p2.head().block).unwrap()
    );
    assert_ne!(
        third.target, g.profile.initial_target,
        "actual branch retarget, never an initial-target fixture"
    );
    assert!(
        history
            .candidate_header(&p1, &Body::Empty, 1003, 1003)
            .is_err()
    );
    assert!(
        history
            .candidate_header(&p2, &Body::Empty, 1000, 1003)
            .is_err()
    );
    assert!(
        history
            .candidate_header(&p2, &Body::Empty, 1064, 1003)
            .is_err()
    );
    let spec = history
        .binding()
        .application_descriptor()
        .source_spec()
        .unwrap();
    let mut unauthorized = AuthorizedTransition {
        parent: p2.head().block,
        request: vec![1],
        updates: vec![ShardUpdate {
            id: spec.control_id,
            old: p2.control().heads(&spec),
            new: p2.control().heads(&spec),
        }],
        proof: vec![],
        owner_signature: [0; 64],
    };
    unauthorized.sign(p2.head().genesis, &SigningKey::from_bytes(&[0x65; 32]));
    assert!(
        history
            .candidate_header(&p2, &Body::Transition(unauthorized), 1003, 1003)
            .is_err()
    );
    assert_eq!(
        HistorySnapshot::read(&history),
        before,
        "metadata failures publish no branch, floor or application state"
    );
}
