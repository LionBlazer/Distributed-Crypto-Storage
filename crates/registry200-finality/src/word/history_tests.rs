//! Real native Word and real weighted signatures under PUBLIC NONSECRET keys.
use super::*;
use sha2::{Digest, Sha256};
use work_finality::{QuorumCertificate, SignedVote, Step, VoteContext, consensus::Context};

fn certified(b: &Binding, context: &Context, block: &CandidateBlock, round: u64) -> Checkpoint {
    let candidate = Candidate::for_context(b, context, block.header().clone()).unwrap();
    certify_candidate(context, candidate, round)
}
fn certify_candidate(context: &Context, candidate: Candidate, round: u64) -> Checkpoint {
    let mut domain = Sha256::new();
    domain.update(b"dcs/work-finality/consensus-vote-instance/v1");
    domain.update(work_finality::profile_digest());
    domain.update(context.id());
    let vote = VoteContext::new(
        context.set(),
        domain.finalize().into(),
        context.slot(),
        round,
        Step::Precommit,
        Some(context.value_id(&candidate.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = keys()
        .iter()
        .take(3)
        .map(|key| SignedVote::sign(vote, key).unwrap())
        .collect();
    let bytes = QuorumCertificate::assemble(context.set(), &vote, &votes)
        .unwrap()
        .encode()
        .unwrap();
    Checkpoint::new(candidate, round, bytes).unwrap()
}
fn altered(
    b: &Binding,
    original: &CandidateBlock,
    change: impl FnOnce(&mut AuthorizedTransition),
) -> CandidateBlock {
    let Body::Transition(mut transition) =
        Body::decode(original.body(), &b.journal_genesis().profile).unwrap()
    else {
        panic!("expected original owner transition")
    };
    change(&mut transition);
    let body = Body::Transition(transition)
        .encode(&b.journal_genesis().profile)
        .unwrap();
    let mut header = original.header().clone();
    header.body_hash = version_journal::hash(&body);
    header.nonce = 0;
    header.mine(16).unwrap();
    CandidateBlock::new(header, body).unwrap()
}
fn own_id(
    a: &Application,
    block: &CandidateBlock,
    b: &Binding,
) -> registry200_joint::word::OperationId {
    let Body::Transition(t) = Body::decode(block.body(), &b.journal_genesis().profile).unwrap()
    else {
        panic!("expected original owner transition")
    };
    registry200_joint::word::OperationId::new(a, &Request::decode(&t.request).unwrap(), &t.proof)
        .unwrap()
}

#[test]
fn history_requires_original_intent_and_rechecks_only_the_latest_semantic_retry() {
    let b = binding();
    let f = fixture();
    let a = Application::new(f.descriptor.clone(), b.journal_genesis()).unwrap();
    let (r, e, bank) = boot(f, &a, b.journal_genesis().id().unwrap());
    let boot = block(&b, r.parent(), 1, &r, &e, Control::Pending);
    let intended = own_id(&a, &boot, &b);
    let mut history = History::new(b.clone()).unwrap();
    let context = history.context().unwrap().clone();
    let qc = certified(&b, &context, &boot, 0);
    let different = altered(&b, &boot, |t| {
        t.request[80] ^= 1;
        t.sign(b.journal_genesis().id().unwrap(), &owner());
    });
    let other_intent = own_id(&a, &different, &b);
    let untouched = history.journal_state_for_test(boot.header().id());
    assert!(history.apply_operation(&qc, &boot, other_intent).is_err());
    assert_eq!(
        history.journal_state_for_test(boot.header().id()),
        untouched
    );
    assert_eq!(history.context().unwrap().id(), context.id());

    let substituted = certified(&b, &context, &different, 0);
    let different_before = history.journal_state_for_test(different.header().id());
    assert!(
        history
            .apply_operation(&substituted, &different, intended)
            .is_err()
    );
    assert_eq!(
        history.journal_state_for_test(different.header().id()),
        different_before
    );

    let checked = history.apply_operation(&qc, &boot, intended).unwrap();
    assert_eq!(checked.operation().operation_id(), intended);
    assert!(checked.operation().bootstrap().is_some());
    assert_eq!(checked.parent().head().block, boot.header().id());
    assert_eq!(history.context().unwrap().slot(), 2);
    let published = history.journal_state_for_test(boot.header().id());
    // Another valid certificate for the same semantic decision is read-only.
    let retry = certified(&b, &context, &boot, 1);
    let again = history.apply_operation(&retry, &boot, intended).unwrap();
    assert_eq!(again.parent().decision_id(), checked.parent().decision_id());
    assert_eq!(
        history.journal_state_for_test(boot.header().id()),
        published
    );
    assert!(
        history
            .apply_operation(&retry, &boot, other_intent)
            .is_err()
    );
    assert_eq!(
        history.journal_state_for_test(boot.header().id()),
        published
    );

    let (r, e) = begin(f, &a, boot.header().id(), bank);
    let before = Control::Active {
        enrollment: r.enrollment(),
        registry: r.claims().old,
    };
    let begin = block(&b, boot.header().id(), 2, &r, &e, before);
    let intended = own_id(&a, &begin, &b);
    let qc2 = certified(&b, history.context().unwrap(), &begin, 0);
    let checked = history.apply_operation(&qc2, &begin, intended).unwrap();
    assert!(checked.operation().control().is_some());
    assert_eq!(checked.parent().head().block, begin.header().id());
    assert_eq!(history.checked_parent().unwrap().unwrap().slot(), 2);
    let published = history.journal_state_for_test(boot.header().id());
    assert!(
        history.apply(&qc, &boot).is_err(),
        "an ancient valid QC cannot roll back history"
    );
    assert_eq!(
        history.journal_state_for_test(boot.header().id()),
        published
    );
    assert_eq!(history.context().unwrap().slot(), 3);
}

#[test]
fn history_never_publishes_bad_qc_owner_native_proof_or_foreign_binding() {
    let b = binding();
    let f = fixture();
    let a = Application::new(f.descriptor.clone(), b.journal_genesis()).unwrap();
    let (r, e, bank) = boot(f, &a, b.journal_genesis().id().unwrap());
    let boot = block(&b, r.parent(), 1, &r, &e, Control::Pending);
    let mut history = History::new(b.clone()).unwrap();
    let qc = certified(&b, history.context().unwrap(), &boot, 0);
    history.apply(&qc, &boot).unwrap();
    let (r, e) = begin(f, &a, boot.header().id(), bank);
    let before = Control::Active {
        enrollment: r.enrollment(),
        registry: r.claims().old,
    };
    let begin = block(&b, boot.header().id(), 2, &r, &e, before);
    let expected = own_id(&a, &begin, &b);
    let context = history.context().unwrap().clone();
    let valid_qc = certified(&b, &context, &begin, 0);
    let mut bytes = valid_qc.certificate().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    let bad_qc = Checkpoint::new(valid_qc.candidate().clone(), 0, bytes).unwrap();
    let untouched = history.journal_state_for_test(begin.header().id());
    assert!(history.apply_operation(&bad_qc, &begin, expected).is_err());
    assert_eq!(
        history.journal_state_for_test(begin.header().id()),
        untouched
    );

    let bad_owner = altered(&b, &begin, |t| t.owner_signature = [0; 64]);
    let bad_proof = altered(&b, &begin, |t| {
        *t.proof.last_mut().unwrap() ^= 1;
        t.sign(b.journal_genesis().id().unwrap(), &owner());
    });
    // These QCs use genuine fixture signatures deliberately even for bad work:
    // the independent receiver must not use a QC as computation verification.
    for (name, bad) in [("owner", bad_owner), ("native Word", bad_proof)] {
        let id = own_id(&a, &bad, &b);
        let qc = certified(&b, &context, &bad, 0);
        let untouched = history.journal_state_for_test(bad.header().id());
        assert!(history.apply_operation(&qc, &bad, id).is_err(), "{name}");
        assert_eq!(history.journal_state_for_test(bad.header().id()), untouched);
        assert_eq!(history.context().unwrap().id(), context.id());
    }
    for offset in [8, 48] {
        // binding and previous decision are independent pins.
        let mut bytes = valid_qc.candidate().encode();
        bytes[offset] ^= 1;
        let foreign = Candidate::decode(&bytes).unwrap();
        let foreign = certify_candidate(&context, foreign, 0);
        context
            .verify_commit(
                &foreign.candidate().encode(),
                foreign.round(),
                foreign.certificate(),
            )
            .unwrap();
        assert!(history.apply(&foreign, &begin).is_err());
        assert_eq!(
            history.journal_state_for_test(begin.header().id()),
            untouched
        );
    }
    let checked = history
        .apply_operation(&valid_qc, &begin, expected)
        .unwrap();
    assert_eq!(checked.parent().slot(), 2);
    assert_eq!(history.context().unwrap().slot(), 3);
}

#[test]
fn history_verifies_immutable_source_and_empty_cannot_mint_an_own_operation() {
    let b = binding();
    let f = fixture();
    let mut damaged = b.source_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let bad_binding = Binding::new(
        f.descriptor.network(),
        b.rules().clone(),
        b.work_genesis().clone(),
        b.journal_genesis().clone(),
        b.application_descriptor().clone(),
        &damaged,
    )
    .unwrap();
    assert!(History::new(bad_binding).is_err());
    let mut history = History::new(b.clone()).unwrap();
    let a = Application::new(f.descriptor.clone(), b.journal_genesis()).unwrap();
    let (r, e, _) = boot(f, &a, b.journal_genesis().id().unwrap());
    let intended = registry200_joint::word::OperationId::new(&a, &r, e.as_bytes()).unwrap();
    let empty = empty(&b);
    let qc = certified(&b, history.context().unwrap(), &empty, 0);
    let untouched = history.journal_state_for_test(empty.header().id());
    assert!(history.apply_operation(&qc, &empty, intended).is_err());
    assert_eq!(
        history.journal_state_for_test(empty.header().id()),
        untouched
    );
    assert!(history.checked_parent().unwrap().is_none());
    let parent = history.apply(&qc, &empty).unwrap();
    assert_eq!(parent.control(), Control::Pending);
    assert_eq!(history.context().unwrap().slot(), 2);
}
