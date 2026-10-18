//! Owning examples. Server-thread TLS is explicit here; the CLI owns a distinct OS daemon.
use super::super::super::model::{Command, Operation as ControlOperation};
use super::fixture::Fixture;
use super::*;
use crate::opening::peer_process::PublicPeer;
use std::cell::Cell;

fn assert_plain(f: &Fixture, checked: &VerifiedEncryptedProjection) {
    let actual = f
        .owner
        .decrypt_public_select_unverified_for_experiment(
            checked.request(),
            checked.encrypted_response(),
        )
        .unwrap();
    assert_eq!(actual, f.oracle); // All8192 original/restored slots, not an echoed answer.
    assert_eq!(
        checked.checked().operation(),
        Operation::PublicPolynomialProduct
    );
}
fn received_from(f: &Fixture, prepared: Prepared, reply: ProofReply) -> Received {
    prepared.require_expected(&f.expected).unwrap();
    Received { prepared, reply }
}

#[test]
fn real_tls_sparse_skip_projection_checks_complete_inputs_arithmetic_and_original_owner_slots() {
    let f = Fixture::new(1, 1).unwrap();
    // No TLS/Store/InstallSetup/Prove I/O has happened during source/owner proof preparation.
    let prepared = f.prepare().unwrap();
    prepared
        .check_before_io(&f.expected, f.history.journal())
        .unwrap();
    let peer = PublicPeer::start(&f.bundle).unwrap();
    let checked = prepared
        .run_remote(&f.expected, f.history.journal(), &peer.remote)
        .unwrap();
    assert_plain(&f, &checked);
    assert_eq!(checked.identity(), f.expected.identity());
    assert!(peer.last_request_id().unwrap() > 0);

    // Exact compiler/root/packet/request pins fail before another worker handoff.
    for bad_encoding in f
        .expected
        .formation
        .encoding
        .formation_context_attack_cases()
    {
        let mut bad = f.expected.clone();
        bad.formation.encoding = bad_encoding;
        let handed_to_worker = Cell::new(false);
        let attempt = (|| {
            let p = prepare(
                &bad,
                f.history.journal(),
                &f.product.encoding_frame,
                &f.product.prerequisites(),
                &f.product.evidence,
            )?;
            handed_to_worker.set(true);
            Ok::<_, Error>(p)
        })();
        assert!(attempt.is_err());
        assert!(!handed_to_worker.get());
    }
    for missing in 0..8 {
        let mut p = f.product.prerequisites();
        let mut encoded = f.product.encoding_frame.as_slice();
        let mut formed = f.product.evidence.as_slice();
        match missing {
            0 => encoded = &[],
            1 => p.key = &[],
            2..=6 => p.bases[missing - 2] = &[],
            _ => formed = &[],
        }
        assert!(prepare(&f.expected, f.history.journal(), encoded, &p, formed).is_err());
    }
    let mut wrong = f.expected.clone();
    wrong.binding.request[31] ^= 1;
    assert!(
        f.prepare()
            .unwrap()
            .check_before_io(&wrong, f.history.journal())
            .is_err()
    );
    let mut wrong = f.expected.clone();
    wrong.binding.query_id[15] ^= 1;
    assert!(
        f.prepare()
            .unwrap()
            .check_before_io(&wrong, f.history.journal())
            .is_err()
    );
    let setup = PublicSetup::from_bytes(&f.expected.setup_bytes).unwrap();
    let other_handle = f
        .owner
        .key_anchor(&setup, f.expected.anchor.scope().clone())
        .unwrap();
    let mut wrong = f.expected.clone();
    wrong.anchor = other_handle.public_anchor().clone();
    assert_ne!(
        wrong.anchor.coefficient_commitment(),
        f.expected.anchor.coefficient_commitment()
    );
    assert!(
        f.prepare()
            .unwrap()
            .check_before_io(&wrong, f.history.journal())
            .is_err()
    );
    assert!(
        Expected::new(
            wrong.formation.clone(),
            wrong.statement.clone(),
            wrong.anchor.clone(),
            wrong.control.clone(),
            wrong.binding.clone(),
            &wrong.setup_bytes
        )
        .is_err()
    );
    let received = f
        .prepare()
        .unwrap()
        .send(&f.expected, f.history.journal(), &peer.remote)
        .unwrap();
    assert!(received.finish(&wrong, f.history.journal()).is_err());
    drop(other_handle);

    // A genuine foreign public-projection operation verifies under its own full
    // wire, but cannot replace this exact independently bound amount operation.
    let evaluator = PublicUpdateEvaluator::from_parameters(&f.expected.parameters).unwrap();
    let context = QueryContext::new(
        f.expected.binding.query_id,
        f.expected.binding.target.data_head().encode(),
        f.expected.binding.target.index_head().encode(),
    );
    let request = evaluator
        .encode_public_select(
            context,
            RowProjection::Age,
            f.expected.formation.mathematical.ciphertext().bytes(),
        )
        .unwrap();
    let canonical = evaluator.select_circuit_request(&request).unwrap();
    let foreign = bfv_query_proof::prove(&canonical).unwrap();
    bfv_query_proof::verify(&canonical, foreign.output(), foreign.proof()).unwrap();
    let reply = ProofReply {
        output: foreign.output().to_vec(),
        proof: foreign.proof().to_vec(),
    };
    assert!(
        received_from(&f, f.prepare().unwrap(), reply)
            .finish(&f.expected, f.history.journal())
            .is_err()
    );
    let prepared = f.prepare().unwrap();
    let mut received = prepared
        .send(&f.expected, f.history.journal(), &peer.remote)
        .unwrap();
    received.reply.proof.clear();
    assert!(received.finish(&f.expected, f.history.journal()).is_err());
    let prepared = f.prepare().unwrap();
    let mut received = prepared
        .send(&f.expected, f.history.journal(), &peer.remote)
        .unwrap();
    *received.reply.output.last_mut().unwrap() ^= 1;
    assert!(received.finish(&f.expected, f.history.journal()).is_err());
    peer.corrupt_index_tail(*f.expected.binding.target.object())
        .unwrap();
    assert!(
        f.prepare()
            .unwrap()
            .send(&f.expected, f.history.journal(), &peer.remote)
            .is_err()
    );
}

#[test]
fn actual_limit_zero_and_all_skipped_histories_project_zero_ciphertexts_without_grant() {
    for (limit, other_limit) in [(0, 1), (1, 4)] {
        let f = Fixture::new(limit, other_limit).unwrap();
        let prepared = f.prepare().unwrap();
        prepared
            .check_before_io(&f.expected, f.history.journal())
            .unwrap();
        let peer = PublicPeer::start(&f.bundle).unwrap();
        let checked = prepared
            .run_remote(&f.expected, f.history.journal(), &peer.remote)
            .unwrap();
        assert_plain(&f, &checked);
        assert!(f.oracle.iter().all(|x| *x == 0));
    }
}

#[test]
fn delayed_real_reply_rejects_transaction_end_release_and_new_id_reacquire_even_with_exact_old_policy()
 {
    let mut f = Fixture::new(1, 1).unwrap();
    let prepared = f.prepare().unwrap();
    let peer = PublicPeer::start(&f.bundle).unwrap();
    let received = prepared
        .send(&f.expected, f.history.journal(), &peer.remote)
        .unwrap();
    // Empty confirmation descendants preserve the exact admitted control context.
    f.history.confirm().unwrap();
    f.expected.check_control(f.history.journal()).unwrap();
    // EndCommit removes transaction1 and releases its real held rows. This is
    // NOT RELEASE SAVEPOINT, which intentionally preserves row locks.
    f.history
        .transition(Command::control(ControlOperation::End, 1, 1, 0))
        .unwrap();
    let mut exact = f.expected.clone();
    exact.binding.freshness = Freshness::Exact(exact.control.acquired());
    // Exact(oldAcquire) itself remains a valid confirmed ancestor, but the real
    // current best control guard rejects ownership reuse before and after RPC.
    f.history
        .journal()
        .resolve(exact.binding.freshness)
        .unwrap();
    assert!(exact.check_control(f.history.journal()).is_err());
    assert!(f.expected.check_control(f.history.journal()).is_err());
    // Preserve original Expected identity: this must reach actual product verification
    // and the post-RPC control gate, rather than fail an unrelated metadata check.
    assert!(matches!(
        received.finish(&f.expected, f.history.journal()),
        Err(Error::Journal(version_journal::Error::StaleHead))
    ));
    // Allocation never reuses ID1: the same principal begins ID3 and genuinely
    // re-acquires the released rows under a different control revision/sequence.
    f.history
        .transition(Command::control(ControlOperation::Begin, 3, 1, 0))
        .unwrap();
    let mut again = Command::control(ControlOperation::Acquire, 3, 1, 0);
    again.mask[16..].fill(255);
    again.mode = 4;
    again.wait = 2;
    again.offset = 1;
    again.limit = 1;
    again.projection = 2;
    f.history.transition(again).unwrap();
    assert!(f.expected.check_control(f.history.journal()).is_err());
    assert!(f.prepare().is_err());
}

#[test]
fn delayed_real_reply_rejects_same_root_sibling_reorganization_by_acquire_ancestry() {
    let mut f = Fixture::new(1, 1).unwrap();
    // LatestConfirmed itself can resolve the new same-root branch; explicit
    // acquired-block ancestry must still reject the old job after actual arithmetic.
    f.expected.binding.freshness = Freshness::LatestConfirmed;
    let prepared = f.prepare().unwrap();
    let peer = PublicPeer::start(&f.bundle).unwrap();
    let received = prepared
        .send(&f.expected, f.history.journal(), &peer.remote)
        .unwrap();
    f.history.losing_same_root_sibling().unwrap();
    assert!(matches!(
        f.history.journal().resolve(f.history.policy()),
        Err(version_journal::Error::Reorganized)
    ));
    assert!(
        f.history
            .journal()
            .resolve(Freshness::LatestConfirmed)
            .is_ok()
    );
    assert!(matches!(
        f.expected.check_control(f.history.journal()),
        Err(Error::Journal(version_journal::Error::StaleHead))
    ));
    assert!(matches!(
        received.finish(&f.expected, f.history.journal()),
        Err(Error::Journal(version_journal::Error::StaleHead))
    ));
}

#[test]
fn durable_public_history_reopens_with_real_proofs_and_exact_retry_preserves_control_context() {
    let (history, product) = super::super::super::journal::projection_input(1, 1).unwrap();
    drop(product); // Hiding proof replay recovers public heads, never this private opening.
    history.check_durable_reopen_and_retry().unwrap();
}
