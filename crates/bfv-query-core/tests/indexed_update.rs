//! All original values, ages, deltas and contexts are public non-secret fixtures.
use bfv_query_core::{
    Error, Geometry, MAX_WIRE_BYTES, Owner, PeerEvaluator, ProofStatus, PublicSetup, QueryContext,
    SelectedField, UnverifiedUpdateOutcome,
};
fn context(id: u8) -> QueryContext {
    QueryContext::new([id; 16], [2; 112], [3; 112])
}
fn field(amount: u16, active: bool) -> SelectedField {
    SelectedField {
        age: 250,
        amount,
        active,
    }
}
fn amounts(outcome: UnverifiedUpdateOutcome) -> Vec<(usize, u16, u16, u16)> {
    match outcome {
        UnverifiedUpdateOutcome::Values(values) => {
            assert_eq!(values.proof, ProofStatus::Unavailable);
            values
                .rows
                .into_iter()
                .map(|row| (row.slot, row.amount, row.low_limb_sum, row.high_limb_sum))
                .collect()
        }
        UnverifiedUpdateOutcome::Overflow { .. } => {
            panic!("Unexpected overflow for safe public fixture")
        }
    }
}
#[test]
fn byte_carry_and_exact_maximum_return_actual_encrypted_addition_results() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let cases = [
        (
            1,
            vec![0, 255, 256, 65280, 65534],
            vec![
                (0, 1, 1, 0),
                (1, 256, 256, 0),
                (2, 257, 1, 1),
                (3, 65281, 1, 255),
                (4, 65535, 255, 255),
            ],
        ),
        (
            255,
            vec![0, 255, 65280],
            vec![(0, 255, 255, 0), (1, 510, 510, 0), (2, 65535, 255, 255)],
        ),
        (
            256,
            vec![0, 255, 65279],
            vec![(0, 256, 0, 1), (1, 511, 255, 1), (2, 65535, 255, 255)],
        ),
        (65535, vec![0], vec![(0, 65535, 255, 255)]),
    ];
    for (delta, originals, expected) in cases {
        let fields: Vec<_> = originals
            .into_iter()
            .map(|amount| field(amount, true))
            .collect();
        let prepared = owner
            .prepare_indexed_update_for_experiment(context(1), &fields, delta)
            .unwrap();
        let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
        let actual = owner
            .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)
            .unwrap();
        assert_eq!(amounts(actual), expected);
        assert_eq!(evaluated.stats.ciphertext_additions, 1);
        assert_eq!(evaluated.stats.ct_ct_multiplications, 0);
        assert_eq!(evaluated.stats.rotations, 0);
        assert_eq!(evaluated.stats.multiplicative_depth, 0);
    }
}

#[test]
fn one_overflowing_last_row_returns_no_partially_accepted_batch() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let mut fields = vec![field(0, true); 256];
    fields[255] = field(65535, true);
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(2), &fields, 1)
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
    let actual = owner
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)
        .unwrap();
    assert_eq!(
        actual,
        UnverifiedUpdateOutcome::Overflow {
            proof: ProofStatus::Unavailable
        }
    );
}
#[test]
fn maximum_16_bit_addends_do_not_alias_to_a_valid_plaintext_residue() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(3), &vec![field(65535, true); 256], 65535)
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
    let actual = owner
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)
        .unwrap();
    assert_eq!(
        actual,
        UnverifiedUpdateOutcome::Overflow {
            proof: ProofStatus::Unavailable
        }
    );
    // A single plaintext-field implementation would wrap 131070 to this in-range value.
    assert_eq!(131070 % 114689, 16381);
}
#[test]
fn inactive_holes_and_missing_slots_stay_zero_without_losing_owner_slot_mapping() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = [field(255, true), field(65535, false), field(256, true)];
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(4), &fields, 1)
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
    let actual = owner
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)
        .unwrap();
    assert_eq!(amounts(actual), vec![(0, 256, 256, 0), (2, 257, 1, 1)]);
}
#[test]
fn empty_and_zero_delta_use_real_addition_with_fixed_request_and_response_lengths() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let mut shape = None;
    let mut previous = None;
    for count in [0, 1, 16, 256] {
        let fields = vec![field(65535, true); count];
        let prepared = owner
            .prepare_indexed_update_for_experiment(context(5), &fields, 0)
            .unwrap();
        let ciphertexts = prepared.ciphertext_payload_bytes().unwrap();
        if let Some(old) = previous.replace(ciphertexts.clone()) {
            assert_ne!(old, ciphertexts);
        }
        let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
        let current = (prepared.request.len(), evaluated.output.len());
        if let Some(old) = shape.replace(current) {
            assert_eq!(old, current);
        }
        assert_eq!(evaluated.stats.ciphertext_additions, 1);
        let actual = owner
            .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)
            .unwrap();
        let rows = amounts(actual);
        assert_eq!(rows.len(), count);
        assert!(
            rows.iter()
                .all(|(_, amount, low, high)| (*amount, *low, *high) == (65535, 255, 255))
        );
    }
}
#[test]
fn restored_public_setup_accepts_update_and_preserves_original_owner_keyset() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let wire = setup.to_bytes().unwrap();
    let restored = PublicSetup::from_bytes(&wire).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), wire);
    let peer = PeerEvaluator::from_public_setup(&restored).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(6), &[field(65280, true)], 255)
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
    let actual = owner
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)
        .unwrap();
    assert_eq!(amounts(actual), vec![(0, 65535, 255, 255)]);
}
#[test]
fn wrong_keyset_and_changed_query_or_heads_are_rejected_before_owner_completion() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let (other, other_setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let other_peer = PeerEvaluator::from_public_setup(&other_setup).unwrap();
    let fields = [field(10, true)];
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(7), &fields, 1)
        .unwrap();
    assert!(matches!(
        other_peer.evaluate_indexed_update(&prepared.request),
        Err(Error::BindingMismatch)
    ));
    let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
    let wrong_owner_pending = owner
        .prepare_indexed_update_for_experiment(context(7), &fields, 1)
        .unwrap()
        .pending;
    assert!(matches!(
        other.decrypt_indexed_update_unverified_for_experiment(
            wrong_owner_pending,
            &evaluated.output
        ),
        Err(Error::BindingMismatch)
    ));
    for changed in [
        QueryContext::new([8; 16], [2; 112], [3; 112]),
        QueryContext::new([7; 16], [4; 112], [3; 112]),
        QueryContext::new([7; 16], [2; 112], [4; 112]),
    ] {
        let pending = owner
            .prepare_indexed_update_for_experiment(changed, &fields, 1)
            .unwrap()
            .pending;
        assert!(matches!(
            owner.decrypt_indexed_update_unverified_for_experiment(pending, &evaluated.output),
            Err(Error::BindingMismatch)
        ));
    }
    assert_eq!(
        amounts(
            owner
                .decrypt_indexed_update_unverified_for_experiment(
                    prepared.pending,
                    &evaluated.output
                )
                .unwrap()
        ),
        vec![(0, 11, 11, 0)]
    );
}
#[test]
fn geometry_budget_trailing_and_oversized_wire_are_errors_not_partial_updates() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    assert!(matches!(
        owner.prepare_indexed_update_for_experiment(context(9), &[field(0, true); 17], 1),
        Err(Error::GeometryLimit)
    ));
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(9), &[field(0, true)], 1)
        .unwrap();
    let mut trailing = prepared.request.clone();
    trailing.push(1);
    assert!(peer.evaluate_indexed_update(&trailing).is_err());
    let mut response = peer
        .evaluate_indexed_update(&prepared.request)
        .unwrap()
        .output;
    response.push(1);
    assert!(
        owner
            .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &response)
            .is_err()
    );
    let oversized = vec![0; MAX_WIRE_BYTES as usize + 1];
    assert!(matches!(
        peer.evaluate_indexed_update(&oversized),
        Err(Error::WireLimit)
    ));
    let pending = owner
        .prepare_indexed_update_for_experiment(context(10), &[], 1)
        .unwrap()
        .pending;
    assert!(matches!(
        owner.decrypt_indexed_update_unverified_for_experiment(pending, &oversized),
        Err(Error::WireLimit)
    ));
}
