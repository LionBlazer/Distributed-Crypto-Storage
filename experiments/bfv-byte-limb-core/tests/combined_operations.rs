//! Public non-secret fixtures check three operations sharing one unchanged owner/public setup.
use compact_bfv_byte_limb_core::{
    Geometry, Owner, PeerEvaluator, Predicate, ProofStatus, PublicSetup, QueryContext,
    SelectedField, UnverifiedUpdateOutcome,
};

#[test]
fn one_owner_and_setup_reuse_all_three_operations_without_crossing_wire_domains() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let setup_wire = setup.to_bytes().unwrap();
    let restored = PublicSetup::from_bytes(&setup_wire).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), setup_wire);
    let peer = PeerEvaluator::from_public_setup(&restored).unwrap();
    let context = QueryContext::new([82; 16], [2; 112], [3; 112]);
    let fields = [
        SelectedField {
            age: 18,
            amount: 255,
            active: true,
        },
        SelectedField {
            age: 18,
            amount: 256,
            active: true,
        },
    ];
    // Public fixture fulfills the exact age check. Real callers must additionally authenticate
    // complete postings, unique ordinals and every field against both current trusted heads.
    assert!(
        fields
            .iter()
            .filter(|field| field.active)
            .all(|field| field.age == 18)
    );
    let exact = owner
        .prepare_exact_index_aggregate_for_experiment(context.clone(), &fields)
        .unwrap();
    let update = owner
        .prepare_indexed_update_for_experiment(context.clone(), &fields, 1)
        .unwrap();
    assert!(peer.evaluate_indexed_update(&exact.request).is_err());
    assert!(
        peer.evaluate_exact_index_aggregate_for_experiment(&update.request)
            .is_err()
    );
    let exact_result = peer
        .evaluate_exact_index_aggregate_for_experiment(&exact.request)
        .unwrap();
    let update_result = peer.evaluate_indexed_update(&update.request).unwrap();
    let wrong_update = owner
        .prepare_indexed_update_for_experiment(context.clone(), &fields, 1)
        .unwrap();
    let wrong_exact = owner
        .prepare_exact_index_aggregate_for_experiment(context.clone(), &fields)
        .unwrap();
    assert!(
        owner
            .decrypt_indexed_update_unverified_for_experiment(
                wrong_update.pending,
                &exact_result.output
            )
            .is_err()
    );
    assert!(
        owner
            .decrypt_exact_index_unverified_for_experiment(
                wrong_exact.pending,
                &update_result.output
            )
            .is_err()
    );
    let aggregate = owner
        .decrypt_exact_index_unverified_for_experiment(exact.pending, &exact_result.output)
        .unwrap();
    assert_eq!((aggregate.count, aggregate.sum), (2, 511));
    assert_eq!(aggregate.proof, ProofStatus::Unavailable);
    let updated = owner
        .decrypt_indexed_update_unverified_for_experiment(update.pending, &update_result.output)
        .unwrap();
    let UnverifiedUpdateOutcome::Values(updated) = updated else {
        panic!("Unexpected overflow")
    };
    let amounts: Vec<_> = updated
        .rows
        .iter()
        .map(|row| (row.slot, row.amount))
        .collect();
    assert_eq!(amounts, vec![(0, 256), (1, 257)]);
    assert_eq!(updated.proof, ProofStatus::Unavailable);
    // The legacy encrypted predicate still works on the same owner/evaluator after both new modes.
    let read = owner
        .prepare(context, &fields, Predicate::Equal(18))
        .unwrap();
    let read_result = peer.evaluate(&read.request).unwrap();
    let read = owner
        .decrypt_unverified(read.pending, &read_result.output)
        .unwrap();
    assert_eq!((read.count, read.sum), (2, 511));
    assert_eq!(read.proof, ProofStatus::Unavailable);
    assert_eq!(setup.to_bytes().unwrap(), setup_wire);
}
