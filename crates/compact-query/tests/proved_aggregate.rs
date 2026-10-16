//! Public source fixtures cross the actual serialized full-residue proof boundary.
#![cfg(feature = "bfv-experiment")]
use bfv_query_core::{PublicSetup, PublicUpdateEvaluator};
use compact_query::{AgeRange, Error, PlainRow, bfv::Owner};
use compact_store::Limits;

#[test]
fn complete_authenticated_extreme_sources_have_genuine_aggregate_evidence_and_refuse_tampering() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([92; 16]).unwrap();
    let setup =
        PublicSetup::from_bytes(&peer.encode_public_setup_for_experiment().unwrap()).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let rows = vec![
        PlainRow {
            age: 18,
            amount: 65535
        };
        256
    ];
    let table = owner.seal(&rows, 17, limits).unwrap();
    let prepared = owner
        .prepare_provable_aggregate(&table, Some(AgeRange::equal(18)), 256, limits)
        .unwrap();
    let input = evaluator
        .aggregate_circuit_request(prepared.request())
        .unwrap();
    let generated = bfv_query_proof::prove(&input).unwrap();
    let mut altered = generated.output().to_vec();
    *altered.last_mut().unwrap() ^= 1;
    assert!(
        owner
            .check_aggregate_proof(&table, &prepared, &altered, generated.proof())
            .is_err()
    );
    let mut damaged = generated.proof().to_vec();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    assert!(
        owner
            .check_aggregate_proof(&table, &prepared, generated.output(), &damaged)
            .is_err()
    );
    let other = owner
        .seal(&[PlainRow { age: 18, amount: 1 }], 17, limits)
        .unwrap();
    assert!(matches!(
        owner.check_aggregate_proof(&other, &prepared, generated.output(), generated.proof()),
        Err(Error::WrongVersion)
    ));
    let checked = owner
        .check_aggregate_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let second = owner
        .prepare_provable_aggregate(&table, Some(AgeRange::equal(18)), 256, limits)
        .unwrap();
    assert!(
        owner
            .complete_checked_aggregate(&table, second, generated.output(), checked)
            .is_err()
    );
    let checked = owner
        .check_aggregate_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();

    let answer = owner
        .complete_checked_aggregate(&table, prepared, generated.output(), checked)
        .unwrap();

    assert_eq!((answer.count(), answer.sum()), (256, Some(16_776_960)));
    assert_eq!(
        answer.evidence().operation(),
        bfv_query_proof::Operation::PublicPolynomialProduct
    );
}

#[test]
fn an_empty_complete_selection_has_encrypted_zero_count_and_sql_null_sum() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([93; 16]).unwrap();
    let setup =
        PublicSetup::from_bytes(&peer.encode_public_setup_for_experiment().unwrap()).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let table = owner
        .seal(
            &[PlainRow {
                age: 18,
                amount: 65535,
            }],
            17,
            limits,
        )
        .unwrap();
    for predicate in [None, Some(AgeRange::equal(7))] {
        let prepared = owner
            .prepare_provable_aggregate(&table, predicate, 256, limits)
            .unwrap();
        let input = evaluator
            .aggregate_circuit_request(prepared.request())
            .unwrap();
        let generated = bfv_query_proof::prove(&input).unwrap();
        let checked = owner
            .check_aggregate_proof(&table, &prepared, generated.output(), generated.proof())
            .unwrap();

        let answer = owner
            .complete_checked_aggregate(&table, prepared, generated.output(), checked)
            .unwrap();

        assert_eq!((answer.count(), answer.sum()), (0, None));
    }
}
