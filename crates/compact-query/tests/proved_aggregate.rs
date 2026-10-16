//! Public source fixtures cross the actual serialized full-residue proof boundary.
#![cfg(feature = "bfv-experiment")]
use bfv_query_core::{PublicSetup, PublicUpdateEvaluator};
use compact_query::{
    AgeSet256, Error, PlainRow,
    bfv::{Owner, POLYNOMIAL_AGGREGATE_CAPACITY},
};
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
        POLYNOMIAL_AGGREGATE_CAPACITY
    ];
    let table = owner.seal(&rows, 17, limits).unwrap();
    let prepared = owner
        .prepare_provable_aggregate(
            &table,
            AgeSet256::equal(18),
            POLYNOMIAL_AGGREGATE_CAPACITY,
            limits,
        )
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
    assert!(
        owner
            .check_aggregate_proof(&table, &prepared, generated.output(), &[])
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
        .prepare_provable_aggregate(
            &table,
            AgeSet256::equal(18),
            POLYNOMIAL_AGGREGATE_CAPACITY,
            limits,
        )
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

    assert_eq!((answer.count(), answer.sum()), (2560, Some(167_769_600)));
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
    for predicate in [AgeSet256::empty(), AgeSet256::equal(7)] {
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

#[test]
fn equal_final_answers_from_different_band_sources_cannot_exchange_genuine_proofs() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([94; 16]).unwrap();
    let setup =
        PublicSetup::from_bytes(&peer.encode_public_setup_for_experiment().unwrap()).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let source: Vec<_> = (0..257)
        .flat_map(|slot| {
            [
                PlainRow {
                    age: 18,
                    amount: if slot == 0 { 65535 } else { 0 },
                },
                PlainRow {
                    age: 7,
                    amount: if slot == 256 { 65535 } else { 0 },
                },
            ]
        })
        .collect();
    let table = owner.seal(&source, 256, limits).unwrap();
    let first = owner
        .prepare_provable_aggregate(
            &table,
            AgeSet256::equal(18),
            POLYNOMIAL_AGGREGATE_CAPACITY,
            limits,
        )
        .unwrap();
    let second = owner
        .prepare_provable_aggregate(
            &table,
            AgeSet256::equal(7),
            POLYNOMIAL_AGGREGATE_CAPACITY,
            limits,
        )
        .unwrap();
    let first_input = evaluator
        .aggregate_circuit_request(first.request())
        .unwrap();
    let second_input = evaluator
        .aggregate_circuit_request(second.request())
        .unwrap();
    let first_proof = bfv_query_proof::prove(&first_input).unwrap();
    let second_proof = bfv_query_proof::prove(&second_input).unwrap();
    assert!(
        owner
            .check_aggregate_proof(&table, &first, second_proof.output(), second_proof.proof())
            .is_err()
    );
    assert!(
        owner
            .check_aggregate_proof(&table, &second, first_proof.output(), first_proof.proof())
            .is_err()
    );
    for (prepared, generated) in [(first, first_proof), (second, second_proof)] {
        let checked = owner
            .check_aggregate_proof(&table, &prepared, generated.output(), generated.proof())
            .unwrap();
        let answer = owner
            .complete_checked_aggregate(&table, prepared, generated.output(), checked)
            .unwrap();
        assert_eq!((answer.count(), answer.sum()), (257, Some(65535)));
    }
}

#[test]
fn complete_aggregate_selection_refuses_overflow_without_widening_row_or_identity_operations() {
    let limits = Limits::default();
    let (owner, _) = Owner::generate([95; 16]).unwrap();
    let rows = vec![PlainRow { age: 18, amount: 1 }; POLYNOMIAL_AGGREGATE_CAPACITY + 1];
    let table = owner.seal(&rows, 256, limits).unwrap();
    for (predicate, budget, expected) in [
        (
            AgeSet256::equal(18),
            usize::MAX,
            POLYNOMIAL_AGGREGATE_CAPACITY,
        ),
        (AgeSet256::equal(18), 255, 255),
    ] {
        assert!(
            matches!(owner.prepare_provable_aggregate(&table, predicate, budget, limits), Err(Error::SelectionBudget { selected: 2561, budget }) if budget == expected)
        );
    }
    assert!(matches!(
        owner.prepare_provable_select(
            &table,
            AgeSet256::equal(18),
            bfv_query_core::RowProjection::AgeAmount,
            usize::MAX,
            limits
        ),
        Err(Error::SelectionBudget {
            selected: 2561,
            budget: 256
        })
    ));
    assert!(matches!(
        owner.prepare_provable_update(&table, AgeSet256::equal(18), 1, usize::MAX, limits),
        Err(Error::SelectionBudget {
            selected: 2561,
            budget: 256
        })
    ));
    assert!(matches!(
        owner.row_references(&table, &(0..257).collect::<Vec<_>>()),
        Err(Error::SelectionBudget {
            selected: 257,
            budget: 256
        })
    ));
    // Even a false predicate still checks the authenticated index/data binding.
    let empty = owner
        .prepare_provable_aggregate(&table, AgeSet256::equal(7), usize::MAX, limits)
        .unwrap();
    assert!(!empty.request().is_empty());
}
