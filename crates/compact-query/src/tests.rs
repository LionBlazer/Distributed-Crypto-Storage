use crate::*;
use compact_store::Limits;
use std::sync::{Mutex, OnceLock};

fn roles() -> std::sync::MutexGuard<'static, (Owner, Evaluator)> {
    static ROLES: OnceLock<Mutex<(Owner, Evaluator)>> = OnceLock::new();
    ROLES
        .get_or_init(|| Mutex::new(Owner::generate([7; 16]).unwrap()))
        .lock()
        .unwrap()
}
fn run(
    owner: &Owner,
    evaluator: &Evaluator,
    table: &Table,
    selection: Selection,
    predicate: AgeRange,
    operation: Operation,
) -> (PreparedQuery, UnverifiedOutput) {
    let mut query = owner
        .prepare(
            table,
            selection,
            predicate,
            operation,
            MAX_ROWS,
            Limits::default(),
        )
        .unwrap();
    let request = query.encode_request().unwrap();
    let mut output = evaluator
        .evaluate(table.snapshot(), &request, Limits::default())
        .unwrap();
    let output = UnverifiedOutput::decode(&output.encode().unwrap()).unwrap();
    (query, output)
}
#[test]
fn full_scan_matches_misses_and_empty_return_exact_32_bit_aggregates() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let table = owner
        .seal(
            &[
                PlainRow {
                    age: 42,
                    amount: 65_535,
                },
                PlainRow {
                    age: 42,
                    amount: 65_535,
                },
                PlainRow { age: 7, amount: 3 },
            ],
            2,
            Limits::default(),
        )
        .unwrap();
    for (predicate, expected) in [
        (
            AgeRange::equal(42),
            Aggregate {
                count: 2,
                sum: 131_070,
            },
        ),
        (AgeRange::equal(99), Aggregate { count: 0, sum: 0 }),
    ] {
        let (query, output) = run(
            owner,
            evaluator,
            &table,
            Selection::FullScan,
            predicate,
            Operation::CountSum,
        );
        assert_eq!(
            owner
                .decrypt_aggregate_for_experiment(&table, &query, &output)
                .unwrap(),
            expected
        );
    }
    let empty = owner.seal(&[], 256, Limits::default()).unwrap();
    let (query, output) = run(
        owner,
        evaluator,
        &empty,
        Selection::FullScan,
        AgeRange::equal(42),
        Operation::CountSum,
    );
    assert_eq!(
        owner
            .decrypt_aggregate_for_experiment(&empty, &query, &output)
            .unwrap(),
        Aggregate { count: 0, sum: 0 }
    );
}
#[test]
fn encrypted_equality_and_range_index_select_complete_duplicate_groups() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let table = owner
        .seal(
            &[
                PlainRow {
                    age: 42,
                    amount: 10,
                },
                PlainRow { age: 41, amount: 7 },
                PlainRow {
                    age: 42,
                    amount: 20,
                },
                PlainRow { age: 1, amount: 99 },
            ],
            2,
            Limits::default(),
        )
        .unwrap();
    for (range, count, sum) in [
        (AgeRange::equal(42), 2, 30),
        (
            AgeRange {
                lower: 41,
                upper: 42,
            },
            3,
            37,
        ),
        (AgeRange::equal(255), 0, 0),
    ] {
        let (query, output) = run(
            owner,
            evaluator,
            &table,
            Selection::IndexedAgeRange(range),
            range,
            Operation::CountSum,
        );
        assert_eq!(query.selected_rows(), count as usize);
        assert_eq!(
            owner
                .decrypt_aggregate_for_experiment(&table, &query, &output)
                .unwrap(),
            Aggregate { count, sum }
        );
    }
}
#[test]
fn selection_budget_and_incomplete_index_range_are_explicit_errors() {
    let roles = roles();
    let (owner, _) = &*roles;
    let range = AgeRange::equal(1);
    let table = owner
        .seal(&[PlainRow { age: 1, amount: 1 }; 4], 2, Limits::default())
        .unwrap();
    for selection in [Selection::FullScan, Selection::IndexedAgeRange(range)] {
        assert!(matches!(
            owner.prepare(
                &table,
                selection,
                range,
                Operation::CountSum,
                3,
                Limits::default()
            ),
            Err(Error::SelectionBudget {
                selected: 4,
                budget: 3
            })
        ));
    }
    assert!(matches!(
        owner.prepare(
            &table,
            Selection::IndexedAgeRange(range),
            AgeRange { lower: 0, upper: 2 },
            Operation::CountSum,
            4,
            Limits::default()
        ),
        Err(Error::InvalidRange)
    ));
}
#[test]
fn duplicate_addresses_wrong_domain_and_stale_requests_are_rejected_before_evaluation() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let range = AgeRange::equal(1);
    let mut table = owner
        .seal(&[PlainRow { age: 1, amount: 1 }; 2], 1, Limits::default())
        .unwrap();
    let mut query = owner
        .prepare(
            &table,
            Selection::FullScan,
            range,
            Operation::CountSum,
            2,
            Limits::default(),
        )
        .unwrap();
    query.request.rows[1].ordinal = query.request.rows[0].ordinal;
    assert!(matches!(
        evaluator.evaluate(
            table.snapshot(),
            &query.encode_request().unwrap(),
            Limits::default()
        ),
        Err(Error::DuplicateAddress)
    ));
    query.request.domain[0] ^= 1;
    assert!(matches!(
        evaluator.evaluate(
            table.snapshot(),
            &query.encode_request().unwrap(),
            Limits::default()
        ),
        Err(Error::WrongDomain)
    ));
    let (mut update, output) = run(
        owner,
        evaluator,
        &table,
        Selection::FullScan,
        range,
        Operation::AddAmount(1),
    );
    let stale_wire = update.encode_request().unwrap();
    owner
        .apply_update_for_experiment(&mut table, &update, &output, Limits::default())
        .unwrap();
    assert!(matches!(
        evaluator.evaluate(table.snapshot(), &stale_wire, Limits::default()),
        Err(Error::WrongVersion)
    ));
    assert!(matches!(
        owner.decrypt_aggregate_for_experiment(&table, &update, &output),
        Err(Error::WrongVersion)
    ));
}
#[test]
fn any_matching_overflow_preserves_every_selected_page_atomically() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let range = AgeRange::equal(42);
    let mut table = owner
        .seal(
            &[
                PlainRow { age: 42, amount: 5 },
                PlainRow {
                    age: 42,
                    amount: 65_535,
                },
                PlainRow {
                    age: 7,
                    amount: 65_535,
                },
            ],
            1,
            Limits::default(),
        )
        .unwrap();
    let before = table.snapshot().encode();
    let (query, output) = run(
        owner,
        evaluator,
        &table,
        Selection::FullScan,
        range,
        Operation::AddAmount(1),
    );
    assert_eq!(
        owner
            .apply_update_for_experiment(&mut table, &query, &output, Limits::default())
            .unwrap(),
        AppliedUpdate {
            rejected: true,
            changed_rows: 0
        }
    );
    assert_eq!(table.snapshot().encode(), before);
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 0, Limits::default())
            .unwrap()
            .amount,
        5
    );
}
#[test]
fn selected_multi_page_update_has_fresh_nonces_no_growth_and_restart() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let range = AgeRange::equal(42);
    let mut table = owner
        .seal(
            &[
                PlainRow { age: 42, amount: 5 },
                PlainRow { age: 7, amount: 3 },
                PlainRow { age: 42, amount: 9 },
            ],
            1,
            Limits::default(),
        )
        .unwrap();
    let original = table.fork_for_experiment();
    let old_nonce = table
        .snapshot()
        .lookup(0, Limits::default())
        .unwrap()
        .verify(table.commitment(), 0, Limits::default())
        .unwrap()
        .nonce();
    let sizes = (table.canonical_data_bytes(), table.encrypted_index_bytes());
    for _ in 0..3 {
        let (query, output) = run(
            owner,
            evaluator,
            &table,
            Selection::IndexedAgeRange(range),
            range,
            Operation::AddAmount(1),
        );
        assert_eq!(
            owner
                .apply_update_for_experiment(&mut table, &query, &output, Limits::default())
                .unwrap(),
            AppliedUpdate {
                rejected: false,
                changed_rows: 2
            }
        );
        assert_eq!(
            (table.canonical_data_bytes(), table.encrypted_index_bytes()),
            sizes
        );
        table = owner
            .restore_table_for_experiment(
                &table.snapshot().encode(),
                &table.encrypted_index().encode(),
                table.commitment(),
                table.index_commitment(),
                Limits::default(),
            )
            .unwrap();
    }
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 0, Limits::default())
            .unwrap()
            .amount,
        8
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 1, Limits::default())
            .unwrap()
            .amount,
        3
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 2, Limits::default())
            .unwrap()
            .amount,
        12
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&original, 0, Limits::default())
            .unwrap()
            .amount,
        5
    );
    let new_nonce = table
        .snapshot()
        .lookup(0, Limits::default())
        .unwrap()
        .verify(table.commitment(), 0, Limits::default())
        .unwrap()
        .nonce();
    assert_ne!(new_nonce, old_nonce);
    assert!(matches!(
        owner.restore_table_for_experiment(
            &table.snapshot().encode(),
            &original.encrypted_index().encode(),
            table.commitment(),
            original.index_commitment(),
            Limits::default()
        ),
        Err(Error::WrongVersion)
    ));
}
#[test]
fn altered_update_result_and_wrong_query_cannot_commit_any_page() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let range = AgeRange::equal(42);
    let mut table = owner
        .seal(&[PlainRow { age: 42, amount: 5 }; 2], 1, Limits::default())
        .unwrap();
    let (query, mut output) = run(
        owner,
        evaluator,
        &table,
        Selection::FullScan,
        range,
        Operation::AddAmount(1),
    );
    let before = table.snapshot().encode();
    output.rows[1].ordinal = output.rows[0].ordinal;
    assert!(matches!(
        owner.apply_update_for_experiment(&mut table, &query, &output, Limits::default()),
        Err(Error::InvalidOutput)
    ));
    assert_eq!(table.snapshot().encode(), before);
    output.id[0] ^= 1;
    assert!(matches!(
        owner.apply_update_for_experiment(&mut table, &query, &output, Limits::default()),
        Err(Error::WrongQuery)
    ));
}
#[test]
fn foreign_owner_cannot_open_an_index_or_prepare_even_an_empty_selection() {
    let roles = roles();
    let (owner, _) = &*roles;
    let table = owner.seal(&[], 256, Limits::default()).unwrap();
    let (foreign, _) = Owner::generate([7; 16]).unwrap();
    assert!(matches!(
        foreign.prepare(
            &table,
            Selection::FullScan,
            AgeRange::equal(1),
            Operation::CountSum,
            0,
            Limits::default()
        ),
        Err(Error::Storage(compact_store::Error::WrongOwner))
    ));
}
#[test]
fn oversized_complete_candidate_group_fails_before_fhe_materialization() {
    let roles = roles();
    let (owner, _) = &*roles;
    let table = owner
        .seal(
            &vec![PlainRow { age: 42, amount: 1 }; MAX_ROWS + 1],
            256,
            Limits::default(),
        )
        .unwrap();
    for selection in [
        Selection::IndexedAgeRange(AgeRange::equal(42)),
        Selection::FullScan,
    ] {
        assert!(
            matches!(owner.prepare(&table,selection,AgeRange::equal(42),Operation::CountSum,
            usize::MAX,Limits::default()),Err(Error::SelectionBudget{selected,budget})
            if selected==MAX_ROWS+1 && budget==MAX_ROWS)
        );
    }
}
