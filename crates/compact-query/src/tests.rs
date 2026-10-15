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
fn index_only_head_change_rejects_pending_aggregate_and_update_without_mutation() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let limits = Limits::default();
    let mut table = owner
        .seal(&[PlainRow { age: 18, amount: 7 }], 2, limits)
        .unwrap();
    let range = AgeRange::equal(18);
    let (read, read_output) = run(
        owner,
        evaluator,
        &table,
        Selection::IndexedAgeRange(range),
        range,
        Operation::CountSum,
    );
    let (update, update_output) = run(
        owner,
        evaluator,
        &table,
        Selection::IndexedAgeRange(range),
        range,
        Operation::AddAmount(1),
    );
    let data_head = table.commitment().clone();
    let previous_index = table.index_commitment().clone();
    let index_limits = crate::index::index_limits();
    let verified = table
        .index
        .lookup(0, index_limits)
        .unwrap()
        .verify(&previous_index, 0, index_limits)
        .unwrap();
    let same_index_content = owner.store.decrypt(&verified).unwrap();

    // A valid new index revision leaves the data head and indexed values unchanged.
    owner
        .store
        .replace_page(
            &mut table.index,
            &previous_index,
            0,
            same_index_content.as_bytes(),
            index_limits,
        )
        .unwrap();

    assert_eq!(table.commitment(), &data_head);
    assert_ne!(table.index_commitment(), &previous_index);
    let before = (table.snapshot().encode(), table.encrypted_index().encode());
    assert!(matches!(
        owner.decrypt_aggregate_for_experiment(&table, &read, &read_output),
        Err(Error::WrongVersion)
    ));
    assert!(matches!(
        owner.apply_update_for_experiment(&mut table, &update, &update_output, limits),
        Err(Error::WrongVersion)
    ));
    assert_eq!(
        (table.snapshot().encode(), table.encrypted_index().encode()),
        before
    );

    let (current_read, current_output) = run(
        owner,
        evaluator,
        &table,
        Selection::IndexedAgeRange(range),
        range,
        Operation::CountSum,
    );
    assert_eq!(
        owner
            .decrypt_aggregate_for_experiment(&table, &current_read, &current_output)
            .unwrap(),
        Aggregate { count: 1, sum: 7 }
    );
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
#[test]
fn scoped_row_workers_preserve_exact_aggregates_and_global_overflow_rejection() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let parallel = evaluator.with_row_workers_for_experiment(8).unwrap();
    let range = AgeRange {
        lower: 41,
        upper: 42,
    };
    let mut table = owner
        .seal(
            &[
                PlainRow { age: 42, amount: 5 },
                PlainRow {
                    age: 41,
                    amount: 65_535,
                },
                PlainRow {
                    age: 7,
                    amount: 65_535,
                },
                PlainRow { age: 42, amount: 9 },
            ],
            1,
            Limits::default(),
        )
        .unwrap();
    for engine in [evaluator, &parallel] {
        let (query, output) = run(
            owner,
            engine,
            &table,
            Selection::FullScan,
            range,
            Operation::CountSum,
        );
        assert_eq!(
            owner
                .decrypt_aggregate_for_experiment(&table, &query, &output)
                .unwrap(),
            Aggregate {
                count: 3,
                sum: 65_549
            }
        );
        let (query, output) = run(
            owner,
            engine,
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
    }
    let range = AgeRange::equal(42);
    let (query, output) = run(
        owner,
        &parallel,
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
            rejected: false,
            changed_rows: 2
        }
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 0, Limits::default())
            .unwrap()
            .amount,
        6
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 3, Limits::default())
            .unwrap()
            .amount,
        10
    );
    assert!(matches!(
        evaluator.with_row_workers_for_experiment(9),
        Err(Error::WorkerBudget {
            requested: 9,
            maximum: 8
        })
    ));
}
#[test]
fn one_row_operator_shapes_keep_encrypted_misses_zero_and_reduce_wire_bounds() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let table = owner
        .seal(
            &[PlainRow {
                age: 42,
                amount: 65_535,
            }],
            256,
            Limits::default(),
        )
        .unwrap();
    let cases = [
        (AgeRange::equal(42), 1),
        (AgeRange::equal(41), 0),
        (
            AgeRange {
                lower: 42,
                upper: 255,
            },
            1,
        ),
        (
            AgeRange {
                lower: 43,
                upper: 255,
            },
            0,
        ),
        (
            AgeRange {
                lower: 0,
                upper: 42,
            },
            1,
        ),
        (
            AgeRange {
                lower: 0,
                upper: 41,
            },
            0,
        ),
        (
            AgeRange {
                lower: 41,
                upper: 43,
            },
            1,
        ),
        (
            AgeRange {
                lower: 43,
                upper: 44,
            },
            0,
        ),
    ];
    let mut encoded_lengths = Vec::new();
    for (range, count) in cases {
        let (mut query, output) = run(
            owner,
            evaluator,
            &table,
            Selection::FullScan,
            range,
            Operation::CountSum,
        );
        assert_eq!(
            owner
                .decrypt_aggregate_for_experiment(&table, &query, &output)
                .unwrap(),
            Aggregate {
                count,
                sum: count * 65_535
            }
        );
        encoded_lengths.push(query.encode_request().unwrap().len());
    }
    assert!(encoded_lengths[0] < encoded_lengths[6]);
    assert_eq!(encoded_lengths[0], encoded_lengths[2]);
    assert_eq!(encoded_lengths[2], encoded_lengths[4]);
    let empty = owner.seal(&[], 256, Limits::default()).unwrap();
    let before = empty.commitment().clone();
    let mut empty = empty;
    let (query, output) = run(
        owner,
        evaluator,
        &empty,
        Selection::FullScan,
        AgeRange::equal(42),
        Operation::AddAmount(1),
    );
    assert_eq!(
        owner
            .apply_update_for_experiment(&mut empty, &query, &output, Limits::default())
            .unwrap(),
        AppliedUpdate {
            rejected: false,
            changed_rows: 0
        }
    );
    assert_eq!(empty.commitment(), &before);
}
#[test]
fn maximum_complete_candidate_group_keeps_exact_count256_and_sum16776960() {
    let roles = roles();
    let (owner, evaluator) = &*roles;
    let table = owner
        .seal(
            &[PlainRow {
                age: 42,
                amount: 65_535,
            }; MAX_ROWS],
            256,
            Limits::default(),
        )
        .unwrap();
    let evaluator = evaluator.with_row_workers_for_experiment(8).unwrap();
    let range = AgeRange::equal(42);
    let (query, output) = run(
        owner,
        &evaluator,
        &table,
        Selection::IndexedAgeRange(range),
        range,
        Operation::CountSum,
    );
    assert_eq!(
        owner
            .decrypt_aggregate_for_experiment(&table, &query, &output)
            .unwrap(),
        Aggregate {
            count: 256,
            sum: 16_776_960
        }
    );
}
