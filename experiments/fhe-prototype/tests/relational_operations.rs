use std::sync::OnceLock;

use fhe_prototype::{Comparison, Error, Evaluator, MAX_ROWS, Owner, PlainRow};

// All plaintext fixtures are intentionally public and synthetic. Secret keys are
// generated at runtime, never checked in or written to files.
fn keys() -> &'static (Owner, Evaluator) {
    static KEYS: OnceLock<(Owner, Evaluator)> = OnceLock::new();
    KEYS.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build_global()
            .unwrap();
        Owner::generate().unwrap()
    })
}

#[test]
fn encrypted_range_includes_the_boundary_and_sums_only_matching_rows() {
    let (owner, evaluator) = keys();
    let table = owner
        .encrypt_table(&[
            PlainRow {
                age: 17,
                amount: 100,
            },
            PlainRow {
                age: 18,
                amount: 10,
            },
            PlainRow {
                age: 42,
                amount: 20,
            },
        ])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 18).unwrap();

    let result = evaluator.aggregate(&table, &predicate).unwrap();

    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (2, 30)
    );
}

#[test]
fn encrypted_equality_excludes_both_smaller_and_larger_ages() {
    let (owner, evaluator) = keys();
    let table = owner
        .encrypt_table(&[
            PlainRow { age: 17, amount: 1 },
            PlainRow { age: 18, amount: 2 },
            PlainRow { age: 19, amount: 3 },
        ])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::Equal, 18).unwrap();

    let result = evaluator.aggregate(&table, &predicate).unwrap();

    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (1, 2)
    );
}

#[test]
fn no_matches_and_an_empty_table_return_zero_aggregates() {
    let (owner, evaluator) = keys();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 18).unwrap();
    for rows in [
        vec![],
        vec![PlainRow {
            age: 17,
            amount: 100,
        }],
    ] {
        let table = owner.encrypt_table(&rows).unwrap();

        let result = evaluator.aggregate(&table, &predicate).unwrap();

        assert_eq!(
            owner.decrypt_aggregate_for_experiment(&result).unwrap(),
            (0, 0)
        );
    }
}

#[test]
fn sums_use_a_wider_accumulator_than_the_stored_amounts() {
    let (owner, evaluator) = keys();
    let table = owner
        .encrypt_table(
            &[PlainRow {
                age: 18,
                amount: u16::MAX,
            }; 2],
        )
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::Equal, 18).unwrap();

    let result = evaluator.aggregate(&table, &predicate).unwrap();

    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (2, 131_070)
    );
}

#[test]
fn multi_input_aggregates_keep_count_carries_and_exact_wide_sums() {
    // Arrange: public fixture crosses the 8-bit COUNT boundary and the u16 SUM range.
    let (owner, evaluator) = keys();
    let rows = vec![
        PlainRow {
            age: 255,
            amount: u16::MAX
        };
        257
    ];
    let table = owner.encrypt_table(&rows).unwrap();
    let predicate = owner.encrypt_predicate(Comparison::Equal, 255).unwrap();

    let result = evaluator.aggregate(&table, &predicate).unwrap();

    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (257, 257 * u32::from(u16::MAX))
    );
}

#[test]
fn repeated_updates_survive_compression_without_growing_the_fixed_schema_image() {
    // Arrange: one matching row and one row that must retain its amount.
    let (owner, evaluator) = keys();
    let mut table = owner
        .encrypt_table(&[
            PlainRow {
                age: 17,
                amount: 50,
            },
            PlainRow {
                age: 18,
                amount: 10,
            },
        ])
        .unwrap();
    let selected = owner.encrypt_predicate(Comparison::AtLeast, 18).unwrap();
    let all = owner.encrypt_predicate(Comparison::AtLeast, 0).unwrap();
    let delta = owner.encrypt_delta(5).unwrap();
    let initial_size = evaluator.compress_table(&table).unwrap().len();

    for cycle in 1..=2 {
        // Act: update, compress, and restore with the same evaluation material.
        let update = evaluator.add_amount(&mut table, &selected, &delta).unwrap();
        assert!(
            !owner
                .decrypt_update_rejection_for_experiment(&update)
                .unwrap()
        );
        let image = evaluator.compress_table(&table).unwrap();
        assert_eq!(image.len(), initial_size);
        table = evaluator.restore_trusted_image(&image).unwrap();

        let result = evaluator.aggregate(&table, &all).unwrap();
        // Assert: the untouched row and both updates are reflected in the total.
        assert_eq!(
            owner.decrypt_aggregate_for_experiment(&result).unwrap(),
            (2, 60 + cycle * 5)
        );
    }
}

#[test]
fn overflow_on_one_matching_row_preserves_every_amount() {
    let (owner, evaluator) = keys();
    let mut table = owner
        .encrypt_table(&[
            PlainRow {
                age: 18,
                amount: u16::MAX,
            },
            PlainRow {
                age: 19,
                amount: 10,
            },
        ])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 18).unwrap();
    let delta = owner.encrypt_delta(1).unwrap();

    let update = evaluator
        .add_amount(&mut table, &predicate, &delta)
        .unwrap();

    assert!(
        owner
            .decrypt_update_rejection_for_experiment(&update)
            .unwrap()
    );
    let result = evaluator.aggregate(&table, &predicate).unwrap();
    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (2, 65_545)
    );
}

#[test]
fn an_overflowing_nonmatching_row_does_not_reject_the_update() {
    let (owner, evaluator) = keys();
    let mut table = owner
        .encrypt_table(&[
            PlainRow {
                age: 17,
                amount: u16::MAX,
            },
            PlainRow {
                age: 18,
                amount: 10,
            },
        ])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 18).unwrap();
    let delta = owner.encrypt_delta(1).unwrap();

    let update = evaluator
        .add_amount(&mut table, &predicate, &delta)
        .unwrap();

    assert!(
        !owner
            .decrypt_update_rejection_for_experiment(&update)
            .unwrap()
    );
    let result = evaluator.aggregate(&table, &predicate).unwrap();
    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (1, 11)
    );
}

#[test]
fn adding_the_largest_delta_to_zero_succeeds_at_the_u16_boundary() {
    // The nonmatching row overflows, but the matching row reaches u16::MAX exactly.
    let (owner, evaluator) = keys();
    let mut table = owner
        .encrypt_table(&[
            PlainRow { age: 17, amount: 1 },
            PlainRow { age: 18, amount: 0 },
        ])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::Equal, 18).unwrap();
    let all = owner.encrypt_predicate(Comparison::AtLeast, 0).unwrap();
    let delta = owner.encrypt_delta(u16::MAX).unwrap();

    let update = evaluator
        .add_amount(&mut table, &predicate, &delta)
        .unwrap();

    assert!(
        !owner
            .decrypt_update_rejection_for_experiment(&update)
            .unwrap()
    );
    let result = evaluator.aggregate(&table, &all).unwrap();
    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (2, 65_536)
    );
}

#[test]
fn a_zero_delta_does_not_reject_the_largest_stored_amount() {
    let (owner, evaluator) = keys();
    let mut table = owner
        .encrypt_table(&[PlainRow {
            age: 18,
            amount: u16::MAX,
        }])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::Equal, 18).unwrap();
    let delta = owner.encrypt_delta(0).unwrap();

    let update = evaluator
        .add_amount(&mut table, &predicate, &delta)
        .unwrap();

    assert!(
        !owner
            .decrypt_update_rejection_for_experiment(&update)
            .unwrap()
    );
    let result = evaluator.aggregate(&table, &predicate).unwrap();
    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (1, 65_535)
    );
}

#[test]
fn an_empty_update_succeeds_and_keeps_the_table_empty() {
    let (owner, evaluator) = keys();
    let mut table = owner.encrypt_table(&[]).unwrap();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 0).unwrap();
    let delta = owner.encrypt_delta(u16::MAX).unwrap();

    let update = evaluator
        .add_amount(&mut table, &predicate, &delta)
        .unwrap();

    assert!(
        !owner
            .decrypt_update_rejection_for_experiment(&update)
            .unwrap()
    );
    assert!(table.is_empty());
}

#[test]
fn oversized_tables_are_rejected_before_encryption() {
    let (owner, _) = keys();
    let rows = vec![PlainRow { age: 0, amount: 0 }; MAX_ROWS + 1];

    assert!(matches!(
        owner.encrypt_table(&rows),
        Err(Error::TooManyRows { .. })
    ));
}

#[test]
fn invalid_or_truncated_images_are_rejected() {
    let (owner, evaluator) = keys();
    assert!(matches!(
        evaluator.restore_trusted_image(b"not an image"),
        Err(Error::InvalidImage(_))
    ));
    let table = owner
        .encrypt_table(&[PlainRow {
            age: 18,
            amount: 10,
        }])
        .unwrap();
    let mut image = evaluator.compress_table(&table).unwrap();
    image.truncate(image.len() / 2);
    assert!(evaluator.restore_trusted_image(&image).is_err());
}

#[test]
fn an_empty_table_survives_compression_and_reload() {
    let (owner, evaluator) = keys();
    let table = owner.encrypt_table(&[]).unwrap();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 0).unwrap();

    let image = evaluator.compress_table(&table).unwrap();
    let restored = evaluator.restore_trusted_image(&image).unwrap();
    let result = evaluator.aggregate(&restored, &predicate).unwrap();

    assert!(restored.is_empty());
    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (0, 0)
    );
}

#[test]
fn images_with_trailing_bytes_are_rejected() {
    let (owner, evaluator) = keys();
    let table = owner.encrypt_table(&[]).unwrap();
    let mut image = evaluator.compress_table(&table).unwrap();
    image.push(0);

    assert!(matches!(
        evaluator.restore_trusted_image(&image),
        Err(Error::InvalidImage(_))
    ));
}

#[test]
fn different_key_domains_cannot_be_mixed_through_the_api() {
    // Arrange: independently generated keys and an empty table in the other domain.
    let (owner, evaluator) = keys();
    let (other_owner, other_evaluator) = Owner::generate().unwrap();
    let mut other_table = other_owner.encrypt_table(&[]).unwrap();
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, 0).unwrap();
    let delta = owner.encrypt_delta(1).unwrap();
    let other_predicate = other_owner
        .encrypt_predicate(Comparison::AtLeast, 0)
        .unwrap();
    let other_result = other_evaluator
        .aggregate(&other_table, &other_predicate)
        .unwrap();
    let other_image = other_evaluator.compress_table(&other_table).unwrap();

    // Act / Assert: mismatches fail before evaluation, loading, or decryption.
    assert!(matches!(
        evaluator.aggregate(&other_table, &predicate),
        Err(Error::DifferentKeyDomain)
    ));
    assert!(matches!(
        evaluator.add_amount(&mut other_table, &predicate, &delta),
        Err(Error::DifferentKeyDomain)
    ));
    assert!(matches!(
        evaluator.restore_trusted_image(&other_image),
        Err(Error::DifferentKeyDomain)
    ));
    assert!(matches!(
        owner.decrypt_aggregate_for_experiment(&other_result),
        Err(Error::DifferentKeyDomain)
    ));
}

#[test]
fn a_foreign_predicate_or_delta_is_rejected_without_changing_the_table() {
    let (owner, evaluator) = keys();
    let (other_owner, _) = Owner::generate().unwrap();
    let mut table = owner
        .encrypt_table(&[PlainRow { age: 18, amount: 7 }])
        .unwrap();
    let predicate = owner.encrypt_predicate(Comparison::Equal, 18).unwrap();
    let delta = owner.encrypt_delta(1).unwrap();
    let foreign_predicate = other_owner
        .encrypt_predicate(Comparison::Equal, 18)
        .unwrap();
    let foreign_delta = other_owner.encrypt_delta(1).unwrap();

    assert!(matches!(
        evaluator.aggregate(&table, &foreign_predicate),
        Err(Error::DifferentKeyDomain)
    ));
    assert!(matches!(
        evaluator.add_amount(&mut table, &foreign_predicate, &delta),
        Err(Error::DifferentKeyDomain)
    ));
    assert!(matches!(
        evaluator.add_amount(&mut table, &predicate, &foreign_delta),
        Err(Error::DifferentKeyDomain)
    ));

    let result = evaluator.aggregate(&table, &predicate).unwrap();
    assert_eq!(
        owner.decrypt_aggregate_for_experiment(&result).unwrap(),
        (1, 7)
    );
}
