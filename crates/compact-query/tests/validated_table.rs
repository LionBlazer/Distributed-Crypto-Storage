#![cfg(feature = "bfv-experiment")]
use compact_query::{Error, PlainRow, TableId, bfv::Owner};
use compact_store::{AuditWorkers, Commitment, Limits};

fn assert_owner_rejects(
    owner: &Owner,
    (data, index): (&[u8], &[u8]),
    (table, data_head, index_head): (&TableId, &Commitment, &Commitment),
    limits: Limits,
    expected: Error,
) {
    assert_eq!(
        owner
            .validate_table_images_for_experiment(
                data, index, table, data_head, index_head, limits,
            )
            .err(),
        Some(expected.clone())
    );
    assert_eq!(
        owner
            .restore_table_for_experiment(data, index, table, data_head, index_head, limits)
            .err(),
        Some(expected)
    );
}

#[test]
fn owner_validates_the_complete_images_without_retaining_a_materialized_table() {
    let (owner, _) = Owner::generate([66; 16]).unwrap();
    let table = owner
        .seal(
            &[PlainRow { age: 18, amount: 7 }; 257],
            256,
            Limits::default(),
        )
        .unwrap();
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    owner
        .validate_table_images_for_experiment(
            &data,
            &index,
            table.table_id(),
            table.commitment(),
            table.index_commitment(),
            Limits::default(),
        )
        .unwrap();
    let restored = owner
        .restore_table_for_experiment(
            &data,
            &index,
            table.table_id(),
            table.commitment(),
            table.index_commitment(),
            Limits::default(),
        )
        .unwrap();
    assert_eq!(restored.snapshot().encode(), data);
    assert_eq!(restored.encrypted_index().encode(), index);
    assert!(
        owner
            .validate_table_images_for_experiment(
                &data,
                &index,
                &TableId::generate().unwrap(),
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
    let mut corrupt = index;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        owner
            .validate_table_images_for_experiment(
                &data,
                &corrupt,
                table.table_id(),
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
}

#[test]
fn owner_cpu_opt_in_keeps_full_image_validation_materialization_and_key_authority() {
    let (mut owner, _) = Owner::generate([171; 16]).unwrap();
    // An odd, partial-tail data image and a complete index above the helper threshold.
    let rows = vec![PlainRow { age: 42, amount: 9 }; 131_073];
    let table = owner.seal(&rows, 256, Limits::default()).unwrap();
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    assert!(index.len() > 4 * 1024 * 1024);
    let pinned = (
        table.table_id(),
        table.commitment(),
        table.index_commitment(),
    );
    let profile = bincode::serialize(&owner.profile()).unwrap();
    let secret_bytes = owner.secret_key_serialized_bytes();
    for workers in [AuditWorkers::One, AuditWorkers::Two, AuditWorkers::One] {
        owner = owner.with_audit_workers(workers);

        owner
            .validate_table_images_for_experiment(
                &data,
                &index,
                pinned.0,
                pinned.1,
                pinned.2,
                Limits::default(),
            )
            .unwrap();
        let restored = owner
            .restore_table_for_experiment(
                &data,
                &index,
                pinned.0,
                pinned.1,
                pinned.2,
                Limits::default(),
            )
            .unwrap();
        assert_eq!(restored.snapshot().encode(), data);
        assert_eq!(restored.encrypted_index().encode(), index);
        assert_eq!(bincode::serialize(&owner.profile()).unwrap(), profile);
        assert_eq!(owner.secret_key_serialized_bytes(), secret_bytes);
        assert_eq!(
            owner
                .decrypt_row_for_experiment(&restored, 131_072, Limits::default())
                .unwrap(),
            PlainRow { age: 42, amount: 9 }
        );

        let mut corrupt_data = data.clone();
        *corrupt_data.last_mut().unwrap() ^= 1;
        assert_owner_rejects(
            &owner,
            (&corrupt_data, &index),
            pinned,
            Limits::default(),
            Error::Storage(compact_store::Error::InvalidProof),
        );
        let mut omitted_index_tail = index.clone();
        *omitted_index_tail.last_mut().unwrap() ^= 1;
        assert_owner_rejects(
            &owner,
            (&data, &omitted_index_tail),
            pinned,
            Limits::default(),
            Error::Storage(compact_store::Error::InvalidProof),
        );
    }
}

#[test]
fn owner_worker_policies_keep_exact_heads_header_table_key_and_error_order() {
    let (mut owner, _) = Owner::generate([172; 16]).unwrap();
    let (mut other_owner, _) = Owner::generate([172; 16]).unwrap();
    let rows = [PlainRow { age: 18, amount: 7 }; 257];
    let table = owner.seal(&rows, 256, Limits::default()).unwrap();
    let alternate = owner.seal(&rows, 256, Limits::default()).unwrap();
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    let alternate_index = alternate.encrypted_index().encode();
    let wrong_table = TableId::generate().unwrap();
    let pinned = (
        table.table_id(),
        table.commitment(),
        table.index_commitment(),
    );
    let foreign = compact_store::Owner::generate([173; 16])
        .unwrap()
        .seal(
            compact_store::Layout {
                schema: [174; 16],
                row_width: 3,
                rows_per_page: 256,
                row_count: 257,
            },
            &[1; 257 * 3],
            Limits::default(),
        )
        .unwrap();
    let foreign_data = foreign.encode();
    for workers in [AuditWorkers::One, AuditWorkers::Two] {
        owner = owner.with_audit_workers(workers);
        other_owner = other_owner.with_audit_workers(workers);
        for (expected, error) in [
            ((&wrong_table, pinned.1, pinned.2), Error::WrongVersion),
            (
                (pinned.0, alternate.commitment(), pinned.2),
                Error::Storage(compact_store::Error::WrongVersion),
            ),
            (
                (pinned.0, pinned.1, alternate.index_commitment()),
                Error::Storage(compact_store::Error::WrongVersion),
            ),
        ] {
            assert_owner_rejects(&owner, (&data, &index), expected, Limits::default(), error);
        }
        // Both supplied images are genuine, but the authenticated header embeds
        // another exact data head; a correct supplied index root cannot bypass it.
        assert_owner_rejects(
            &owner,
            (&data, &alternate_index),
            (alternate.table_id(), pinned.1, alternate.index_commitment()),
            Limits::default(),
            Error::WrongVersion,
        );
        assert_owner_rejects(
            &other_owner,
            (&data, &index),
            pinned,
            Limits::default(),
            Error::Storage(compact_store::Error::WrongOwner),
        );

        let mut bad_data = data.clone();
        *bad_data.last_mut().unwrap() ^= 1;
        let mut bad_index = index.clone();
        *bad_index.last_mut().unwrap() ^= 1;
        let mut future_index = bad_index.clone();
        future_index[compact_store::MANIFEST_BYTES..compact_store::MANIFEST_BYTES + 8]
            .copy_from_slice(&1u64.to_le_bytes());
        assert_owner_rejects(
            &owner,
            (&bad_data, &future_index),
            pinned,
            Limits::default(),
            Error::Storage(compact_store::Error::InvalidProof),
        );
        assert_owner_rejects(
            &owner,
            (&data, &future_index),
            pinned,
            Limits::default(),
            Error::Storage(compact_store::Error::InvalidFormat),
        );
        // The complete index audit precedes schema and owner header checks.
        let foreign_heads = (pinned.0, foreign.commitment(), pinned.2);
        assert_owner_rejects(
            &owner,
            (&foreign_data, &bad_index),
            foreign_heads,
            Limits::default(),
            Error::Storage(compact_store::Error::InvalidProof),
        );
        assert_owner_rejects(
            &owner,
            (&foreign_data, &index),
            foreign_heads,
            Limits::default(),
            Error::InvalidSchema,
        );
        assert_owner_rejects(
            &owner,
            (&data, &bad_index),
            pinned,
            Limits {
                max_image_bytes: data.len() - 1,
                ..Limits::default()
            },
            Error::Storage(compact_store::Error::ResourceLimit),
        );
    }
}
