//! Public non-secret fixtures exercising the storage/crypto composition boundary.
use super::*;
fn row(age: u8, amount: u16) -> PlainRow {
    PlainRow { age, amount }
}
fn aggregate(
    owner: &Owner,
    peer: &Evaluator,
    table: &Table,
    range: AgeRange,
) -> UnverifiedAggregate {
    let prepared = owner
        .prepare_exact_aggregate_for_experiment(table, range, 256, Limits::default())
        .unwrap();
    let evaluated = peer.evaluate_exact_aggregate(prepared.request()).unwrap();
    assert_eq!(
        (
            evaluated.stats.ct_ct_multiplications,
            evaluated.stats.rotations
        ),
        (0, 8)
    );
    owner
        .complete_exact_aggregate_unverified_for_experiment(table, prepared, &evaluated.output)
        .unwrap()
}
#[test]
fn exact_index_aggregates_empty_duplicates_full_age_range_and_max_unsigned_sum() {
    let (owner, peer) = Owner::generate([7; 16]).unwrap();
    for count in [0, 1, 16, 128, 256] {
        let table = owner
            .seal(&vec![row(42, 65535); count], 8, Limits::default())
            .unwrap();
        let result = aggregate(&owner, &peer, &table, AgeRange::equal(42));
        assert_eq!(
            (result.count, result.sum),
            (count as u32, count as u32 * 65535)
        );
        assert_eq!(result.proof, ProofStatus::Unavailable);
        let absent = aggregate(&owner, &peer, &table, AgeRange::equal(255));
        assert_eq!((absent.count, absent.sum), (0, 0));
        let all = aggregate(
            &owner,
            &peer,
            &table,
            AgeRange {
                lower: 0,
                upper: 255,
            },
        );
        assert_eq!((all.count, all.sum), (result.count, result.sum));
    }
}
#[test]
fn exact_selection_rejects_complete_groups_over_budget_and_authenticated_wrong_age() {
    let (owner, _) = Owner::generate([8; 16]).unwrap();
    let mut table = owner.seal(&[row(42, 1); 4], 2, Limits::default()).unwrap();
    assert!(matches!(
        owner.prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange::equal(42),
            3,
            Limits::default()
        ),
        Err(Error::SelectionBudget {
            selected: 4,
            budget: 3
        })
    ));
    table.index = crate::index::build(&owner.store, &[row(18, 1); 4], table.commitment()).unwrap();
    assert!(matches!(
        owner.prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange::equal(18),
            4,
            Limits::default()
        ),
        Err(Error::InvalidIndex)
    ));
    assert!(matches!(
        owner.prepare_exact_update_for_experiment(
            &table,
            AgeRange::equal(18),
            1,
            4,
            Limits::default()
        ),
        Err(Error::InvalidIndex)
    ));
}
#[test]
fn multi_page_update_has_fresh_nonces_preserved_index_suffix_no_growth_and_global_overflow() {
    let (owner, peer) = Owner::generate([9; 16]).unwrap();
    let mut table = owner
        .seal(
            &[row(42, 255), row(7, 65535), row(42, 256)],
            1,
            Limits::default(),
        )
        .unwrap();
    let size = (table.canonical_data_bytes(), table.encrypted_index_bytes());
    let before = table
        .snapshot()
        .lookup(0, Limits::default())
        .unwrap()
        .verify(table.commitment(), 0, Limits::default())
        .unwrap();
    let nonce = before.nonce();
    let before = table
        .index
        .lookup(0, crate::index::index_limits())
        .unwrap()
        .verify(table.index_commitment(), 0, crate::index::index_limits())
        .unwrap();
    let suffix = owner.store.decrypt(&before).unwrap().as_bytes()[112..].to_vec();
    let prepared = owner
        .prepare_exact_update_for_experiment(&table, AgeRange::equal(42), 1, 256, Limits::default())
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(prepared.request()).unwrap();
    assert_eq!(evaluated.stats.ciphertext_additions, 1);
    assert_eq!(
        owner
            .apply_exact_update_checked_for_experiment(
                &mut table,
                prepared,
                &evaluated.output,
                Limits::default()
            )
            .unwrap(),
        AppliedUpdate {
            rejected: false,
            changed_rows: 2
        }
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 0, Limits::default())
            .unwrap(),
        row(42, 256)
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 1, Limits::default())
            .unwrap(),
        row(7, 65535)
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 2, Limits::default())
            .unwrap(),
        row(42, 257)
    );
    let after = table
        .snapshot()
        .lookup(0, Limits::default())
        .unwrap()
        .verify(table.commitment(), 0, Limits::default())
        .unwrap();
    assert_ne!(after.nonce(), nonce);
    let after = table
        .index
        .lookup(0, crate::index::index_limits())
        .unwrap()
        .verify(table.index_commitment(), 0, crate::index::index_limits())
        .unwrap();
    assert_eq!(
        &owner.store.decrypt(&after).unwrap().as_bytes()[112..],
        suffix
    );
    assert_eq!(
        (table.canonical_data_bytes(), table.encrypted_index_bytes()),
        size
    );
    table = owner
        .restore_table_for_experiment(
            &table.snapshot().encode(),
            &table.index.encode(),
            table.commitment(),
            table.index_commitment(),
            Limits::default(),
        )
        .unwrap();
    let before = (table.snapshot().encode(), table.index.encode());
    let prepared = owner
        .prepare_exact_update_for_experiment(
            &table,
            AgeRange::equal(42),
            65535,
            256,
            Limits::default(),
        )
        .unwrap();
    let output = peer.evaluate_indexed_update(prepared.request()).unwrap();
    assert_eq!(
        owner
            .apply_exact_update_checked_for_experiment(
                &mut table,
                prepared,
                &output.output,
                Limits::default()
            )
            .unwrap(),
        AppliedUpdate {
            rejected: true,
            changed_rows: 0
        }
    );
    assert_eq!((table.snapshot().encode(), table.index.encode()), before);
}
#[test]
fn either_changed_head_rejects_pending_results_and_public_evaluator_clones_share_keys() {
    let (owner, peer) = Owner::generate([10; 16]).unwrap();
    let clone = peer.clone();
    assert!(Arc::ptr_eq(&peer.peer, &clone.peer));
    assert!(Arc::ptr_eq(&peer.setup, &clone.setup));
    let mut table = owner.seal(&[row(42, 10)], 1, Limits::default()).unwrap();
    let prepared = owner
        .prepare_exact_aggregate_for_experiment(&table, AgeRange::equal(42), 256, Limits::default())
        .unwrap();
    let output = peer.evaluate_exact_aggregate(prepared.request()).unwrap();
    let verified = table
        .index
        .lookup(0, crate::index::index_limits())
        .unwrap()
        .verify(table.index_commitment(), 0, crate::index::index_limits())
        .unwrap();
    let plaintext = owner.store.decrypt(&verified).unwrap();
    let old = table.index_commitment().clone();
    owner
        .store
        .replace_page(
            &mut table.index,
            &old,
            0,
            plaintext.as_bytes(),
            crate::index::index_limits(),
        )
        .unwrap();
    assert!(matches!(
        owner.complete_exact_aggregate_unverified_for_experiment(&table, prepared, &output.output),
        Err(Error::WrongVersion)
    ));
    let prepared = owner
        .prepare_exact_aggregate_for_experiment(&table, AgeRange::equal(42), 256, Limits::default())
        .unwrap();
    let output = peer.evaluate_exact_aggregate(prepared.request()).unwrap();
    let update = owner
        .prepare_exact_update_for_experiment(&table, AgeRange::equal(42), 1, 256, Limits::default())
        .unwrap();
    let updated = peer.evaluate_indexed_update(update.request()).unwrap();
    owner
        .apply_exact_update_checked_for_experiment(
            &mut table,
            update,
            &updated.output,
            Limits::default(),
        )
        .unwrap();
    assert!(matches!(
        owner.complete_exact_aggregate_unverified_for_experiment(&table, prepared, &output.output),
        Err(Error::WrongVersion)
    ));
}
#[test]
fn wrong_owner_or_public_keyset_cannot_accept_even_an_empty_operation() {
    let (owner, peer) = Owner::generate([11; 16]).unwrap();
    let (other, other_peer) = Owner::generate([12; 16]).unwrap();
    let table = owner.seal(&[], 1, Limits::default()).unwrap();
    assert!(
        other
            .prepare_exact_aggregate_for_experiment(
                &table,
                AgeRange::equal(42),
                256,
                Limits::default()
            )
            .is_err()
    );
    let prepared = owner
        .prepare_exact_aggregate_for_experiment(&table, AgeRange::equal(42), 256, Limits::default())
        .unwrap();
    assert!(
        other_peer
            .evaluate_exact_aggregate(prepared.request())
            .is_err()
    );
    let output = peer.evaluate_exact_aggregate(prepared.request()).unwrap();
    assert!(
        other
            .complete_exact_aggregate_unverified_for_experiment(&table, prepared, &output.output)
            .is_err()
    );
}
#[derive(serde::Deserialize)]
struct ObservedRequest {
    magic: [u8; 8],
    version: u16,
    operation: u32,
    keyset_id: [u8; 32],
    context: bfv_core::QueryContext,
    geometry: bfv_core::Geometry,
    amounts: Vec<u8>,
    deltas: Vec<u8>,
}
#[derive(serde::Serialize)]
struct PublicEcho {
    magic: [u8; 8],
    version: u16,
    operation: u32,
    keyset_id: [u8; 32],
    context: bfv_core::QueryContext,
    geometry: bfv_core::Geometry,
    updated_limbs: Vec<u8>,
}
#[test]
fn in_bounds_public_echo_after_genuine_addition_never_authorizes_any_write() {
    use bincode::Options;
    let (owner, peer) = Owner::generate([13; 16]).unwrap();
    let mut table = owner
        .seal(&[row(42, 10), row(42, 20)], 1, Limits::default())
        .unwrap();
    let before = (table.snapshot().encode(), table.index.encode());
    let prepared = owner
        .prepare_exact_update_for_experiment(&table, AgeRange::equal(42), 1, 256, Limits::default())
        .unwrap();
    let honest = peer.evaluate_indexed_update(prepared.request()).unwrap();
    assert_eq!(honest.stats.ciphertext_additions, 1);
    let options = || {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(bfv_core::MAX_WIRE_BYTES)
            .reject_trailing_bytes()
    };
    let observed: ObservedRequest = options().deserialize(prepared.request()).unwrap();
    assert_eq!(
        (observed.magic, observed.version, observed.operation),
        (*b"BFVADDQ1", 1, 1)
    );
    assert!(!observed.deltas.is_empty());
    let forged = options()
        .serialize(&PublicEcho {
            magic: *b"BFVADDR1",
            version: observed.version,
            operation: observed.operation,
            keyset_id: observed.keyset_id,
            context: observed.context,
            geometry: observed.geometry,
            updated_limbs: observed.amounts,
        })
        .unwrap();
    assert_eq!(
        owner
            .apply_exact_update_checked_for_experiment(
                &mut table,
                prepared,
                &forged,
                Limits::default()
            )
            .unwrap_err(),
        Error::InvalidOutput
    );
    assert_eq!((table.snapshot().encode(), table.index.encode()), before);
}

#[test]
fn safe_positive256_update_checks_every_row_across_pages_carry_and_index_binding() {
    let (owner, peer) = Owner::generate([14; 16]).unwrap();
    // Explicit public fixture; every odd row is an unselected maximum, not an overflow input.
    let rows: Vec<_> = (0..256)
        .flat_map(|amount| [row(42, amount), row(7, 65535)])
        .collect();
    let mut table = owner.seal(&rows, 17, Limits::default()).unwrap();
    let size = (table.canonical_data_bytes(), table.encrypted_index_bytes());
    let old_data = table.commitment().clone();
    let old_index = table.index_commitment().clone();
    let verified = table
        .index
        .lookup(0, crate::index::index_limits())
        .unwrap()
        .verify(&old_index, 0, crate::index::index_limits())
        .unwrap();
    let old_header = owner.store.decrypt(&verified).unwrap();
    let prepared = owner
        .prepare_exact_update_for_experiment(&table, AgeRange::equal(42), 1, 256, Limits::default())
        .unwrap();
    assert_eq!(prepared.selected_rows(), 256);
    let output = peer.evaluate_indexed_update(prepared.request()).unwrap();
    assert_eq!(output.stats.ciphertext_additions, 1);
    assert_eq!(
        owner
            .apply_exact_update_checked_for_experiment(
                &mut table,
                prepared,
                &output.output,
                Limits::default()
            )
            .unwrap(),
        AppliedUpdate {
            rejected: false,
            changed_rows: 256
        }
    );
    for (ordinal, original) in rows.iter().enumerate() {
        let actual = owner
            .decrypt_row_for_experiment(&table, ordinal as u64, Limits::default())
            .unwrap();
        let expected = if ordinal % 2 == 0 {
            row(42, original.amount + 1)
        } else {
            *original
        };
        assert_eq!(actual, expected, "public fixture ordinal{ordinal}");
    }
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&table, 510, Limits::default())
            .unwrap()
            .amount,
        256
    );
    assert_ne!(table.commitment(), &old_data);
    assert_ne!(table.index_commitment(), &old_index);
    let verified = table
        .index
        .lookup(0, crate::index::index_limits())
        .unwrap()
        .verify(table.index_commitment(), 0, crate::index::index_limits())
        .unwrap();
    let header = owner.store.decrypt(&verified).unwrap();
    assert_eq!(&header.as_bytes()[..112], &table.commitment().encode());
    assert_eq!(&header.as_bytes()[112..], &old_header.as_bytes()[112..]);
    assert_eq!(
        (table.canonical_data_bytes(), table.encrypted_index_bytes()),
        size
    );
    let actual = aggregate(&owner, &peer, &table, AgeRange::equal(42));
    assert_eq!((actual.count, actual.sum), (256, 32_896));
}

#[test]
fn hard256_materialization_and_reversed_ranges_reject_as_selection_errors() {
    let (owner, _) = Owner::generate([15; 16]).unwrap();
    let table = owner
        .seal(&[row(42, 1); 257], 17, Limits::default())
        .unwrap();
    assert!(matches!(
        owner.prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange::equal(42),
            usize::MAX,
            Limits::default()
        ),
        Err(Error::SelectionBudget {
            selected: 257,
            budget: 256
        })
    ));
    assert!(matches!(
        owner.prepare_exact_update_for_experiment(
            &table,
            AgeRange::equal(42),
            1,
            usize::MAX,
            Limits::default()
        ),
        Err(Error::SelectionBudget {
            selected: 257,
            budget: 256
        })
    ));
    assert!(matches!(
        owner.prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange {
                lower: 252,
                upper: 250
            },
            256,
            Limits::default()
        ),
        Err(Error::InvalidRange)
    ));
}

fn selected_rows(
    owner: &Owner,
    peer: &Evaluator,
    table: &Table,
    range: AgeRange,
    projection: RowProjection,
) -> UnverifiedSelectedRows {
    let prepared = owner
        .prepare_exact_select_for_experiment(table, range, projection, 256, Limits::default())
        .unwrap();
    let evaluated = peer.evaluate_indexed_select(prepared.request()).unwrap();
    assert_eq!(
        (
            evaluated.stats.ct_ct_multiplications,
            evaluated.stats.relinearizations
        ),
        (1, 1)
    );
    owner
        .complete_exact_select_unverified_for_experiment(table, prepared, &evaluated.output)
        .unwrap()
}

#[test]
fn genuine_encrypted_select_preserves_complete_ordered_multpage_range_and_projection() {
    let (owner, peer) = Owner::generate([16; 16]).unwrap();
    let table = owner
        .seal(
            &[row(42, 255), row(7, 65535), row(18, 0), row(42, 256)],
            1,
            Limits::default(),
        )
        .unwrap();
    let range = AgeRange {
        lower: 18,
        upper: 42,
    };
    let actual = selected_rows(&owner, &peer, &table, range, RowProjection::AgeAmount);
    assert_eq!(actual.proof, ProofStatus::Unavailable);
    assert_eq!(
        actual.rows,
        vec![
            SelectedRow {
                ordinal: 0,
                age: Some(42),
                amount: Some(255)
            },
            SelectedRow {
                ordinal: 2,
                age: Some(18),
                amount: Some(0)
            },
            SelectedRow {
                ordinal: 3,
                age: Some(42),
                amount: Some(256)
            },
        ]
    );
    let amount = selected_rows(
        &owner,
        &peer,
        &table,
        AgeRange::equal(42),
        RowProjection::Amount,
    );
    assert_eq!(
        amount
            .rows
            .iter()
            .map(|row| (row.ordinal, row.age, row.amount))
            .collect::<Vec<_>>(),
        vec![(0, None, Some(255)), (3, None, Some(256))]
    );
    assert!(
        selected_rows(
            &owner,
            &peer,
            &table,
            AgeRange::equal(255),
            RowProjection::Age
        )
        .rows
        .is_empty()
    );
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(
            &table,
            range,
            RowProjection::Age,
            2,
            Limits::default()
        ),
        Err(Error::SelectionBudget {
            selected: 3,
            budget: 2
        })
    ));
}

#[test]
fn encrypted_select_rejects_authenticated_wrong_age_foreign_owner_and_mismatched_index() {
    let (owner, _) = Owner::generate([17; 16]).unwrap();
    let (other, _) = Owner::generate([18; 16]).unwrap();
    let mut table = owner.seal(&[row(42, 10)], 1, Limits::default()).unwrap();
    assert!(
        other
            .prepare_exact_select_for_experiment(
                &table,
                AgeRange::equal(42),
                RowProjection::Age,
                1,
                Limits::default()
            )
            .is_err()
    );
    table.index = crate::index::build(&owner.store, &[row(18, 10)], table.commitment()).unwrap();
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(
            &table,
            AgeRange::equal(18),
            RowProjection::Age,
            1,
            Limits::default()
        ),
        Err(Error::InvalidIndex)
    ));
    table.index = crate::index::build(&owner.store, &[row(42, 10)], table.commitment()).unwrap();
    let old = table.commitment().clone();
    owner
        .store
        .replace_page(&mut table.data, &old, 0, &[42, 11, 0], Limits::default())
        .unwrap();
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(
            &table,
            AgeRange::equal(42),
            RowProjection::Age,
            1,
            Limits::default()
        ),
        Err(Error::WrongVersion)
    ));
}

#[test]
fn encrypted_select_pending_rejects_either_changed_head_and_old_or_corrupt_images() {
    let (owner, peer) = Owner::generate([19; 16]).unwrap();
    let mut table = owner.seal(&[row(42, 255)], 1, Limits::default()).unwrap();
    let old_data = table.snapshot().encode();
    let old_index = table.encrypted_index().encode();
    let select = owner
        .prepare_exact_select_for_experiment(
            &table,
            AgeRange::equal(42),
            RowProjection::AgeAmount,
            1,
            Limits::default(),
        )
        .unwrap();
    let output = peer.evaluate_indexed_select(select.request()).unwrap();
    // Independently replace only the authenticated index header nonce/revision first.
    let verified = table
        .index
        .lookup(0, crate::index::index_limits())
        .unwrap()
        .verify(table.index_commitment(), 0, crate::index::index_limits())
        .unwrap();
    let plain = owner.store.decrypt(&verified).unwrap();
    let head = table.index_commitment().clone();
    owner
        .store
        .replace_page(
            &mut table.index,
            &head,
            0,
            plain.as_bytes(),
            crate::index::index_limits(),
        )
        .unwrap();
    assert!(matches!(
        owner.complete_exact_select_unverified_for_experiment(&table, select, &output.output),
        Err(Error::WrongVersion)
    ));
    let select = owner
        .prepare_exact_select_for_experiment(
            &table,
            AgeRange::equal(42),
            RowProjection::AgeAmount,
            1,
            Limits::default(),
        )
        .unwrap();
    let output = peer.evaluate_indexed_select(select.request()).unwrap();
    let update = owner
        .prepare_exact_update_for_experiment(&table, AgeRange::equal(42), 1, 1, Limits::default())
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(update.request()).unwrap();
    owner
        .apply_exact_update_checked_for_experiment(
            &mut table,
            update,
            &evaluated.output,
            Limits::default(),
        )
        .unwrap();
    assert!(matches!(
        owner.complete_exact_select_unverified_for_experiment(&table, select, &output.output),
        Err(Error::WrongVersion)
    ));
    assert_eq!(
        selected_rows(
            &owner,
            &peer,
            &table,
            AgeRange::equal(42),
            RowProjection::Amount
        )
        .rows[0]
            .amount,
        Some(256)
    );
    assert!(
        owner
            .restore_table_for_experiment(
                &old_data,
                &old_index,
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
    let mut corrupt = table.snapshot().encode();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(
        owner
            .restore_table_for_experiment(
                &corrupt,
                &table.encrypted_index().encode(),
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
}
