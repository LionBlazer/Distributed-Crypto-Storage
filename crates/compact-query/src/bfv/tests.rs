//! Public non-secret fixtures exercising the storage/crypto composition boundary.
use super::*;
fn row(age: u8, amount: u16) -> PlainRow {
    PlainRow { age, amount }
}

struct CountedData<'a> {
    snapshot: &'a compact_store::EncryptedSnapshot,
    pages: std::cell::RefCell<Vec<u64>>,
    unavailable: Option<u64>,
}
impl crate::PageSource for CountedData<'_> {
    fn commitment(&self) -> &Commitment {
        self.snapshot.commitment()
    }
    fn lookup(&self, page: u64, limits: Limits) -> Result<compact_store::VerifiedPage> {
        self.pages.borrow_mut().push(page);
        if self.unavailable == Some(page) {
            return Err(Error::Codec("Candidate page unavailable".into()));
        }
        Ok(self
            .snapshot
            .lookup(page, limits)?
            .verify(self.snapshot.commitment(), page, limits)?)
    }
}

#[test]
fn limited_select_validates_all_candidate_pages_once_and_rejects_discarded_wrong_age() {
    let limits = Limits::default();
    let (owner, _) = Owner::generate([76; 16]).unwrap();
    let mut rows = vec![row(42, 17); 300];
    let mut table = owner.seal(&rows, 17, limits).unwrap();
    for limit in [0, 1, 100, 256] {
        let counted = CountedData {
            snapshot: table.snapshot(),
            pages: Default::default(),
            unavailable: None,
        };
        let source =
            crate::ReadView::new(table.read_heads(), &counted, table.encrypted_index()).unwrap();
        let prepared = owner
            .prepare_provable_select_limited_from_source(
                &source,
                AgeSet256::equal(42),
                RowProjection::Amount,
                limit,
                256,
                limits,
            )
            .unwrap();
        assert_eq!(prepared.selected_rows(), limit);
        assert_eq!(*counted.pages.borrow(), (0..18).collect::<Vec<_>>());
    }
    for limit in [0, 1] {
        let counted = CountedData {
            snapshot: table.snapshot(),
            pages: Default::default(),
            unavailable: Some(17),
        };
        let source =
            crate::ReadView::new(table.read_heads(), &counted, table.encrypted_index()).unwrap();
        assert!(matches!(owner.prepare_provable_select_limited_from_source(
            &source, AgeSet256::equal(42), RowProjection::Amount, limit, 256, limits,
        ), Err(Error::Codec(message)) if message == "Candidate page unavailable"));
        assert_eq!(*counted.pages.borrow(), (0..18).collect::<Vec<_>>());
    }
    // Genuine owner-encrypted but invalid index: the wrong original age is AFTER
    // every retained row, on the last page. Even LIMIT0 must reject it.
    rows[299].age = 7;
    table = owner.seal(&rows, 17, limits).unwrap();
    table.index = crate::index::build(
        &owner.store,
        &[row(42, 17); 300],
        table.commitment(),
        table.table_id(),
        &crate::RowIds::generate(300).unwrap(),
    )
    .unwrap();
    for limit in [0, 1, 100, 256] {
        assert!(matches!(
            owner.prepare_provable_select_limited_from_source(
                &table.read_view(),
                AgeSet256::equal(42),
                RowProjection::Amount,
                limit,
                256,
                limits,
            ),
            Err(Error::InvalidIndex)
        ));
    }
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
    table.index = crate::index::build(
        &owner.store,
        &[row(18, 1); 4],
        table.commitment(),
        table.table_id(),
        &crate::RowIds::generate(table.commitment().layout().row_count as usize).unwrap(),
    )
    .unwrap();
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
            table.table_id(),
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
    table.index = crate::index::build(
        &owner.store,
        &[row(18, 10)],
        table.commitment(),
        table.table_id(),
        &crate::RowIds::generate(table.commitment().layout().row_count as usize).unwrap(),
    )
    .unwrap();
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
    table.index = crate::index::build(
        &owner.store,
        &[row(42, 10)],
        table.commitment(),
        table.table_id(),
        &crate::RowIds::generate(table.commitment().layout().row_count as usize).unwrap(),
    )
    .unwrap();
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
                table.table_id(),
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
                table.table_id(),
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
}

#[test]
fn genuine_insert_grows_actual_ciphertext_and_index_with_monotonic_heads_and_zero_max_rows() {
    let (owner, peer) = Owner::generate([51; 16]).unwrap();
    let mut table = owner.seal(&[], 1, Limits::default()).unwrap();
    let mut expected = Vec::new();
    for incoming in [row(0, 0), row(255, 65535), row(42, 256)] {
        let old_data = table.commitment().clone();
        let old_index = table.index_commitment().clone();
        let old = table.snapshot().encode();
        let prepared = owner
            .prepare_insert_for_experiment(
                &table,
                &[incoming],
                crate::RowIds::generate(1).unwrap(),
                256,
                Limits::default(),
            )
            .unwrap();
        let evaluated = peer.evaluate_indexed_insert(prepared.request()).unwrap();
        assert_eq!(evaluated.stats.ciphertext_additions, 1);
        assert_eq!(evaluated.stats.rotations, 0);
        owner
            .apply_insert_checked_for_experiment(
                &mut table,
                prepared,
                &evaluated.output,
                Limits::default(),
            )
            .unwrap();
        expected.push(incoming);
        assert_eq!(table.commitment().revision(), old_data.revision() + 1);
        assert_eq!(
            table.index_commitment().revision(),
            old_index.revision() + 1
        );
        assert_eq!(table.commitment().database(), old_data.database());
        assert_eq!(table.commitment().key_domain(), old_data.key_domain());
        for (slot, expected) in expected.iter().enumerate() {
            assert_eq!(
                owner
                    .decrypt_row_for_experiment(&table, slot as u64, Limits::default())
                    .unwrap(),
                *expected
            );
        }
        assert!(
            owner
                .restore_table_for_experiment(
                    &old,
                    &table.index.encode(),
                    table.table_id(),
                    table.commitment(),
                    table.index_commitment(),
                    Limits::default()
                )
                .is_err()
        );
        let actual = aggregate(
            &owner,
            &peer,
            &table,
            AgeRange {
                lower: 0,
                upper: 255,
            },
        );
        assert_eq!(
            (actual.count, actual.sum),
            (
                expected.len() as u32,
                expected.iter().map(|row| u32::from(row.amount)).sum()
            )
        );
    }
}

#[test]
fn in_bounds_wrong_inserted_relation_never_authorizes_any_compact_write() {
    let (owner, peer) = Owner::generate([52; 16]).unwrap();
    let mut table = owner.seal(&[row(18, 255)], 1, Limits::default()).unwrap();
    let before = (table.snapshot().encode(), table.index.encode());
    let prepared = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(42, 256)],
            crate::RowIds::generate(1).unwrap(),
            256,
            Limits::default(),
        )
        .unwrap();
    // Test-only wrong relation, with identical public binding and real encrypted peer append.
    // The core's public addition-forgery test independently shows such in-bounds values are not proven.
    let wrong = owner
        .key
        .prepare_indexed_insert_for_experiment(
            prepared.pending.context().clone(),
            &prepared.selection.fields,
            &[bfv_core::SelectedField {
                age: 43,
                amount: 256,
                active: true,
            }],
        )
        .unwrap();
    let wrong = peer.evaluate_indexed_insert(&wrong.request).unwrap();
    assert_eq!(
        owner
            .apply_insert_checked_for_experiment(
                &mut table,
                prepared,
                &wrong.output,
                Limits::default()
            )
            .unwrap_err(),
        Error::InvalidOutput
    );
    assert_eq!((table.snapshot().encode(), table.index.encode()), before);
}

#[test]
fn pending_insert_rejects_either_changed_head_and_wrong_owner_without_mutation() {
    let (owner, peer) = Owner::generate([53; 16]).unwrap();
    let (other, _) = Owner::generate([54; 16]).unwrap();
    let mut table = owner.seal(&[row(18, 255)], 1, Limits::default()).unwrap();
    assert!(
        other
            .prepare_insert_for_experiment(
                &table,
                &[row(42, 1)],
                crate::RowIds::generate(1).unwrap(),
                256,
                Limits::default()
            )
            .is_err()
    );
    let first = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(42, 1)],
            crate::RowIds::generate(1).unwrap(),
            256,
            Limits::default(),
        )
        .unwrap();
    let output = peer.evaluate_indexed_insert(first.request()).unwrap();
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
    let before = (table.snapshot().encode(), table.index.encode());
    assert_eq!(
        owner
            .apply_insert_checked_for_experiment(
                &mut table,
                first,
                &output.output,
                Limits::default()
            )
            .unwrap_err(),
        Error::WrongVersion
    );
    assert_eq!((table.snapshot().encode(), table.index.encode()), before);
    let first = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(42, 1)],
            crate::RowIds::generate(1).unwrap(),
            256,
            Limits::default(),
        )
        .unwrap();
    let first_output = peer.evaluate_indexed_insert(first.request()).unwrap();
    let second = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(7, 2)],
            crate::RowIds::generate(1).unwrap(),
            256,
            Limits::default(),
        )
        .unwrap();
    let output = peer.evaluate_indexed_insert(second.request()).unwrap();
    owner
        .apply_insert_checked_for_experiment(&mut table, second, &output.output, Limits::default())
        .unwrap();
    let before = (table.snapshot().encode(), table.index.encode());
    assert_eq!(
        owner
            .apply_insert_checked_for_experiment(
                &mut table,
                first,
                &first_output.output,
                Limits::default()
            )
            .unwrap_err(),
        Error::WrongVersion
    );
    assert_eq!((table.snapshot().encode(), table.index.encode()), before);
}

#[test]
fn speculative_appends_keep_old_ids_and_allocate_independent_new_ids() {
    let (owner, peer) = Owner::generate([86; 16]).unwrap();
    let table = owner.seal(&[row(42, 1)], 256, Limits::default()).unwrap();
    let original = owner.row_references(&table, &[0]).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let mut branch = table.fork_for_experiment();
        let prepared = owner
            .prepare_insert_for_experiment(
                &branch,
                &[row(42, 1)],
                crate::RowIds::generate(1).unwrap(),
                256,
                Limits::default(),
            )
            .unwrap();
        let output = peer.evaluate_indexed_insert(prepared.request()).unwrap();
        owner
            .apply_insert_checked_for_experiment(
                &mut branch,
                prepared,
                &output.output,
                Limits::default(),
            )
            .unwrap();
        let refs = owner.row_references(&branch, &[0, 1]).unwrap();
        assert_eq!(refs.table_id(), original.table_id());
        assert_eq!(refs.rows()[0].row_id(), original.rows()[0].row_id());
        ids.push(*refs.rows()[1].row_id());
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(
        owner.row_references(&table, &[0]).unwrap().rows(),
        original.rows()
    );
}
