//! Explicitly public fixtures at the authenticated compact-storage/FHE-proof boundary.
#![cfg(feature = "bfv-experiment")]

use bfv_query_core::{PublicSetup, PublicUpdateEvaluator};
use bfv_query_proof::{GeneratedOperation, Operation, prove};
use compact_query::bfv::{
    Evaluator, Owner, PreparedSelect, PreparedUpdate, RowProjection, SelectedRow,
};
use compact_query::{AgeRange, Error, PlainRow, Table};
use compact_store::Limits;

fn row(age: u8, amount: u16) -> PlainRow {
    PlainRow { age, amount }
}
fn range_all() -> Option<AgeRange> {
    Some(AgeRange {
        lower: 0,
        upper: 255,
    })
}
fn encrypted_images(table: &Table) -> (Vec<u8>, Vec<u8>) {
    (table.snapshot().encode(), table.encrypted_index().encode())
}
fn public_evaluator(peer: &Evaluator) -> PublicUpdateEvaluator {
    // A real public-setup serialization boundary, without the owner or any secret key.
    let setup =
        PublicSetup::from_bytes(&peer.encode_public_setup_for_experiment().unwrap()).unwrap();
    PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap()
}
fn prove_select(
    peer: &PublicUpdateEvaluator,
    prepared: &PreparedSelect,
) -> (Vec<u8>, GeneratedOperation) {
    let input = peer.select_circuit_request(prepared.request()).unwrap();
    let result = prove(&input).unwrap();
    (input, result)
}
fn prove_update(peer: &PublicUpdateEvaluator, prepared: &PreparedUpdate) -> GeneratedOperation {
    prove(&peer.circuit_request(prepared.request()).unwrap()).unwrap()
}

#[test]
fn proved_select_covers_complete_postings_across_pages_and_keeps_empty_count_encrypted() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([81; 16]).unwrap();
    let public = public_evaluator(&peer);
    let profile = peer.profile();
    assert_eq!(profile.degree, 8192);
    let residue_bytes = profile.degree * profile.coefficient_moduli.len() * 2 * 8;
    // The 242 age-18 postings start after 5,798 earlier-bucket bytes. Their
    // authenticated posting list crosses the 8,192-byte index-page boundary;
    // selected data rows also span separate pages. All input rows are public.
    let rows: Vec<_> = (0..6040)
        .map(|ordinal| row(if ordinal % 25 == 0 { 18 } else { 7 }, ordinal as u16))
        .collect();
    let table = owner.seal(&rows, 17, limits).unwrap();
    let prepared = owner
        .prepare_provable_select(
            &table,
            Some(AgeRange::equal(18)),
            RowProjection::Amount,
            256,
            limits,
        )
        .unwrap();
    assert_eq!(prepared.selected_rows(), 242);
    let (selected_input, generated) = prove_select(&public, &prepared);

    let selected = owner
        .complete_proved_select(&table, prepared, generated.output(), generated.proof())
        .unwrap();

    assert_eq!(
        selected.evidence().operation(),
        Operation::PublicPolynomialProduct
    );
    let expected: Vec<_> = (0..6040)
        .step_by(25)
        .map(|ordinal| SelectedRow {
            ordinal,
            age: None,
            amount: Some(ordinal as u16),
        })
        .collect();
    assert_eq!(selected.rows(), expected);
    assert!(matches!(
        owner.prepare_provable_select(
            &table,
            Some(AgeRange::equal(18)),
            RowProjection::Amount,
            241,
            limits
        ),
        Err(Error::SelectionBudget {
            selected: 242,
            budget: 241
        })
    ));

    // Neither an authenticated absent bucket nor a schema-proven false predicate
    // places private match bits/counts in the public projection polynomial.
    for predicate in [Some(AgeRange::equal(99)), None] {
        let prepared = owner
            .prepare_provable_select(&table, predicate, RowProjection::Amount, 256, limits)
            .unwrap();
        assert_eq!(prepared.selected_rows(), 0);
        let (empty_input, generated) = prove_select(&public, &prepared);
        let right_start = 40 + residue_bytes;
        assert_eq!(empty_input.len(), selected_input.len());
        assert_eq!(&empty_input[right_start..], &selected_input[right_start..]);
        assert_eq!(generated.output().len(), residue_bytes + 40);
        let empty = owner
            .complete_proved_select(&table, prepared, generated.output(), generated.proof())
            .unwrap();
        assert!(empty.into_rows().is_empty());
    }
}

#[test]
fn proved_insert_stages_larger_encrypted_images_and_a_subsequent_proved_select_reads_the_new_row() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([82; 16]).unwrap();
    let public = public_evaluator(&peer);
    let table = owner
        .seal(&[row(18, 255), row(7, 65535)], 1, limits)
        .unwrap();
    let before = encrypted_images(&table);
    let original_ids = owner.row_references(&table, &[0, 1]).unwrap();
    let old_data = table.commitment().clone();
    let old_index = table.index_commitment().clone();
    let prepared = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(42, 256)],
            compact_query::RowIds::generate(1).unwrap(),
            256,
            limits,
        )
        .unwrap();
    let input = public.insert_circuit_request(prepared.request()).unwrap();
    let generated = prove(&input).unwrap();

    let staged = owner
        .stage_proved_insert(
            &table,
            prepared,
            generated.output(),
            generated.proof(),
            limits,
        )
        .unwrap();

    assert_eq!(
        encrypted_images(&table),
        before,
        "staging cannot publish into its source table"
    );
    let appended_ids = owner.row_references(&staged, &[0, 1, 2]).unwrap();
    assert_eq!(appended_ids.table_id(), original_ids.table_id());
    assert_eq!(&appended_ids.rows()[..2], original_ids.rows());
    assert!(
        original_ids
            .rows()
            .iter()
            .all(|row| row.row_id() != appended_ids.rows()[2].row_id())
    );
    let restored = owner
        .restore_table_for_experiment(
            &staged.snapshot().encode(),
            &staged.encrypted_index().encode(),
            staged.table_id(),
            staged.commitment(),
            staged.index_commitment(),
            limits,
        )
        .unwrap();
    assert_eq!(
        owner.row_references(&restored, &[0, 1, 2]).unwrap().rows(),
        appended_ids.rows()
    );
    assert_eq!(staged.commitment().layout().row_count, 3);
    assert_eq!(staged.commitment().revision(), old_data.revision() + 1);
    assert_eq!(
        staged.index_commitment().revision(),
        old_index.revision() + 1
    );
    assert_eq!(staged.commitment().database(), old_data.database());
    assert_eq!(staged.commitment().key_domain(), old_data.key_domain());
    let prepared = owner
        .prepare_provable_select(&staged, range_all(), RowProjection::AgeAmount, 256, limits)
        .unwrap();
    let (_, generated) = prove_select(&public, &prepared);
    let selected = owner
        .complete_proved_select(&staged, prepared, generated.output(), generated.proof())
        .unwrap();
    assert_eq!(
        selected.into_rows(),
        vec![
            SelectedRow {
                ordinal: 0,
                age: Some(18),
                amount: Some(255)
            },
            SelectedRow {
                ordinal: 1,
                age: Some(7),
                amount: Some(65535)
            },
            SelectedRow {
                ordinal: 2,
                age: Some(42),
                amount: Some(256)
            },
        ]
    );
    assert!(
        owner
            .restore_table_for_experiment(
                &before.0,
                &before.1,
                staged.table_id(),
                staged.commitment(),
                staged.index_commitment(),
                limits
            )
            .is_err()
    );
}

#[test]
fn proved_update_writes_decoded_carries_but_global_overflow_publishes_neither_image() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([83; 16]).unwrap();
    let public = public_evaluator(&peer);
    let table = owner
        .seal(&[row(42, 255), row(7, 65535), row(42, 256)], 1, limits)
        .unwrap();
    let before = encrypted_images(&table);
    let original_ids = owner.row_references(&table, &[0, 1, 2]).unwrap();
    let sizes = (table.canonical_data_bytes(), table.encrypted_index_bytes());
    let prepared = owner
        .prepare_provable_update(&table, Some(AgeRange::equal(42)), 1, 256, limits)
        .unwrap();
    let generated = prove_update(&public, &prepared);

    let staged = owner
        .stage_proved_update(
            &table,
            prepared,
            generated.output(),
            generated.proof(),
            limits,
        )
        .unwrap();

    assert_eq!(staged.evidence().operation(), Operation::Addition);
    assert!(!staged.overflowed());
    assert_eq!(staged.matched_rows(), 2);
    assert_eq!(staged.changed_rows(), 2);
    assert_eq!(staged.replaced_data_pages(), &[0, 2]);
    assert_eq!(staged.replaced_index_pages(), &[0]);
    let staged = staged.into_table().unwrap();
    let updated_ids = owner.row_references(&staged, &[0, 1, 2]).unwrap();
    assert_eq!(updated_ids.table_id(), original_ids.table_id());
    assert_eq!(updated_ids.rows(), original_ids.rows());
    assert_ne!(updated_ids.data_head(), original_ids.data_head());
    assert_ne!(updated_ids.index_head(), original_ids.index_head());
    assert_eq!(encrypted_images(&table), before);
    assert_eq!(
        (
            staged.canonical_data_bytes(),
            staged.encrypted_index_bytes()
        ),
        sizes
    );
    assert_eq!(
        staged.commitment().revision(),
        table.commitment().revision() + 1
    );
    assert_eq!(
        staged.index_commitment().revision(),
        table.index_commitment().revision() + 1
    );
    for (ordinal, expected) in [row(42, 256), row(7, 65535), row(42, 257)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            owner
                .decrypt_row_for_experiment(&staged, ordinal as u64, limits)
                .unwrap(),
            expected
        );
    }
    let prepared = owner
        .prepare_provable_update(&staged, Some(AgeRange::equal(42)), 0, 256, limits)
        .unwrap();
    let generated = prove_update(&public, &prepared);
    let unchanged = owner
        .stage_proved_update(
            &staged,
            prepared,
            generated.output(),
            generated.proof(),
            limits,
        )
        .unwrap();
    assert_eq!(unchanged.matched_rows(), 2);
    assert_eq!(unchanged.changed_rows(), 0);
    assert!(unchanged.replaced_data_pages().is_empty());
    assert!(unchanged.replaced_index_pages().is_empty());
    assert_eq!(
        encrypted_images(&unchanged.into_table().unwrap()),
        encrypted_images(&staged)
    );
    // Index page proofs use the private format's byte limits, not the data-row cap.
    let page = staged
        .lookup_index_page(0)
        .unwrap()
        .verify(
            staged.index_commitment(),
            0,
            compact_store::Limits {
                max_rows: compact_store::Limits::default().max_image_bytes as u64,
                ..limits
            },
        )
        .unwrap();
    assert_eq!(page.page_index(), 0);
    let staged_before = encrypted_images(&staged);
    let prepared = owner
        .prepare_provable_update(&staged, range_all(), 1, 256, limits)
        .unwrap();
    let generated = prove_update(&public, &prepared);

    let overflow = owner
        .stage_proved_update(
            &staged,
            prepared,
            generated.output(),
            generated.proof(),
            limits,
        )
        .unwrap();

    assert!(overflow.overflowed());
    assert_eq!(overflow.matched_rows(), 3);
    assert_eq!(overflow.changed_rows(), 0);
    assert!(overflow.replaced_data_pages().is_empty());
    assert!(overflow.replaced_index_pages().is_empty());
    assert!(overflow.into_table().is_none());
    assert_eq!(encrypted_images(&staged), staged_before);
    assert_eq!(encrypted_images(&table), before);
}

#[test]
fn old_heads_replayed_proofs_and_forged_results_cannot_complete_or_stage_changes() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([84; 16]).unwrap();
    let public = public_evaluator(&peer);
    let table = owner.seal(&[row(42, 255)], 1, limits).unwrap();
    let before = encrypted_images(&table);
    let select = owner
        .prepare_provable_select(&table, range_all(), RowProjection::Amount, 256, limits)
        .unwrap();
    let (_, selected) = prove_select(&public, &select);
    let another = owner
        .prepare_provable_select(&table, range_all(), RowProjection::Amount, 256, limits)
        .unwrap();
    assert!(matches!(
        owner.complete_proved_select(&table, another, selected.output(), selected.proof()),
        Err(Error::ComputationProof(_))
    ));
    let prepared = owner
        .prepare_provable_update(&table, range_all(), 1, 256, limits)
        .unwrap();
    let updated = prove_update(&public, &prepared);
    let staged = owner
        .stage_proved_update(&table, prepared, updated.output(), updated.proof(), limits)
        .unwrap()
        .into_table()
        .unwrap();

    let stale = owner.complete_proved_select(&staged, select, selected.output(), selected.proof());

    assert!(matches!(stale, Err(Error::WrongVersion)));
    assert_eq!(encrypted_images(&table), before);
    let prepared = owner
        .prepare_provable_update(&table, range_all(), 1, 256, limits)
        .unwrap();
    let forged = prove_update(&public, &prepared);
    let mut bad_output = forged.output().to_vec();
    // Preserve shape and binding; change a canonical ciphertext residue only.
    let last = bad_output.len() - 8;
    let coefficient = u64::from_le_bytes(bad_output[last..].try_into().unwrap());
    let changed = (coefficient + 1) % 17_592_184_717_313_u64;
    bad_output[last..].copy_from_slice(&changed.to_le_bytes());

    let rejected = owner.stage_proved_update(&table, prepared, &bad_output, forged.proof(), limits);

    assert!(matches!(rejected, Err(Error::ComputationProof(_))));
    assert_eq!(encrypted_images(&table), before);
    assert_eq!(
        owner.decrypt_row_for_experiment(&table, 0, limits).unwrap(),
        row(42, 255)
    );
}

#[test]
fn borrowed_select_verification_preserves_pending_but_checked_evidence_cannot_finish_another_statement()
 {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([85; 16]).unwrap();
    let public = public_evaluator(&peer);
    let table = owner.seal(&[row(42, 255)], 1, limits).unwrap();
    let images = encrypted_images(&table);
    let prepared = owner
        .prepare_provable_select(&table, range_all(), RowProjection::Amount, 256, limits)
        .unwrap();
    let (input, generated) = prove_select(&public, &prepared);
    assert!(matches!(
        owner.check_select_proof(&table, &prepared, generated.output(), &[]),
        Err(Error::ComputationProof(_))
    ));
    // A rejected candidate has not consumed the one-use owner preparation.
    let checked = owner
        .check_select_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    assert!(checked.matches_statement(&input, generated.output()));
    let another = owner
        .prepare_provable_select(&table, range_all(), RowProjection::Amount, 256, limits)
        .unwrap();

    let wrong_request = owner.complete_checked_select(&table, another, generated.output(), checked);

    assert!(matches!(wrong_request, Err(Error::ComputationProof(_))));
    let checked = owner
        .check_select_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let mut changed = generated.output().to_vec();
    let last = changed.len() - 8;
    let value = u64::from_le_bytes(changed[last..].try_into().unwrap());
    let modulus = *peer.profile().coefficient_moduli.last().unwrap();
    changed[last..].copy_from_slice(&((value + 1) % modulus).to_le_bytes());
    assert!(!checked.matches_statement(&input, &changed));

    let wrong_output = owner.complete_checked_select(&table, prepared, &changed, checked);

    assert!(matches!(wrong_output, Err(Error::ComputationProof(_))));
    assert_eq!(encrypted_images(&table), images);
}

#[test]
fn checked_mutation_evidence_is_bound_to_its_pending_request_even_between_two_addition_operations()
{
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([86; 16]).unwrap();
    let public = public_evaluator(&peer);
    let table = owner.seal(&[row(42, 255)], 1, limits).unwrap();
    let images = encrypted_images(&table);
    let prepared = owner
        .prepare_provable_update(&table, range_all(), 1, 256, limits)
        .unwrap();
    let generated = prove_update(&public, &prepared);
    assert!(matches!(
        owner.check_update_proof(&table, &prepared, generated.output(), &[]),
        Err(Error::ComputationProof(_))
    ));
    let checked = owner
        .check_update_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let another = owner
        .prepare_provable_update(&table, range_all(), 1, 256, limits)
        .unwrap();

    let wrong_update =
        owner.stage_checked_update(&table, another, generated.output(), checked, limits);

    assert!(matches!(wrong_update, Err(Error::ComputationProof(_))));
    let checked = owner
        .check_update_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let incoming = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(21, 12)],
            compact_query::RowIds::generate(1).unwrap(),
            256,
            limits,
        )
        .unwrap();
    // UPDATE and INSERT both use the same Addition proof primitive. Their exact
    // authenticated requests, rather than an operation-name check, distinguish them.
    assert_eq!(checked.operation(), Operation::Addition);

    let wrong_insert =
        owner.stage_checked_insert(&table, incoming, generated.output(), checked, limits);

    assert!(matches!(wrong_insert, Err(Error::ComputationProof(_))));
    let checked = owner
        .check_update_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let updated = owner
        .stage_checked_update(&table, prepared, generated.output(), checked, limits)
        .unwrap()
        .into_table()
        .unwrap();
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&updated, 0, limits)
            .unwrap(),
        row(42, 256)
    );
    assert_eq!(encrypted_images(&table), images);
    let prepared = owner
        .prepare_insert_for_experiment(
            &table,
            &[row(21, 12)],
            compact_query::RowIds::generate(1).unwrap(),
            256,
            limits,
        )
        .unwrap();
    let generated = prove(&public.insert_circuit_request(prepared.request()).unwrap()).unwrap();
    assert!(matches!(
        owner.check_insert_proof(&table, &prepared, generated.output(), &[]),
        Err(Error::ComputationProof(_))
    ));
    let checked = owner
        .check_insert_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let inserted = owner
        .stage_checked_insert(&table, prepared, generated.output(), checked, limits)
        .unwrap();
    assert_eq!(inserted.commitment().layout().row_count, 2);
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&inserted, 1, limits)
            .unwrap(),
        row(21, 12)
    );
    assert_eq!(encrypted_images(&table), images);
}

#[test]
fn a_whole_batch_requires_one_exact_proof_and_stages_all_rows_once() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([77; 16]).unwrap();
    let evaluator = public_evaluator(&peer);
    let original = vec![row(18, 255); 254];
    let table = owner.seal(&original, 17, limits).unwrap();
    let before = encrypted_images(&table);
    let old_ids = owner
        .row_references(&table, &(0..254).collect::<Vec<_>>())
        .unwrap();
    assert!(
        owner
            .prepare_insert_for_experiment(
                &table,
                &[],
                compact_query::RowIds::generate(0).unwrap(),
                256,
                limits
            )
            .is_err()
    );
    assert!(
        owner
            .prepare_insert_for_experiment(
                &table,
                &[row(1, 1); 3],
                compact_query::RowIds::generate(3).unwrap(),
                256,
                limits
            )
            .is_err()
    );
    let incoming = [row(42, 256), row(7, 65535)];
    let prepared = owner
        .prepare_insert_for_experiment(
            &table,
            &incoming,
            compact_query::RowIds::generate(incoming.len()).unwrap(),
            256,
            limits,
        )
        .unwrap();
    let input = evaluator
        .insert_circuit_request(prepared.request())
        .unwrap();
    let proved = prove(&input).unwrap();
    let mut tampered = proved.output().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        owner
            .check_insert_proof(&table, &prepared, &tampered, proved.proof())
            .is_err()
    );
    assert!(
        owner
            .check_insert_proof(&table, &prepared, proved.output(), &[])
            .is_err()
    );
    let wrong_version = owner.seal(&original, 17, limits).unwrap();
    assert!(matches!(
        owner.check_insert_proof(&wrong_version, &prepared, proved.output(), proved.proof()),
        Err(Error::WrongVersion)
    ));
    let checked = owner
        .check_insert_proof(&table, &prepared, proved.output(), proved.proof())
        .unwrap();
    let staged = owner
        .stage_checked_insert(&table, prepared, proved.output(), checked, limits)
        .unwrap();
    assert_eq!(encrypted_images(&table), before);
    assert_eq!(
        staged.commitment().revision(),
        table.commitment().revision() + 1
    );
    assert_eq!(staged.commitment().layout().row_count, 256);
    let ids = owner
        .row_references(&staged, &(0..256).collect::<Vec<_>>())
        .unwrap();
    assert_eq!(ids.table_id(), old_ids.table_id());
    assert_eq!(&ids.rows()[..254], old_ids.rows());
    assert_ne!(ids.rows()[254].row_id(), ids.rows()[255].row_id());
    assert!(
        old_ids
            .rows()
            .iter()
            .all(|old| old.row_id() != ids.rows()[254].row_id()
                && old.row_id() != ids.rows()[255].row_id())
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&staged, 253, limits)
            .unwrap(),
        original[253]
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&staged, 254, limits)
            .unwrap(),
        incoming[0]
    );
    assert_eq!(
        owner
            .decrypt_row_for_experiment(&staged, 255, limits)
            .unwrap(),
        incoming[1]
    );
}
