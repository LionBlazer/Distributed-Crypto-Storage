#![recursion_limit = "256"]
#![allow(dead_code)]
//! Fresh writer. Only ciphertext/public receipts leave this process.
include!("../shared.rs");
use compact_store::Layout;
#[path = "../process_protocol.rs"]
mod process_protocol;
#[path = "../runtime_support.rs"]
mod runtime_support;
#[path = "../writer_catalog.rs"]
mod writer_catalog;
use process_protocol::{
    Config, PublicAnchor, UpdateReceipt, WriterReceipt, read_secret_prefix, require_eof,
    write_public_line,
};
use runtime_support::*;
use sealed_owner_bundle::{CheckpointBinding, OriginalPublic, WrappingKey, seal_checkpoint};
use zeroize::Zeroizing;
static STAGE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn stage(value: usize) {
    STAGE.store(value, std::sync::atomic::Ordering::Relaxed)
}

fn original_update(
    entry: &mut disk::CatalogEntry,
    bfv: &BfvOwner,
    peer: &PeerEvaluator,
    pir: &Pir<'_>,
) -> ProbeResult<(UpdateReceipt, serde_json::Value)> {
    let started = Instant::now();
    disk::admit(
        "before_writer_authenticated_update",
        entry.id,
        32 * 1024 * 1024,
    )?;
    stage(5);
    let data_wire = disk::read_exact_image(&entry.data_path, entry.data_len, 8 * 1024 * 1024)?;
    let index_wire = disk::read_exact_image(&entry.index_path, entry.index_len, 8 * 1024 * 1024)?;
    let mut data = EncryptedSnapshot::decode(&data_wire, Limits::default())?;
    let mut index = EncryptedSnapshot::decode(&index_wire, padded_index_codec::index_limits())?;
    if data.commitment() != &entry.data_head || index.commitment() != &entry.index_head {
        return Err("Writer original trusted heads mismatch".into());
    }
    drop(data_wire);
    drop(index_wire);
    let data_store = Store {
        id: 0,
        snapshot: &data,
        head: &entry.data_head,
        db: None,
        limits: Limits::default(),
    };
    let index_store = Store {
        id: 1,
        snapshot: &index,
        head: &entry.index_head,
        db: None,
        limits: padded_index_codec::index_limits(),
    };
    let index_source = source(Access::Visible, &index_store, pir);
    let range = QuerySpec::Equal(250).selection_range()?;
    let header = padded_index_codec::check_binding(&entry.owner, &index_source, &entry.data_head)?;
    let (counts, _) = header.metadata();
    if counts[250] != 1 {
        return Err("Complete original EQ group must be exactly one before update".into());
    }
    posting_page_preflight(&header, range)?;
    let mut selected_wire = 0;
    let posting_source = source(Access::Visible, &index_store, pir);
    let selected = padded_index_codec::select_from_header(
        &entry.owner,
        &posting_source,
        &entry.data_head,
        range,
        SLOT_BUDGET,
        &mut selected_wire,
        header,
    )?;
    if selected.len() != 1 {
        return Err("Complete original selection changed".into());
    }
    let ordinal = selected[0];
    let page_id = data_page_preflight(&selected)?.ok_or("Expected original data page")?;
    let data_source = source(Access::Visible, &data_store, pir);
    let plain = data_source.plain(&entry.owner, page_id)?;
    let offset = (ordinal as usize % PAGE_ROWS) * ROW_BYTES as usize;
    let row = &plain.as_bytes()[offset..offset + ROW_BYTES as usize];
    let original = u16::from_le_bytes([row[1], row[2]]);
    let fields = [SelectedField {
        age: row[0],
        amount: original,
        active: true,
    }];
    check_exact_selected_ages(QuerySpec::Equal(250), &fields, selected.len())?;
    let context = QueryContext::new(
        nonce()?,
        entry.data_head.encode(),
        entry.index_head.encode(),
    );
    let prepare = Instant::now();
    stage(6);
    let prepared = bfv.prepare_indexed_update_for_experiment(context, &fields, 1)?;
    let prepare_ms = ms(prepare);
    let request_bytes = prepared.request.len();
    let evaluated = peer.evaluate_indexed_update(&prepared.request)?;
    let response_bytes = evaluated.output.len();
    if prepared.pending.context().data_head() != entry.data_head.encode()
        || prepared.pending.context().index_head() != entry.index_head.encode()
    {
        return Err("Original update pending head mismatch".into());
    }
    let outcome =
        bfv.decrypt_indexed_update_unverified_for_experiment(prepared.pending, &evaluated.output)?;
    let values = match outcome {
        compact_bfv_byte_limb_core::UnverifiedUpdateOutcome::Values(v) => v,
        compact_bfv_byte_limb_core::UnverifiedUpdateOutcome::Overflow { .. } => {
            return Err("Bounded original update overflowed".into());
        }
    };
    let expected = original
        .checked_add(1)
        .ok_or("Local overflow authorizes no mutation")?;
    if values.rows.len() != 1 || values.rows[0].slot != 0 || values.rows[0].amount != expected {
        return Err("Unverified FHE update failed owner local arithmetic authorization".into());
    }
    let mut changed = Zeroizing::new(plain.as_bytes().to_vec());
    changed[offset + 1..offset + 3].copy_from_slice(&values.rows[0].amount.to_le_bytes());
    let prior_data = entry.data_head.encode();
    let prior_index = entry.index_head.encode();
    // Stage both versions in RAM before writing. This is not crash-atomic file publication.
    stage(7);
    let next_data = entry.owner.replace_page(
        &mut data,
        &entry.data_head,
        page_id,
        &changed,
        Limits::default(),
    )?;
    let verified = index
        .lookup(0, padded_index_codec::index_limits())?
        .verify(&entry.index_head, 0, padded_index_codec::index_limits())?;
    let mut changed_header = Zeroizing::new(entry.owner.decrypt(&verified)?.as_bytes().to_vec());
    changed_header[..112].copy_from_slice(&next_data.encode());
    let next_index = entry.owner.replace_page(
        &mut index,
        &entry.index_head,
        0,
        &changed_header,
        padded_index_codec::index_limits(),
    )?;
    let cached = disk::capture_owner_header(&entry.owner, &index, &next_data)?;
    let data_image = data.encode();
    let index_image = index.encode();
    if data_image.len() != entry.data_len || index_image.len() != entry.index_len {
        return Err("Amount update changed canonical geometry".into());
    }
    std::fs::write(&entry.data_path, &data_image)?;
    std::fs::write(&entry.index_path, &index_image)?;
    entry.data_head = next_data;
    entry.index_head = next_index;
    entry.cached = cached;
    let receipt = UpdateReceipt {
        table_id: entry.id,
        ordinal,
        delta: 1,
        original_amount: original,
        updated_amount: expected,
        prior_data_head: prior_data.to_vec(),
        prior_index_head: prior_index.to_vec(),
    };
    Ok((
        receipt,
        json!({"whole_writer_update_ms":ms(started),"prepare_ms":prepare_ms,"request_bytes":request_bytes,
        "response_bytes":response_bytes,"peer":evaluated.stats,"selected_ordinals_from_original_index":selected,
        "local_arithmetic_authorization":true,"computation_proof":false,"data_revision":entry.data_head.revision(),
        "index_revision":entry.index_head.revision(),"canonical_growth_bytes":0}),
    ))
}
fn run() -> ProbeResult<()> {
    stage(1);
    let config = Config::from_args()?;
    let mut input = std::io::stdin().lock();
    let secret = read_secret_prefix(&mut input)?;
    require_eof(&mut input)?;
    drop(input);
    let wrapping = WrappingKey::from_protected_memory(secret);
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build_global()?;
    let monitor = resources::Monitor::start(2_000_000_000);
    native::configure("combined")?;
    std::fs::create_dir(&config.directory)?;
    let all = Instant::now();
    let params = spiral_owner_state::profile_params();
    let pir_domain = public_id()?;
    let start = Instant::now();
    stage(2);
    let setup = spiral_owner_state::OwnerState::generate(&params, pir_domain)?;
    let pir_generate_ms = ms(start);
    let pir_public = PublicParameters::deserialize(&params, &setup.public_wire);
    let pir = Pir {
        params: &params,
        client: &setup.client,
        public: &pir_public,
    };
    let start = Instant::now();
    let (bfv, public) = BfvOwner::generate(Geometry::Rows256)?;
    let bfv_generate_ms = ms(start);
    let start = Instant::now();
    let bfv_wire = public.to_bytes()?;
    let bfv_public_serialize_ms = ms(start);
    if bfv_wire.len() != 13_395_426 || setup.public_wire.len() != 6_029_344 {
        return Err("Original public setup size/profile mismatch".into());
    }
    let start = Instant::now();
    let peer = PeerEvaluator::from_public_setup(&public)?;
    let peer_restore_ms = ms(start);
    runtime_profile_gate(&bfv, &peer)?;
    disk::write_new(&config.directory.join("shared-bfv-public.bin"), &bfv_wire)?;
    disk::write_new(
        &config.directory.join("shared-pir-public.bin"),
        &setup.public_wire,
    )?;
    let start = Instant::now();
    stage(3);
    let mut catalog = writer_catalog::build_catalog(
        &config.directory,
        config.tables,
        config.max_canonical_bytes,
    )?;
    let canonical_generate_ms = ms(start);
    let bundle_id = public_id()?;
    let start = Instant::now();
    stage(4);
    let previous = seal_checkpoint(
        &wrapping,
        CheckpointBinding {
            bundle_id,
            checkpoint_id: public_id()?,
            generation: 0,
        },
        &checkpoints(&catalog),
        &bfv,
        OriginalPublic {
            bfv: &bfv_wire,
            pir: &setup.public_wire,
        },
        &setup.owner,
        pir_domain,
    )?;
    let previous_seal_ms = ms(start);
    disk::write_new(
        &config.directory.join("owner-previous.sealed"),
        &previous.wire,
    )?;
    let (update, update_stats) = original_update(
        catalog.last_mut().ok_or("No writer table")?,
        &bfv,
        &peer,
        &pir,
    )?;
    disk::persist_catalog(&config.directory, &catalog)?;
    write_public_line(
        &json!({"experiment":"restart-writer-update","table_id":update.table_id,"stats":update_stats}),
    )?;
    let start = Instant::now();
    stage(8);
    let current = seal_checkpoint(
        &wrapping,
        CheckpointBinding {
            bundle_id,
            checkpoint_id: public_id()?,
            generation: 1,
        },
        &checkpoints(&catalog),
        &bfv,
        OriginalPublic {
            bfv: &bfv_wire,
            pir: &setup.public_wire,
        },
        &setup.owner,
        pir_domain,
    )?;
    let current_seal_ms = ms(start);
    disk::write_new(
        &config.directory.join("owner-current.sealed"),
        &current.wire,
    )?;
    let original_public_setup_preserved = public.to_bytes()? == bfv_wire;
    let final_file_ledger = file_ledger(&config.directory)?;
    let receipt = WriterReceipt {
        experiment: "restart-writer-receipt".into(),
        protocol_version: 1,
        writer_pid: std::process::id(),
        tables: config.tables,
        previous: PublicAnchor::capture(&previous.anchor),
        current: PublicAnchor::capture(&current.anchor),
        update,
        native: native_memory(),
        file_ledger: final_file_ledger,
        original_public_setup_preserved,
        setup: json!({"writer_initialization_before_exit_ms":ms(all),"pir_generate_ms":pir_generate_ms,
            "bfv_generate_ms":bfv_generate_ms,"bfv_public_serialize_ms":bfv_public_serialize_ms,"peer_restore_ms":peer_restore_ms,
            "canonical_generate_ms":canonical_generate_ms,"previous_export_seal_ms":previous_seal_ms,
            "current_export_seal_ms":current_seal_ms,"table_owner_key_count":catalog.len(),"compact_secret_key_bytes":catalog.len()*32,
            "bfv_secret_serialized_bytes":bfv.secret_key_serialized_bytes(),"bfv_owner_image_bytes":compact_bfv_byte_limb_core::OWNER_RECOVERY_IMAGE_BYTES,
            "pir_owner_image_bytes":spiral_owner_state::OWNER_STATE_BYTES,"pir_client_secret_and_identity_payload_bytes":180224,
            "original_bfv_public_bytes":bfv_wire.len(),"original_pir_public_bytes":setup.public_wire.len(),
            "profile":bfv.profile(),"maximum_sampled_threads":monitor.maximum_sampled_threads(),
            "secret_images_or_wrapping_key_written":false,"full_machine_restart":false}),
    };
    receipt.validate(&config)?;
    write_public_line(&receipt)?;
    drop(wrapping);
    Ok(())
}
fn main() {
    if run().is_err() {
        let phases = [
            "configuration",
            "secret-pipe",
            "original-setup",
            "canonical-files",
            "previous-checkpoint",
            "original-authenticated-selection",
            "fresh-bfv-update",
            "authorized-file-rebind",
            "current-checkpoint",
        ];
        let phase = STAGE.load(std::sync::atomic::Ordering::Relaxed);
        let _ = write_public_line(
            &json!({"experiment":"restart-writer-failed","phase":phases.get(phase).unwrap_or(&"unknown-public-phase")}),
        );
        eprintln!("restart writer failed; private diagnostics are not formatted or persisted");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod update_selection_tests {
    use super::*;
    #[test]
    fn header_and_far_posting_page_have_independent_authenticated_one_page_budgets() {
        let params = spiral_owner_state::profile_params();
        let setup = spiral_owner_state::OwnerState::generate(&params, [27; 32]).unwrap();
        let public = PublicParameters::deserialize(&params, &setup.public_wire);
        let pir = Pir {
            params: &params,
            client: &setup.client,
            public: &public,
        };
        let owner = Owner::generate(*b"public-restart!0").unwrap();
        let rows = public_rows(MAX_TABLE_ROWS, 0);
        let packed: Vec<u8> = rows
            .iter()
            .flat_map(|r| [r.age, r.amount as u8, (r.amount >> 8) as u8])
            .collect();
        let data = owner
            .seal(
                Layout {
                    schema: SCHEMA,
                    row_width: ROW_BYTES,
                    rows_per_page: PAGE_ROWS as u32,
                    row_count: MAX_TABLE_ROWS as u64,
                },
                &packed,
                Limits::default(),
            )
            .unwrap();
        let index = padded_index_codec::build(&owner, &rows, data.commitment()).unwrap();
        let store = Store {
            id: 1,
            snapshot: &index,
            head: index.commitment(),
            db: None,
            limits: padded_index_codec::index_limits(),
        };
        let header_source = source(Access::Visible, &store, &pir);
        let range = QuerySpec::Equal(250).selection_range().unwrap();
        let header =
            padded_index_codec::check_binding(&owner, &header_source, data.commitment()).unwrap();
        // Observable regression: one Source cannot spend a one-page budget on both page0 and a far posting.
        assert!(
            padded_index_codec::select_from_header(
                &owner,
                &header_source,
                data.commitment(),
                range,
                SLOT_BUDGET,
                &mut 0,
                header
            )
            .is_err()
        );
        let header =
            padded_index_codec::check_binding(&owner, &header_source, data.commitment()).unwrap();
        let posting_source = source(Access::Visible, &store, &pir);
        let selected = padded_index_codec::select_from_header(
            &owner,
            &posting_source,
            data.commitment(),
            range,
            SLOT_BUDGET,
            &mut 0,
            header,
        )
        .unwrap();
        assert_eq!(selected, [0]);
        assert_eq!(header_source.posting_page.get(), Some(0));
        assert_ne!(posting_source.posting_page.get(), Some(0));
    }
}
