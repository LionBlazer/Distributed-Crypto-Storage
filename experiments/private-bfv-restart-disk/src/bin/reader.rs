#![recursion_limit = "256"]
#![allow(dead_code)]
//! Reader process: imports authenticated ORIGINAL owner material, never generates an Owner.
include!("../shared.rs");
#[cfg(test)]
use compact_store::Layout;
use std::collections::HashMap;
#[path = "../process_protocol.rs"]
mod process_protocol;
#[path = "../runtime_support.rs"]
mod runtime_support;
use process_protocol::{
    Config, ReaderReceipt, ReaderStart, read_public_frame, read_secret_prefix, require_eof,
    write_public_line,
};
use runtime_support::*;
use sealed_owner_bundle::{CheckpointAnchor, OriginalPublic, WrappingKey, restore_checkpoint};
use zeroize::Zeroizing;

struct RestoreInput<'a> {
    wrapping: &'a WrappingKey,
    expected: &'a CheckpointAnchor,
    sealed: &'a [u8],
    bfv: &'a [u8],
    pir: &'a [u8],
    params: &'a Params,
    directory: &'a std::path::Path,
}
fn rejects(name: &str, input: &RestoreInput<'_>) -> ProbeResult<()> {
    if restore_checkpoint(
        input.wrapping,
        input.expected,
        input.sealed,
        OriginalPublic {
            bfv: input.bfv,
            pir: input.pir,
        },
        input.params,
        input.directory,
    )
    .is_ok()
    {
        return Err("Invalid restoration unexpectedly produced owners".into());
    }
    write_public_line(
        &json!({"experiment":"restart-reader-negative","scenario":name,"rejected":true,
        "before_query_bfv_prepare":true,"returned_owner_handles":0}),
    )?;
    Ok(())
}
fn run() -> ProbeResult<()> {
    let config = Config::from_args()?;
    let mut input = std::io::stdin().lock();
    let secret = read_secret_prefix(&mut input)?;
    let start: ReaderStart = read_public_frame(&mut input)?;
    require_eof(&mut input)?;
    drop(input);
    if start.protocol_version != 1 || !start.writer_exited_successfully {
        return Err("Actual writer exit barrier required".into());
    }
    start.writer.validate(&config)?;
    if start.writer.writer_pid == std::process::id() {
        return Err("Distinct child process required".into());
    }
    let mut wrong_secret = Zeroizing::new([0u8; 32]);
    wrong_secret.copy_from_slice(secret.as_ref());
    wrong_secret[0] ^= 1;
    let wrong = WrappingKey::from_protected_memory(wrong_secret);
    let wrapping = WrappingKey::from_protected_memory(secret);
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build_global()?;
    let monitor = resources::Monitor::start(2_000_000_000);
    native::configure("combined")?;
    let all = Instant::now();
    let params = spiral_owner_state::profile_params();
    let start_file = Instant::now();
    let bfv_wire = read_bounded(
        &config.directory.join("shared-bfv-public.bin"),
        1,
        sealed_owner_bundle::MAX_BFV_PUBLIC_BYTES,
    )?;
    let pir_wire = read_bounded(
        &config.directory.join("shared-pir-public.bin"),
        spiral_owner_state::PUBLIC_SETUP_BYTES,
        spiral_owner_state::PUBLIC_SETUP_BYTES,
    )?;
    let current = read_bounded(
        &config.directory.join("owner-current.sealed"),
        128,
        sealed_owner_bundle::MAX_SEALED_BUNDLE_BYTES,
    )?;
    let previous = read_bounded(
        &config.directory.join("owner-previous.sealed"),
        128,
        sealed_owner_bundle::MAX_SEALED_BUNDLE_BYTES,
    )?;
    let public_cipher_read_ms = ms(start_file);
    let expected = start.writer.current.restore()?;
    let old_expected = start.writer.previous.restore()?;
    let base = RestoreInput {
        wrapping: &wrapping,
        expected: &expected,
        sealed: &current,
        bfv: &bfv_wire,
        pir: &pir_wire,
        params: &params,
        directory: &config.directory,
    };
    let negative_start = Instant::now();
    rejects(
        "wrong-wrapping-key",
        &RestoreInput {
            wrapping: &wrong,
            ..base
        },
    )?;
    drop(wrong);
    let mut corrupted = current.clone();
    *corrupted.last_mut().ok_or("Empty checkpoint")? ^= 1;
    rejects(
        "corrupt-sealed-tag",
        &RestoreInput {
            sealed: &corrupted,
            ..base
        },
    )?;
    drop(corrupted);
    rejects(
        "truncated-sealed-checkpoint",
        &RestoreInput {
            sealed: &current[..current.len() - 1],
            ..base
        },
    )?;
    let oversize = vec![0u8; sealed_owner_bundle::MAX_SEALED_BUNDLE_BYTES + 1];
    rejects(
        "oversized-sealed-before-decode",
        &RestoreInput {
            sealed: &oversize,
            ..base
        },
    )?;
    drop(oversize);
    let mut wrong_public = bfv_wire.clone();
    wrong_public[0] ^= 1;
    rejects(
        "wrong-original-bfv-public-or-profile",
        &RestoreInput {
            bfv: &wrong_public,
            ..base
        },
    )?;
    drop(wrong_public);
    let mut wrong_pir = pir_wire.clone();
    wrong_pir[0] ^= 1;
    rejects(
        "wrong-original-pir-public",
        &RestoreInput {
            pir: &wrong_pir,
            ..base
        },
    )?;
    drop(wrong_pir);
    let mut wrong_anchor = expected.clone();
    wrong_anchor.catalog_digest[0] ^= 1;
    rejects(
        "wrong-trusted-catalog-or-table-binding",
        &RestoreInput {
            expected: &wrong_anchor,
            ..base
        },
    )?;
    rejects(
        "valid-old-backup-vs-current-independent-anchor",
        &RestoreInput {
            sealed: &previous,
            ..base
        },
    )?;
    rejects(
        "valid-old-backup-and-old-anchor-vs-current-physical-heads",
        &RestoreInput {
            sealed: &previous,
            expected: &old_expected,
            ..base
        },
    )?;
    let negative_ms = ms(negative_start);
    disk::admit("before_original_owner_restore", 0, 96 * 1024 * 1024)?;
    let start_restore = Instant::now();
    let restored = restore_checkpoint(
        &wrapping,
        &expected,
        &current,
        OriginalPublic {
            bfv: &bfv_wire,
            pir: &pir_wire,
        },
        &params,
        &config.directory,
    )?;
    let authenticated_secret_restore_ms = ms(start_restore);
    if restored.anchor() != &expected || restored.tables().len() != config.tables {
        return Err("Original checkpoint completeness mismatch".into());
    }
    // Full canonical root recomputation precedes any NTT use. Move each restored owner;
    // no cloning of owner keys and no self-referential reconstructed runtime.
    let parts = restored.into_parts();
    let bfv = parts.bfv_owner;
    let start_peer = Instant::now();
    let peer = PeerEvaluator::from_public_setup(&parts.bfv_public)?;
    runtime_profile_gate(&bfv, &peer)?;
    if parts.bfv_public.to_bytes()? != bfv_wire {
        return Err("Original public BFV setup changed across process restoration".into());
    }
    let peer_restore_ms = ms(start_peer);
    let public_bytes = bfv_wire.len() + pir_wire.len();
    let original_bfv_counts = parts.bfv_public.byte_counts()?;
    let secret_counts = bfv.secret_key_serialized_bytes() + spiral_owner_state::OWNER_STATE_BYTES;
    let pir_expanded = 23_855_104;
    let start_bootstrap = Instant::now();
    let mut catalog = Vec::with_capacity(config.tables);
    for table in parts.tables {
        let metadata = table.metadata();
        if metadata.table_id as usize != catalog.len() {
            return Err("Restored catalog must cover exact contiguous original IDs".into());
        }
        disk::admit(
            "before_restored_authenticated_header_bootstrap",
            metadata.table_id as usize,
            8 * 1024 * 1024,
        )?;
        // Bootstrap is deliberately separate from query timers; actual queries reread full images on misses.
        // Only the index needs a cached header. Full decode recomputes its Merkle root.
        let image = disk::read_exact_image(
            &config.directory.join(&metadata.index_file),
            metadata.index_bytes as usize,
            8 * 1024 * 1024,
        )?;
        let index = EncryptedSnapshot::decode(&image, padded_index_codec::index_limits())?;
        if index.commitment() != &metadata.index_head {
            return Err("Restored index full Merkle commitment mismatch".into());
        }
        let cached = disk::capture_owner_header(table.owner(), &index, &metadata.data_head)?;
        drop(index);
        drop(image);
        let table = table.into_parts();
        let metadata = table.metadata;
        catalog.push(disk::CatalogEntry {
            id: metadata.table_id as usize,
            owner: table.owner,
            data_path: config.directory.join(metadata.data_file),
            index_path: config.directory.join(metadata.index_file),
            data_head: metadata.data_head,
            index_head: metadata.index_head,
            data_len: metadata.data_bytes as usize,
            index_len: metadata.index_bytes as usize,
            cached,
        });
    }
    let authenticated_header_bootstrap_ms = ms(start_bootstrap);
    let target = &catalog[start.writer.update.table_id];
    if target.data_head.encode().as_slice() == start.writer.update.prior_data_head
        || target.index_head.encode().as_slice() == start.writer.update.prior_index_head
        || target.data_head.revision() == 0
        || target.index_head.revision() == 0
    {
        return Err("Current checkpoint failed to retain actual nonzero update versions".into());
    }
    drop(parts.bfv_public);
    drop(bfv_wire);
    drop(pir_wire);
    drop(current);
    drop(previous);
    drop(wrapping);
    let pir = Pir {
        params: &params,
        client: &parts.pir.client,
        public: &parts.pir.public,
    };
    let restore = json!({"initialization_including_negative_controls_ms":ms(all),"public_cipher_file_read_ms":public_cipher_read_ms,
        "negative_controls_ms":negative_ms,"authenticated_original_secret_restore_ms":authenticated_secret_restore_ms,
        "original_public_peer_restore_ms":peer_restore_ms,"authenticated_header_bootstrap_ms":authenticated_header_bootstrap_ms,
        "original_bfv_public_bytes":13_395_426,"original_pir_public_bytes":6_029_344,"bfv_key_bytes":original_bfv_counts,
        "shared_secret_serialized_counts":secret_counts,"per_table_owner_secret_key_bytes":catalog.len()*32,
        "compact_owner_recovery_image_bytes":compact_store::OWNER_RECOVERY_IMAGE_BYTES,
        "bfv_owner_recovery_image_bytes":compact_bfv_byte_limb_core::OWNER_RECOVERY_IMAGE_BYTES,
        "pir_owner_recovery_image_bytes":spiral_owner_state::OWNER_STATE_BYTES,
        "shared_expanded_pir_public_payload_bytes":pir_expanded,"pir_client_secret_and_identity_payload_bytes":180224,
        "cached_headers_including_both_heads_bytes":catalog.len()*2276,"trusted_heads_bytes":catalog.len()*224,
        "restored_table_owner_count":catalog.len(),"restored_bfv_owner_count":1,"restored_pir_owner_count":1,
        "reader_key_path":"authenticated-original-secret-import","wrapping_key_dropped_before_queries":true,
        "original_public_setup_preserved":true,"writer_exited_successfully":true,"original_writer_pid":start.writer.writer_pid,
        "profile":bfv.profile(),"negative_control_count":9,"no_new_encrypted_fixture_or_owner_key_generation_in_reader":true,"public_fixture_oracle_reconstructed_after_each_query_timer":true,
        "rollback_authority_external":true,"backup_authentication_is_not_rollback_protection":true});
    write_public_line(
        &json!({"experiment":"restart-reader-initialized","restore":&restore,"resources":native_memory()}),
    )?;
    let mut loader = disk::Loader::new(1)?;
    let preparations = Cell::new(0);
    let mut previous_fingerprints = HashMap::<(usize, String, KernelMode), [u8; 32]>::new();
    let mut shapes = HashMap::<String, (usize, usize, usize)>::new();
    let mut pair_round = 0usize;
    for sample in 0..config.samples {
        for case in CASES {
            for profile in [Profile::AddressOnly, Profile::Fixed256] {
                for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                    for access in [Access::Private, Access::Visible] {
                        for kernel in KernelMode::pair_order(pair_round) {
                            for &id in &config.ids {
                                for repeat in 0..2 {
                                    let before = loader.current.as_ref().map(|x| x.id);
                                    let result = loader.execute(
                                        &catalog[id],
                                        Plan {
                                            kernel,
                                            access,
                                            profile,
                                            header,
                                            query: case.query,
                                            query_id: nonce()?,
                                        },
                                        &bfv,
                                        &peer,
                                        &pir,
                                        &preparations,
                                    )?;
                                    if result.load.event
                                        != if repeat == 0 { "TableMiss" } else { "TableHit" }
                                    {
                                        return Err(
                                            "Actual capacity-one miss/hit shape mismatch".into()
                                        );
                                    }
                                    // Public fixture oracle runs only AFTER full pipeline timing.
                                    let (expected, mut sum) = oracle(id, case.query);
                                    if id == start.writer.update.table_id
                                        && expected.contains(&start.writer.update.ordinal)
                                    {
                                        sum += u32::from(start.writer.update.delta);
                                    }
                                    if result.query.selected != expected
                                        || result.query.actual.count != expected.len() as u32
                                        || result.query.actual.sum != sum
                                    {
                                        return Err("Restored ORIGINAL keys/files did not yield updated fixture aggregate".into());
                                    }
                                    let fingerprint: [u8; 32] =
                                        sha2::Sha256::digest(&result.query.ciphertext_payload)
                                            .into();
                                    if previous_fingerprints
                                        .insert((id, case.name.to_owned(), kernel), fingerprint)
                                        == Some(fingerprint)
                                    {
                                        return Err(
                                            "Repeated ciphertext payload freshness failure".into(),
                                        );
                                    }
                                    let s = &result.query.stages;
                                    let request = s.header.request_bytes
                                        + s.posting.request_bytes
                                        + s.data.request_bytes
                                        + s.bfv_request_bytes;
                                    let response = s.header.response_bytes
                                        + s.posting.response_bytes
                                        + s.data.response_bytes
                                        + s.bfv_response_bytes;
                                    let rpcs = s.header.calls + s.posting.calls + s.data.calls + 1;
                                    if matches!(profile, Profile::Fixed256) {
                                        let key = format!(
                                            "{kernel:?}/{header:?}/{access:?}/{}",
                                            case.query.kind()
                                        );
                                        if shapes
                                            .insert(key, (request, response, rpcs))
                                            .is_some_and(|old| old != (request, response, rpcs))
                                        {
                                            return Err("Fixed256 public request shape depended on table or result count".into());
                                        }
                                    }
                                    write_public_line(
                                        &json!({"experiment":"restart-disk-read","kernel":format!("{kernel:?}"),"sample":sample,
                                        "case":case.name,"query_kind":case.query.kind(),"table_id":id,"profile":format!("{profile:?}"),
                                        "header":format!("{header:?}"),"access":format!("{access:?}"),"repeat":repeat,"prior_loaded_table":before,
                                        "whole_local_ms":result.whole_ms,"query_only_nested_ms":result.query.total_ms,"load":result.load,
                                        "query_stages":result.query.stages,"selected_ordinals_from_real_index":result.query.selected,
                                        "aggregate":result.query.actual,"correct":true,"fresh_ciphertexts":true,"request_bytes":request,
                                        "response_bytes":response,"wire_bytes":request+response,"sequential_rpcs":rpcs,"loader":loader.ledger(),
                                        "resources":resources::memory_sample(),"maximum_sampled_threads":monitor.maximum_sampled_threads(),
                                        "query_timer_excludes_restore_bootstrap":true,"application_miss_not_physical_disk_cold":true,
                                        "owner_online":true,"network_measured":false,"computation_proof":false}),
                                    )?;
                                }
                            }
                        }
                        pair_round += 1;
                    }
                }
            }
        }
    }
    let expected_operations = config.samples * CASES.len() * 32 * config.ids.len();
    if preparations.get() != expected_operations {
        return Err("Actual restored BFV preparation count incomplete".into());
    }
    let ledger = disk_accounting(
        &config.directory,
        &catalog,
        &loader,
        SharedBytes {
            public_wire: public_bytes,
            owner_counts: secret_counts,
            pir_public_ram: pir_expanded,
        },
    )?;
    let final_files = file_ledger(&config.directory)?;
    let receipt = ReaderReceipt {
        experiment: "restart-reader-receipt".into(),
        protocol_version: 1,
        reader_pid: std::process::id(),
        original_writer_pid: start.writer.writer_pid,
        completed: true,
        correct: true,
        matrix_operations: preparations.get(),
        reader_key_path: "authenticated-original-secret-import".into(),
        native: native_memory(),
        restore,
        file_ledger: json!({"actual_files":final_files,"process_accounting":ledger,
            "loaded_capacity":1,"active_loaded_count":usize::from(loader.current.is_some()),"retained_public_headers":catalog.len()}),
    };
    write_public_line(&receipt)?;
    drop(parts.pir.owner);
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("restart reader failed; private diagnostics are not formatted or persisted");
        std::process::exit(1)
    }
}
