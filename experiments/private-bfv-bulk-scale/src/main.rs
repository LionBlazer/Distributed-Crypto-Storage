//! Source-only prepared whole-table bulk alternative; NOT PIR. Public synthetic data only.
mod bulk_wire;
mod disk_scale;
mod fixture;
mod resources;
#[allow(dead_code)]
// Byte-pinned role module retains Resident APIs for inherited tests; runtime is Disk-only.
mod roles;
#[cfg(test)]
mod scale_tests;
#[cfg(test)]
mod tests;
use compact_query::bfv;
use serde_json::json;
use sha2::{Digest, Sha256};
use spiral_rs::{client::PublicParameters, poly::PolyMatrixNTT};
use std::{path::PathBuf, time::Instant};
type ProbeResult<T> = Result<T, Box<dyn std::error::Error>>;
fn expanded_public_bytes(public: &PublicParameters<'_>) -> usize {
    fn group(items: &[PolyMatrixNTT<'_>]) -> usize {
        items.iter().map(|item| item.data.len() * 8).sum()
    }
    group(&public.v_packing)
        + public.v_expansion_left.as_ref().map_or(0, |v| group(v))
        + public.v_expansion_right.as_ref().map_or(0, |v| group(v))
        + public.v_conversion.as_ref().map_or(0, |v| group(v))
}
fn memory_json() -> ProbeResult<serde_json::Value> {
    let m = resources::guard(0)?;
    Ok(
        json!({"rss":m.working_set_bytes,"peak_rss":m.peak_working_set_bytes,"commit":m.private_commit_bytes,"peak_commit":m.peak_commit_bytes}),
    )
}
fn modeled_network(wire: usize, local_ms: f64) -> serde_json::Value {
    let values=[100.0,1000.0].into_iter().flat_map(|mbps|[0.0,10.0].into_iter().map(move|rtt|{
        let transfer_ms=wire as f64*8.0/(mbps*1000.0);
        json!({"bandwidth_mbps":mbps,"rtt_ms":rtt,"transfer_ms":transfer_ms,"sequential_rpcs":2,
            "model_total_ms":local_ms+transfer_ms+2.0*rtt,"measured_network":false,"overlap_assumed":false})
    })).collect::<Vec<_>>();
    let remaining = 500.0 - local_ms;
    json!({"serialized_two_rpc_model":values,"minimum_mbps_for500ms_rtt0":if remaining>0.0{Some(wire as f64*8.0/(remaining*1000.0))}else{None},
        "maximum_rtt_ms_for500ms_at100mbps":if remaining>wire as f64*8.0/100000.0{Some((remaining-wire as f64*8.0/100000.0)/2.0)}else{None}})
}
fn profile_gate(owner: &roles::OwnerTable, peer: &roles::DiskPeer) -> ProbeResult<()> {
    let actual = owner.profile();
    let remote = peer.evaluator.profile();
    let moduli = [
        8796092858369,
        8796092792833,
        17592186028033,
        17592185438209,
        17592184717313,
    ];
    if actual.degree != 8192
        || actual.plaintext_modulus != 114689
        || actual.coefficient_moduli != moduli
        || actual.initial_level != 0
        || actual.output_level != 0
        || actual.optimized_ntt
        || actual.fused_ge
        || !actual.additive_range
        || serde_json::to_value(&actual)? != serde_json::to_value(&remote)?
        || peer.evaluator.public_setup_bytes()?.serialized_wire != 13_395_426
    {
        return Err("Original BFV full profile/keyset wire changed".into());
    }
    Ok(())
}
fn run() -> ProbeResult<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let directory = PathBuf::from(args.get(1).ok_or("Supply a NEW ignored .local directory")?);
    let tables = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("3")
        .parse::<usize>()?;
    let budget = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("6500000000")
        .parse::<u64>()?;
    if ![3, 1000].contains(&tables)
        || directory.exists()
        || !directory.components().any(|c| c.as_os_str() == ".local")
    {
        return Err("Use new .local child and explicit3/1000 table count".into());
    }
    let parent = directory
        .parent()
        .filter(|p| p.is_dir())
        .ok_or("Existing dataset parent required")?;
    let available = disk_scale::free_bytes(parent)?;
    let planned = disk_scale::preflight(tables, budget, available)?;
    println!(
        "{}",
        json!({"experiment":"bulk-scale-preflight","tables":tables,"budget_bytes":budget,"canonical_plus_catalog_reserved_bytes":planned,
        "actual_available_disk_bytes":available,"free_space_preflight_before_keys_and_writes":true})
    );
    resources::guard(512 * 1024 * 1024)?;
    std::fs::create_dir(&directory)?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()?;
    let setup_all = Instant::now();
    let params = spiral_owner_state::profile_params();
    let mut domain = [0_u8; 32];
    getrandom::getrandom(&mut domain).map_err(|_| "OS randomness unavailable")?;
    let started = Instant::now();
    let pir = spiral_owner_state::OwnerState::generate(&params, domain)?;
    let pir_public = PublicParameters::deserialize(&params, &pir.public_wire);
    let pir_setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    if pir.public_wire.len() != spiral_owner_state::PUBLIC_SETUP_BYTES {
        return Err("Original PIR profile/wire changed".into());
    }
    let started = Instant::now();
    // ONE owner/keyset for ONE database; every canonical table is independently sealed below.
    let (authority, evaluator) = bfv::Owner::generate(*b"public-bulk-db01")?;
    let bfv_setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    let counts = evaluator.public_setup_bytes()?;
    let public_wire = evaluator.encode_public_setup_for_experiment()?;
    let digest = Sha256::digest(&public_wire);
    drop(public_wire);
    let started = Instant::now();
    let catalog = disk_scale::Catalog::create(&directory, tables, budget, &authority)?;
    let canonical_setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut owner = roles::OwnerTable::new(authority, catalog.entries[0].trusted.clone());
    let check_peer = roles::DiskPeer::new(
        evaluator.clone(),
        catalog.entries[0].trusted.clone(),
        catalog.entries[0].data_path.clone(),
        catalog.entries[0].index_path.clone(),
    );
    profile_gate(&owner, &check_peer)?;
    drop(check_peer);
    let ledger = catalog.ledger()?;
    let setup_memory = memory_json()?;
    println!(
        "{}",
        json!({"experiment":"bulk-scale-setup","tables":tables,"database_owners":1,"bfv_keysets":1,"rayon_threads":8,"fresh_independently_sealed_tables":true,
        "setup_ms":setup_all.elapsed().as_secs_f64()*1000.0,"pir_setup_ms":pir_setup_ms,"bfv_setup_ms":bfv_setup_ms,"canonical_seal_write_ms":canonical_setup_ms,
        "bfv_profile":owner.profile(),"bfv_public_serialized_counts":counts,"bfv_public_sha256":format!("{digest:x}"),"bfv_public_native_arc_retained":true,"bfv_flat_wire_copy_retained":false,
        "bfv_secret_serialized_count":owner.secret_key_count(),"compact_owner_key_bytes":32,"pir_owner_image_bytes":spiral_owner_state::OWNER_STATE_BYTES,
        "original_pir_public_wire_bytes":pir.public_wire.len(),"pir_full_expanded_matrix_u64_payload_bytes":expanded_public_bytes(&pir_public),
        "pir_public_seed_bytes":pir_public.seed.as_ref().map_or(0,|s|s.len()),"pir_client_stack_struct_bytes":std::mem::size_of_val(&pir.client),"pir_client_private_buffers_in_native_peak":true,
        "original_full_bfv_and_pir_material_retained":true,"pir_used":false,"ntt_database_overlay_bytes":0,"public_setup_persisted_bytes":0,
        "ledger":ledger,"memory":setup_memory,"owner_online":true,"network_measured":false,"complete_restart":false,"durable_fsync":false})
    );
    let ids = if tables == 1000 {
        [0, 499, 999]
    } else {
        [0, 1, 2]
    };
    let counters = roles::Counters::default();
    let mut shape = None;
    let mut bodies = std::collections::HashMap::new();
    for sample in 0..3 {
        for case in fixture::CASES {
            for table in ids {
                for observation in 0..2 {
                    std::hint::black_box((&pir.owner, &pir.client, &pir.public_wire, &pir_public));
                    let result = disk_scale::execute(
                        &catalog, table, &mut owner, &evaluator, case, &counters,
                    )?;
                    let (ordinals, sum) = fixture::oracle_for_table(table, case); // Only AFTER the whole dispatch/drop clock.
                    let pages = ordinals
                        .iter()
                        .map(|id| *id / u64::from(fixture::PAGE_ROWS))
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    let inner = result.inner;
                    if inner.actual.count != ordinals.len() as u32
                        || inner.actual.sum != sum
                        || inner.selected_rows != ordinals.len()
                        || inner.actual.proof != bfv::ProofStatus::Unavailable
                    {
                        return Err(
                            "Actual disk/bulk/BFV differs from post-timer public oracle".into()
                        );
                    }
                    if case.age == 255 && (ordinals.len() != 256 || pages != 256) {
                        return Err("Sparse256 fixture geometry changed".into());
                    }
                    let stages = &inner.stages;
                    let current = (
                        stages.bulk_request_bytes,
                        stages.bulk_response_bytes,
                        stages.bfv_request_bytes,
                        stages.bfv_response_bytes,
                    );
                    if shape.replace(current).is_some_and(|old| old != current) {
                        return Err("Whole wire shape varies".into());
                    }
                    if bodies
                        .insert(table, inner.payload_sha256)
                        .is_some_and(|old| old != inner.payload_sha256)
                    {
                        return Err("Same table bulk body varies across queries".into());
                    }
                    let outgoing = stages.bulk_request_bytes + stages.bfv_request_bytes;
                    let incoming = stages.bulk_response_bytes + stages.bfv_response_bytes;
                    println!(
                        "{}",
                        json!({"experiment":"bulk-scale-full-query","sample":sample,"case":case.name,"table_id":table,"observation":observation,
                        "whole_local_ms":result.whole_ms,"nested_frozen_execute_ms":inner.whole_ms,"dispatch_and_peer_drop_in_outer_timer":true,"mode":"DiskOnly",
                        "stages":inner.stages,"aggregate":inner.actual,"selected_rows_from_authenticated_prepare":inner.selected_rows,"fixture_expected_pages_after_timer":pages,
                        "outgoing_bytes":outgoing,"incoming_bytes":incoming,"total_wire_bytes":outgoing+incoming,"sequential_rpcs":2,
                        "bulk_payload_sha256":inner.payload_sha256.iter().map(|b|format!("{b:02x}")).collect::<String>(),"body_constant_for_same_table":true,"whole_wire_shape_constant":true,
                        "exact_public_oracle_after_timer":true,"resident_ciphertext_cache_bytes":0,"owner_response_cache_bytes":0,"canonical_snapshots_retained_between_calls":0,
                        "actual_full_file_reads_every_call":true,"not_application_miss_hit_classification":true,"network_model":modeled_network(outgoing+incoming,result.whole_ms),"memory":memory_json()?})
                    );
                }
            }
        }
    }
    let expected = 3 * fixture::CASES.len() * ids.len() * 2;
    if expected != 54
        || counters.prepare_calls.get() != expected
        || counters.prepare_successes.get() != expected
        || counters.peer_evaluations.get() != expected
        || counters.owner_completions.get() != expected
    {
        return Err("Finite full-operation counts differ".into());
    }
    std::hint::black_box((&pir.owner, &pir.client, &pir.public_wire, &pir_public));
    let ledger = catalog.ledger()?;
    let memory = memory_json()?;
    let files = ledger["actual_file_bytes"].as_u64().ok_or("File ledger")?;
    let peak = memory["peak_commit"].as_u64().ok_or("Native ledger")?;
    let combined = files.checked_add(peak).ok_or("Combined ledger overflow")?;
    println!(
        "{}",
        json!({"experiment":"bulk-scale-complete","completed":true,"correct":true,"full_operations":expected,"supplied_ids":ids,
        "samples":3,"observations_each":2,"original_full_bfv_and_pir_material_still_retained":true,"pir_used":false,"ledger":ledger,"memory":memory,
        "actual_files_plus_observed_native_peak_private_bytes":combined,"joint_ratio":combined as f64/(tables as f64*3_000_000.0),"same_db_owner_count":1,"network_measured":false,
        "not_pir":true,"complete_restart":false,"durable_fsync":false,"computation_proof":false})
    );
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("bulk scale rejected; no secret diagnostics are formatted");
        std::process::exit(1)
    }
}
