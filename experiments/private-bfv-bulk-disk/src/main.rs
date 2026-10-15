//! Source-only prepared whole-table bulk alternative; NOT PIR. Public synthetic data only.
mod bulk_wire;
mod fixture;
mod resources;
mod roles;
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
    let directory = PathBuf::from(
        args.get(1)
            .ok_or("Required new ignored .local dataset directory")?,
    );
    let rounds = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("3")
        .parse::<usize>()?;
    if !(1..=3).contains(&rounds)
        || directory.exists()
        || !directory.components().any(|c| c.as_os_str() == ".local")
        || !directory.parent().is_some_and(std::path::Path::is_dir)
    {
        return Err("Use fresh .local child directory and rounds1..=3".into());
    }
    resources::guard(512 * 1024 * 1024)?;
    std::fs::create_dir(&directory)?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()?;
    let setup_all = Instant::now();
    // Same original PIR owner/client/wire/full expanded public key material is retained, but UNUSED for retrieval.
    let params = spiral_owner_state::profile_params();
    let mut domain = [0u8; 32];
    getrandom::getrandom(&mut domain).map_err(|_| "OS randomness unavailable")?;
    let start = Instant::now();
    let pir = spiral_owner_state::OwnerState::generate(&params, domain)?;
    let pir_public = PublicParameters::deserialize(&params, &pir.public_wire);
    let pir_setup_ms = start.elapsed().as_secs_f64() * 1000.0;
    if pir.public_wire.len() != spiral_owner_state::PUBLIC_SETUP_BYTES {
        return Err("Original PIR profile/wire changed".into());
    }
    let start = Instant::now();
    let (authority, evaluator) = bfv::Owner::generate(*b"public-bulk-db01")?;
    let bfv_setup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let public_counts = evaluator.public_setup_bytes()?;
    let public_wire = evaluator.encode_public_setup_for_experiment()?;
    let bfv_public_digest = Sha256::digest(&public_wire);
    drop(public_wire);
    let start = Instant::now();
    let rows = fixture::public_rows();
    let table = authority.seal(&rows, fixture::PAGE_ROWS, roles::data_limits())?;
    drop(rows);
    let trusted = roles::TrustedTable::capture(0, &table)?;
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    let rebuildable_hash_bytes = table.rebuildable_hash_bytes();
    drop(table);
    let data_path = directory.join("data.bin");
    let index_path = directory.join("index.bin");
    roles::write_new(&data_path, &data)?;
    roles::write_new(&index_path, &index)?;
    drop(data);
    drop(index);
    let anchor = json!({"table_id":trusted.table_id,"data_head":trusted.data_head.encode().as_slice(),"index_head":trusted.index_head.encode().as_slice(),"data_len":trusted.data_len,"index_len":trusted.index_len});
    roles::write_new(
        &directory.join("public-heads.json"),
        &serde_json::to_vec(&anchor)?,
    )?;
    let canonical_setup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let owner = roles::OwnerTable::new(authority, trusted.clone());
    let mut peer = roles::DiskPeer::new(evaluator, trusted, data_path, index_path);
    profile_gate(&owner, &peer)?;
    let canonical = peer.trusted.data_len + peer.trusted.index_len;
    if canonical != 5_065_148 {
        return Err("Canonical fixed geometry changed; re-audit source profile".into());
    }
    let auxiliary = std::fs::metadata(directory.join("public-heads.json"))?.len();
    println!(
        "{}",
        json!({"experiment":"bulk-setup","rayon_threads":8,"rows":fixture::ROWS,"logical_bytes":fixture::ROWS*3,"canonical_bytes":canonical,
        "canonical_only_ratio":canonical as f64/(fixture::ROWS*3)as f64,"auxiliary_public_anchor_file_bytes":auxiliary,
        "setup_ms":setup_all.elapsed().as_secs_f64()*1000.0,"pir_setup_ms":pir_setup_ms,"bfv_setup_ms":bfv_setup_ms,"canonical_fixture_seal_write_ms":canonical_setup_ms,
        "bfv_profile":owner.profile(),"bfv_public_serialized_counts":public_counts,"bfv_public_sha256":format!("{bfv_public_digest:x}"),
        "bfv_public_setup_retained_in_native_arc":true,"bfv_flat_wire_copy_retained":false,"public_setup_persisted_bytes":0,
        "bfv_owner_secret_serialized_count":owner.secret_key_count(),"compact_owner_key_bytes":32,
        "pir_owner_image_bytes":spiral_owner_state::OWNER_STATE_BYTES,"pir_original_public_wire_bytes":pir.public_wire.len(),
        "pir_full_expanded_matrix_u64_payload_bytes":expanded_public_bytes(&pir_public),"pir_public_seed_bytes":pir_public.seed.as_ref().map_or(0,|seed|seed.len()),
        "pir_client_struct_bytes":std::mem::size_of_val(&pir.client),"pir_client_private_buffers_in_native_peak_only":true,
        "all_pir_owner_client_wire_and_expanded_public_retained":true,"pir_used":false,"ntt_database_overlay_bytes":0,
        "transient_full_table_merkle_payload_bytes":rebuildable_hash_bytes,"owner_retained_response_cache_bytes":0,
        "one_table_probe_no_joint2x_claim":true,"network_measured":false,"memory":memory_json()?})
    );
    let counters = roles::Counters::default();
    let mut shape = None;
    let mut body_hash = None;
    for mode in [roles::Mode::Disk, roles::Mode::Resident] {
        peer.clear_resident();
        let start = Instant::now();
        if matches!(mode, roles::Mode::Resident) {
            peer.preload_resident()?;
        }
        println!(
            "{}",
            json!({"experiment":"bulk-server-mode-setup","mode":mode,"server_retained_ciphertext_bytes":peer.resident_bytes(),"mode_initialization_ms":start.elapsed().as_secs_f64()*1000.0,"excluded_from_query_timer":true,"owner_response_cache_bytes":0})
        );
        for sample in 0..rounds {
            for case in fixture::CASES {
                std::hint::black_box((&pir.owner, &pir.client, &pir.public_wire, &pir_public));
                let result = owner.execute(&peer, mode, case, &counters)?;
                // PUBLIC oracle and fixture geometry are reconstructed only after the full timer.
                let (ids, sum) = fixture::oracle(case);
                if result.actual.count != ids.len() as u32
                    || result.actual.sum != sum
                    || result.selected_rows != ids.len()
                    || result.actual.proof != bfv::ProofStatus::Unavailable
                {
                    return Err("Full bulk/BFV query differs from public oracle".into());
                }
                let pages = ids
                    .iter()
                    .map(|id| *id / u64::from(fixture::PAGE_ROWS))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                if case.age == 255 && (ids.len() != 256 || pages != 256) {
                    return Err("Sparse fixture failed to span256 distinct data pages".into());
                }
                let s = &result.stages;
                let measured_shape = (
                    s.bulk_request_bytes,
                    s.bulk_response_bytes,
                    s.bfv_request_bytes,
                    s.bfv_response_bytes,
                );
                if shape
                    .replace(measured_shape)
                    .is_some_and(|old| old != measured_shape)
                    || body_hash
                        .replace(result.payload_sha256)
                        .is_some_and(|old| old != result.payload_sha256)
                {
                    return Err(
                        "Bulk body/whole wire shape changed with selected count or mode".into(),
                    );
                }
                let outgoing = s.bulk_request_bytes + s.bfv_request_bytes;
                let incoming = s.bulk_response_bytes + s.bfv_response_bytes;
                println!(
                    "{}",
                    json!({"experiment":"bulk-full-query","mode":mode,"sample":sample,"case":case.name,"whole_local_ms":result.whole_ms,
                "stages":result.stages,"aggregate":result.actual,"selected_rows_from_authenticated_prepare":result.selected_rows,
                "fixture_expected_data_pages_after_timer":pages,"bulk_request_messages":1,"bfv_request_messages":1,"sequential_rpcs":2,
                "outgoing_bytes":outgoing,"incoming_bytes":incoming,"total_wire_bytes":outgoing+incoming,"bulk_payload_sha256":result.payload_sha256.iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
                "bulk_shape_and_payload_constant":true,"oracle_exact":true,"owner_online":true,"access":"whole-table bulk, NOT PIR",
                "public_table_roots_lengths_timing":true,"owner_response_cache_bytes":0,"server_retained_ciphertext_bytes":peer.resident_bytes(),
                "local_timer_includes_diagnostic_full_payload_sha256":true,"network_model":modeled_network(outgoing+incoming,result.whole_ms),"memory":memory_json()?})
                );
            }
        }
    }
    let expected = rounds * fixture::CASES.len() * 2;
    if counters.prepare_calls.get() != expected
        || counters.prepare_successes.get() != expected
        || counters.peer_evaluations.get() != expected
        || counters.owner_completions.get() != expected
    {
        return Err("Full operation count mismatch".into());
    }
    std::hint::black_box((&pir.owner, &pir.client, &pir.public_wire, &pir_public));
    println!(
        "{}",
        json!({"experiment":"bulk-complete","completed":true,"correct":true,"full_operations":expected,"all_pir_material_still_retained":true,"original_pir_public_bytes":pir.public_wire.len(),"expanded_pir_matrix_bytes":expanded_public_bytes(&pir_public),"owner_response_cache_bytes":0,"memory":memory_json()?})
    );
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("bulk probe rejected; no secret diagnostics are formatted");
        std::process::exit(1)
    }
}
