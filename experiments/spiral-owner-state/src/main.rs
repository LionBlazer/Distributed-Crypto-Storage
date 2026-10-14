//! Public non-secret recovery fixture. Never prints or writes seeds or owner images.
#![forbid(unsafe_code)]
use serde_json::json;
use spiral_owner_state::{
    profile_params, OwnerState, OWNER_STATE_BYTES, RECORD_BYTES, RECORD_SLOTS, SDK_REVISION,
};
use spiral_rs::{
    client::{Client, PublicParameters, Query},
    discrete_gaussian::DiscreteGaussian,
    params::Params,
    server::{load_db_from_seek, process_query},
};
use std::{io::Cursor, mem::size_of};
use zeroize::Zeroizing;

const DOMAIN: [u8; 32] = *b"public-owner-recovery-fixture-v1";
const PUBLIC_TEST_SEED: [u8; 32] = [0x42; 32];
fn record(slot: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..RECORD_BYTES)
        .map(|offset| ((slot * 37 + offset * 13 + offset / 97) % 256) as u8)
        .collect();
    bytes[..8].copy_from_slice(&(slot as u64).to_le_bytes());
    bytes
}
fn fetch(
    params: &Params,
    client: &Client<'_>,
    public: &PublicParameters<'_>,
    db: &[u64],
    slot: usize,
) -> Vec<u8> {
    let wire = client.generate_query(slot).serialize();
    let query = Query::deserialize(params, &wire);
    let response = process_query(params, public, &query, db);
    let mut decoded = client.decode_response(&response);
    // Pinned PolyMatrixRaw::to_vec adds 32 zero guard bytes after the record.
    assert_eq!(decoded.len(), RECORD_BYTES + 32);
    assert!(decoded[RECORD_BYTES..].iter().all(|byte| *byte == 0));
    decoded.truncate(RECORD_BYTES);
    decoded
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = profile_params();
    let setup = OwnerState::create_with_seed_for_experiment(
        &params,
        DOMAIN,
        Zeroizing::new(PUBLIC_TEST_SEED),
    )?;
    let owner_image = setup.owner.encode_secret_for_experiment();
    let public_wire = setup.public_wire;
    let public = PublicParameters::deserialize(&params, &public_wire);
    let records: Vec<u8> = (0..RECORD_SLOTS).flat_map(record).collect();
    let db = load_db_from_seek(&params, &mut Cursor::new(records));
    if fetch(
        &params,
        &setup.client,
        &public,
        db.as_slice(),
        RECORD_SLOTS / 2,
    ) != record(RECORD_SLOTS / 2)
    {
        return Err("Original public fixture PIR read failed".into());
    }
    drop(public);
    drop(setup.client);
    drop(setup.owner);
    let restored = OwnerState::restore(&params, DOMAIN, owner_image.as_ref(), &public_wire)?;
    if restored.public.serialize() != public_wire
        || restored.owner.encode_secret_for_experiment().as_ref() != owner_image.as_ref()
    {
        return Err("Restored setup or owner image differs".into());
    }
    for slot in [0, RECORD_SLOTS / 2, RECORD_SLOTS - 1] {
        if fetch(
            &params,
            &restored.client,
            &restored.public,
            db.as_slice(),
            slot,
        ) != record(slot)
        {
            return Err("Restored client returned a mismatched public fixture record".into());
        }
    }
    // Deliberately bypass the trusted image API to demonstrate wrong-key failure.
    let mut wrong = Client::init(&params);
    wrong.generate_secret_keys_from_seed([0x43; 32]);
    if fetch(
        &params,
        &wrong,
        &restored.public,
        db.as_slice(),
        RECORD_SLOTS / 2,
    ) == record(RECORD_SLOTS / 2)
    {
        return Err("Controlled wrong seed unexpectedly recovered the fixture".into());
    }
    let dg = DiscreteGaussian::init(params.noise_width);
    let ntt_payload: usize = params
        .ntt_tables
        .iter()
        .flatten()
        .map(|v| v.len() * 8)
        .sum();
    let ntt_capacity: usize = params
        .ntt_tables
        .iter()
        .flatten()
        .map(|v| v.capacity() * 8)
        .sum();
    let ntt_headers = params.ntt_tables.capacity() * size_of::<Vec<Vec<u64>>>()
        + params
            .ntt_tables
            .iter()
            .map(|v| v.capacity() * size_of::<Vec<u64>>())
            .sum::<usize>();
    println!(
        "{}",
        json!({
            "experiment":"spiral-owner-recovery", "sdk_revision":SDK_REVISION,
            "fixture":"public-nonsecret", "record_slots":RECORD_SLOTS,"record_bytes":RECORD_BYTES,
            "original_reads":1,"restored_reads":3,"wrong_seed_oracle_mismatch":true,
            "identical_original_public_wire_restored":true,"owner_image_roundtrip":true,
            "secret_seed_bytes":32,"canonical_owner_image_bytes":OWNER_STATE_BYTES,
            "original_public_setup_bytes":public_wire.len(),"owner_plus_public_bytes":OWNER_STATE_BYTES+public_wire.len(),
            "live_base_secret_payload_bytes":(params.n+1)*params.poly_len*8,
            "live_derived_secret_payload_bytes":(params.n*(params.n+1)+2)*params.poly_len*8,
            "client_inline_bytes":size_of::<Client<'_>>(),"owner_state_inline_bytes":size_of::<OwnerState>(),
            "params_inline_bytes":size_of::<Params>(),"params_ntt_payload_bytes":ntt_payload,
            "params_ntt_capacity_bytes":ntt_capacity,"params_ntt_nested_vector_capacity_bytes":ntt_headers,
            "params_scratch_capacity_bytes":params.scratch.capacity()*8,
            "public_gaussian_cdf_payload_bytes":dg.cdf_table.len()*8,"public_gaussian_cdf_capacity_bytes":dg.cdf_table.capacity()*8,
            "cdf_struct_inline_bytes":size_of::<DiscreteGaussian>(),
            "database_ntt_payload_bytes":db.len()*8,"query_rng":"fresh SDK entropy per query",
            "secret_image_written":false,"public_setup_regenerated_on_restore":false,
            "counts_exclude_allocator_thread_tls_and_process_overhead":true,
            "not_query_authentication_or_security_estimate":true
        })
    );
    Ok(())
}
