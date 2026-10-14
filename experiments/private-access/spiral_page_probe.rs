#![recursion_limit = "256"]
//! Native Spiral privately retrieves existing compact-store AEAD pages and proofs.
//! Keys stay owner-side; only public parameters and encrypted PIR queries reach server.
use compact_store::{
    Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse, Owner, VerifiedPage,
};
use serde_json::json;
use spiral_rs::{
    aligned_memory::AlignedMemory64,
    client::{Client, PublicParameters, Query},
    params::Params,
    server::{load_db_from_seek, process_query},
    util::{CFG_20_256, params_from_json_obj},
};
use std::{io::Cursor, time::Instant};

const RECORD_BYTES: usize = 8192;
const PAGE_ROWS: usize = 2048;
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn fixture(rows: usize) -> Vec<u8> {
    (0..rows)
        .flat_map(|i| {
            let age = ((i * 37 + (i >> 8) * 17 + 11) % 256) as u8;
            let amount = ((i * 719 + (i >> 16) * 927 + 123) % 65536) as u16;
            [age, amount as u8, (amount >> 8) as u8]
        })
        .collect()
}
#[cfg(windows)]
fn memory() -> (usize, usize) {
    #[repr(C)]
    struct Counters {
        cb: u32,
        faults: u32,
        peak: usize,
        current: usize,
        rest: [usize; 6],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(p: *mut std::ffi::c_void, c: *mut Counters, size: u32) -> i32;
    }
    let mut c = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        faults: 0,
        peak: 0,
        current: 0,
        rest: [0; 6],
    };
    assert_ne!(
        unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut c,
                std::mem::size_of::<Counters>() as u32,
            )
        },
        0
    );
    (c.current, c.peak)
}
#[cfg(not(windows))]
fn memory() -> (usize, usize) {
    (0, 0)
}
fn records(snapshot: &EncryptedSnapshot, params: &Params, limits: Limits) -> (Vec<u8>, usize) {
    let pages = snapshot.commitment().layout().page_count().unwrap();
    assert!(pages <= params.num_items());
    let mut data = vec![0u8; params.num_items() * RECORD_BYTES];
    let mut proof_bytes = 0;
    for page in 0..pages {
        let response = snapshot.lookup(page as u64, limits).unwrap().encode();
        assert!(response.len() + 4 <= RECORD_BYTES);
        proof_bytes += response.len();
        let slot = &mut data[page * RECORD_BYTES..(page + 1) * RECORD_BYTES];
        slot[..4].copy_from_slice(&(response.len() as u32).to_le_bytes());
        slot[4..4 + response.len()].copy_from_slice(&response);
    }
    (data, proof_bytes)
}
fn decode_page(
    data: &[u8],
    head: &Commitment,
    page: usize,
    limits: Limits,
) -> Result<VerifiedPage, compact_store::Error> {
    if data.len() != RECORD_BYTES {
        return Err(compact_store::Error::InvalidFormat);
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if len > RECORD_BYTES - 4 {
        return Err(compact_store::Error::InvalidFormat);
    }
    LookupResponse::decode(&data[4..4 + len], limits)?.verify(head, page as u64, limits)
}
fn prepare(
    snapshot: &EncryptedSnapshot,
    params: &Params,
    limits: Limits,
) -> (AlignedMemory64, usize, f64, f64) {
    let start = Instant::now();
    let (data, proof_bytes) = records(snapshot, params, limits);
    let records_ms = ms(start);
    let start = Instant::now();
    let db = load_db_from_seek(params, &mut Cursor::new(&data));
    let ntt_ms = ms(start);
    (db, proof_bytes, records_ms, ntt_ms)
}
fn private_fetch(
    params: &Params,
    client: &Client,
    public: &PublicParameters,
    db: &AlignedMemory64,
    page: usize,
) -> (Vec<u8>, usize, usize, f64, f64, f64) {
    let start = Instant::now();
    let query = client.generate_query(page);
    let request = query.serialize();
    let server_query = Query::deserialize(params, &request);
    let query_ms = ms(start);
    let start = Instant::now();
    let response = process_query(params, public, &server_query, db.as_slice());
    let server_ms = ms(start);
    let start = Instant::now();
    let mut decoded = client.decode_response(&response);
    assert!(decoded.len() >= params.db_item_size);
    decoded.truncate(params.db_item_size); // Native to_vec adds scratch padding after useful bytes.
    let recovery_ms = ms(start);
    (
        decoded,
        request.len(),
        response.len(),
        query_ms,
        server_ms,
        recovery_ms,
    )
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rows: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(1_000_000);
    let rounds: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(4);
    let threads: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(8);
    assert!(
        (1..=1_000_000).contains(&rows) && (1..=20).contains(&rounds) && (1..=8).contains(&threads)
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .unwrap();
    let limits = Limits::default();
    let owner = Owner::generate(*b"public-pir-page!").unwrap();
    let mut plain = fixture(rows);
    let layout = Layout {
        schema: *b"age8/amount16-v1",
        row_width: 3,
        rows_per_page: PAGE_ROWS as u32,
        row_count: rows as u64,
    };
    let start = Instant::now();
    let original = owner.seal(layout, &plain, limits).unwrap();
    let seal_ms = ms(start);
    let initial_image_bytes = original.encoded_len();
    let initial_head = original.commitment().clone();
    let image = original.encode();
    drop(original);
    let start = Instant::now();
    let mut snapshot = EncryptedSnapshot::decode(&image, limits).unwrap();
    let canonical_restore_ms = ms(start);
    drop(image);
    // Preserve the author's ring/noise/decomposition settings. Only DB geometry changes.
    let mut cfg: serde_json::Value = serde_json::from_str(&CFG_20_256.replace('\'', "\"")).unwrap();
    cfg["nu_1"] = json!(7);
    cfg["nu_2"] = json!(2);
    let params = params_from_json_obj(&cfg);
    assert_eq!(params.num_items(), 512);
    assert_eq!(params.db_item_size, RECORD_BYTES);
    let start = Instant::now();
    let mut client = Client::init(&params);
    let public = client.generate_keys();
    let public_wire = public.serialize();
    let public_wire_bytes = public_wire.len();
    let server_public = PublicParameters::deserialize(&params, &public_wire);
    let public_parameter_payload_bytes: usize = server_public
        .v_packing
        .iter()
        .chain(server_public.v_expansion_left.iter().flatten())
        .chain(server_public.v_expansion_right.iter().flatten())
        .chain(server_public.v_conversion.iter().flatten())
        .map(|m| m.data.len() * 8)
        .sum();
    let keygen_and_restore_ms = ms(start);
    drop(public_wire);
    drop(public);
    let (db, proof_bytes, records_ms, ntt_ms) = prepare(&snapshot, &params, limits);
    let (resident, peak) = memory();
    println!(
        "{}",
        json!({"experiment":"spiral-authenticated-page-setup","source_revision":"fdb7206517c249603b0c91b65f1f29f95272107c","rows":rows,"logical_bytes":plain.len(),"canonical_image_bytes":initial_image_bytes,"pages":layout.page_count().unwrap(),"page_rows":PAGE_ROWS,"record_slots":params.num_items(),"record_bytes":RECORD_BYTES,"proof_response_payload_bytes":proof_bytes,"padded_record_buffer_bytes":params.num_items()*RECORD_BYTES,"record_buffer_retained":false,"ntt_cache_bytes":db.len()*8,"ntt_cache_persisted_bytes":0,"index_hash_bytes":snapshot.index_hash_bytes(),"pir_public_parameter_wire_bytes":public_wire_bytes,"pir_public_parameter_ntt_payload_bytes":public_parameter_payload_bytes,"pir_client_hint_bytes":0,"owner_base_secret_polynomial_payload_bytes":(params.n+1)*params.poly_len*8,"owner_derived_secret_matrix_payload_bytes":(params.n*(params.n+1)+2)*params.poly_len*8,"owner_key_serialization_measured":false,"owner_aead_key_bytes":32,"trusted_head_bytes":initial_head.encode().len(),"fixture_buffer_bytes":plain.len(),"poly_len":params.poly_len,"crt_moduli":&params.moduli[..params.crt_count],"gaussian_width":params.noise_width,"gaussian_stddev":params.noise_width/(2.0*std::f64::consts::PI).sqrt(),"plaintext_modulus":params.pt_modulus,"n":params.n,"db_dim_1":params.db_dim_1,"db_dim_2":params.db_dim_2,"t_gsw":params.t_gsw,"t_conv":params.t_conv,"t_exp_left":params.t_exp_left,"t_exp_right":params.t_exp_right,"q2_bits":params.q2_bits,"threads":threads,"seal_ms":seal_ms,"canonical_restore_ms":canonical_restore_ms,"keygen_and_restore_ms":keygen_and_restore_ms,"records_ms":records_ms,"ntt_ms":ntt_ms,"resident_bytes":resident,"peak_resident_bytes":peak,"fhe":false,"index_navigation":false,"network_measured":false,"sql_computation_proof":false})
    );
    let pages = layout.page_count().unwrap();
    let mut old_record = Vec::new();
    for round in 0..rounds {
        let page = match round % 4 {
            0 => 0,
            1 => pages - 1,
            2 => pages / 2,
            _ => 0,
        };
        // Separate visible-address control on exactly the same page geometry/fixture.
        let visible_start = Instant::now();
        let visible_wire = snapshot.lookup(page as u64, limits).unwrap().encode();
        let visible_page = LookupResponse::decode(&visible_wire, limits)
            .unwrap()
            .verify(&initial_head, page as u64, limits)
            .unwrap();
        let visible_plain = owner.decrypt(&visible_page).unwrap();
        let visible_offset = page * PAGE_ROWS * 3;
        assert_eq!(
            visible_plain.as_bytes(),
            &plain[visible_offset..usize::min(visible_offset + PAGE_ROWS * 3, plain.len())]
        );
        let visible_total_ms = ms(visible_start);
        let total = Instant::now();
        let (decoded, request_bytes, response_bytes, query_ms, server_ms, recovery_ms) =
            private_fetch(&params, &client, &server_public, &db, page);
        let start = Instant::now();
        let verified = decode_page(&decoded, &initial_head, page, limits).unwrap();
        let decrypted = owner.decrypt(&verified).unwrap();
        let offset = page * PAGE_ROWS * 3;
        assert_eq!(
            decrypted.as_bytes(),
            &plain[offset..usize::min(offset + PAGE_ROWS * 3, plain.len())]
        );
        let verify_and_decrypt_ms = ms(start);
        let total_ms = ms(total);
        if round == 0 {
            old_record = decoded.clone();
        }
        let mut corrupt = decoded.clone();
        corrupt[4 + 16 + 32] ^= 128;
        assert!(decode_page(&corrupt, &initial_head, page, limits).is_err());
        if pages > 1 {
            assert!(decode_page(&decoded, &initial_head, (page + 1) % pages, limits).is_err());
        }
        assert!(decode_page(&vec![0u8; RECORD_BYTES], &initial_head, page, limits).is_err());
        let (resident, peak) = memory();
        println!(
            "{}",
            json!({"experiment":"spiral-authenticated-page-query","round":round,"page":page,"query_ms":query_ms,"server_ms":server_ms,"recovery_ms":recovery_ms,"verify_and_decrypt_ms":verify_and_decrypt_ms,"total_ms":total_ms,"cold_cache_restore_plus_query_ms":if round==0 {Some(canonical_restore_ms+records_ms+ntt_ms+total_ms)} else {None},"request_bytes":request_bytes,"response_bytes":response_bytes,"roundtrips":1,"resident_bytes":resident,"peak_resident_bytes":peak,"correct":true,"corrupt_page_rejected":true,"visible_control_total_ms":visible_total_ms,"visible_control_request_bytes":8,"visible_control_response_bytes":visible_wire.len()})
        );
    }
    drop(db);
    let total = Instant::now();
    plain[0] ^= 1;
    let next = owner
        .replace_page(
            &mut snapshot,
            &initial_head,
            0,
            &plain[..usize::min(PAGE_ROWS * 3, plain.len())],
            limits,
        )
        .unwrap();
    assert_eq!(snapshot.encoded_len(), initial_image_bytes);
    assert!(decode_page(&old_record, &next, 0, limits).is_err());
    let replace_ms = ms(total);
    let (fresh_db, _, records_ms, ntt_ms) = prepare(&snapshot, &params, limits);
    let start = Instant::now();
    let (decoded, request_bytes, response_bytes, query_ms, server_ms, recovery_ms) =
        private_fetch(&params, &client, &server_public, &fresh_db, 0);
    let verified = decode_page(&decoded, &next, 0, limits).unwrap();
    let decrypted = owner.decrypt(&verified).unwrap();
    assert_eq!(
        decrypted.as_bytes(),
        &plain[..usize::min(PAGE_ROWS * 3, plain.len())]
    );
    let updated_query_ms = ms(start);
    let (resident, peak) = memory();
    println!(
        "{}",
        json!({"experiment":"spiral-authenticated-page-update","replace_ms":replace_ms,"records_ms":records_ms,"ntt_ms":ntt_ms,"updated_query_ms":updated_query_ms,"query_ms":query_ms,"server_ms":server_ms,"recovery_ms":recovery_ms,"request_bytes":request_bytes,"response_bytes":response_bytes,"total_replace_rebuild_query_ms":ms(total),"canonical_image_bytes":snapshot.encoded_len(),"ntt_cache_bytes":fresh_db.len()*8,"old_cache_dropped_before_rebuild":true,"stale_proof_rejected":true,"correct":true,"resident_bytes":resident,"peak_resident_bytes":peak,"durable_restart":false,"write_access_concealed":false})
    );
}
