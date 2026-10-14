#![recursion_limit = "256"]
//! Real authenticated page retrieval -> fresh TFHE inputs -> encrypted predicate/COUNT/SUM.
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
) -> ProbeResult<(Vec<u8>, usize, usize, f64, f64, f64)> {
    let start = Instant::now();
    let query = client.generate_query(page);
    let request = query.serialize();
    if request.len() != params.query_bytes() {
        return Err("Unexpected PIR query length".into());
    }
    let server_query = Query::deserialize(params, &request);
    let query_ms = ms(start);
    let start = Instant::now();
    let response = process_query(params, public, &server_query, db.as_slice());
    let server_ms = ms(start);
    let bits = params.instances
        * ((params.q2_bits as usize * params.n * params.poly_len)
            + ((4 * params.pt_modulus).ilog2() as usize * params.n * params.n * params.poly_len));
    if response.len() != bits.div_ceil(64) * 8 {
        return Err("Unexpected PIR answer length before secret decoding".into());
    }
    let start = Instant::now();
    let mut decoded = client.decode_response(&response);
    if decoded.len() < params.db_item_size {
        return Err("Truncated decoded PIR record".into());
    }
    decoded.truncate(params.db_item_size); // Native to_vec adds scratch padding after useful bytes.
    let recovery_ms = ms(start);
    Ok((
        decoded,
        request.len(),
        response.len(),
        query_ms,
        server_ms,
        recovery_ms,
    ))
}

use bincode::Options;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use tfhe::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use tfhe::{
    ClientKey, ConfigBuilder, FheBool, FheUint8, FheUint16, ServerKey, generate_keys,
    set_server_key,
};

type ProbeResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const WIRE_LIMIT: u64 = 4 * 1024 * 1024;
const KEY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
fn options(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
}
#[derive(Serialize, Deserialize)]
struct ReadRequest {
    query_id: u64,
    snapshot_root: [u8; 32],
    age: FheUint8,
    amount: FheUint16,
    threshold: FheUint8,
}
#[derive(Serialize, Deserialize)]
struct ReadAnswer {
    query_id: u64,
    snapshot_root: [u8; 32],
    count: FheUint8,
    sum: FheUint16,
}
#[derive(Serialize, Deserialize)]
struct IncrementRequest {
    query_id: u64,
    snapshot_root: [u8; 32],
    amount: FheUint16,
    delta: FheUint16,
}
#[derive(Serialize, Deserialize)]
struct IncrementAnswer {
    query_id: u64,
    snapshot_root: [u8; 32],
    candidate: FheUint16,
    overflow: FheBool,
}
#[derive(Default, Serialize)]
struct Stages {
    retrieval_query_ms: f64,
    retrieval_server_ms: f64,
    retrieval_recovery_ms: f64,
    page_verify_decrypt_ms: f64,
    owner_fhe_encrypt_ms: f64,
    request_serialize_ms: f64,
    evaluation_key_restore_ms: f64,
    peer_decode_ms: f64,
    peer_fhe_ms: f64,
    peer_serialize_ms: f64,
    owner_answer_decode_decrypt_ms: f64,
    retrieval_request_bytes: usize,
    retrieval_response_bytes: usize,
    fhe_request_bytes: usize,
    fhe_response_bytes: usize,
}
#[derive(Clone, Copy, Debug)]
enum Access {
    Visible,
    Private,
}
struct OwnerSession<'a> {
    storage: &'a Owner,
    fhe: &'a ClientKey,
    pir: &'a Client<'a>,
    head: &'a Commitment,
}
struct PeerStore<'a> {
    params: &'a Params,
    public: &'a PublicParameters<'a>,
    db: &'a AlignedMemory64,
    snapshot: &'a EncryptedSnapshot,
}
// Metadata checks precede FHE owner decryption; they are not computation proofs.
fn check_binding(
    actual_id: u64,
    actual_root: [u8; 32],
    expected_id: u64,
    expected_root: [u8; 32],
) -> ProbeResult<()> {
    if actual_id != expected_id || actual_root != expected_root {
        return Err(
            "FHE answer metadata does not match the local request and trusted snapshot".into(),
        );
    }
    Ok(())
}

fn peer_read(wire: &[u8], stages: &mut Stages) -> ProbeResult<Vec<u8>> {
    let start = Instant::now();
    let request: ReadRequest = options(WIRE_LIMIT).deserialize(wire)?;
    stages.peer_decode_ms = ms(start);
    let start = Instant::now();
    let matched = request.age.ge(&request.threshold);
    let answer = ReadAnswer {
        query_id: request.query_id,
        snapshot_root: request.snapshot_root,
        count: FheUint8::cast_from(matched.clone()),
        sum: matched.if_then_else(&request.amount, &FheUint16::encrypt_trivial(0u16)),
    };
    stages.peer_fhe_ms = ms(start);
    let start = Instant::now();
    let response = options(WIRE_LIMIT).serialize(&answer)?;
    stages.peer_serialize_ms = ms(start);
    stages.fhe_response_bytes = response.len();
    Ok(response)
}
// The peer computes the overflow flag homomorphically; it never sees amount or delta.
fn peer_increment(wire: &[u8], stages: &mut Stages) -> ProbeResult<Vec<u8>> {
    let start = Instant::now();
    let request: IncrementRequest = options(WIRE_LIMIT).deserialize(wire)?;
    stages.peer_decode_ms = ms(start);
    let start = Instant::now();
    let (candidate, overflow) = (&request.amount).overflowing_add(&request.delta);
    let answer = IncrementAnswer {
        query_id: request.query_id,
        snapshot_root: request.snapshot_root,
        candidate,
        overflow,
    };
    stages.peer_fhe_ms = ms(start);
    let start = Instant::now();
    let response = options(WIRE_LIMIT).serialize(&answer)?;
    stages.peer_serialize_ms = ms(start);
    stages.fhe_response_bytes = response.len();
    Ok(response)
}
fn visible_record(
    snapshot: &EncryptedSnapshot,
    page: usize,
    limits: Limits,
) -> ProbeResult<Vec<u8>> {
    let response = snapshot.lookup(page as u64, limits)?.encode();
    let mut record = vec![0u8; RECORD_BYTES];
    record[..4].copy_from_slice(&(response.len() as u32).to_le_bytes());
    record[4..4 + response.len()].copy_from_slice(&response);
    Ok(record)
}
fn retrieve(
    access: Access,
    row: usize,
    owner: &OwnerSession,
    peer: &PeerStore,
    limits: Limits,
    stages: &mut Stages,
) -> ProbeResult<Vec<u8>> {
    let page = row / PAGE_ROWS;
    match access {
        Access::Visible => {
            let start = Instant::now();
            // Exact public page request, followed by the same bounded owner verification.
            let response = peer.snapshot.lookup(page as u64, limits)?.encode();
            let mut record = vec![0u8; RECORD_BYTES];
            record[..4].copy_from_slice(&(response.len() as u32).to_le_bytes());
            record[4..4 + response.len()].copy_from_slice(&response);
            stages.retrieval_request_bytes = 8;
            stages.retrieval_response_bytes = response.len();
            stages.retrieval_server_ms = ms(start);
            Ok(record)
        }
        Access::Private => {
            let (record, qbytes, abytes, qms, ams, rms) =
                private_fetch(peer.params, owner.pir, peer.public, peer.db, page)?;
            stages.retrieval_request_bytes = qbytes;
            stages.retrieval_response_bytes = abytes;
            stages.retrieval_query_ms = qms;
            stages.retrieval_server_ms = ams;
            stages.retrieval_recovery_ms = rms;
            Ok(record)
        }
    }
}
fn owner_row(
    record: &[u8],
    row: usize,
    owner: &OwnerSession,
    limits: Limits,
) -> ProbeResult<[u8; 3]> {
    let page = row / PAGE_ROWS;
    let verified = decode_page(record, owner.head, page, limits)?;
    let plain = owner.storage.decrypt(&verified)?;
    let offset = (row % PAGE_ROWS) * 3;
    let bytes = plain
        .as_bytes()
        .get(offset..offset + 3)
        .ok_or("Selected row outside verified page")?;
    Ok(bytes.try_into()?)
}
fn ensure_context(key_wire: &mut Option<Vec<u8>>, stages: &mut Stages) -> ProbeResult<()> {
    if let Some(bytes) = key_wire.take() {
        let start = Instant::now();
        let key: ServerKey = options(KEY_LIMIT).deserialize(&bytes)?;
        set_server_key(key);
        stages.evaluation_key_restore_ms = ms(start);
        drop(bytes);
    }
    Ok(())
}
struct LocalRead {
    answer: (u8, u16),
    stages: Stages,
    total_ms: f64,
    age_ciphertext: Vec<u8>,
}
struct ReadPlan {
    access: Access,
    row: usize,
    threshold: u8,
    query_id: u64,
}
fn read(
    plan: ReadPlan,
    owner: &OwnerSession,
    peer: &PeerStore,
    key_wire: &mut Option<Vec<u8>>,
    limits: Limits,
) -> ProbeResult<LocalRead> {
    let total = Instant::now();
    let mut stages = Stages::default();
    let record = retrieve(plan.access, plan.row, owner, peer, limits, &mut stages)?;
    let start = Instant::now();
    let selected = owner_row(&record, plan.row, owner, limits)?;
    stages.page_verify_decrypt_ms = ms(start);
    let start = Instant::now();
    let request = ReadRequest {
        query_id: plan.query_id,
        snapshot_root: owner.head.root(),
        age: FheUint8::encrypt(selected[0], owner.fhe),
        amount: FheUint16::encrypt(u16::from_le_bytes([selected[1], selected[2]]), owner.fhe),
        threshold: FheUint8::encrypt(plan.threshold, owner.fhe),
    };
    stages.owner_fhe_encrypt_ms = ms(start);
    let start = Instant::now();
    let wire = options(WIRE_LIMIT).serialize(&request)?;
    stages.request_serialize_ms = ms(start);
    stages.fhe_request_bytes = wire.len();
    ensure_context(key_wire, &mut stages)?;
    let answer_wire = peer_read(&wire, &mut stages)?;
    let start = Instant::now();
    let answer: ReadAnswer = options(WIRE_LIMIT).deserialize(&answer_wire)?;
    check_binding(
        answer.query_id,
        answer.snapshot_root,
        plan.query_id,
        owner.head.root(),
    )?;
    let actual = (
        answer.count.decrypt(owner.fhe),
        answer.sum.decrypt(owner.fhe),
    );
    stages.owner_answer_decode_decrypt_ms = ms(start);
    let total_ms = ms(total);
    // Outside latency: assert fresh encryption even for the same selected value/address.
    let age_ciphertext = options(WIRE_LIMIT).serialize(&request.age)?;
    Ok(LocalRead {
        answer: actual,
        stages,
        total_ms,
        age_ciphertext,
    })
}
struct IncrementPlan {
    row: usize,
    delta: u16,
    query_id: u64,
}
fn increment(
    plan: IncrementPlan,
    owner: &OwnerSession,
    peer: &PeerStore,
    limits: Limits,
) -> ProbeResult<(u16, bool, Stages, f64)> {
    let total = Instant::now();
    let mut stages = Stages::default();
    let record = retrieve(Access::Private, plan.row, owner, peer, limits, &mut stages)?;
    let start = Instant::now();
    let selected = owner_row(&record, plan.row, owner, limits)?;
    stages.page_verify_decrypt_ms = ms(start);
    let start = Instant::now();
    let request = IncrementRequest {
        query_id: plan.query_id,
        snapshot_root: owner.head.root(),
        amount: FheUint16::encrypt(u16::from_le_bytes([selected[1], selected[2]]), owner.fhe),
        delta: FheUint16::encrypt(plan.delta, owner.fhe),
    };
    stages.owner_fhe_encrypt_ms = ms(start);
    let start = Instant::now();
    let wire = options(WIRE_LIMIT).serialize(&request)?;
    stages.request_serialize_ms = ms(start);
    stages.fhe_request_bytes = wire.len();
    let response = peer_increment(&wire, &mut stages)?;
    let start = Instant::now();
    let answer: IncrementAnswer = options(WIRE_LIMIT).deserialize(&response)?;
    check_binding(
        answer.query_id,
        answer.snapshot_root,
        plan.query_id,
        owner.head.root(),
    )?;
    let candidate: u16 = answer.candidate.decrypt(owner.fhe);
    let overflow: bool = answer.overflow.decrypt(owner.fhe);
    stages.owner_answer_decode_decrypt_ms = ms(start);
    Ok((candidate, overflow, stages, ms(total)))
}
#[derive(Default)]
struct Counter(u64);
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn main() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let rows: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(1_000_000);
    let rounds: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    let threads: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(8);
    if rows != 1_000_000 || !(4..=20).contains(&rounds) || !(1..=8).contains(&threads) {
        return Err("Use exactly 1000000 public rows,4..20 rounds,1..8 threads".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let setup_start = Instant::now();
    let limits = Limits::default();
    let storage_owner = Owner::generate(*b"public-fhe-pir!!")?;
    let mut plain = fixture(rows);
    let layout = Layout {
        schema: *b"age8/amount16-v1",
        row_width: 3,
        rows_per_page: PAGE_ROWS as u32,
        row_count: rows as u64,
    };
    let start = Instant::now();
    let original = storage_owner.seal(layout, &plain, limits)?;
    let seal_ms = ms(start);
    let encoded = original.encode();
    drop(original);
    let start = Instant::now();
    let mut snapshot = EncryptedSnapshot::decode(&encoded, limits)?;
    let canonical_restore_ms = ms(start);
    drop(encoded);
    let mut head = snapshot.commitment().clone();
    let initial_bytes = snapshot.encoded_len();
    let mut cfg: serde_json::Value = serde_json::from_str(&CFG_20_256.replace('\'', "\""))?;
    cfg["nu_1"] = json!(7);
    cfg["nu_2"] = json!(2);
    let params = params_from_json_obj(&cfg);
    let start = Instant::now();
    let mut pir_owner = Client::init(&params);
    let public = pir_owner.generate_keys();
    let public_wire = public.serialize();
    let public_wire_bytes = public_wire.len();
    let pir_public = PublicParameters::deserialize(&params, &public_wire);
    drop(public_wire);
    drop(public);
    let pir_public_payload_bytes: usize = pir_public
        .v_packing
        .iter()
        .chain(pir_public.v_expansion_left.iter().flatten())
        .chain(pir_public.v_expansion_right.iter().flatten())
        .chain(pir_public.v_conversion.iter().flatten())
        .map(|m| m.data.len() * 8)
        .sum();
    let pir_key_setup_ms = ms(start);
    let (initial_db, proof_payload_bytes, records_ms, ntt_ms) = prepare(&snapshot, &params, limits);
    let mut db = Some(initial_db);
    let start = Instant::now();
    let (fhe_owner, fhe_peer) = generate_keys(
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build(),
    );
    let fhe_keygen_ms = ms(start);
    let start = Instant::now();
    let mut counter = Counter::default();
    options(KEY_LIMIT).serialize_into(&mut counter, &fhe_owner)?;
    let fhe_key_wire = options(KEY_LIMIT).serialize(&fhe_peer)?;
    let fhe_peer_key_bytes = fhe_key_wire.len();
    drop(fhe_peer);
    let key_serialization_ms = ms(start);
    let mut key_wire = Some(fhe_key_wire);
    let setup_ms = ms(setup_start);
    let (_, peak) = memory();
    println!(
        "{}",
        json!({"experiment":"spiral-fhe-setup","logical_rows":rows,"logical_bytes":plain.len(),"canonical_image_bytes":initial_bytes,"canonical_expansion":initial_bytes as f64/plain.len() as f64,"merkle_index_bytes":snapshot.index_hash_bytes(),"sql_index_bytes":0,"persistent_fhe_row_cache_bytes":0,"replicas":1,"record_slots":params.num_items(),"record_bytes":RECORD_BYTES,"proof_payload_bytes":proof_payload_bytes,"temporary_record_buffer_bytes":params.num_items()*RECORD_BYTES,"ntt_cache_bytes":db.as_ref().unwrap().len()*8,"ntt_cache_persisted_bytes":0,"pir_public_parameter_wire_bytes":public_wire_bytes,"pir_public_parameter_ram_payload_bytes":pir_public_payload_bytes,"pir_owner_base_secret_payload_bytes":(params.n+1)*params.poly_len*8,"pir_owner_derived_secret_payload_bytes":(params.n*(params.n+1)+2)*params.poly_len*8,"fhe_owner_key_wire_bytes":counter.0,"fhe_peer_key_wire_bytes":fhe_peer_key_bytes,"storage_owner_secret_bytes":32,"trusted_head_bytes":head.encode().len(),"fixture_buffer_bytes":plain.len(),"seal_ms":seal_ms,"canonical_restore_ms":canonical_restore_ms,"pir_key_setup_ms":pir_key_setup_ms,"records_ms":records_ms,"ntt_ms":ntt_ms,"fhe_keygen_ms":fhe_keygen_ms,"key_serialization_ms":key_serialization_ms,"setup_ms":setup_ms,"process_peak_resident_bytes":peak,"threads":threads,"tfhe_parameter":"PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128","tfhe_version":"1.8.1","pir_revision":"fdb7206517c249603b0c91b65f1f29f95272107c","pir_poly_len":params.poly_len,"pir_crt_moduli":&params.moduli[..params.crt_count],"pir_gaussian_width":params.noise_width,"pir_n":params.n,"pir_p":params.pt_modulus,"pir_q2_bits":params.q2_bits,"pir_t_gsw":params.t_gsw,"pir_t_conv":params.t_conv,"pir_t_exp_left":params.t_exp_left,"pir_t_exp_right":params.t_exp_right,"pir_nu1":params.db_dim_1,"pir_nu2":params.db_dim_2,"network_measured":false,"disk_io_measured":false,"sql_index_navigation":false,"sql_computation_proof":false})
    );
    let maximum_row = (0..rows)
        .find(|i| u16::from_le_bytes([plain[i * 3 + 1], plain[i * 3 + 2]]) == u16::MAX)
        .ok_or("No maximum fixture")?;
    let cases = [
        (0, 12u8),
        (1, 48),
        (maximum_row, 0),
        (rows - 1, 255),
        (0, 0),
        (1, 49),
        (rows / 2, 18),
        (0, 12),
    ];
    let mut previous = std::collections::HashMap::<usize, Vec<u8>>::new();
    let mut query_id = 0u64;
    for round in 0..rounds {
        let (row, threshold) = cases[round % cases.len()];
        let order = if round % 2 == 0 {
            [Access::Private, Access::Visible]
        } else {
            [Access::Visible, Access::Private]
        };
        for access in order {
            let owner = OwnerSession {
                storage: &storage_owner,
                fhe: &fhe_owner,
                pir: &pir_owner,
                head: &head,
            };
            let peer = PeerStore {
                params: &params,
                public: &pir_public,
                db: db.as_ref().unwrap(),
                snapshot: &snapshot,
            };
            let actual = read(
                ReadPlan {
                    access,
                    row,
                    threshold,
                    query_id,
                },
                &owner,
                &peer,
                &mut key_wire,
                limits,
            )?;
            let expected = if plain[row * 3] >= threshold {
                (
                    1,
                    u16::from_le_bytes([plain[row * 3 + 1], plain[row * 3 + 2]]),
                )
            } else {
                (0, 0)
            };
            assert_eq!(actual.answer, expected);
            if let Some(old) = previous.insert(row, actual.age_ciphertext.clone()) {
                assert_ne!(
                    old, actual.age_ciphertext,
                    "Fresh encryption is required for repeated values"
                );
            }
            let (resident, peak) = memory();
            println!(
                "{}",
                json!({"experiment":"spiral-fhe-read","access":format!("{access:?}"),"round":round,"public_fixture_row":row,"query_id":query_id,"total_local_ms":actual.total_ms,"stages":actual.stages,"count":actual.answer.0,"sum":actual.answer.1,"correct":true,"fresh_ciphertexts":true,"resident_bytes":resident,"process_peak_resident_bytes":peak,"roundtrips":2,"network_measured":false,"computation_proof":false})
            );
            query_id += 1;
        }
    }
    // These failures occur during owner authentication before any FHE encryption/evaluation.
    {
        let owner = OwnerSession {
            storage: &storage_owner,
            fhe: &fhe_owner,
            pir: &pir_owner,
            head: &head,
        };
        let mut tampered = visible_record(&snapshot, 0, limits)?;
        tampered[4 + 16 + 32] ^= 128;
        assert!(owner_row(&tampered, 0, &owner, limits).is_err());
        assert!(owner_row(&vec![0; RECORD_BYTES], 0, &owner, limits).is_err());
        let valid = visible_record(&snapshot, 0, limits)?;
        assert!(owner_row(&valid, PAGE_ROWS, &owner, limits).is_err());
    }
    // Genuine FHE overflow refusal leaves the compact image and trusted head byte-identical.
    let before = snapshot.encode();
    let before_head = head.clone();
    let (candidate, overflow, overflow_stages, overflow_query_ms) = {
        let owner = OwnerSession {
            storage: &storage_owner,
            fhe: &fhe_owner,
            pir: &pir_owner,
            head: &head,
        };
        let peer = PeerStore {
            params: &params,
            public: &pir_public,
            db: db.as_ref().unwrap(),
            snapshot: &snapshot,
        };
        increment(
            IncrementPlan {
                row: maximum_row,
                delta: 1,
                query_id,
            },
            &owner,
            &peer,
            limits,
        )?
    };
    query_id += 1;
    assert!(overflow);
    assert_eq!(candidate, 0);
    assert_eq!(snapshot.encode(), before);
    assert_eq!(head, before_head);
    println!(
        "{}",
        json!({"experiment":"spiral-fhe-overflow-rejected","private_query_ms":overflow_query_ms,"stages":overflow_stages,"overflow":overflow,"canonical_bytes_unchanged":true,"head_unchanged":true,"correct":true})
    );
    drop(before);
    let old_record = visible_record(&snapshot, 0, limits)?;
    let update_total = Instant::now();
    let (candidate, overflow, update_stages, update_query_ms) = {
        let owner = OwnerSession {
            storage: &storage_owner,
            fhe: &fhe_owner,
            pir: &pir_owner,
            head: &head,
        };
        let peer = PeerStore {
            params: &params,
            public: &pir_public,
            db: db.as_ref().unwrap(),
            snapshot: &snapshot,
        };
        increment(
            IncrementPlan {
                row: 0,
                delta: 7,
                query_id,
            },
            &owner,
            &peer,
            limits,
        )?
    };
    query_id += 1;
    assert!(!overflow);
    assert_eq!(candidate, 130);
    let start = Instant::now();
    let verified = decode_page(&old_record, &head, 0, limits)?;
    let verified_plain = storage_owner.decrypt(&verified)?;
    let mut replacement = verified_plain.as_bytes().to_vec();
    replacement[1..3].copy_from_slice(&candidate.to_le_bytes());
    head = storage_owner.replace_page(&mut snapshot, &head, 0, &replacement, limits)?;
    plain[1..3].copy_from_slice(&candidate.to_le_bytes());
    assert_eq!(snapshot.encoded_len(), initial_bytes);
    assert!(decode_page(&old_record, &head, 0, limits).is_err());
    let compact_writeback_ms = ms(start);
    drop(db.take());
    let (fresh, _, update_records_ms, update_ntt_ms) = prepare(&snapshot, &params, limits);
    db = Some(fresh);
    let update_commit_and_cache_ms = ms(update_total);
    let fresh_read = {
        let owner = OwnerSession {
            storage: &storage_owner,
            fhe: &fhe_owner,
            pir: &pir_owner,
            head: &head,
        };
        let peer = PeerStore {
            params: &params,
            public: &pir_public,
            db: db.as_ref().unwrap(),
            snapshot: &snapshot,
        };
        read(
            ReadPlan {
                access: Access::Private,
                row: 0,
                threshold: 0,
                query_id,
            },
            &owner,
            &peer,
            &mut key_wire,
            limits,
        )?
    };
    assert_eq!(fresh_read.answer, (1, 130));
    let (resident, peak) = memory();
    println!(
        "{}",
        json!({"experiment":"spiral-fhe-update","fhe_increment_private_query_ms":update_query_ms,"stages":update_stages,"compact_writeback_ms":compact_writeback_ms,"records_rebuild_ms":update_records_ms,"ntt_rebuild_ms":update_ntt_ms,"read_after_update_ms":fresh_read.total_ms,"read_after_update_stages":fresh_read.stages,"update_commit_and_cache_ms":update_commit_and_cache_ms,"total_update_rebuild_read_ms":ms(update_total),"canonical_image_bytes":snapshot.encoded_len(),"ntt_cache_bytes":db.as_ref().unwrap().len()*8,"stale_proof_rejected_before_fhe":true,"tamper_rejected_before_fhe":true,"wrong_page_rejected_before_fhe":true,"omitted_record_rejected_before_fhe":true,"count":fresh_read.answer.0,"sum":fresh_read.answer.1,"correct":true,"resident_bytes":resident,"process_peak_resident_bytes":peak,"write_access_concealed":false,"durable_restart":false,"computation_proof":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn answer_with_old_query_identifier_is_rejected_before_owner_decryption() {
        assert!(check_binding(10, [7; 32], 11, [7; 32]).is_err());
    }
    #[test]
    fn answer_at_a_different_snapshot_is_rejected_before_owner_decryption() {
        assert!(check_binding(11, [6; 32], 11, [7; 32]).is_err());
    }
    #[test]
    fn answer_for_the_requested_identifier_and_snapshot_is_locally_bound() {
        assert!(check_binding(11, [7; 32], 11, [7; 32]).is_ok());
    }
}
