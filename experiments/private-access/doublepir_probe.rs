//! Genuine DoublePIR primitive probe; public fixtures and ephemeral AES keys only.
//! No malicious-server authentication, SQL, index traversal, or FHE computation.
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use doublepir_rs::{
    arith::arith::base_p,
    database::Db,
    doublepir::{LOGQ, SEC_PARAM, answer, init, pick_params, query, recover, setup},
    matrix::Matrix,
    serializer::{DeserializeSlice, Serialize, State},
};
use rand::RngCore;
use serde_json::json;
use std::time::Instant;

type AesCtr = ctr::Ctr128BE<Aes128>;

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
        fn GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            counters: *mut Counters,
            size: u32,
        ) -> i32;
    }
    let mut counters = Counters {
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
                &mut counters,
                std::mem::size_of::<Counters>() as u32,
            )
        },
        0
    );
    (counters.current, counters.peak)
}
#[cfg(not(windows))]
fn memory() -> (usize, usize) {
    (0, 0)
}
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn state_bytes(state: &State) -> usize {
    state.iter().map(|m| m.data.len() * 4).sum()
}
fn expected(i: usize) -> [u8; 3] {
    let age = ((i * 37 + (i >> 8) * 17 + 11) % 256) as u8;
    let amount = ((i * 719 + (i >> 16) * 927 + 123) % 65_536) as u16;
    [age, amount as u8, (amount >> 8) as u8]
}
fn packed(bytes: &[u8]) -> u64 {
    bytes[0] as u64 | (bytes[1] as u64) << 8 | (bytes[2] as u64) << 16
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rows: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(1_000_000);
    let rounds: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    let threads: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(8);
    assert!((1..=1_000_000).contains(&rows));
    assert!((1..=100).contains(&rounds));
    assert!((1..=8).contains(&threads));
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .unwrap();
    let start = Instant::now();
    let mut key = [0u8; 16];
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut ciphertext: Vec<u8> = (0..rows).flat_map(expected).collect();
    AesCtr::new(&key.into(), &nonce.into()).apply_keystream(&mut ciphertext);
    let params = pick_params(rows as u64, 24, SEC_PARAM, LOGQ);
    let mut db = Db::new(rows as u64, 24, &params);
    db.data = Matrix::new(params.l, params.m);
    for i in 0..rows {
        let value = packed(&ciphertext[i * 3..i * 3 + 3]);
        for j in 0..db.info.ne {
            db.data[(i / params.m) * db.info.ne + j][i % params.m] =
                base_p(params.p, value, j as u64) as u32;
        }
    }
    db.data -= (params.p / 2) as u32;
    let encode_ms = ms(start);
    let start = Instant::now();
    let shared = init(&db.info, &params);
    let shared_ms = ms(start);
    let start = Instant::now();
    let (server, hint) = setup(&mut db, &shared, &params);
    let preprocessing_ms = ms(start);
    let hint_wire = hint.serialize();
    let hint_wire_bytes = hint_wire.len();
    let client_hint = State::deserialize(&hint_wire);
    drop(hint_wire);
    let (resident, peak) = memory();
    println!(
        "{}",
        json!({
            "experiment":"doublepir-24bit-setup", "rows":rows, "logical_bytes":rows*3,
            "source_revision":"fdb7206517c249603b0c91b65f1f29f95272107c", "n":params.n,"logq":params.logq,"sigma":params.sigma,"p":params.p,
            "l":params.l,"m":params.m,"entry_field_elements":db.info.ne,"x":db.info.x,
            "database_encoded_bytes":db.data.data.len()*4,"database_serialized_bytes":db.data.serialize().len(),
            "server_state_bytes":state_bytes(&server),"server_state_wire_bytes":server.serialize().len(),
            "shared_state_bytes":state_bytes(&shared),"shared_seed_bytes":32,"hint_bytes":state_bytes(&hint),"hint_wire_bytes":hint_wire_bytes,
            "owner_aes_key_bytes":16,"public_nonce_bytes":16,"additional_fixture_buffer_bytes":ciphertext.len(),
            "encode_ms":encode_ms,"shared_init_ms":shared_ms,"preprocessing_ms":preprocessing_ms,"threads":threads,
            "resident_bytes":resident,"peak_resident_bytes":peak,"fhe_evaluation_key_bytes_included":0,
            "authenticated":false,"index":false,"sql":false,"fhe":false,"network_measured":false
        })
    );
    let indices = [
        0,
        rows - 1,
        rows / 2,
        13 % rows,
        0,
        13 % rows,
        rows / 3,
        rows * 2 / 3,
    ];
    for round in 0..rounds {
        let i = if round < indices.len() {
            indices[round]
        } else {
            (round * 104_729 + 13) % rows
        };
        let total = Instant::now();
        let start = Instant::now();
        let (secret, q) = query(i as u64, &shared, &params, &db.info);
        let q_wire = vec![q].serialize();
        let q_client = Vec::<State>::deserialize(&q_wire);
        let query_ms = ms(start);
        let start = Instant::now();
        let a = answer(&db, &q_client, &server, &shared, &params, None, None);
        let a_wire = a.serialize();
        let a_owner = State::deserialize(&a_wire);
        let answer_ms = ms(start);
        let start = Instant::now();
        let value = recover(
            i as u64,
            0,
            &client_hint,
            &q_client[0],
            &a_owner,
            &shared,
            &secret,
            &params,
            &db.info,
        );
        assert_eq!(value, packed(&ciphertext[i * 3..i * 3 + 3]));
        let mut row = [
            (value & 255) as u8,
            ((value >> 8) & 255) as u8,
            ((value >> 16) & 255) as u8,
        ];
        let mut cipher = AesCtr::new(&key.into(), &nonce.into());
        use ctr::cipher::StreamCipherSeek;
        cipher.seek((i * 3) as u64);
        cipher.apply_keystream(&mut row);
        assert_eq!(row, expected(i));
        let recover_ms = ms(start);
        let total_ms = ms(total);
        let (resident, peak) = memory();
        println!(
            "{}",
            json!({"experiment":"doublepir-24bit-query","round":round,"row":i,"request_bytes":q_wire.len(),"response_bytes":a_wire.len(),"client_query_state_bytes":state_bytes(&secret),"client_query_state_wire_bytes":secret.serialize().len(),"query_ms":query_ms,"answer_ms":answer_ms,"recover_and_decrypt_ms":recover_ms,"total_ms":total_ms,"threads":threads,"resident_bytes":resident,"peak_resident_bytes":peak,"correct":true,"roundtrips":1})
        );
    }
}
