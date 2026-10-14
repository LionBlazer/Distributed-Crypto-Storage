//! Compact public-fixture pages -> genuine FHE conditional COUNT/SUM on one addressed row.
//! This is an experiment, not an authenticated index or a verifiable query protocol.
#[path = "../src/metrics.rs"]
mod metrics;

use bincode::Options;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use tfhe::transciphering::{
    AesPlainState, OneTimePadPlainSecretMask, OneTimePadPlainState, StreamCipher,
};
use tfhe::{
    ClientKey, ConfigBuilder, FheUint8, FheUint16, HlStreamCipher, HlTranscipherer,
    OneTimePadFheSecretMask, ServerKey, TranscipherSession, generate_keys, set_server_key,
    unset_server_key,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const HEADER_BYTES: usize = 72;
const TAG_BYTES: usize = 32;
const PAGE_OVERHEAD: usize = HEADER_BYTES + TAG_BYTES;
const MAX_ROWS: usize = 65_536;
const MAX_WIRE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSCTR01";
const MAC_DOMAIN: &[u8] = b"DCS public-fixture compact-page MAC v1\0";
const OPRF_DOMAIN: &[u8] = b"DCS public-fixture native-OPRF row-mask v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Mode {
    OwnerAes,
    NativeOprf,
    NativeOprfRerandomized,
    OwnerAesRadix,
}

impl Mode {
    fn uses_owner_aes(self) -> bool {
        matches!(self, Self::OwnerAes | Self::OwnerAesRadix)
    }
}

// Only this owner-side state contains symmetric secret keys. It never crosses the boundary.
struct OwnerSecrets {
    aes_key: [u8; 16],
    mac_key: [u8; 32],
}

impl OwnerSecrets {
    fn fresh() -> Result<Self> {
        let mut aes_key = [0; 16];
        let mut mac_key = [0; 32];
        fill_random(&mut aes_key)?;
        fill_random(&mut mac_key)?;
        Ok(Self { aes_key, mac_key })
    }
}

struct Page<'a> {
    mode: Mode,
    page_id: u64,
    version: u64,
    rows: usize,
    nonce: [u8; 32],
    payload: &'a [u8],
}

fn parse_page(bytes: &[u8]) -> Result<Page<'_>> {
    if bytes.len() < PAGE_OVERHEAD || &bytes[..8] != MAGIC {
        return Err("Invalid compact page header".into());
    }
    let read_u64 = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let rows = usize::try_from(read_u64(24))?;
    if !(1..=MAX_ROWS).contains(&rows) || bytes.len() != PAGE_OVERHEAD + rows * 3 {
        return Err("Invalid compact page length or row count".into());
    }
    Ok(Page {
        mode: match read_u64(32) {
            0 => Mode::OwnerAes,
            1 => Mode::NativeOprf,
            2 => Mode::NativeOprfRerandomized,
            3 => Mode::OwnerAesRadix,
            _ => return Err("Invalid page cipher mode".into()),
        },
        page_id: read_u64(8),
        version: read_u64(16),
        rows,
        nonce: bytes[40..72].try_into().unwrap(),
        payload: &bytes[HEADER_BYTES..bytes.len() - TAG_BYTES],
    })
}

fn root(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn page_mac(bytes_without_tag: &[u8], mac_key: &[u8; 32]) -> blake3::Hash {
    let mut mac = blake3::Hasher::new_keyed(mac_key);
    mac.update(MAC_DOMAIN).update(bytes_without_tag).finalize()
}

// The expected root is owner-held state from the locally trusted write, not a peer claim.
// This detects page tampering/replay in this experiment; it supplies no FHE computation proof.
fn owner_authenticate(bytes: &[u8], expected_root: [u8; 32], mac_key: &[u8; 32]) -> Result<()> {
    parse_page(bytes)?;
    if root(bytes) != expected_root {
        return Err("Page does not match the owner's confirmed local root".into());
    }
    let tag_offset = bytes.len() - TAG_BYTES;
    let tag = blake3::Hash::from_bytes(bytes[tag_offset..].try_into().unwrap());
    if page_mac(&bytes[..tag_offset], mac_key) != tag {
        return Err("Invalid page authentication tag".into());
    }
    Ok(())
}

fn aes_mask(page: &Page<'_>, row: usize, aes_key: [u8; 16]) -> Result<Vec<u8>> {
    let iv: [u8; 16] = page.nonce[..16].try_into().unwrap();
    let mut stream = AesPlainState::new(aes_key, iv);
    stream.seek((row * 24) as u64);
    Ok(stream.next_keystream_bits(24)?)
}

// The library's own OprfSeed accepts byte strings. Fixed-width fields and an explicit
// domain identify the page revision, row and field. The nonce is fresh at every rewrite.
// No custom PRF of a TFHE secret key is implemented here. Security for repeated known
// plaintext storage remains an acceptance question, even when local correctness passes.
fn native_seed(page: &Page<'_>, row: usize, field: u8) -> Vec<u8> {
    let mut seed = OPRF_DOMAIN.to_vec();
    seed.extend_from_slice(&page.page_id.to_le_bytes());
    seed.extend_from_slice(&page.version.to_le_bytes());
    seed.extend_from_slice(&page.nonce);
    seed.extend_from_slice(&(row as u64).to_le_bytes());
    seed.push(field);
    seed
}

fn native_fhe_mask(mode: Mode, page: &Page<'_>, row: usize) -> Result<(FheUint8, FheUint16)> {
    if mode == Mode::NativeOprfRerandomized {
        let context = tfhe::PrfReRandomizationContext::default();
        Ok((
            FheUint8::generate_oblivious_pseudo_random_and_re_randomize(
                native_seed(page, row, 0),
                tfhe::ReRandomizationMode::default(),
                &context,
            )?,
            FheUint16::generate_oblivious_pseudo_random_and_re_randomize(
                native_seed(page, row, 1),
                tfhe::ReRandomizationMode::default(),
                &context,
            )?,
        ))
    } else {
        Ok((
            FheUint8::generate_oblivious_pseudo_random(native_seed(page, row, 0)),
            FheUint16::generate_oblivious_pseudo_random(native_seed(page, row, 1)),
        ))
    }
}
fn fixture(row: usize) -> (u8, u16) {
    if row < 4 {
        [(17, 10), (18, 20), (42, 65_535), (7, 40)][row]
    } else {
        (
            ((row * 73 + 11) % 256) as u8,
            ((row * 137 + 29) % 65_536) as u16,
        )
    }
}

fn owner_write_page(
    mode: Mode,
    rows: usize,
    owner: &OwnerSecrets,
    key: &ClientKey,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(PAGE_OVERHEAD + rows * 3);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&7u64.to_le_bytes());
    bytes.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend_from_slice(&(rows as u64).to_le_bytes());
    bytes.extend_from_slice(
        &(match mode {
            Mode::OwnerAes => 0u64,
            Mode::NativeOprf => 1u64,
            Mode::NativeOprfRerandomized => 2u64,
            Mode::OwnerAesRadix => 3u64,
        })
        .to_le_bytes(),
    );
    let mut nonce = [0; 32];
    fill_random(&mut nonce)?;
    bytes.extend_from_slice(&nonce);
    bytes.resize(PAGE_OVERHEAD + rows * 3, 0);
    for row in 0..rows {
        let page = parse_page(&bytes)?;
        let pad = match mode {
            Mode::OwnerAes | Mode::OwnerAesRadix => aes_mask(&page, row, owner.aes_key)?,
            Mode::NativeOprf | Mode::NativeOprfRerandomized => {
                // Write-time owner role: only the owner decrypts the native FHE mask.
                // The resulting plaintext pad is consumed here and never persisted.
                let (age, amount) = native_fhe_mask(mode, &page, row)?;
                let age: u8 = age.decrypt(key);
                let amount: u16 = amount.decrypt(key);
                let amount = amount.to_le_bytes();
                vec![age, amount[0], amount[1]]
            }
        };
        let (age, amount) = fixture(row);
        let plain = [age, amount as u8, (amount >> 8) as u8];
        for field in 0..3 {
            bytes[HEADER_BYTES + row * 3 + field] = plain[field] ^ pad[field];
        }
    }
    let tag_offset = bytes.len() - TAG_BYTES;
    let tag = page_mac(&bytes[..tag_offset], &owner.mac_key);
    bytes[tag_offset..].copy_from_slice(tag.as_bytes());
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
struct Request {
    query_id: u64,
    mode: Mode,
    expected_root: [u8; 32],
    row: usize,
    threshold: FheUint8,
    encrypted_mask: Option<OneTimePadFheSecretMask>,
    radix_mask: Option<(FheUint8, FheUint16)>,
}

#[derive(Serialize, Deserialize)]
struct UnverifiedAnswer {
    query_id: u64,
    root: [u8; 32],
    count: FheUint8,
    sum: FheUint16,
}

#[derive(Default, Serialize)]
struct Stages {
    page_transfer_bytes: usize,
    owner_page_authenticate_ms: f64,
    owner_mask_and_threshold_encrypt_ms: f64,
    request_serialize_ms: f64,
    request_bytes: usize,
    peer_decode_and_root_check_ms: f64,
    peer_mask_regenerate_or_decode_ms: f64,
    peer_compact_to_fhe_ms: f64,
    peer_input_rerandomization_ms: f64,
    peer_conditional_count_sum_ms: f64,
    response_serialize_ms: f64,
    response_bytes: usize,
    owner_response_decode_and_decrypt_ms: f64,
}

fn fill_random(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

fn ms(timer: Instant) -> f64 {
    timer.elapsed().as_secs_f64() * 1000.0
}

fn wire_options(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
}

struct OwnerQuerySession<'a> {
    secrets: &'a OwnerSecrets,
    fhe_key: &'a ClientKey,
    confirmed_root: [u8; 32],
}

fn owner_request(
    mode: Mode,
    page_bytes: &[u8],
    row: usize,
    query_id: u64,
    owner_session: &OwnerQuerySession<'_>,
    stages: &mut Stages,
) -> Result<Vec<u8>> {
    let owner = owner_session.secrets;
    let key = owner_session.fhe_key;
    let expected_root = owner_session.confirmed_root;
    let timer = Instant::now();
    owner_authenticate(page_bytes, expected_root, &owner.mac_key)?;
    let page = parse_page(page_bytes)?;
    if mode != page.mode || row >= page.rows {
        return Err("Addressed row is outside this page".into());
    }
    stages.owner_page_authenticate_ms = ms(timer);
    stages.page_transfer_bytes = page_bytes.len();
    let timer = Instant::now();
    let encrypted_mask = match mode {
        Mode::OwnerAes => Some(OneTimePadFheSecretMask::try_encrypt(
            OneTimePadPlainSecretMask::new(aes_mask(&page, row, owner.aes_key)?, 24),
            key,
        )?),
        Mode::NativeOprf | Mode::NativeOprfRerandomized | Mode::OwnerAesRadix => None,
    };
    let radix_mask = if mode == Mode::OwnerAesRadix {
        let pad = aes_mask(&page, row, owner.aes_key)?;
        Some((
            FheUint8::encrypt(pad[0], key),
            FheUint16::encrypt(u16::from_le_bytes([pad[1], pad[2]]), key),
        ))
    } else {
        None
    };
    let request = Request {
        query_id,
        mode,
        expected_root,
        row,
        threshold: FheUint8::encrypt(18u8, key),
        encrypted_mask,
        radix_mask,
    };
    stages.owner_mask_and_threshold_encrypt_ms = ms(timer);
    let timer = Instant::now();
    let wire = wire_options(MAX_WIRE_BYTES).serialize(&request)?;
    stages.request_serialize_ms = ms(timer);
    stages.request_bytes = wire.len();
    Ok(wire)
}

// Peer boundary: only compact ciphertext bytes, the encrypted request and a server
// key in TFHE's context are available. No ClientKey or symmetric secret key argument.
fn peer_query(page_bytes: &[u8], wire: &[u8], stages: &mut Stages) -> Result<Vec<u8>> {
    let timer = Instant::now();
    let mut request: Request = wire_options(MAX_WIRE_BYTES).deserialize(wire)?;
    let page = parse_page(page_bytes)?;
    if root(page_bytes) != request.expected_root
        || request.row >= page.rows
        || page.mode != request.mode
    {
        return Err("Request root or addressed row does not match the page".into());
    }
    let start = request.row * 3;
    let masked: [u8; 3] = page.payload[start..start + 3].try_into().unwrap();
    stages.peer_decode_and_root_check_ms = ms(timer);
    let timer = Instant::now();
    let (mut age, mut amount) = match request.mode {
        Mode::OwnerAes => {
            if request.radix_mask.is_some() {
                return Err("OTP query must not contain a radix pad".into());
            }
            let mask = request
                .encrypted_mask
                .ok_or("AES query requires an encrypted mask")?;
            let mut session = TranscipherSession::one_time_pad(mask)?;
            stages.peer_mask_regenerate_or_decode_ms = ms(timer);
            let timer = Instant::now();
            // Build TFHE's public shape/counter wrapper without storing its per-value
            // serialization overhead. XOR of public zero with these public masked bytes
            // leaves the exact original masked bytes; this does not decrypt the record.
            let mut shape =
                OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(masked.to_vec(), 24));
            let compact_age = shape.try_encrypt(0u8)?;
            let compact_amount = shape.try_encrypt(0u16)?;
            let age: FheUint8 = session.transcipher(&compact_age)?;
            let amount: FheUint16 = session.transcipher(&compact_amount)?;
            stages.peer_compact_to_fhe_ms = ms(timer);
            (age, amount)
        }
        Mode::OwnerAesRadix => {
            if request.encrypted_mask.is_some() {
                return Err("Radix query must not contain an OTP bit pad".into());
            }
            let (age_pad, amount_pad) = request
                .radix_mask
                .ok_or("Radix query requires encrypted row pads")?;
            stages.peer_mask_regenerate_or_decode_ms = ms(timer);
            let timer = Instant::now();
            let values = (
                age_pad ^ masked[0],
                amount_pad ^ u16::from_le_bytes([masked[1], masked[2]]),
            );
            stages.peer_compact_to_fhe_ms = ms(timer);
            values
        }
        Mode::NativeOprf | Mode::NativeOprfRerandomized => {
            if request.encrypted_mask.is_some() || request.radix_mask.is_some() {
                return Err("Native OPRF query must not contain a stored pad".into());
            }
            let (age_pad, amount_pad) = native_fhe_mask(request.mode, &page, request.row)?;
            stages.peer_mask_regenerate_or_decode_ms = ms(timer);
            let timer = Instant::now();
            let values = (
                age_pad ^ masked[0],
                amount_pad ^ u16::from_le_bytes([masked[1], masked[2]]),
            );
            stages.peer_compact_to_fhe_ms = ms(timer);
            values
        }
    };
    let timer = Instant::now();
    if request.mode == Mode::NativeOprfRerandomized {
        // Re-randomize every input to the conditional aggregate under one fresh
        // invocation context, including the owner's encrypted threshold.
        let mut nonce = [0; 32];
        fill_random(&mut nonce)?;
        let description = b"public-row-address;age>=threshold;COUNT;SUM;u8,u16";
        let query_id = request.query_id.to_le_bytes();
        let mut context = tfhe::ReRandomizationContext::new(
            *b"DCS_RR01",
            [
                description.as_slice(),
                nonce.as_slice(),
                request.expected_root.as_slice(),
                query_id.as_slice(),
            ],
            *b"TFHE_Enc",
        );
        context.add_ciphertext(&age);
        context.add_ciphertext(&amount);
        context.add_ciphertext(&request.threshold);
        let mut seeds = context.finalize();
        age.re_randomize(
            tfhe::ReRandomizationMode::default(),
            seeds.next_seed().unwrap(),
        )?;
        amount.re_randomize(
            tfhe::ReRandomizationMode::default(),
            seeds.next_seed().unwrap(),
        )?;
        request.threshold.re_randomize(
            tfhe::ReRandomizationMode::default(),
            seeds.next_seed().unwrap(),
        )?;
        stages.peer_input_rerandomization_ms = ms(timer);
    }
    let timer = Instant::now();
    let matches = age.ge(&request.threshold);
    let answer = UnverifiedAnswer {
        query_id: request.query_id,
        root: request.expected_root,
        count: FheUint8::cast_from(matches.clone()),
        sum: matches.if_then_else(&amount, &FheUint16::encrypt_trivial(0u16)),
    };
    stages.peer_conditional_count_sum_ms = ms(timer);
    let timer = Instant::now();
    let wire = wire_options(MAX_WIRE_BYTES).serialize(&answer)?;
    stages.response_serialize_ms = ms(timer);
    stages.response_bytes = wire.len();
    Ok(wire)
}

#[derive(Default)]
struct ByteCounter(u64);
impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("Size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help") {
        println!(
            "transcipher_query [owner-aes|owner-aes-radix|native-oprf|native-oprf-rerand] [rows] [rounds] [threads]\nCPU: 1..32 Rayon threads, default two. Defaults: owner-aes, 1024 rows (native-oprf: 64), four rounds.\nPublic synthetic fixtures; no data/key files are written. Native OPRF storage security is not established."
        );
        return Ok(());
    }
    let mode = match args.get(1).map(String::as_str).unwrap_or("owner-aes") {
        "owner-aes" => Mode::OwnerAes,
        "owner-aes-radix" => Mode::OwnerAesRadix,
        "native-oprf" => Mode::NativeOprf,
        "native-oprf-rerand" => Mode::NativeOprfRerandomized,
        _ => {
            return Err(
                "Mode must be owner-aes, owner-aes-radix, native-oprf or native-oprf-rerand".into(),
            );
        }
    };
    let rows: usize = args
        .get(2)
        .map(String::as_str)
        .unwrap_or(if mode.uses_owner_aes() { "1024" } else { "64" })
        .parse()?;
    let rounds: usize = args.get(3).map(String::as_str).unwrap_or("4").parse()?;
    let threads: usize = args.get(4).map(String::as_str).unwrap_or("2").parse()?;
    if !(1..=MAX_ROWS).contains(&rows)
        || !(1..=20).contains(&rounds)
        || !(1..=32).contains(&threads)
    {
        return Err("Use 1..65536 rows, 1..20 rounds and 1..32 Rayon threads".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let timer = Instant::now();
    let mut builder =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_oprf_key(true);
    if mode == Mode::NativeOprfRerandomized {
        builder = builder.enable_ciphertext_re_randomization(
            tfhe::shortint::parameters::ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
        );
    }
    let config = builder.build();
    let (key, server_key) = generate_keys(config);
    let key_generation_ms = ms(timer);
    let timer = Instant::now();
    let mut owner_key_counter = ByteCounter::default();
    bincode::serialize_into(&mut owner_key_counter, &key)?;
    let server_key_bytes = bincode::serialize(&server_key)?;
    let key_size_measurement_ms = ms(timer);
    let server_key_serialized_bytes = server_key_bytes.len() as u64;
    let has_dedicated_oprf_key = server_key.has_oprf_key();
    let has_transciphering_key = server_key.has_transciphering_key();
    set_server_key(server_key);
    let owner = OwnerSecrets::fresh()?;
    let timer = Instant::now();
    let page_bytes = owner_write_page(mode, rows, &owner, &key)?;
    let owner_write_page_ms = ms(timer);
    let expected_root = root(&page_bytes);
    owner_authenticate(&page_bytes, expected_root, &owner.mac_key)?;
    let owner_symmetric_and_root_bytes = if mode.uses_owner_aes() {
        16 + 32 + 32
    } else {
        32 + 32
    };
    let logical_bytes = rows * 3;
    let compact_and_owner_bytes = page_bytes.len() as u64 + owner_symmetric_and_root_bytes;
    let joint_persistent_bytes =
        compact_and_owner_bytes + owner_key_counter.0 + server_key_serialized_bytes;
    let projected_logical_bytes = 1024u64 * 1024 * 1024;
    let projected_pages = projected_logical_bytes.div_ceil(logical_bytes as u64);
    let projected_total_bytes = projected_logical_bytes
        + projected_pages * (PAGE_OVERHEAD as u64 + 32)
        + (owner_symmetric_and_root_bytes - 32)
        + owner_key_counter.0
        + server_key_serialized_bytes;
    println!(
        "{}",
        serde_json::json!({
            "kind": "setup", "mode": mode, "threads": threads, "rows": rows, "logical_plaintext_bytes": logical_bytes,
            "compact_payload_bytes": logical_bytes, "page_metadata_and_tag_bytes": PAGE_OVERHEAD,
            "serialized_page_bytes": page_bytes.len(), "owner_symmetric_keys_and_root_bytes": owner_symmetric_and_root_bytes,
            "owner_fhe_key_serialized_bytes": owner_key_counter.0, "peer_evaluation_key_serialized_bytes": server_key_serialized_bytes,
            "persistent_fhe_row_cache_bytes": 0, "persistent_row_pad_bytes": 0, "persistent_indexes_bytes": 0,
            "persistent_replicas_bytes": 0, "persistent_query_proofs_bytes": 0,
            "page_expansion": page_bytes.len() as f64 / logical_bytes as f64,
            "compact_and_owner_state_expansion": compact_and_owner_bytes as f64 / logical_bytes as f64,
            "joint_persistent_bytes": joint_persistent_bytes,
            "joint_persistent_expansion": joint_persistent_bytes as f64 / logical_bytes as f64,
            "projected_1gib_logical_joint_bytes_not_measured": projected_total_bytes,
            "projected_1gib_logical_joint_expansion_not_measured": projected_total_bytes as f64 / projected_logical_bytes as f64,
            "key_generation_ms": key_generation_ms, "key_serialization_ms": key_size_measurement_ms,
            "owner_write_page_ms": owner_write_page_ms,
            "has_dedicated_oprf_key": has_dedicated_oprf_key, "has_transciphering_key": has_transciphering_key,
            "process_peak_resident_bytes": metrics::peak_resident_bytes(),
            "native_oprf_storage_security_established": false, "query_proof_implemented": false,
            "privacy_model": "public addressed row; encrypted age predicate; one locally confirmed page root",
        })
    );
    // Fresh evaluation-key restoration is counted on the first query. This process
    // already performed writes; it is not a cold-OS/disk or first-ever-PBS measurement.
    unset_server_key();
    let mut server_key_bytes = Some(server_key_bytes);
    let owner_session = OwnerQuerySession {
        secrets: &owner,
        fhe_key: &key,
        confirmed_root: expected_root,
    };
    for round in 0..rounds {
        let row = round % rows;
        let timer = Instant::now();
        let reload_ms = if let Some(bytes) = server_key_bytes.take() {
            let reload_timer = Instant::now();
            let restored: ServerKey = wire_options(MAX_KEY_BYTES).deserialize(&bytes)?;
            set_server_key(restored);
            let elapsed = ms(reload_timer);
            drop(bytes);
            elapsed
        } else {
            0.0
        };
        let mut stages = Stages::default();
        let request = owner_request(
            mode,
            &page_bytes,
            row,
            round as u64,
            &owner_session,
            &mut stages,
        )?;
        let response = peer_query(&page_bytes, &request, &mut stages)?;
        let decode_timer = Instant::now();
        let answer: UnverifiedAnswer = wire_options(MAX_WIRE_BYTES).deserialize(&response)?;
        if answer.query_id != round as u64 || answer.root != expected_root {
            return Err("Answer is not bound to this local request/root".into());
        }
        let actual: (u8, u16) = (answer.count.decrypt(&key), answer.sum.decrypt(&key));
        stages.owner_response_decode_and_decrypt_ms = ms(decode_timer);
        let end_to_end_local_ms = ms(timer);
        let (age, amount) = fixture(row);
        let expected = if age >= 18 { (1, amount) } else { (0, 0) };
        assert_eq!(
            actual, expected,
            "FHE conditional aggregate must match the public fixture"
        );
        println!(
            "{}",
            serde_json::json!({
                "kind": "query", "mode": mode, "threads": threads, "round": round, "addressed_row": row,
                "cache_state": if round == 0 { "evaluation-key-reload; no stored row/pad cache" } else { "warm evaluation key; freshly converted row" },
                "evaluation_key_reload_ms": reload_ms, "stages": stages,
                "end_to_end_local_ms": end_to_end_local_ms,
                "end_to_end_local_excluding_key_reload_ms": end_to_end_local_ms - reload_ms,
                "count": actual.0, "sum": actual.1,
                "process_peak_resident_bytes": metrics::peak_resident_bytes(),
                "network_rtt_ms": 0, "disk_io_measured": false, "query_proof_implemented": false,
                "correctness_assertion_is_not_a_query_proof": true,
            })
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated_fixture() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let key = [7; 32]; // Explicitly public non-secret test fixture.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&[3; 32]);
        bytes.extend_from_slice(&[91, 82, 73]);
        let tag = page_mac(&bytes, &key);
        bytes.extend_from_slice(tag.as_bytes());
        let expected_root = root(&bytes);
        (bytes, expected_root, key)
    }

    #[test]
    fn owner_accepts_the_exact_page_at_its_confirmed_root() {
        let (bytes, expected_root, key) = authenticated_fixture();
        assert!(owner_authenticate(&bytes, expected_root, &key).is_ok());
    }

    #[test]
    fn changed_ciphertext_is_rejected_even_when_peer_supplies_its_new_hash() {
        let (mut bytes, expected_root, key) = authenticated_fixture();
        bytes[HEADER_BYTES] ^= 1;
        assert!(owner_authenticate(&bytes, expected_root, &key).is_err());
        assert!(owner_authenticate(&bytes, root(&bytes), &key).is_err());
    }

    #[test]
    fn valid_old_page_is_rejected_against_a_new_confirmed_root() {
        let (old, _, key) = authenticated_fixture();
        let mut newer = old.clone();
        newer[16..24].copy_from_slice(&2u64.to_le_bytes());
        newer[40..72].copy_from_slice(&[4; 32]);
        let tag_offset = newer.len() - TAG_BYTES;
        let tag = page_mac(&newer[..tag_offset], &key);
        newer[tag_offset..].copy_from_slice(tag.as_bytes());
        let new_root = root(&newer);
        assert!(owner_authenticate(&newer, new_root, &key).is_ok());
        assert!(owner_authenticate(&old, new_root, &key).is_err());
    }

    #[test]
    fn truncated_or_extra_page_bytes_are_rejected() {
        let (mut bytes, expected_root, key) = authenticated_fixture();
        bytes.push(0);
        assert!(owner_authenticate(&bytes, expected_root, &key).is_err());
        bytes.truncate(HEADER_BYTES + 2);
        assert!(owner_authenticate(&bytes, expected_root, &key).is_err());
    }
}
