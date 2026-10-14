#![recursion_limit = "256"]
//! Real private PaddedV2 index -> authenticated data PIR -> fresh TFHE COUNT/SUM.
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
    store_id: u8,
    root: [u8; 32],
) -> ProbeResult<(Vec<u8>, usize, usize, f64, f64, f64)> {
    let start = Instant::now();
    let query = client.generate_query(page);
    let payload = query.serialize();
    if payload.len() != params.query_bytes() {
        return Err("Unexpected PIR query length".into());
    }
    let mut request = Vec::with_capacity(33 + payload.len());
    request.push(store_id);
    request.extend_from_slice(&root);
    request.extend_from_slice(&payload);
    if request[0] != store_id || request[1..33] != root {
        return Err("PIR request cache/root framing mismatch".into());
    }
    let server_query = Query::deserialize(params, &request[33..]);
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
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io::{self, Write},
};
use tfhe::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use tfhe::{
    ClientKey, ConfigBuilder, FheBool, FheUint8, FheUint16, FheUint32, ServerKey, generate_keys,
    with_server_key_as_context,
};

#[path = "padded_index_codec.rs"]
mod padded_index_codec;
use padded_index_codec::{IndexHeader, PageSource};
type ProbeResult<T> = Result<T, Box<dyn std::error::Error>>;
type IndexResult<T> = Result<T, IndexError>;
const MAX_TABLE_ROWS: usize = 1_000_000;
const MAX_ROWS: usize = 256; // Original codec contract. This probe preflights at 16.
const SLOT_BUDGET: usize = 16;
const ROW_BYTES: u32 = 3;
const SCHEMA: [u8; 16] = *b"CQAGEAMOUNT00001";
const INDEX_SCHEMA: [u8; 16] = *b"CQAGEINDEX000002";
const INDEX_HEADER_BYTES: usize = compact_store::MANIFEST_BYTES + (256 + 257) * 4;
const WIRE_LIMIT: u64 = 32 * 1024 * 1024;
const KEY_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum IndexError {
    InvalidIndex,
    WrongVersion,
    InvalidRange,
    DuplicateAddress,
    SelectionBudget { selected: usize, budget: usize },
    PageBudget,
    Storage(compact_store::Error),
    Fetch(String),
}
impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for IndexError {}
impl From<compact_store::Error> for IndexError {
    fn from(value: compact_store::Error) -> Self {
        Self::Storage(value)
    }
}
#[derive(Clone, Copy, Debug)]
struct PlainRow {
    age: u8,
    amount: u16,
}
#[derive(Clone, Copy)]
struct AgeRange {
    lower: u8,
    upper: u8,
}
impl AgeRange {
    fn equal(age: u8) -> Self {
        Self {
            lower: age,
            upper: age,
        }
    }
    fn validate(self) -> IndexResult<()> {
        if self.lower > self.upper {
            Err(IndexError::InvalidRange)
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    fn contains(self, age: u8) -> bool {
        self.lower <= age && age <= self.upper
    }
}
fn public_rows(rows: usize) -> Vec<PlainRow> {
    (0..rows)
        .map(|ordinal| match ordinal {
            0 => PlainRow {
                age: 250,
                amount: 100,
            },
            1..=4 => PlainRow {
                age: 251,
                amount: 200 + ordinal as u16,
            },
            5..=20 => PlainRow {
                age: 252,
                amount: 300 + ordinal as u16,
            },
            _ => PlainRow {
                age: ((ordinal * 73 + 11) % 200) as u8,
                amount: ((ordinal * 137 + 29) % 65536) as u16,
            },
        })
        .collect()
}
fn options(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
}
#[derive(Clone, Copy, Debug)]
enum Access {
    Visible,
    Private,
}
#[derive(Clone, Copy, Debug)]
enum Profile {
    AddressOnly,
    Fixed16,
}
#[derive(Clone, Copy, Debug)]
enum HeaderMode {
    Uncached,
    Cached,
}

struct Store<'a> {
    id: u8,
    snapshot: &'a EncryptedSnapshot,
    head: &'a Commitment,
    db: &'a AlignedMemory64,
    limits: Limits,
}
struct Pir<'a> {
    params: &'a Params,
    client: &'a Client<'a>,
    public: &'a PublicParameters<'a>,
}
#[derive(Default, Serialize)]
struct FetchStages {
    calls: usize,
    query_ms: f64,
    server_ms: f64,
    recovery_ms: f64,
    verify_decrypt_ms: f64,
    request_bytes: usize,
    response_bytes: usize,
}
struct Source<'a> {
    access: Access,
    store: &'a Store<'a>,
    pir: &'a Pir<'a>,
    stats: RefCell<FetchStages>,
    posting_page: Cell<Option<u64>>,
    one_page: bool,
}
impl Source<'_> {
    fn fetch(&self, page: u64) -> ProbeResult<Vec<u8>> {
        if self.one_page && self.posting_page.get().is_some_and(|old| old != page) {
            return Err(IndexError::PageBudget.into());
        }
        self.posting_page.set(Some(page));
        if self.store.head != self.store.snapshot.commitment() {
            return Err("Peer cache snapshot does not match independently trusted head".into());
        }
        let mut stats = self.stats.borrow_mut();
        stats.calls += 1;
        let record = match self.access {
            Access::Visible => {
                let start = Instant::now();
                let mut request = Vec::with_capacity(41);
                request.push(self.store.id);
                request.extend_from_slice(&self.store.head.root());
                request.extend_from_slice(&page.to_le_bytes());
                if request[0] != self.store.id
                    || request[1..33] != self.store.snapshot.commitment().root()
                {
                    return Err("Visible request cache/root framing mismatch".into());
                }
                let requested_page = u64::from_le_bytes(request[33..41].try_into()?);
                let wire = self
                    .store
                    .snapshot
                    .lookup(requested_page, self.store.limits)?
                    .encode();
                let mut record = vec![0u8; RECORD_BYTES];
                record[..4].copy_from_slice(&(wire.len() as u32).to_le_bytes());
                record[4..4 + wire.len()].copy_from_slice(&wire);
                stats.request_bytes += request.len();
                stats.response_bytes += wire.len();
                stats.server_ms += ms(start);
                record
            }
            Access::Private => {
                // Native crypto is unchanged. The real serialized query/answer path
                // is inside private_fetch, including serialized public store id/root framing.
                let (record, qbytes, abytes, qms, ams, rms) = private_fetch(
                    self.pir.params,
                    self.pir.client,
                    self.pir.public,
                    self.store.db,
                    page as usize,
                    self.store.id,
                    self.store.head.root(),
                )?;
                stats.request_bytes += qbytes;
                stats.response_bytes += abytes;
                stats.query_ms += qms;
                stats.server_ms += ams;
                stats.recovery_ms += rms;
                record
            }
        };
        let start = Instant::now();
        // Return bounded response bytes to the codec; it then authenticates/AEAD-decodes.
        if record.len() != RECORD_BYTES {
            return Err("Invalid PIR record length".into());
        }
        let length = u32::from_le_bytes(record[..4].try_into()?) as usize;
        if length > RECORD_BYTES - 4 {
            return Err("Invalid PIR record payload length".into());
        }
        let wire = record[4..4 + length].to_vec();
        stats.recovery_ms += ms(start);
        Ok(wire)
    }
    fn plain(&self, owner: &Owner, page: u64) -> ProbeResult<compact_store::PlainPage> {
        let wire = self.fetch(page)?;
        let start = Instant::now();
        let verified = LookupResponse::decode(&wire, self.store.limits)?.verify(
            self.store.head,
            page,
            self.store.limits,
        )?;
        let plain = owner.decrypt(&verified)?;
        self.stats.borrow_mut().verify_decrypt_ms += ms(start);
        Ok(plain)
    }
}
impl PageSource for Source<'_> {
    fn commitment(&self) -> &Commitment {
        self.store.head
    }
    fn lookup_wire(&self, page: u64, _: Limits) -> IndexResult<Vec<u8>> {
        self.fetch(page)
            .map_err(|error| IndexError::Fetch(error.to_string()))
    }
}
#[derive(Clone)]
struct CachedHeader {
    counts: [u32; 256],
    offsets: [u32; 257],
    data_head: [u8; compact_store::MANIFEST_BYTES],
    index_head: [u8; compact_store::MANIFEST_BYTES],
}
impl CachedHeader {
    fn capture(header: &IndexHeader, data: &Commitment, index: &Commitment) -> Self {
        let (counts, offsets) = header.metadata();
        Self {
            counts,
            offsets,
            data_head: data.encode(),
            index_head: index.encode(),
        }
    }
    fn restore(&self, data: &Commitment, index: &Commitment) -> IndexResult<IndexHeader> {
        if self.data_head != data.encode() || self.index_head != index.encode() {
            return Err(IndexError::WrongVersion);
        }
        Ok(IndexHeader::from_cached(self.counts, self.offsets))
    }
    fn payload_bytes(&self) -> usize {
        256 * 4 + 257 * 4 + 2 * compact_store::MANIFEST_BYTES
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedRow {
    age: FheUint8,
    amount: FheUint16,
    valid: FheBool,
}
#[derive(Serialize, Deserialize)]
struct ReadRequest {
    query_id: u64,
    data_root: [u8; 32],
    index_root: [u8; 32],
    target: FheUint8,
    zero_count: FheUint8,
    zero_sum: FheUint32,
    rows: Vec<EncryptedRow>,
}
#[derive(Serialize, Deserialize)]
struct ReadAnswer {
    query_id: u64,
    data_root: [u8; 32],
    index_root: [u8; 32],
    count: FheUint8,
    sum: FheUint32,
}
#[derive(Default, Serialize)]
struct Stages {
    header: FetchStages,
    posting: FetchStages,
    data: FetchStages,
    index_verify_decrypt_select_ms: f64,
    owner_fhe_encrypt_ms: f64,
    request_serialize_ms: f64,
    evaluation_key_restore_ms: f64,
    peer_decode_ms: f64,
    peer_fhe_ms: f64,
    peer_serialize_ms: f64,
    owner_answer_decode_decrypt_ms: f64,
    fhe_request_bytes: usize,
    fhe_response_bytes: usize,
}
fn binding(answer: &ReadAnswer, id: u64, data: &Commitment, index: &Commitment) -> ProbeResult<()> {
    metadata_binding(
        (answer.query_id, answer.data_root, answer.index_root),
        (id, data.root(), index.root()),
    )
}
fn peer_read(
    wire: &[u8],
    key: &ServerKey,
    workers: usize,
    stages: &mut Stages,
) -> ProbeResult<Vec<u8>> {
    let start = Instant::now();
    let request: ReadRequest = options(WIRE_LIMIT).deserialize(wire)?;
    if request.rows.len() > SLOT_BUDGET {
        return Err("FHE input slot budget exceeded".into());
    }
    stages.peer_decode_ms = ms(start);
    let start = Instant::now();
    let results: Vec<(FheUint8, FheUint32)> = std::thread::scope(|scope| {
        let chunk = request.rows.len().div_ceil(workers).max(1);
        let handles: Vec<_> = request
            .rows
            .chunks(chunk)
            .map(|rows| {
                let target = &request.target;
                scope.spawn(move || {
                    with_server_key_as_context(key.clone(), || {
                        rows.iter()
                            .map(|row| {
                                let matched = &row.valid & row.age.eq(target);
                                let selected = matched
                                    .if_then_else(&row.amount, &FheUint16::encrypt_trivial(0u16));
                                (FheUint8::cast_from(matched), FheUint32::cast_from(selected))
                            })
                            .collect::<Vec<_>>()
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("FHE row worker panicked"))
            .collect()
    });
    let (counts, sums): (Vec<_>, Vec<_>) = results.into_iter().unzip();
    let (count, sum) = if counts.is_empty() {
        // Empty COUNT/SUM has no candidate arithmetic. These are fresh owner
        // ciphertexts of the identities, never plaintext or public trivial outputs.
        (request.zero_count, request.zero_sum)
    } else {
        with_server_key_as_context(key.clone(), || {
            (
                counts.into_iter().sum::<FheUint8>(),
                sums.into_iter().sum::<FheUint32>(),
            )
        })
    };
    stages.peer_fhe_ms = ms(start);
    let answer = ReadAnswer {
        query_id: request.query_id,
        data_root: request.data_root,
        index_root: request.index_root,
        count,
        sum,
    };
    let start = Instant::now();
    let answer_wire = options(WIRE_LIMIT).serialize(&answer)?;
    stages.peer_serialize_ms = ms(start);
    stages.fhe_response_bytes = answer_wire.len();
    Ok(answer_wire)
}
struct Session<'a> {
    owner: &'a Owner,
    fhe: &'a ClientKey,
    pir: &'a Pir<'a>,
    data: &'a Store<'a>,
    index: &'a Store<'a>,
    cached: &'a CachedHeader,
    workers: usize,
}
struct Plan {
    access: Access,
    profile: Profile,
    header: HeaderMode,
    age: u8,
    query_id: u64,
}
struct ReadResult {
    actual: (u8, u32),
    stages: Stages,
    total_ms: f64,
    selected: Vec<u64>,
    slots: usize,
    target_ciphertext: Vec<u8>,
}
fn source<'a>(access: Access, store: &'a Store<'a>, pir: &'a Pir<'a>) -> Source<'a> {
    Source {
        access,
        store,
        pir,
        stats: RefCell::default(),
        posting_page: Cell::new(None),
        one_page: true,
    }
}
fn read(
    plan: Plan,
    session: &Session,
    key_wire: &mut Option<Vec<u8>>,
    key: &mut Option<ServerKey>,
) -> ProbeResult<ReadResult> {
    let total = Instant::now();
    let mut stages = Stages::default();
    let header_source = source(plan.access, session.index, session.pir);
    let start = Instant::now();
    let header = match plan.header {
        HeaderMode::Uncached => {
            padded_index_codec::check_binding(session.owner, &header_source, session.data.head)?
        }
        HeaderMode::Cached => session
            .cached
            .restore(session.data.head, session.index.head)?,
    };
    stages.header = header_source.stats.into_inner();
    posting_page_preflight(&header, plan.age)?;
    let posting_source = source(plan.access, session.index, session.pir);
    let selected = padded_index_codec::select_from_header(
        session.owner,
        &posting_source,
        session.data.head,
        AgeRange::equal(plan.age),
        SLOT_BUDGET,
        &mut 0,
        header,
    )?;
    if matches!(plan.profile, Profile::Fixed16) && posting_source.stats.borrow().calls == 0 {
        // Native encrypted dummy query maintains the public one-posting-read schedule.
        // Authenticate the dummy even though its plaintext is not used for selection.
        drop(posting_source.plain(session.owner, 0)?);
    }
    stages.index_verify_decrypt_select_ms = ms(start);
    stages.posting = posting_source.stats.into_inner();

    let data_source = source(plan.access, session.data, session.pir);
    let page = data_page_preflight(&selected)?;
    let data_page = if let Some(page) = page {
        Some(data_source.plain(session.owner, page)?)
    } else if matches!(plan.profile, Profile::Fixed16) {
        Some(data_source.plain(session.owner, 0)?)
    } else {
        None
    };
    let mut fields = Vec::with_capacity(selected.len());
    for ordinal in &selected {
        let offset = (*ordinal as usize % PAGE_ROWS) * 3;
        let bytes = data_page
            .as_ref()
            .ok_or("Missing selected page")?
            .as_bytes()
            .get(offset..offset + 3)
            .ok_or("Selected ordinal outside authenticated data page")?;
        fields.push((bytes[0], u16::from_le_bytes([bytes[1], bytes[2]]), true));
    }
    if matches!(plan.profile, Profile::Fixed16) {
        fields.resize(SLOT_BUDGET, (0u8, 0u16, false));
    }
    stages.data = data_source.stats.into_inner();
    let slots = fields.len();
    let start = Instant::now();
    let request = ReadRequest {
        query_id: plan.query_id,
        data_root: session.data.head.root(),
        index_root: session.index.head.root(),
        target: FheUint8::encrypt(plan.age, session.fhe),
        zero_count: FheUint8::encrypt(0u8, session.fhe),
        zero_sum: FheUint32::encrypt(0u32, session.fhe),
        rows: fields
            .into_iter()
            .map(|(age, amount, valid)| EncryptedRow {
                age: FheUint8::encrypt(age, session.fhe),
                amount: FheUint16::encrypt(amount, session.fhe),
                valid: FheBool::encrypt(valid, session.fhe),
            })
            .collect(),
    };
    stages.owner_fhe_encrypt_ms = ms(start);
    let start = Instant::now();
    let wire = options(WIRE_LIMIT).serialize(&request)?;
    stages.request_serialize_ms = ms(start);
    stages.fhe_request_bytes = wire.len();
    if let Some(bytes) = key_wire.take() {
        let start = Instant::now();
        *key = Some(options(KEY_LIMIT).deserialize(&bytes)?);
        stages.evaluation_key_restore_ms = ms(start);
    }
    let answer_wire = peer_read(
        &wire,
        key.as_ref().ok_or("No peer evaluation key")?,
        session.workers,
        &mut stages,
    )?;
    let start = Instant::now();
    let answer: ReadAnswer = options(WIRE_LIMIT).deserialize(&answer_wire)?;
    binding(
        &answer,
        plan.query_id,
        session.data.head,
        session.index.head,
    )?;
    let actual = (
        answer.count.decrypt(session.fhe),
        answer.sum.decrypt(session.fhe),
    );
    stages.owner_answer_decode_decrypt_ms = ms(start);
    let total_ms = ms(total);
    let target_ciphertext = options(WIRE_LIMIT).serialize(&request.target)?;
    Ok(ReadResult {
        actual,
        stages,
        total_ms,
        selected,
        slots,
        target_ciphertext,
    })
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
fn nonce() -> ProbeResult<u64> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|_| "OS randomness failed")?;
    Ok(u64::from_le_bytes(bytes))
}

fn main() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let rows: usize = args
        .get(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(MAX_TABLE_ROWS);
    let rounds: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    let threads: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(8);
    if rows != MAX_TABLE_ROWS || !(4..=12).contains(&rounds) || !(1..=8).contains(&threads) {
        return Err(
            "Use exactly 1000000 public rows, 4..12 rounds, 1..8 Rayon/initiating workers".into(),
        );
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let setup = Instant::now();
    let owner = Owner::generate(*b"public-indexfhe!")?;
    let plain = public_rows(rows);
    let packed: Vec<u8> = plain
        .iter()
        .flat_map(|row| [row.age, row.amount as u8, (row.amount >> 8) as u8])
        .collect();
    let start = Instant::now();
    let mut data = owner.seal(
        Layout {
            schema: SCHEMA,
            row_width: ROW_BYTES,
            rows_per_page: PAGE_ROWS as u32,
            row_count: rows as u64,
        },
        &packed,
        Limits::default(),
    )?;
    let data_seal_ms = ms(start);
    let start = Instant::now();
    let mut index = padded_index_codec::build(&owner, &plain, data.commitment())?;
    let index_build_seal_ms = ms(start);
    let start = Instant::now();
    let data_image = data.encode();
    let index_image = index.encode();
    data = EncryptedSnapshot::decode(&data_image, Limits::default())?;
    index = EncryptedSnapshot::decode(&index_image, padded_index_codec::index_limits())?;
    let canonical_roundtrip_ms = ms(start);
    drop(data_image);
    drop(index_image);
    let mut data_head = data.commitment().clone();
    let mut index_head = index.commitment().clone();
    let logical_bytes = packed.len();
    let fixture_buffer_bytes =
        packed.capacity() + plain.capacity() * std::mem::size_of::<PlainRow>();
    let expected: HashMap<u8, Vec<u64>> = [250, 251, 252, 255]
        .into_iter()
        .map(|age| {
            (
                age,
                plain
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| row.age == age)
                    .map(|(i, _)| i as u64)
                    .collect(),
            )
        })
        .collect();
    let expected_sum: HashMap<u8, u32> = expected
        .iter()
        .map(|(age, ordinals)| {
            (
                *age,
                ordinals
                    .iter()
                    .map(|i| u32::from(plain[*i as usize].amount))
                    .sum(),
            )
        })
        .collect();
    drop(packed);
    drop(plain);
    let mut cfg: serde_json::Value = serde_json::from_str(&CFG_20_256.replace('\'', "\""))?;
    cfg["nu_1"] = json!(7);
    cfg["nu_2"] = json!(2);
    let params = params_from_json_obj(&cfg);
    assert_eq!(params.num_items(), 512);
    let start = Instant::now();
    let mut pir_client = Client::init(&params);
    let public = pir_client.generate_keys();
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
    let (initial_data_db, data_proof_bytes, data_records_ms, data_ntt_ms) =
        prepare(&data, &params, Limits::default());
    let (initial_index_db, index_proof_bytes, index_records_ms, index_ntt_ms) =
        prepare(&index, &params, padded_index_codec::index_limits());
    let mut data_db = Some(initial_data_db);
    let mut index_db = Some(initial_index_db);
    let start = Instant::now();
    let (fhe_owner, fhe_peer) = generate_keys(
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build(),
    );
    let fhe_keygen_ms = ms(start);
    let start = Instant::now();
    let mut owner_counter = Counter::default();
    options(KEY_LIMIT).serialize_into(&mut owner_counter, &fhe_owner)?;
    let peer_key_wire = options(KEY_LIMIT).serialize(&fhe_peer)?;
    let peer_key_bytes = peer_key_wire.len();
    drop(fhe_peer);
    let key_serialization_ms = ms(start);
    let mut key_wire = Some(peer_key_wire);
    let mut peer_key = None;
    let pir = Pir {
        params: &params,
        client: &pir_client,
        public: &pir_public,
    };
    let cache_fill = Instant::now();
    let initial_store = Store {
        id: 1,
        snapshot: &index,
        head: &index_head,
        db: index_db.as_ref().unwrap(),
        limits: padded_index_codec::index_limits(),
    };
    let initial_source = source(Access::Private, &initial_store, &pir);
    let header = padded_index_codec::check_binding(&owner, &initial_source, &data_head)?;
    let mut cached = CachedHeader::capture(&header, &data_head, &index_head);
    drop(header);
    let cache_fill_ms = ms(cache_fill);
    let cache_fill_stages = initial_source.stats.into_inner();
    let (_, peak) = memory();
    println!(
        "{}",
        json!({
            "experiment":"spiral-index-fhe-setup","logical_rows":rows,"logical_bytes":logical_bytes,
            "canonical_data_bytes":data.encoded_len(),"canonical_index_bytes":index.encoded_len(),
            "canonical_combined_bytes":data.encoded_len()+index.encoded_len(),
            "canonical_combined_expansion":(data.encoded_len()+index.encoded_len()) as f64/logical_bytes as f64,
            "data_pages":data_head.layout().page_count()?,"index_pages":index_head.layout().page_count()?,
            "data_merkle_bytes":data.index_hash_bytes(),"index_merkle_bytes":index.index_hash_bytes(),
            "record_slots_per_database":params.num_items(),"record_bytes":RECORD_BYTES,
            "data_proof_payload_bytes":data_proof_bytes,"index_proof_payload_bytes":index_proof_bytes,
            "temporary_record_buffer_bytes":params.num_items()*RECORD_BYTES,
            "data_ntt_cache_bytes":data_db.as_ref().unwrap().len()*8,
            "index_ntt_cache_bytes":index_db.as_ref().unwrap().len()*8,"ntt_persisted_bytes":0,
            "persistent_fhe_row_cache_bytes":0,"replicas":1,
            "pir_shared_public_wire_bytes":public_wire_bytes,"pir_public_ram_payload_bytes":pir_public_payload_bytes,
            "pir_owner_base_secret_payload_bytes":(params.n+1)*params.poly_len*8,
            "pir_owner_derived_secret_payload_bytes":(params.n*(params.n+1)+2)*params.poly_len*8,
            "fhe_owner_key_wire_bytes":owner_counter.0,"fhe_peer_key_wire_bytes":peer_key_bytes,
            "storage_owner_secret_bytes":32,"trusted_head_bytes":2*compact_store::MANIFEST_BYTES,
            "cached_header_payload_bytes":cached.payload_bytes(),
            "cached_header_counts_offsets_bytes":(256+257)*4,
            "cached_header_duplicated_head_bindings_bytes":2*compact_store::MANIFEST_BYTES,
            "fixture_setup_buffer_capacity_bytes":fixture_buffer_bytes,"fixture_dropped_before_queries":true,
            "data_seal_ms":data_seal_ms,"index_build_seal_ms":index_build_seal_ms,
            "canonical_encode_decode_ms":canonical_roundtrip_ms,"pir_key_setup_ms":pir_key_setup_ms,
            "data_records_ms":data_records_ms,"index_records_ms":index_records_ms,
            "data_ntt_ms":data_ntt_ms,"index_ntt_ms":index_ntt_ms,
            "fhe_keygen_ms":fhe_keygen_ms,"key_serialization_ms":key_serialization_ms,
            "owner_header_private_cache_fill_ms":cache_fill_ms,"cache_fill_stages":cache_fill_stages,
            "setup_ms":ms(setup),"process_peak_resident_bytes":peak,"rayon_threads":threads,"row_workers":threads,
            "tfhe_parameter":"PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128","tfhe_version":"1.8.1",
            "pir_revision":"fdb7206517c249603b0c91b65f1f29f95272107c","codec_revision":"6763556",
            "pir_poly_len":params.poly_len,"pir_crt_moduli":&params.moduli[..params.crt_count],
            "pir_gaussian_width":params.noise_width,"pir_n":params.n,"pir_p":params.pt_modulus,
            "pir_q2_bits":params.q2_bits,"pir_t_gsw":params.t_gsw,"pir_t_conv":params.t_conv,
            "pir_t_exp_left":params.t_exp_left,"pir_t_exp_right":params.t_exp_right,
            "pir_nu1":params.db_dim_1,"pir_nu2":params.db_dim_2,
            "network_measured":false,"disk_io_measured":false,"computation_proof":false
        })
    );
    let mut previous = HashMap::<u8, Vec<u8>>::new();
    for round in 0..rounds {
        let age = [250, 251, 252, 255][round % 4];
        for profile in [Profile::AddressOnly, Profile::Fixed16] {
            for header_mode in [HeaderMode::Uncached, HeaderMode::Cached] {
                let order = if round % 2 == 0 {
                    [Access::Private, Access::Visible]
                } else {
                    [Access::Visible, Access::Private]
                };
                for access in order {
                    let data_store = Store {
                        id: 0,
                        snapshot: &data,
                        head: &data_head,
                        db: data_db.as_ref().unwrap(),
                        limits: Limits::default(),
                    };
                    let index_store = Store {
                        id: 1,
                        snapshot: &index,
                        head: &index_head,
                        db: index_db.as_ref().unwrap(),
                        limits: padded_index_codec::index_limits(),
                    };
                    let session = Session {
                        owner: &owner,
                        fhe: &fhe_owner,
                        pir: &pir,
                        data: &data_store,
                        index: &index_store,
                        cached: &cached,
                        workers: threads,
                    };
                    let id = nonce()?;
                    let result = read(
                        Plan {
                            access,
                            profile,
                            header: header_mode,
                            age,
                            query_id: id,
                        },
                        &session,
                        &mut key_wire,
                        &mut peer_key,
                    )?;
                    assert_eq!(
                        result.selected, expected[&age],
                        "Index must decode the complete posting list"
                    );
                    assert_eq!(
                        result.actual,
                        (expected[&age].len() as u8, expected_sum[&age])
                    );
                    if let Some(old) = previous.insert(age, result.target_ciphertext.clone()) {
                        assert_ne!(
                            old, result.target_ciphertext,
                            "Repeated target must be freshly encrypted"
                        );
                    }
                    let requests = result.stages.header.request_bytes
                        + result.stages.posting.request_bytes
                        + result.stages.data.request_bytes
                        + result.stages.fhe_request_bytes;
                    let responses = result.stages.header.response_bytes
                        + result.stages.posting.response_bytes
                        + result.stages.data.response_bytes
                        + result.stages.fhe_response_bytes;
                    let rpcs = result.stages.header.calls
                        + result.stages.posting.calls
                        + result.stages.data.calls
                        + 1;
                    let (resident, peak) = memory();
                    println!(
                        "{}",
                        json!({
                            "experiment":"spiral-index-fhe-read","round":round,"public_fixture_age":age,
                            "profile":format!("{profile:?}"),"header":format!("{header_mode:?}"),
                            "access":format!("{access:?}"),"query_id":id,"total_local_ms":result.total_ms,
                            "stages":result.stages,"selected_ordinals_from_decoded_index":result.selected,
                            "fhe_slots":result.slots,"count":result.actual.0,"sum":result.actual.1,
                            "request_bytes":requests,"response_bytes":responses,"total_wire_bytes":requests+responses,
                            "sequential_rpcs":rpcs,"fresh_ciphertexts":true,"correct":true,
                            "resident_bytes":resident,"process_peak_resident_bytes":peak,
                            "candidate_count_visible":matches!(profile, Profile::AddressOnly),
                            "network_measured":false,"computation_proof":false
                        })
                    );
                }
            }
        }
    }
    // Owner-local malicious response checks; no FHE encryption/evaluation is reached.
    let zero = vec![0; RECORD_BYTES];
    assert!(decode_page(&zero, &index_head, 0, padded_index_codec::index_limits()).is_err());
    let old_index_record = visible_record(&index, 0, padded_index_codec::index_limits())?;
    let old_data_record = visible_record(&data, 0, Limits::default())?;
    let mut tampered = old_index_record.clone();
    tampered[4 + 16 + 32] ^= 128;
    assert!(
        decode_page(
            &tampered,
            &index_head,
            0,
            padded_index_codec::index_limits()
        )
        .is_err()
    );
    assert!(
        decode_page(
            &old_index_record,
            &index_head,
            1,
            padded_index_codec::index_limits()
        )
        .is_err()
    );

    // A real amount-only canonical replacement also rebinds index page zero.
    // No full index rebuild or owner fixture selector is used for this mutation.
    let update = Instant::now();
    let verified = decode_page(&old_data_record, &data_head, 0, Limits::default())?;
    let mut new_page = owner.decrypt(&verified)?.as_bytes().to_vec();
    new_page[1..3].copy_from_slice(&101u16.to_le_bytes());
    let old_data_head = data_head.clone();
    data_head = owner.replace_page(&mut data, &old_data_head, 0, &new_page, Limits::default())?;
    assert!(decode_page(&old_data_record, &data_head, 0, Limits::default()).is_err());
    assert!(cached.restore(&data_head, &index_head).is_err());
    let old_index_head = index_head.clone();
    let old_header_page = decode_page(
        &old_index_record,
        &old_index_head,
        0,
        padded_index_codec::index_limits(),
    )?;
    let mut index_page = owner.decrypt(&old_header_page)?.as_bytes().to_vec();
    assert_eq!(
        &index_page[..compact_store::MANIFEST_BYTES],
        &old_data_head.encode()
    );
    index_page[..compact_store::MANIFEST_BYTES].copy_from_slice(&data_head.encode());
    index_head = owner.replace_page(
        &mut index,
        &old_index_head,
        0,
        &index_page,
        padded_index_codec::index_limits(),
    )?;
    assert!(
        decode_page(
            &old_index_record,
            &index_head,
            0,
            padded_index_codec::index_limits()
        )
        .is_err()
    );
    assert!(cached.restore(&data_head, &index_head).is_err());
    let canonical_update_ms = ms(update);
    drop(data_db.take());
    drop(index_db.take());
    let (new_data_db, _, data_records_rebuild_ms, data_ntt_rebuild_ms) =
        prepare(&data, &params, Limits::default());
    data_db = Some(new_data_db);
    let (new_index_db, _, index_records_rebuild_ms, index_ntt_rebuild_ms) =
        prepare(&index, &params, padded_index_codec::index_limits());
    index_db = Some(new_index_db);
    let data_store = Store {
        id: 0,
        snapshot: &data,
        head: &data_head,
        db: data_db.as_ref().unwrap(),
        limits: Limits::default(),
    };
    let index_store = Store {
        id: 1,
        snapshot: &index,
        head: &index_head,
        db: index_db.as_ref().unwrap(),
        limits: padded_index_codec::index_limits(),
    };
    let fill = Instant::now();
    let index_source = source(Access::Private, &index_store, &pir);
    let header = padded_index_codec::check_binding(&owner, &index_source, &data_head)?;
    cached = CachedHeader::capture(&header, &data_head, &index_head);
    drop(header);
    let header_refresh_ms = ms(fill);
    let cache_refresh_stages = index_source.stats.into_inner();
    let update_cache_ready_ms = ms(update);
    let session = Session {
        owner: &owner,
        fhe: &fhe_owner,
        pir: &pir,
        data: &data_store,
        index: &index_store,
        cached: &cached,
        workers: threads,
    };
    let result = read(
        Plan {
            access: Access::Private,
            profile: Profile::AddressOnly,
            header: HeaderMode::Cached,
            age: 250,
            query_id: nonce()?,
        },
        &session,
        &mut key_wire,
        &mut peer_key,
    )?;
    assert_eq!(result.selected, vec![0]);
    assert_eq!(result.actual, (1, 101));
    let (resident, peak) = memory();
    println!(
        "{}",
        json!({
            "experiment":"spiral-index-fhe-update-freshness","canonical_update_ms":canonical_update_ms,
            "data_records_rebuild_ms":data_records_rebuild_ms,"data_ntt_rebuild_ms":data_ntt_rebuild_ms,
            "index_records_rebuild_ms":index_records_rebuild_ms,"index_ntt_rebuild_ms":index_ntt_rebuild_ms,
            "header_refresh_ms":header_refresh_ms,"header_refresh_stages":cache_refresh_stages,
            "update_cache_ready_ms":update_cache_ready_ms,"read_after_update_ms":result.total_ms,
            "read_after_update_stages":result.stages,"total_update_cache_refresh_read_ms":ms(update),
            "canonical_data_bytes":data.encoded_len(),"canonical_index_bytes":index.encoded_len(),
            "stale_data_rejected_before_fhe":true,"stale_index_rejected_before_fhe":true,
            "stale_owner_header_rejected_before_fhe":true,"tamper_rejected_before_fhe":true,
            "wrong_page_rejected_before_fhe":true,"omitted_record_rejected_before_fhe":true,
            "write_addresses_concealed":false,"durable_restart":false,"computation_proof":false,
            "count":result.actual.0,"sum":result.actual.1,"correct":true,
            "resident_bytes":resident,"process_peak_resident_bytes":peak
        })
    );
    Ok(())
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

fn posting_page_preflight(header: &IndexHeader, age: u8) -> IndexResult<()> {
    let (counts, offsets) = header.metadata();
    if counts[age as usize] != 0 {
        let start = INDEX_HEADER_BYTES + offsets[age as usize] as usize;
        let end = INDEX_HEADER_BYTES + offsets[age as usize + 1] as usize;
        if end <= start || start / 4096 != (end - 1) / 4096 {
            return Err(IndexError::PageBudget);
        }
    }
    Ok(())
}
fn data_page_preflight(selected: &[u64]) -> IndexResult<Option<u64>> {
    let page = selected.first().map(|row| row / PAGE_ROWS as u64);
    if selected
        .iter()
        .any(|row| Some(row / PAGE_ROWS as u64) != page)
    {
        return Err(IndexError::PageBudget);
    }
    Ok(page)
}
#[cfg(test)]
mod pipeline_tests {
    use super::*;
    #[test]
    fn a_selection_spanning_two_data_pages_is_rejected_without_truncation() {
        assert_eq!(
            data_page_preflight(&[2047, 2048]),
            Err(IndexError::PageBudget)
        );
    }
    #[test]
    fn absent_selection_has_no_real_data_address() {
        assert_eq!(data_page_preflight(&[]).unwrap(), None);
    }
    #[test]
    fn a_posting_varint_crossing_a_page_is_rejected_before_transport() {
        let mut counts = [0; 256];
        let mut offsets = [0; 257];
        counts[1] = 1;
        offsets[1] = (4095 - INDEX_HEADER_BYTES) as u32;
        offsets[2] = offsets[1] + 2;
        let header = IndexHeader::from_cached(counts, offsets);
        assert_eq!(
            posting_page_preflight(&header, 1),
            Err(IndexError::PageBudget)
        );
    }
    #[test]
    fn cached_header_at_an_old_data_head_is_rejected_before_any_page_read() {
        let owner = Owner::generate([74; 16]).unwrap();
        let mut data = owner
            .seal(
                Layout {
                    schema: SCHEMA,
                    row_width: 3,
                    rows_per_page: PAGE_ROWS as u32,
                    row_count: 1,
                },
                &[250, 100, 0],
                Limits::default(),
            )
            .unwrap();
        let index = padded_index_codec::build(
            &owner,
            &[PlainRow {
                age: 250,
                amount: 100,
            }],
            data.commitment(),
        )
        .unwrap();
        let header = padded_index_codec::check_binding(&owner, &index, data.commitment()).unwrap();
        let cached = CachedHeader::capture(&header, data.commitment(), index.commitment());
        let old = data.commitment().clone();
        let new = owner
            .replace_page(&mut data, &old, 0, &[250, 101, 0], Limits::default())
            .unwrap();
        assert!(matches!(
            cached.restore(&new, index.commitment()),
            Err(IndexError::WrongVersion)
        ));
        assert_eq!(cached.payload_bytes(), 2276);
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    #[test]
    fn replayed_identifier_is_rejected_before_owner_decryption() {
        assert!(metadata_binding((1, [2; 32], [3; 32]), (4, [2; 32], [3; 32])).is_err());
    }
    #[test]
    fn response_at_an_old_data_or_index_root_is_rejected_before_owner_decryption() {
        for actual in [(4, [0; 32], [3; 32]), (4, [2; 32], [0; 32])] {
            assert!(metadata_binding(actual, (4, [2; 32], [3; 32])).is_err());
        }
    }
    #[test]
    fn matching_public_metadata_does_not_establish_a_computation_proof() {
        assert!(metadata_binding((4, [2; 32], [3; 32]), (4, [2; 32], [3; 32])).is_ok());
    }
}
fn metadata_binding(
    actual: (u64, [u8; 32], [u8; 32]),
    expected: (u64, [u8; 32], [u8; 32]),
) -> ProbeResult<()> {
    if actual != expected {
        return Err("FHE answer replay/root mismatch before owner decryption".into());
    }
    Ok(())
}
