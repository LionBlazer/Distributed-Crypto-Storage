#![recursion_limit = "256"]
//! Actual retained independent tables sharing public BFV/PIR setup, with full private queries.
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

use compact_bfv_byte_limb_core::{
    Geometry, Owner as BfvOwner, PeerEvaluator, Predicate, PublicSetup, QueryContext,
    SelectedField, UnverifiedAggregate,
};
use serde::Serialize;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};
#[path = "padded_index_codec.rs"]
mod padded_index_codec;
mod resources;
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
fn public_rows(rows: usize, table: usize) -> Vec<PlainRow> {
    let base = (table * 37 + 29) % 450 * PAGE_ROWS;
    (0..rows)
        .map(|ordinal| {
            let rare = ordinal.checked_sub(base);
            match rare {
                Some(0) => PlainRow {
                    age: 250,
                    amount: 100 + table as u16,
                },
                Some(1..=4) => PlainRow {
                    age: 251,
                    amount: 200 + table as u16 * 11 + (ordinal - base) as u16,
                },
                Some(5..=20) => PlainRow {
                    age: 252,
                    amount: 300 + table as u16 * 17 + (ordinal - base) as u16,
                },
                _ => PlainRow {
                    age: ((ordinal * 73 + table * 31 + 11) % 200) as u8,
                    amount: ((ordinal * 137 + table * 641 + 29) % 65536) as u16,
                },
            }
        })
        .collect()
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
    replacement_wire: Option<&'a [u8]>,
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
        Ok(self.replacement_wire.map_or(wire, <[u8]>::to_vec))
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

#[derive(Default, Serialize)]
struct Stages {
    header: FetchStages,
    posting: FetchStages,
    data: FetchStages,
    index_verify_decrypt_select_ms: f64,
    owner_bfv_prepare_serialize_ms: f64,
    peer_bfv: Option<compact_bfv_byte_limb_core::EvaluationStats>,
    freshness_evidence_ms: f64,
    owner_answer_decode_decrypt_ms: f64,
    bfv_request_bytes: usize,
    bfv_response_bytes: usize,
}
struct Session<'a> {
    owner: &'a Owner,
    bfv: &'a BfvOwner,
    evaluator: &'a PeerEvaluator,
    pir: &'a Pir<'a>,
    data: &'a Store<'a>,
    index: &'a Store<'a>,
    cached: &'a CachedHeader,
    preparations: &'a Cell<usize>,
    replacement_wire: Option<(u8, &'a [u8])>,
}
#[derive(Clone, Copy)]
struct Plan {
    access: Access,
    profile: Profile,
    header: HeaderMode,
    age: u8,
    query_id: [u8; 16],
}
struct ReadResult {
    actual: UnverifiedAggregate,
    stages: Stages,
    total_ms: f64,
    selected: Vec<u64>,
    ciphertext_payload: Vec<u8>,
}
fn source<'a>(access: Access, store: &'a Store<'a>, pir: &'a Pir<'a>) -> Source<'a> {
    Source {
        access,
        store,
        pir,
        stats: RefCell::default(),
        posting_page: Cell::new(None),
        one_page: true,
        replacement_wire: None,
    }
}
fn fault_source<'a>(mut source: Source<'a>, replacement: Option<(u8, &'a [u8])>) -> Source<'a> {
    source.replacement_wire = replacement
        .filter(|(store_id, _)| *store_id == source.store.id)
        .map(|(_, wire)| wire);
    source
}
fn read(plan: Plan, session: &Session<'_>) -> ProbeResult<ReadResult> {
    let total = Instant::now();
    let mut stages = Stages::default();
    let header_source = fault_source(
        source(plan.access, session.index, session.pir),
        session.replacement_wire,
    );
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
    let (counts, _) = header.metadata();
    let complete_count = counts[plan.age as usize] as usize;
    if complete_count > SLOT_BUDGET {
        return Err(IndexError::SelectionBudget {
            selected: complete_count,
            budget: SLOT_BUDGET,
        }
        .into());
    }
    posting_page_preflight(&header, plan.age)?;
    let posting_source = fault_source(
        source(plan.access, session.index, session.pir),
        session.replacement_wire,
    );
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
        drop(posting_source.plain(session.owner, 0)?);
    }
    stages.index_verify_decrypt_select_ms = ms(start);
    stages.posting = posting_source.stats.into_inner();
    let data_source = fault_source(
        source(plan.access, session.data, session.pir),
        session.replacement_wire,
    );
    let page = data_page_preflight(&selected)?;
    let data_page = if let Some(page) = page {
        Some(data_source.plain(session.owner, page)?)
    } else if matches!(plan.profile, Profile::Fixed16) {
        Some(data_source.plain(session.owner, 0)?)
    } else {
        None
    };
    let mut fields = Vec::with_capacity(SLOT_BUDGET);
    for ordinal in &selected {
        let offset = (*ordinal as usize % PAGE_ROWS) * 3;
        let bytes = data_page
            .as_ref()
            .ok_or("Missing selected page")?
            .as_bytes()
            .get(offset..offset + 3)
            .ok_or("Selected ordinal outside authenticated data page")?;
        fields.push(SelectedField {
            age: bytes[0],
            amount: u16::from_le_bytes([bytes[1], bytes[2]]),
            active: true,
        });
    }
    // Both profiles use the tested fixed sixteen-slot BFV kernel. The active
    // count remains only in the owner token; even absent input runs the circuit.
    fields.resize(
        SLOT_BUDGET,
        SelectedField {
            age: 0,
            amount: 0,
            active: false,
        },
    );
    stages.data = data_source.stats.into_inner();
    let start = Instant::now();
    session.preparations.set(session.preparations.get() + 1);
    let prepared = session.bfv.prepare(
        QueryContext::new(
            plan.query_id,
            session.data.head.encode(),
            session.index.head.encode(),
        ),
        &fields,
        Predicate::Equal(plan.age),
    )?;
    stages.owner_bfv_prepare_serialize_ms = ms(start);
    stages.bfv_request_bytes = prepared.request.len();
    let evidence = Instant::now();
    let ciphertext_payload = prepared.ciphertext_payload_bytes()?;
    stages.freshness_evidence_ms = ms(evidence);
    let evaluated = session.evaluator.evaluate(&prepared.request)?;
    stages.bfv_response_bytes = evaluated.output.len();
    stages.peer_bfv = Some(evaluated.stats);
    let start = Instant::now();
    if prepared.pending.context().data_head() != session.data.head.encode()
        || prepared.pending.context().index_head() != session.index.head.encode()
    {
        return Err("Trusted live heads changed before BFV completion".into());
    }
    let actual = session
        .bfv
        .decrypt_unverified(prepared.pending, &evaluated.output)?;
    stages.owner_answer_decode_decrypt_ms = ms(start);
    let total_ms = ms(total);
    // The whole-operation timer includes ciphertext-only freshness evidence.
    Ok(ReadResult {
        actual,
        stages,
        total_ms,
        selected,
        ciphertext_payload,
    })
}
fn nonce() -> ProbeResult<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "OS randomness failed")?;
    Ok(bytes)
}
fn runtime_profile_gate(owner: &BfvOwner, peer: &PeerEvaluator) -> ProbeResult<()> {
    let actual = owner.profile();
    let peer_actual = peer.profile();
    let moduli = [
        8796092858369,
        8796092792833,
        17592186028033,
        17592185438209,
        17592184717313,
    ];
    if owner.geometry() != Geometry::Rows16
        || actual.degree != 8192
        || actual.plaintext_modulus != 114689
        || actual.coefficient_moduli != moduli
        || actual.initial_level != 0
        || actual.output_level != 0
        || actual.optimized_ntt
        || actual.fused_ge
        || !actual.additive_range
        || serde_json::to_value(&actual)? != serde_json::to_value(&peer_actual)?
    {
        return Err("Runtime BFV parameter/profile mismatch".into());
    }
    Ok(())
}
const MEMORY_LIMIT: usize = 2_000_000_000;
const RESERVE: usize = 80 * 1024 * 1024;
const BASELINE: &str = "cd3d23d2ff0ab4738817c14009642e1fecc0a9f3";
struct RetainedTable {
    id: usize,
    owner: Owner,
    data: EncryptedSnapshot,
    index: EncryptedSnapshot,
    data_head: Commitment,
    index_head: Commitment,
    cached: CachedHeader,
    data_db: Option<AlignedMemory64>,
    index_db: Option<AlignedMemory64>,
    expected: HashMap<u8, Vec<u64>>,
    expected_sum: HashMap<u8, u32>,
    data_proof_bytes: usize,
    index_proof_bytes: usize,
}
fn admits(current: usize, peak_resident: usize, peak_private: usize, additional: usize) -> bool {
    current
        .checked_add(additional)
        .and_then(|v| v.checked_add(RESERVE))
        .is_some_and(|v| v < MEMORY_LIMIT)
        && peak_resident < MEMORY_LIMIT
        && peak_private < MEMORY_LIMIT
}
fn admission(stage: &str, table: usize, additional: usize) -> bool {
    let s = resources::sample();
    let current = s.working_set_bytes.max(s.private_commit_bytes);
    let admitted = admits(
        current,
        s.native_peak_working_set_bytes,
        s.native_peak_private_commit_bytes,
        additional,
    );
    println!(
        "{}",
        json!({
            "experiment":"amortization-admission","stage":stage,"table_id":table,
            "expected_additional_bytes":additional,"reserved_headroom_bytes":RESERVE,
            "memory_limit_bytes":MEMORY_LIMIT,"resources":s,"admitted":admitted
        })
    );
    admitted
}
fn table_domain(id: usize) -> [u8; 16] {
    let mut domain = *b"public-amortize!";
    domain[8..16].copy_from_slice(&(id as u64).to_le_bytes());
    domain
}
fn build_table(
    id: usize,
    pir: &Pir<'_>,
    directory: &std::path::Path,
) -> ProbeResult<Option<RetainedTable>> {
    if !admission("before_independent_table", id, 80 * 1024 * 1024) {
        return Ok(None);
    }
    let started = Instant::now();
    let owner = Owner::generate(table_domain(id))?;
    let plain = public_rows(MAX_TABLE_ROWS, id);
    let packed: Vec<u8> = plain
        .iter()
        .flat_map(|r| [r.age, r.amount as u8, (r.amount >> 8) as u8])
        .collect();
    let expected: HashMap<u8, Vec<u64>> = [250, 251, 252, 255]
        .into_iter()
        .map(|age| {
            (
                age,
                plain
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.age == age)
                    .map(|(i, _)| i as u64)
                    .collect(),
            )
        })
        .collect();
    let expected_sum = expected
        .iter()
        .map(|(age, ids)| {
            (
                *age,
                ids.iter()
                    .map(|i| u32::from(plain[*i as usize].amount))
                    .sum(),
            )
        })
        .collect();
    let data = owner.seal(
        Layout {
            schema: SCHEMA,
            row_width: ROW_BYTES,
            rows_per_page: PAGE_ROWS as u32,
            row_count: MAX_TABLE_ROWS as u64,
        },
        &packed,
        Limits::default(),
    )?;
    let index = padded_index_codec::build(&owner, &plain, data.commitment())?;
    drop(packed);
    drop(plain);
    let image_start = Instant::now();
    let data_image = data.encode();
    let index_image = index.encode();
    // Write the actual primary canonical public-synthetic ciphertext images.
    // Owner secret material is never written here or supplied to a peer.
    std::fs::write(directory.join(format!("table-{id}-data.bin")), &data_image)?;
    std::fs::write(
        directory.join(format!("table-{id}-index.bin")),
        &index_image,
    )?;
    drop(data);
    drop(index);
    let data = EncryptedSnapshot::decode(&data_image, Limits::default())?;
    let index = EncryptedSnapshot::decode(&index_image, padded_index_codec::index_limits())?;
    drop(data_image);
    drop(index_image);
    let canonical_write_roundtrip_ms = ms(image_start);
    let data_head = data.commitment().clone();
    let index_head = index.commitment().clone();
    if !admission("before_data_cache", id, 48 * 1024 * 1024) {
        return Ok(None);
    }
    let (data_db, data_proof_bytes, data_records_ms, data_ntt_ms) =
        prepare(&data, pir.params, Limits::default());
    if !admission("before_index_cache", id, 48 * 1024 * 1024) {
        return Ok(None);
    }
    let (index_db, index_proof_bytes, index_records_ms, index_ntt_ms) =
        prepare(&index, pir.params, padded_index_codec::index_limits());
    let store = Store {
        id: 1,
        snapshot: &index,
        head: &index_head,
        db: &index_db,
        limits: padded_index_codec::index_limits(),
    };
    let fill = Instant::now();
    let input = source(Access::Private, &store, pir);
    let header = padded_index_codec::check_binding(&owner, &input, &data_head)?;
    let cached = CachedHeader::capture(&header, &data_head, &index_head);
    drop(header);
    println!(
        "{}",
        json!({
            "experiment":"amortization-table-built","table_id":id,
            "data_head":data_head.encode().to_vec(),"index_head":index_head.encode().to_vec(),
            "data_bytes":data.encoded_len(),"index_bytes":index.encoded_len(),
            "merkle_bytes":data.index_hash_bytes()+index.index_hash_bytes(),
            "data_ntt_bytes":data_db.len()*8,"index_ntt_bytes":index_db.len()*8,
            "represented_data_proof_record_payload_bytes":data_proof_bytes,
            "represented_index_proof_record_payload_bytes":index_proof_bytes,
            "retained_raw_proof_record_buffer_bytes":0,
            "canonical_write_roundtrip_ms":canonical_write_roundtrip_ms,
            "data_records_ms":data_records_ms,"data_ntt_ms":data_ntt_ms,
            "index_records_ms":index_records_ms,"index_ntt_ms":index_ntt_ms,
            "header_fill_ms":ms(fill),"header_fill_stages":input.stats.into_inner(),
            "table_ready_ms":ms(started),"resources":resources::sample()
        })
    );
    Ok(Some(RetainedTable {
        id,
        owner,
        data,
        index,
        data_head,
        index_head,
        cached,
        data_db: Some(data_db),
        index_db: Some(index_db),
        expected,
        expected_sum,
        data_proof_bytes,
        index_proof_bytes,
    }))
}
fn ledger(
    tables: &[RetainedTable],
    shared_wire: usize,
    owner_shared_bytes: usize,
    pir_public_ram: usize,
) -> serde_json::Value {
    let n = tables.len();
    let logical = n * MAX_TABLE_ROWS * ROW_BYTES as usize;
    let canonical: usize = tables
        .iter()
        .map(|t| t.data.encoded_len() + t.index.encoded_len())
        .sum();
    let merkle: usize = tables
        .iter()
        .map(|t| t.data.index_hash_bytes() + t.index.index_hash_bytes())
        .sum();
    let ntt: usize = tables
        .iter()
        .map(|t| {
            t.data_db.as_ref().map_or(0, |db| db.len() * 8)
                + t.index_db.as_ref().map_or(0, |db| db.len() * 8)
        })
        .sum();
    let proof_records: usize = tables
        .iter()
        .map(|t| t.data_proof_bytes + t.index_proof_bytes)
        .sum();
    let owner_per_table: usize = tables
        .iter()
        .map(|t| 32 + 2 * compact_store::MANIFEST_BYTES + t.cached.payload_bytes())
        .sum();
    let known = canonical + shared_wire + owner_shared_bytes + owner_per_table;
    let pir_live_secret_payload = 49_152 + 131_072;
    let known_representations = known + merkle + ntt + pir_public_ram + pir_live_secret_payload;
    json!({
        "retained_independent_tables":n,"logical_rows":n*MAX_TABLE_ROWS,"logical_bytes":logical,
        "canonical_primary_image_bytes":canonical,"canonical_primary_expansion":canonical as f64/logical as f64,
        "shared_public_setup_wire_bytes":shared_wire,"shared_owner_state_count_bytes":owner_shared_bytes,
        "table_owner_key_heads_header_payload_bytes":owner_per_table,
        "known_joint_image_keys_owner_payload_bytes":known,"known_joint_expansion":known as f64/logical as f64,
        "retained_merkle_hash_payload_bytes":merkle,
        "known_joint_including_hash_payload_bytes":known+merkle,
        "known_joint_including_hash_expansion":(known+merkle) as f64/logical as f64,
        "retained_ntt_caches":n*2,"retained_ntt_overlay_bytes":ntt,"ntt_persisted_bytes":0,
        "represented_proof_record_payload_in_ntt_bytes":proof_records,
        "retained_raw_proof_record_overlay_bytes":0,"proof_payload_is_subset_of_ntt":true,
        "canonical_once_plus_known_retained_auxiliary_bytes":known_representations,
    "pir_expanded_public_polynomial_payload_bytes":pir_public_ram,
    "pir_live_secret_polynomial_payload_bytes":pir_live_secret_payload,
    "bfv_native_expanded_keys_and_containers_unpartitioned":true,
    "resident_canonical_snapshot_copy_exists":true,
        "canonical_once_plus_known_retained_auxiliary_expansion":known_representations as f64/logical as f64,
        "all_owner_keys_secret_counts_only_not_written":true,
        "complete_portable_owner_state_established":false,
        "resources":resources::sample()
    })
}
fn primary_files(directory: &std::path::Path) -> ProbeResult<serde_json::Value> {
    let mut canonical = 0u64;
    let mut public = 0u64;
    let mut count = 0;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if !meta.is_file() {
            return Err("Unexpected generated directory entry".into());
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("table-") {
            canonical += meta.len();
        } else if name.starts_with("shared-") {
            public += meta.len();
        } else {
            return Err("Unaccounted generated file".into());
        }
        count += 1;
    }
    let s = resources::sample();
    Ok(json!({
        "actual_primary_file_count":count,"actual_canonical_file_bytes":canonical,
        "actual_shared_public_file_bytes":public,"actual_primary_file_bytes":canonical+public,
        "actual_disk_files_plus_current_process_working_bytes":canonical+public+s.working_set_bytes as u64,
        "actual_disk_files_plus_current_process_private_bytes":canonical+public+s.private_commit_bytes as u64,
        "resources":s,"filesystem_cache_outside_process_not_counted":true,
        "owner_secret_images_written":false,"expanded_ntt_files_written":false
    }))
}
fn main() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let table_count: usize = args.get(1).map(|v| v.parse()).transpose()?.unwrap_or(20);
    let samples: usize = args.get(2).map(|v| v.parse()).transpose()?.unwrap_or(2);
    let threads: usize = args.get(3).map(|v| v.parse()).transpose()?.unwrap_or(8);
    let ids: Vec<usize> = args
        .get(4)
        .map(String::as_str)
        .unwrap_or("0,9,19")
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let directory = std::path::PathBuf::from(
        args.get(5)
            .ok_or("Supply new ignored canonical output directory")?,
    );
    if !(2..=20).contains(&table_count)
        || !(1..=2).contains(&samples)
        || !(1..=8).contains(&threads)
        || ids.is_empty()
        || ids.iter().any(|id| *id >= table_count)
        || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
    {
        return Err(
            "Use2..20tables,1..2samples,1..8threads and distinct existing table IDs".into(),
        );
    }
    std::fs::create_dir(&directory)?; // New only: never overwrite previous canonical evidence.
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let monitor = resources::Monitor::start(MEMORY_LIMIT);
    let setup = Instant::now();
    let mut cfg: serde_json::Value = serde_json::from_str(&CFG_20_256.replace('\'', "\""))?;
    cfg["nu_1"] = json!(7);
    cfg["nu_2"] = json!(2);
    let params = params_from_json_obj(&cfg);
    assert_eq!(params.num_items(), 512);
    let key_start = Instant::now();
    let owner_domain = [0x42u8; 32]; // Public experiment purpose, not an owner secret.
    let original = spiral_owner_state::OwnerState::generate(&params, owner_domain)?;
    let owner_image = original.owner.encode_secret_for_experiment();
    let public_wire = original.public_wire;
    drop(original.client);
    drop(original.owner);
    let pir_public_bytes = public_wire.len();
    std::fs::write(directory.join("shared-pir-public.bin"), &public_wire)?;
    let restored = spiral_owner_state::OwnerState::restore(
        &params,
        owner_domain,
        owner_image.as_ref(),
        &public_wire,
    )?;
    drop(owner_image);
    drop(public_wire);
    let pir_owner_state = restored.owner;
    let pir_client = restored.client;
    let pir_public = restored.public;
    let pir_owner_image_bytes = spiral_owner_state::OWNER_STATE_BYTES;
    let pir_key_setup_restore_ms = ms(key_start);
    let pir_public_ram: usize = pir_public
        .v_packing
        .iter()
        .chain(pir_public.v_expansion_left.iter().flatten())
        .chain(pir_public.v_expansion_right.iter().flatten())
        .chain(pir_public.v_conversion.iter().flatten())
        .map(|p| p.data.len() * 8)
        .sum();
    let key_start = Instant::now();
    let (bfv_owner, bfv_setup) = BfvOwner::generate(Geometry::Rows16)?;
    let bfv_keygen_ms = ms(key_start);
    let bfv_owner_bytes = bfv_owner.secret_key_serialized_bytes();
    let bfv_counts = bfv_setup.byte_counts()?;
    let bfv_wire = bfv_setup.to_bytes()?;
    let bfv_public_bytes = bfv_wire.len();
    std::fs::write(directory.join("shared-bfv-public.bin"), &bfv_wire)?;
    drop(bfv_setup);
    let restore = Instant::now();
    let public_setup = PublicSetup::from_bytes(&bfv_wire)?;
    drop(bfv_wire);
    let evaluator = PeerEvaluator::from_public_setup(&public_setup)?;
    drop(public_setup);
    runtime_profile_gate(&bfv_owner, &evaluator)?;
    let bfv_restore_ms = ms(restore);
    let pir = Pir {
        params: &params,
        client: &pir_client,
        public: &pir_public,
    };
    let mut tables = Vec::with_capacity(table_count);
    for id in 0..table_count {
        let Some(table) = build_table(id, &pir, &directory)? else {
            println!(
                "{}",
                json!({
                    "experiment":"amortization-budget-abort","completed":false,
                    "requested_tables":table_count,"actual_disk_process_accounting":primary_files(&directory)?,"ledger":ledger(&tables,pir_public_bytes+bfv_public_bytes,bfv_owner_bytes+pir_owner_image_bytes,pir_public_ram)
                })
            );
            return Ok(());
        };
        assert!(
            tables.iter().all(
                |t: &RetainedTable| t.data_head.root() != table.data_head.root()
                    && t.index_head.root() != table.index_head.root()
            ),
            "Every table has independent roots"
        );
        tables.push(table);
    }
    let shared_wire = pir_public_bytes + bfv_public_bytes;
    let owner_shared = bfv_owner_bytes + pir_owner_image_bytes;
    let _retained_owner_state = pir_owner_state;
    println!(
        "{}",
        json!({
            "experiment":"amortization-setup","baseline":BASELINE,"completed":true,
            "requested_tables":table_count,"supplied_query_table_ids":ids,"samples_per_case":samples,
            "actual_disk_process_accounting":primary_files(&directory)?,"ledger":ledger(&tables,shared_wire,owner_shared,pir_public_ram),
            "shared_bfv_public_bytes":bfv_counts,"shared_bfv_secret_serialized_count":bfv_owner_bytes,
            "shared_pir_public_wire_bytes":pir_public_bytes,"shared_pir_public_ram_payload":pir_public_ram,
            "pir_owner_recovery_image_bytes":pir_owner_image_bytes,"owner_seed_or_keys_logged":false,
            "pir_live_base_polynomial_payload":(params.n+1)*params.poly_len*8,
            "pir_live_derived_polynomial_payload":(params.n*(params.n+1)+2)*params.poly_len*8,
            "bfv_profile":bfv_owner.profile(),"bfv_keygen_ms":bfv_keygen_ms,
            "bfv_public_restore_ms":bfv_restore_ms,"pir_setup_secret_restore_ms":pir_key_setup_restore_ms,
            "setup_ms":ms(setup),"rayon_threads":threads,"maximum_sampled_threads":monitor.maximum_sampled_threads(),
            "network_measured":false,"query_disk_reads":false,"computation_proof":false
        })
    );
    let preparations = Cell::new(0);
    let mut previous = HashMap::<(usize, u8), Vec<u8>>::new();
    let mut shapes = HashMap::<String, (usize, usize, usize)>::new();
    for sample in 0..samples {
        for &id in &ids {
            let table = &tables[id];
            for age in [250, 251, 252, 255] {
                for profile in [Profile::AddressOnly, Profile::Fixed16] {
                    for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                        let order = if sample % 2 == 0 {
                            [Access::Private, Access::Visible]
                        } else {
                            [Access::Visible, Access::Private]
                        };
                        for access in order {
                            let data = Store {
                                id: 0,
                                snapshot: &table.data,
                                head: &table.data_head,
                                db: table.data_db.as_ref().unwrap(),
                                limits: Limits::default(),
                            };
                            let index = Store {
                                id: 1,
                                snapshot: &table.index,
                                head: &table.index_head,
                                db: table.index_db.as_ref().unwrap(),
                                limits: padded_index_codec::index_limits(),
                            };
                            let session = Session {
                                owner: &table.owner,
                                bfv: &bfv_owner,
                                evaluator: &evaluator,
                                pir: &pir,
                                data: &data,
                                index: &index,
                                cached: &table.cached,
                                preparations: &preparations,
                                replacement_wire: None,
                            };
                            let result = read(
                                Plan {
                                    access,
                                    profile,
                                    header,
                                    age,
                                    query_id: nonce()?,
                                },
                                &session,
                            )?;
                            assert_eq!(result.selected, table.expected[&age]);
                            assert_eq!(
                                (result.actual.count, result.actual.sum),
                                (table.expected[&age].len() as u32, table.expected_sum[&age])
                            );
                            if let Some(old) =
                                previous.insert((id, age), result.ciphertext_payload.clone())
                            {
                                assert_ne!(
                                    old, result.ciphertext_payload,
                                    "Actual ciphertext freshness excluding metadata"
                                );
                            }
                            let request = result.stages.header.request_bytes
                                + result.stages.posting.request_bytes
                                + result.stages.data.request_bytes
                                + result.stages.bfv_request_bytes;
                            let response = result.stages.header.response_bytes
                                + result.stages.posting.response_bytes
                                + result.stages.data.response_bytes
                                + result.stages.bfv_response_bytes;
                            let rpcs = result.stages.header.calls
                                + result.stages.posting.calls
                                + result.stages.data.calls
                                + 1;
                            if matches!(profile, Profile::Fixed16) {
                                let key = format!("{id}/{header:?}/{access:?}");
                                let shape = (request, response, rpcs);
                                if let Some(old) = shapes.insert(key, shape) {
                                    assert_eq!(old, shape);
                                }
                            }
                            println!(
                                "{}",
                                json!({
                                    "experiment":"amortization-read","sample":sample,"table_id":id,
                                    "public_fixture_age":age,"profile":format!("{profile:?}"),
                                    "header":format!("{header:?}"),"access":format!("{access:?}"),
                                    "total_local_ms":result.total_ms,"stages":result.stages,"aggregate":result.actual,
                                    "selected_ordinals_from_real_index":result.selected,"correct":true,"fresh_ciphertexts":true,
                                    "request_bytes":request,"response_bytes":response,"wire_bytes":request+response,
                                    "sequential_rpcs":rpcs,"resources":resources::sample(),
                                    "retained_tables":tables.len(),"maximum_sampled_threads":monitor.maximum_sampled_threads(),
                                    "computation_proof":false
                                })
                            );
                        }
                    }
                }
            }
        }
    }
    // Validate actual cross-table and stale responses before BFV preparation.
    let target_id = *ids.last().unwrap();
    let other_id = if target_id == 0 { 1 } else { 0 };
    let preparations_before_failures = preparations.get();
    {
        let target = &tables[target_id];
        let other = &tables[other_id];
        let wrong_index = other
            .index
            .lookup(0, padded_index_codec::index_limits())?
            .encode();
        let wrong_data = other
            .data
            .lookup(
                (target.expected[&250][0] / PAGE_ROWS as u64) as u64,
                Limits::default(),
            )?
            .encode();
        for (name, store_id, wire) in [
            ("wrong_table_index", 1, wrong_index.as_slice()),
            ("wrong_table_data", 0, wrong_data.as_slice()),
            ("omitted_index", 1, &[][..]),
        ] {
            let data = Store {
                id: 0,
                snapshot: &target.data,
                head: &target.data_head,
                db: target.data_db.as_ref().unwrap(),
                limits: Limits::default(),
            };
            let index = Store {
                id: 1,
                snapshot: &target.index,
                head: &target.index_head,
                db: target.index_db.as_ref().unwrap(),
                limits: padded_index_codec::index_limits(),
            };
            let session = Session {
                owner: &target.owner,
                bfv: &bfv_owner,
                evaluator: &evaluator,
                pir: &pir,
                data: &data,
                index: &index,
                cached: &target.cached,
                preparations: &preparations,
                replacement_wire: Some((store_id, wire)),
            };
            let before = preparations.get();
            assert!(
                read(
                    Plan {
                        access: Access::Private,
                        profile: Profile::Fixed16,
                        header: HeaderMode::Uncached,
                        age: 250,
                        query_id: nonce()?,
                    },
                    &session
                )
                .is_err(),
                "{name}"
            );
            assert_eq!(
                before,
                preparations.get(),
                "Bad cross-table page must stop before prepare"
            );
            println!(
                "{}",
                json!({
                    "experiment":"amortization-rejection","table_id":target_id,"case":name,
                    "before_bfv_prepare":true,"resources":resources::sample()
                })
            );
        }
    }
    assert_eq!(preparations_before_failures, preparations.get());
    // Mutate one actual independent table while every other table/cache pair stays live.
    let unchanged_heads: Vec<_> = tables
        .iter()
        .map(|t| (t.data_head.encode(), t.index_head.encode()))
        .collect();
    let table = &mut tables[target_id];
    let old_data_head = table.data_head.clone();
    let old_index_head = table.index_head.clone();
    let old_cached = table.cached.clone();
    let page = table.expected[&250][0] / PAGE_ROWS as u64;
    let old_data = visible_record(&table.data, page as usize, Limits::default())?;
    let old_index = visible_record(&table.index, 0, padded_index_codec::index_limits())?;
    let verified = decode_page(&old_data, &old_data_head, page as usize, Limits::default())?;
    let offset = (table.expected[&250][0] as usize % PAGE_ROWS) * 3 + 1;
    let mut bytes = table.owner.decrypt(&verified)?.as_bytes().to_vec();
    let previous_amount = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let new_amount = previous_amount
        .checked_add(1)
        .ok_or("Fixture update overflow")?;
    bytes[offset..offset + 2].copy_from_slice(&new_amount.to_le_bytes());
    let sizes = (table.data.encoded_len(), table.index.encoded_len());
    let update = Instant::now();
    table.data_head = table.owner.replace_page(
        &mut table.data,
        &old_data_head,
        page,
        &bytes,
        Limits::default(),
    )?;
    let verified = decode_page(
        &old_index,
        &old_index_head,
        0,
        padded_index_codec::index_limits(),
    )?;
    let mut bytes = table.owner.decrypt(&verified)?.as_bytes().to_vec();
    bytes[..compact_store::MANIFEST_BYTES].copy_from_slice(&table.data_head.encode());
    table.index_head = table.owner.replace_page(
        &mut table.index,
        &old_index_head,
        0,
        &bytes,
        padded_index_codec::index_limits(),
    )?;
    assert_eq!(sizes, (table.data.encoded_len(), table.index.encoded_len()));
    let canonical_replacement_ms = ms(update);
    // Replace the actual primary images; no extra committed journal is modelled.
    std::fs::write(
        directory.join(format!("table-{}-data.bin", table.id)),
        table.data.encode(),
    )?;
    std::fs::write(
        directory.join(format!("table-{}-index.bin", table.id)),
        table.index.encode(),
    )?;
    let canonical_rewrite_ms = ms(update);
    drop(table.data_db.take());
    drop(table.index_db.take());
    if !admission("before_updated_data_cache", target_id, 48 * 1024 * 1024) {
        println!(
            "{}",
            json!({"experiment":"amortization-budget-abort","completed":false,"stage":"update_data"})
        );
        return Ok(());
    }
    let (data_db, _, data_records_ms, data_ntt_ms) =
        prepare(&table.data, &params, Limits::default());
    table.data_db = Some(data_db);
    if !admission("before_updated_index_cache", target_id, 48 * 1024 * 1024) {
        println!(
            "{}",
            json!({"experiment":"amortization-budget-abort","completed":false,"stage":"update_index"})
        );
        return Ok(());
    }
    let (index_db, _, index_records_ms, index_ntt_ms) =
        prepare(&table.index, &params, padded_index_codec::index_limits());
    table.index_db = Some(index_db);
    let data = Store {
        id: 0,
        snapshot: &table.data,
        head: &table.data_head,
        db: table.data_db.as_ref().unwrap(),
        limits: Limits::default(),
    };
    let index = Store {
        id: 1,
        snapshot: &table.index,
        head: &table.index_head,
        db: table.index_db.as_ref().unwrap(),
        limits: padded_index_codec::index_limits(),
    };
    let refresh = Instant::now();
    let input = source(Access::Private, &index, &pir);
    let header = padded_index_codec::check_binding(&table.owner, &input, &table.data_head)?;
    table.cached = CachedHeader::capture(&header, &table.data_head, &table.index_head);
    drop(header);
    let refresh_ms = ms(refresh);
    let ready_ms = ms(update);
    let session = Session {
        owner: &table.owner,
        bfv: &bfv_owner,
        evaluator: &evaluator,
        pir: &pir,
        data: &data,
        index: &index,
        cached: &table.cached,
        preparations: &preparations,
        replacement_wire: None,
    };
    let result = read(
        Plan {
            access: Access::Private,
            profile: Profile::Fixed16,
            header: HeaderMode::Cached,
            age: 250,
            query_id: nonce()?,
        },
        &session,
    )?;
    assert_eq!(result.selected, table.expected[&250]);
    assert_eq!(
        (result.actual.count, result.actual.sum),
        (1, u32::from(new_amount))
    );
    println!(
        "{}",
        json!({
            "experiment":"amortization-owner-replacement","table_id":target_id,
            "canonical_replacement_ms":canonical_replacement_ms,"canonical_rewrite_elapsed_ms":canonical_rewrite_ms,
            "data_records_ms":data_records_ms,"data_ntt_ms":data_ntt_ms,
            "index_records_ms":index_records_ms,"index_ntt_ms":index_ntt_ms,
            "private_header_refresh_ms":refresh_ms,"cache_header_ready_ms":ready_ms,
            "whole_fresh_read_ms":result.total_ms,"whole_replace_rebuild_refresh_read_ms":ms(update),
            "correct":true,"canonical_no_growth":true,"aggregate":result.actual,
            "bfv_update":false,"write_addresses_concealed":false,"all_other_tables_retained":true,
            "resources":resources::sample()
        })
    );
    for (name, cache, replacement) in [
        ("stale_owner_header", &old_cached, None),
        (
            "stale_data_response",
            &table.cached,
            Some((0, record_wire(&old_data)?)),
        ),
        (
            "stale_index_response",
            &table.cached,
            Some((1, record_wire(&old_index)?)),
        ),
    ] {
        let session = Session {
            owner: &table.owner,
            bfv: &bfv_owner,
            evaluator: &evaluator,
            pir: &pir,
            data: &data,
            index: &index,
            cached: cache,
            preparations: &preparations,
            replacement_wire: replacement,
        };
        let before = preparations.get();
        assert!(
            read(
                Plan {
                    access: Access::Private,
                    profile: Profile::Fixed16,
                    header: if name == "stale_index_response" {
                        HeaderMode::Uncached
                    } else {
                        HeaderMode::Cached
                    },
                    age: 250,
                    query_id: nonce()?,
                },
                &session
            )
            .is_err(),
            "{name}"
        );
        assert_eq!(before, preparations.get());
        println!(
            "{}",
            json!({
                "experiment":"amortization-rejection","table_id":target_id,"case":name,
                "before_bfv_prepare":true,"resources":resources::sample()
            })
        );
    }
    for (i, t) in tables.iter().enumerate() {
        if i != target_id {
            assert_eq!(
                (t.data_head.encode(), t.index_head.encode()),
                unchanged_heads[i]
            );
        }
    }
    println!(
        "{}",
        json!({
            "experiment":"amortization-complete","completed":true,"correct":true,
            "successful_full_operations":preparations.get(),
            "requested_tables":table_count,"actual_disk_process_accounting":primary_files(&directory)?,"ledger":ledger(&tables,shared_wire,owner_shared,pir_public_ram),
            "maximum_sampled_threads":monitor.maximum_sampled_threads(),
            "all_cache_pairs_retained":true,"network_measured":false,"computation_proof":false
        })
    );
    Ok(())
}
include!("codec_helpers.rs");

#[cfg(test)]
mod amortization_tests {
    use super::*;
    #[test]
    fn admission_preserves_the_reserve_and_rejects_known_native_peak_or_overflow() {
        assert!(admits(
            1_500_000_000,
            1_700_000_000,
            1_700_000_000,
            80 * 1024 * 1024
        ));
        assert!(!admits(MEMORY_LIMIT - RESERVE, 1, 1, 1));
        assert!(!admits(1, MEMORY_LIMIT, 1, 1));
        assert!(!admits(1, 1, MEMORY_LIMIT, 1));
        assert!(!admits(usize::MAX, 1, 1, 1));
    }
    #[test]
    fn public_table_fixtures_have_complete_varied_groups_on_real_distinct_pages() {
        let mut starts = std::collections::HashSet::new();
        for id in [0, 9, 19] {
            let rows = public_rows(MAX_TABLE_ROWS, id);
            assert_eq!(rows.iter().filter(|r| r.age == 250).count(), 1);
            assert_eq!(rows.iter().filter(|r| r.age == 251).count(), 4);
            assert_eq!(rows.iter().filter(|r| r.age == 252).count(), 16);
            assert_eq!(rows.iter().filter(|r| r.age == 255).count(), 0);
            let ids: Vec<_> = rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.age >= 250)
                .map(|(i, _)| i as u64)
                .collect();
            assert_eq!(
                data_page_preflight(&ids).unwrap(),
                Some(ids[0] / PAGE_ROWS as u64)
            );
            assert!(starts.insert(ids[0]));
            assert_eq!(rows[ids[0] as usize].amount, 100 + id as u16);
        }
        assert_ne!(table_domain(0), table_domain(19));
    }
}
