#![recursion_limit = "256"]
//! Real private PaddedV2 index -> authenticated data PIR -> fresh byte-limb BFV COUNT/SUM.
//! Keys stay owner-side; only public parameters and encrypted PIR queries reach server.
use compact_store::{
    Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse, Owner, VerifiedPage,
};
use serde_json::json;
use spiral_rs::{
    aligned_memory::AlignedMemory64,
    client::{Client, PublicParameters, Query},
    params::Params,
    server::load_db_from_seek,
    util::{CFG_20_256, params_from_json_obj},
};
use std::{io::Cursor, time::Instant};

mod expansion_controls;
mod expansion_schedule;
mod server_schedule;
use expansion_schedule::Schedule;
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
    pir: &Pir<'_>,
    db: &AlignedMemory64,
    page: usize,
    store_id: u8,
    root: [u8; 32],
) -> ProbeResult<(Vec<u8>, usize, usize, f64, f64, f64)> {
    let params = pir.params;
    let client = pir.client;
    let public = pir.public;
    let schedule = pir.schedule.get();
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
    let response =
        expansion_schedule::evaluate(params, public, &server_query, db.as_slice(), schedule);
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
const MAX_ROWS: usize = 256;
const SLOT_BUDGET: usize = 256;
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
#[derive(Clone, Copy, Debug)]
enum QuerySpec {
    Equal(u8),
    AtLeast(u8),
    ClosedRange { lower: u8, upper: u8 },
}
impl QuerySpec {
    fn selection_range(self) -> IndexResult<AgeRange> {
        let range = match self {
            Self::Equal(age) => AgeRange::equal(age),
            Self::AtLeast(lower) => AgeRange { lower, upper: 255 },
            Self::ClosedRange { lower, upper } => AgeRange { lower, upper },
        };
        range.validate()?;
        Ok(range)
    }
    fn predicate(self) -> Predicate {
        match self {
            Self::Equal(age) => Predicate::Equal(age),
            Self::AtLeast(lower) => Predicate::AtLeast(lower),
            Self::ClosedRange { lower, upper } => Predicate::ClosedRange { lower, upper },
        }
    }
    fn kind(self) -> &'static str {
        match self {
            Self::Equal(_) => "EQ",
            Self::AtLeast(_) => "GE",
            Self::ClosedRange { .. } => "Range",
        }
    }
    fn contains(self, age: u8) -> bool {
        match self {
            Self::Equal(value) => age == value,
            Self::AtLeast(lower) => age >= lower,
            Self::ClosedRange { lower, upper } => lower <= age && age <= upper,
        }
    }
}
#[derive(Clone, Copy)]
struct NamedCase {
    name: &'static str,
    query: QuerySpec,
}
const CASES: [NamedCase; 6] = [
    NamedCase {
        name: "range21",
        query: QuerySpec::ClosedRange {
            lower: 250,
            upper: 252,
        },
    },
    NamedCase {
        name: "eq256_max",
        query: QuerySpec::Equal(255),
    },
    NamedCase {
        name: "ge256_max",
        query: QuerySpec::AtLeast(255),
    },
    NamedCase {
        name: "eq64",
        query: QuerySpec::Equal(240),
    },
    NamedCase {
        name: "range256",
        query: QuerySpec::ClosedRange {
            lower: 240,
            upper: 241,
        },
    },
    NamedCase {
        name: "absent",
        query: QuerySpec::Equal(253),
    },
];
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
            21..=84 => PlainRow {
                age: 240,
                amount: [0, 1, 255, 256, 257, 65280, 65534, 65535][(ordinal - 21) % 8],
            },
            85..=276 => PlainRow {
                age: 241,
                amount: ((ordinal * 137 + 29) % 65536) as u16,
            },
            277..=532 => PlainRow {
                age: 255,
                amount: u16::MAX,
            },
            // Deliberate complete <=256 group whose actual encoded postings straddle a page.
            533..=788 => PlainRow {
                age: 230,
                amount: (ordinal % 65536) as u16,
            },
            // Deliberate complete group across data pages0/1, never silently truncated.
            2047 | 2048 => PlainRow {
                age: 243,
                amount: 7,
            },
            789..=2526 => PlainRow {
                age: 0,
                amount: ((ordinal * 137 + 29) % 65536) as u16,
            },
            _ => PlainRow {
                age: ((ordinal * 73 + 11) % 200) as u8,
                amount: ((ordinal * 137 + 29) % 65536) as u16,
            },
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
    Fixed256,
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
    schedule: Cell<Schedule>,
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
                    self.pir,
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
    query: QuerySpec,
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
    let range = plan.query.selection_range()?;
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
    let complete_count = counts[range.lower as usize..=range.upper as usize]
        .iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(*value as usize)
                .ok_or(IndexError::InvalidIndex)
        })?;
    if complete_count > SLOT_BUDGET {
        return Err(IndexError::SelectionBudget {
            selected: complete_count,
            budget: SLOT_BUDGET,
        }
        .into());
    }
    posting_page_preflight(&header, range)?;
    let posting_source = fault_source(
        source(plan.access, session.index, session.pir),
        session.replacement_wire,
    );
    let selected = padded_index_codec::select_from_header(
        session.owner,
        &posting_source,
        session.data.head,
        range,
        SLOT_BUDGET,
        &mut 0,
        header,
    )?;
    if matches!(plan.profile, Profile::Fixed256) && posting_source.stats.borrow().calls == 0 {
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
    } else if matches!(plan.profile, Profile::Fixed256) {
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
    // Both profiles use the tested fixed 256-slot BFV kernel. The active
    // count remains only in the owner token; even absent input runs the same predicate circuit.
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
        plan.query.predicate(),
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
    if owner.geometry() != Geometry::Rows256
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
fn main() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let rows: usize = args
        .get(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(MAX_TABLE_ROWS);
    let rounds: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(2);
    let threads: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(8);
    if rows != MAX_TABLE_ROWS || !(1..=3).contains(&rounds) || !(1..=8).contains(&threads) {
        return Err(
            "Use exactly 1000000 public rows, 1..3 full matrix samples, 1..8 Rayon/initiating workers".into(),
        );
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let monitor = resources::Monitor::start(2_000_000_000);
    let setup = Instant::now();
    let owner = Owner::generate(*b"public-indexbfv!")?;
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
    let expected: HashMap<&str, Vec<u64>> = CASES
        .iter()
        .map(|case| {
            (
                case.name,
                plain
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| case.query.contains(row.age))
                    .map(|(i, _)| i as u64)
                    .collect(),
            )
        })
        .collect();
    let expected_sum: HashMap<&str, u32> = expected
        .iter()
        .map(|(name, ordinals)| {
            (
                *name,
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
    let (bfv_owner, setup_public) = BfvOwner::generate(Geometry::Rows256)?;
    let bfv_keygen_ms = ms(start);
    let start = Instant::now();
    let bfv_secret_bytes = bfv_owner.secret_key_serialized_bytes();
    let bfv_setup_bytes = setup_public.byte_counts()?;
    let public_wire = setup_public.to_bytes()?;
    let bfv_public_wire_bytes = public_wire.len();
    drop(setup_public);
    let wire_serialize_ms = ms(start);
    let start = Instant::now();
    let restored_setup = PublicSetup::from_bytes(&public_wire)?;
    drop(public_wire);
    let evaluator = PeerEvaluator::from_public_setup(&restored_setup)?;
    runtime_profile_gate(&bfv_owner, &evaluator)?;
    drop(restored_setup);
    let bfv_setup_decode_key_restore_ms = ms(start);
    let pir = Pir {
        params: &params,
        client: &pir_client,
        public: &pir_public,
        schedule: Cell::new(Schedule::Official),
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
    let canonical_bytes = data.encoded_len() + index.encoded_len();
    let known_joint_bytes = canonical_bytes
        + public_wire_bytes
        + bfv_public_wire_bytes
        + bfv_secret_bytes
        + 32
        + 2 * compact_store::MANIFEST_BYTES
        + cached.payload_bytes()
        + (params.n + 1) * params.poly_len * 8
        + (params.n * (params.n + 1) + 2) * params.poly_len * 8;
    println!(
        "{}",
        json!({
            "experiment":"private-pir-expansion-setup", "logical_rows":rows, "logical_bytes":logical_bytes,
            "canonical_data_bytes":data.encoded_len(), "canonical_index_bytes":index.encoded_len(),
            "canonical_combined_bytes":canonical_bytes,
            "canonical_combined_expansion":canonical_bytes as f64/logical_bytes as f64,
            "known_joint_serialized_or_secret_payload_bytes":known_joint_bytes,
            "known_joint_expansion":known_joint_bytes as f64/logical_bytes as f64,
            "data_pages":data_head.layout().page_count()?, "index_pages":index_head.layout().page_count()?,
            "data_merkle_bytes":data.index_hash_bytes(), "index_merkle_bytes":index.index_hash_bytes(),
            "record_slots_per_database":params.num_items(), "record_bytes":RECORD_BYTES,
            "data_proof_payload_bytes":data_proof_bytes,"index_proof_payload_bytes":index_proof_bytes,
            "temporary_record_buffer_bytes":params.num_items()*RECORD_BYTES,
            "data_ntt_cache_bytes":data_db.as_ref().unwrap().len()*8,
            "index_ntt_cache_bytes":index_db.as_ref().unwrap().len()*8,"ntt_persisted_bytes":0,
            "persistent_fhe_row_cache_bytes":0,"replicas":1,
            "pir_shared_public_wire_bytes":public_wire_bytes,
            "pir_public_ram_payload_bytes":pir_public_payload_bytes,
            "pir_owner_base_secret_payload_bytes":(params.n+1)*params.poly_len*8,
            "pir_owner_derived_secret_payload_bytes":(params.n*(params.n+1)+2)*params.poly_len*8,
            "bfv_owner_secret_key_serialized_bytes":bfv_secret_bytes,
            "bfv_public_setup":bfv_setup_bytes,"bfv_public_setup_wire_bytes":bfv_public_wire_bytes,
            "bfv_parameter_profile":bfv_owner.profile(),"bfv_geometry":Geometry::Rows256,
            "storage_owner_secret_bytes":32,"trusted_head_bytes":2*compact_store::MANIFEST_BYTES,
            "cached_header_payload_bytes":cached.payload_bytes(),
            "cached_header_counts_offsets_bytes":(256+257)*4,
            "cached_header_duplicated_head_bindings_bytes":2*compact_store::MANIFEST_BYTES,
            "fixture_setup_buffer_capacity_bytes":fixture_buffer_bytes,"fixture_dropped_before_queries":true,
            "data_seal_ms":data_seal_ms,"index_build_seal_ms":index_build_seal_ms,
            "canonical_encode_decode_ms":canonical_roundtrip_ms,"pir_key_setup_ms":pir_key_setup_ms,
            "data_records_ms":data_records_ms,"index_records_ms":index_records_ms,
            "data_ntt_ms":data_ntt_ms,"index_ntt_ms":index_ntt_ms,"bfv_keygen_ms":bfv_keygen_ms,
            "bfv_public_serialize_owner_secret_count_ms":wire_serialize_ms,
            "bfv_public_decode_peer_key_restore_ms":bfv_setup_decode_key_restore_ms,
            "owner_header_private_cache_fill_ms":cache_fill_ms,"cache_fill_stages":cache_fill_stages,
            "setup_ms":ms(setup),"resources":resources::sample(),
            "maximum_sampled_threads":monitor.maximum_sampled_threads(),"rayon_threads":threads,
            "pir_revision":"fdb7206517c249603b0c91b65f1f29f95272107c","codec_revision":"6763556",
            "pir_poly_len":params.poly_len,"pir_crt_moduli":&params.moduli[..params.crt_count],
            "pir_gaussian_width":params.noise_width,"pir_n":params.n,"pir_p":params.pt_modulus,
            "pir_q2_bits":params.q2_bits,"pir_t_gsw":params.t_gsw,"pir_t_conv":params.t_conv,
            "pir_t_exp_left":params.t_exp_left,"pir_t_exp_right":params.t_exp_right,
            "pir_nu1":params.db_dim_1,"pir_nu2":params.db_dim_2,
            "network_measured":false,"disk_io_measured":false,"computation_proof":false
        })
    );
    if !expansion_controls::run(
        &owner,
        &pir,
        &data,
        data_db.as_ref().unwrap(),
        &index,
        index_db.as_ref().unwrap(),
    )? {
        return Ok(());
    }
    let preparations = Cell::new(0);
    let mut previous = HashMap::<&str, Vec<u8>>::new();
    let mut fixed_shape = HashMap::<String, (usize, usize, usize, usize, usize)>::new();
    for round in 0..rounds {
        for case in CASES
            .iter()
            .filter(|case| matches!(case.name, "range21" | "range256"))
        {
            let profile = Profile::Fixed256;
            {
                for header_mode in [HeaderMode::Cached, HeaderMode::Uncached] {
                    let order = if round % 2 == 0 {
                        [Access::Private, Access::Visible]
                    } else {
                        [Access::Visible, Access::Private]
                    };
                    for access in order {
                        for schedule in Schedule::pair_order(round) {
                            pir.schedule.set(schedule);
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
                                bfv: &bfv_owner,
                                evaluator: &evaluator,
                                pir: &pir,
                                data: &data_store,
                                index: &index_store,
                                cached: &cached,
                                preparations: &preparations,
                                replacement_wire: None,
                            };
                            let id = nonce()?;
                            let result = read(
                                Plan {
                                    access,
                                    profile,
                                    header: header_mode,
                                    query: case.query,
                                    query_id: id,
                                },
                                &session,
                            )?;
                            // Public fixture oracle is used only AFTER the complete actual operation timer.
                            assert_eq!(
                                result.selected, expected[case.name],
                                "Complete authenticated posting range"
                            );
                            assert_eq!(result.actual.count, expected[case.name].len() as u32);
                            assert_eq!(result.actual.sum, expected_sum[case.name]);
                            if let Some(old) =
                                previous.insert(case.name, result.ciphertext_payload.clone())
                            {
                                assert_ne!(
                                    old, result.ciphertext_payload,
                                    "Fresh actual ciphertexts, excluding publiccontext"
                                );
                            }
                            let requests = result.stages.header.request_bytes
                                + result.stages.posting.request_bytes
                                + result.stages.data.request_bytes
                                + result.stages.bfv_request_bytes;
                            let responses = result.stages.header.response_bytes
                                + result.stages.posting.response_bytes
                                + result.stages.data.response_bytes
                                + result.stages.bfv_response_bytes;
                            let rpcs = result.stages.header.calls
                                + result.stages.posting.calls
                                + result.stages.data.calls
                                + 1;
                            if matches!(profile, Profile::Fixed256) {
                                let shape = (
                                    requests,
                                    responses,
                                    rpcs,
                                    result.stages.bfv_request_bytes,
                                    result.stages.bfv_response_bytes,
                                );
                                let key =
                                    format!("{header_mode:?}/{access:?}/{}", case.query.kind());
                                if let Some(previous) = fixed_shape.insert(key, shape) {
                                    assert_eq!(
                                        previous, shape,
                                        "Fixed256 shape differs within public predicate kind"
                                    );
                                }
                            }
                            println!(
                                "{}",
                                json!({"experiment":"private-pir-expansion-read","round":round,"case":case.name,"schedule":schedule,
            "public_fixture_query":format!("{:?}",case.query),"predicate_kind":case.query.kind(),
            "profile":format!("{profile:?}"),"header":format!("{header_mode:?}"),"access":format!("{access:?}"),"query_id":id,
            "total_local_ms":result.total_ms,"stages":result.stages,"selected_ordinals_from_decoded_index":result.selected,
            "bfv_slots":SLOT_BUDGET,"aggregate":result.actual,"request_bytes":requests,"response_bytes":responses,"total_wire_bytes":requests+responses,
            "sequential_rpcs":rpcs,"fresh_ciphertexts":true,"correct":true,"resources":resources::sample(),
            "maximum_sampled_threads":monitor.maximum_sampled_threads(),"empty_schedule_visible":matches!(profile,Profile::AddressOnly),
            "active_count_on_bfv_wire":false,"range_endpoints_on_peer_wire":false,"network_measured":false,"computation_proof":false})
                            );
                        }
                    }
                }
            }
        }
    }
    pir.schedule.set(Schedule::Combined);
    let old_index_record = visible_record(&index, 0, padded_index_codec::index_limits())?;
    let old_data_record = visible_record(&data, 0, Limits::default())?;
    let wrong_page = index
        .lookup(1, padded_index_codec::index_limits())?
        .encode();
    let mut tampered = record_wire(&old_index_record)?.to_vec();
    tampered[16 + 32] ^= 128;
    // Replay/omission/tamper is injected at the untrusted response boundary
    // after a real private query/recovery. Authentication must stop before prepare.
    for (name, store_id, wire) in [
        ("omitted_index", 1, &[][..]),
        ("tampered_index", 1, tampered.as_slice()),
        ("wrong_index_page", 1, wrong_page.as_slice()),
        ("omitted_data", 0, &[][..]),
    ] {
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
            bfv: &bfv_owner,
            evaluator: &evaluator,
            pir: &pir,
            data: &data_store,
            index: &index_store,
            cached: &cached,
            preparations: &preparations,
            replacement_wire: Some((store_id, wire)),
        };
        let before = preparations.get();
        assert!(
            read(
                Plan {
                    access: Access::Private,
                    profile: Profile::AddressOnly,
                    header: HeaderMode::Uncached,
                    query: QuerySpec::Equal(250),
                    query_id: nonce()?,
                },
                &session
            )
            .is_err(),
            "{name}"
        );
        assert_eq!(
            preparations.get(),
            before,
            "Failure must precede BFV preparation"
        );
        println!(
            "{}",
            json!({
                "experiment":"private-pir-expansion-rejection","case":name,
                "rejected_before_bfv_prepare":true,"resources":resources::sample()
            })
        );
    }
    // Real complete index groups exercise three honest operation limits and reversal.
    for (name, query, expected_error) in [
        (
            "complete_group_over256",
            QuerySpec::Equal(0),
            "SelectionBudget",
        ),
        (
            "actual_posting_page_crossing",
            QuerySpec::Equal(230),
            "PageBudget",
        ),
        (
            "actual_data_page_crossing",
            QuerySpec::Equal(243),
            "PageBudget",
        ),
        (
            "reversed_range",
            QuerySpec::ClosedRange {
                lower: 252,
                upper: 250,
            },
            "InvalidRange",
        ),
    ] {
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
            bfv: &bfv_owner,
            evaluator: &evaluator,
            pir: &pir,
            data: &data_store,
            index: &index_store,
            cached: &cached,
            preparations: &preparations,
            replacement_wire: None,
        };
        let before = preparations.get();
        let error = read(
            Plan {
                access: Access::Private,
                profile: Profile::AddressOnly,
                header: HeaderMode::Cached,
                query,
                query_id: nonce()?,
            },
            &session,
        )
        .err()
        .ok_or("Unsupported selection unexpectedly accepted")?;
        assert!(
            error.to_string().contains(expected_error),
            "{name}: {error}"
        );
        assert_eq!(
            before,
            preparations.get(),
            "Budget/reversal failure must precede BFVpreparation"
        );
        println!(
            "{}",
            json!({"experiment":"private-pir-expansion-rejection","case":name,"error":error.to_string(),"rejected_before_bfv_prepare":true,"resources":resources::sample()})
        );
    }
    let old_cached = cached.clone();
    let canonical_before = (data.encoded_len(), index.encoded_len());
    let update = Instant::now();
    let verified = decode_page(&old_data_record, &data_head, 0, Limits::default())?;
    let mut new_page = owner.decrypt(&verified)?.as_bytes().to_vec();
    new_page[1..3].copy_from_slice(&101u16.to_le_bytes());
    let old_data_head = data_head.clone();
    data_head = owner.replace_page(&mut data, &old_data_head, 0, &new_page, Limits::default())?;
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
    assert_eq!(canonical_before, (data.encoded_len(), index.encoded_len()));
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
        bfv: &bfv_owner,
        evaluator: &evaluator,
        pir: &pir,
        data: &data_store,
        index: &index_store,
        cached: &cached,
        preparations: &preparations,
        replacement_wire: None,
    };
    let result = read(
        Plan {
            access: Access::Private,
            profile: Profile::Fixed256,
            header: HeaderMode::Cached,
            query: QuerySpec::Equal(250),
            query_id: nonce()?,
        },
        &session,
    )?;
    assert_eq!(result.selected, vec![0]);
    assert_eq!((result.actual.count, result.actual.sum), (1, 101));
    println!(
        "{}",
        json!({
            "experiment":"private-pir-expansion-owner-replacement-freshness",
            "canonical_update_ms":canonical_update_ms,"data_records_rebuild_ms":data_records_rebuild_ms,
            "data_ntt_rebuild_ms":data_ntt_rebuild_ms,"index_records_rebuild_ms":index_records_rebuild_ms,
            "index_ntt_rebuild_ms":index_ntt_rebuild_ms,"header_refresh_ms":header_refresh_ms,
            "header_refresh_stages":cache_refresh_stages,"update_cache_ready_ms":update_cache_ready_ms,
            "read_after_update_ms":result.total_ms,"read_after_update_stages":result.stages,
            "total_update_cache_refresh_read_ms":ms(update),
            "canonical_data_bytes":data.encoded_len(),"canonical_index_bytes":index.encoded_len(),
            "canonical_no_growth":true,"bfv_update":false,"write_addresses_concealed":false,
            "durable_restart":false,"computation_proof":false,"aggregate":result.actual,"correct":true,
            "successful_bfv_preparations":preparations.get(),
            "resources":resources::sample(),"maximum_sampled_threads":monitor.maximum_sampled_threads()
        })
    );
    for (name, old_cache, replacement) in [
        ("stale_owner_header", &old_cached, None),
        (
            "stale_index_response",
            &cached,
            Some((1, record_wire(&old_index_record)?)),
        ),
        (
            "stale_data_response",
            &cached,
            Some((0, record_wire(&old_data_record)?)),
        ),
    ] {
        let session = Session {
            owner: &owner,
            bfv: &bfv_owner,
            evaluator: &evaluator,
            pir: &pir,
            data: &data_store,
            index: &index_store,
            cached: old_cache,
            preparations: &preparations,
            replacement_wire: replacement,
        };
        let before = preparations.get();
        assert!(
            read(
                Plan {
                    access: Access::Private,
                    profile: Profile::Fixed256,
                    header: HeaderMode::Cached,
                    query: QuerySpec::Equal(250),
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
            "Stale input must precede BFV preparation"
        );
        println!(
            "{}",
            json!({
                "experiment":"private-pir-expansion-rejection","case":name,
                "rejected_before_bfv_prepare":true,"resources":resources::sample()
            })
        );
    }
    Ok(())
}
fn record_wire(record: &[u8]) -> ProbeResult<&[u8]> {
    if record.len() != RECORD_BYTES {
        return Err("Invalid record length".into());
    }
    let length = u32::from_le_bytes(record[..4].try_into()?) as usize;
    record
        .get(4..4 + length)
        .ok_or_else(|| "Invalid record framing".into())
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

fn posting_page_preflight(header: &IndexHeader, range: AgeRange) -> IndexResult<()> {
    range.validate()?;
    let (counts, offsets) = header.metadata();
    if counts[range.lower as usize..=range.upper as usize]
        .iter()
        .any(|count| *count != 0)
    {
        let start = INDEX_HEADER_BYTES + offsets[range.lower as usize] as usize;
        let end = INDEX_HEADER_BYTES + offsets[range.upper as usize + 1] as usize;
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
            posting_page_preflight(&header, AgeRange::equal(1)),
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
mod range_contract_tests {
    use super::*;

    #[test]
    fn rare_case_cardinalities_and_maximum_sum_are_public_fixture_contracts() {
        let rows = public_rows(MAX_TABLE_ROWS);
        for (case, expected) in CASES.iter().zip([21, 256, 256, 64, 256, 0]) {
            let selected = rows
                .iter()
                .filter(|row| case.query.contains(row.age))
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), expected, "{}", case.name);
            if matches!(case.query, QuerySpec::Equal(255) | QuerySpec::AtLeast(255)) {
                assert_eq!(
                    selected
                        .iter()
                        .map(|row| u32::from(row.amount))
                        .sum::<u32>(),
                    16_776_960
                );
            }
        }
    }

    #[test]
    fn actual_complete_ranges_fit_while_deliberate_crossings_are_rejected() {
        let owner = Owner::generate([75; 16]).unwrap();
        let rows = public_rows(MAX_TABLE_ROWS);
        let packed: Vec<u8> = rows
            .iter()
            .flat_map(|row| [row.age, row.amount as u8, (row.amount >> 8) as u8])
            .collect();
        let data = owner
            .seal(
                Layout {
                    schema: SCHEMA,
                    row_width: 3,
                    rows_per_page: PAGE_ROWS as u32,
                    row_count: rows.len() as u64,
                },
                &packed,
                Limits::default(),
            )
            .unwrap();
        let index = padded_index_codec::build(&owner, &rows, data.commitment()).unwrap();
        for case in CASES {
            let range = case.query.selection_range().unwrap();
            let header =
                padded_index_codec::check_binding(&owner, &index, data.commitment()).unwrap();
            posting_page_preflight(&header, range).unwrap();
            let selected = padded_index_codec::select_from_header(
                &owner,
                &index,
                data.commitment(),
                range,
                SLOT_BUDGET,
                &mut 0,
                header,
            )
            .unwrap();
            let expected = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| case.query.contains(row.age))
                .map(|(i, _)| i as u64)
                .collect::<Vec<_>>();
            assert_eq!(selected, expected, "{}", case.name);
            data_page_preflight(&selected).unwrap();
        }
        let header = padded_index_codec::check_binding(&owner, &index, data.commitment()).unwrap();
        assert_eq!(
            posting_page_preflight(&header, AgeRange::equal(230)),
            Err(IndexError::PageBudget)
        );
        let selected = padded_index_codec::select_from_header(
            &owner,
            &index,
            data.commitment(),
            AgeRange::equal(243),
            SLOT_BUDGET,
            &mut 0,
            header,
        )
        .unwrap();
        assert_eq!(selected, vec![2047, 2048]);
        assert_eq!(data_page_preflight(&selected), Err(IndexError::PageBudget));
        assert!(matches!(
            padded_index_codec::select(
                &owner,
                &index,
                data.commitment(),
                AgeRange {
                    lower: 230,
                    upper: 241
                },
                SLOT_BUDGET,
                &mut 0
            ),
            Err(IndexError::SelectionBudget { .. })
        ));
    }

    #[test]
    fn reversed_closed_range_is_rejected_before_any_transport_or_encryption() {
        assert!(matches!(
            QuerySpec::ClosedRange {
                lower: 252,
                upper: 250
            }
            .selection_range(),
            Err(IndexError::InvalidRange)
        ));
    }
}
