#![recursion_limit = "256"]
//! Real private PaddedV2 index -> authenticated data PIR -> fresh byte-limb BFV COUNT/SUM.
//! Keys stay owner-side; only public parameters and encrypted PIR queries reach server.
use compact_store::{Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse, Owner};
use serde_json::json;
use spiral_rs::{
    aligned_memory::AlignedMemory64,
    client::{Client, PublicParameters, Query},
    params::Params,
};
use std::time::Instant;

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
    let response = native::process(params, public, &server_query, db.as_slice());
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
use sha2::Digest;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};
mod disk;
mod expansion_schedule;
mod native;
#[path = "padded_index_codec.rs"]
mod padded_index_codec;
mod resources;
mod server_schedule;
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
const CASES: [NamedCase; 8] = [
    NamedCase {
        name: "eq0",
        query: QuerySpec::Equal(253),
    },
    NamedCase {
        name: "eq1",
        query: QuerySpec::Equal(250),
    },
    NamedCase {
        name: "eq16",
        query: QuerySpec::Equal(252),
    },
    NamedCase {
        name: "eq256",
        query: QuerySpec::Equal(255),
    },
    NamedCase {
        name: "ge256",
        query: QuerySpec::AtLeast(255),
    },
    NamedCase {
        name: "range256",
        query: QuerySpec::ClosedRange {
            lower: 240,
            upper: 241,
        },
    },
    NamedCase {
        name: "eq64",
        query: QuerySpec::Equal(240),
    },
    NamedCase {
        name: "range21",
        query: QuerySpec::ClosedRange {
            lower: 250,
            upper: 252,
        },
    },
];
fn public_rows(rows: usize, table: usize) -> Vec<PlainRow> {
    let base = (table * 37 % 400) * PAGE_ROWS;
    (0..rows)
        .map(|ordinal| match ordinal.checked_sub(base) {
            Some(0) => PlainRow {
                age: 250,
                amount: 100 + (table % 1000) as u16,
            },
            Some(1..=4) => PlainRow {
                age: 251,
                amount: 200 + (table % 1000) as u16 + (ordinal - base) as u16,
            },
            Some(5..=20) => PlainRow {
                age: 252,
                amount: 300 + (table % 1000) as u16 + (ordinal - base) as u16,
            },
            Some(21..=84) => PlainRow {
                age: 240,
                amount: [0, 1, 255, 256, 257, 65280, 65534, 65535][(ordinal - base - 21) % 8],
            },
            Some(85..=276) => PlainRow {
                age: 241,
                amount: ((ordinal * 137 + table * 641 + 29) % 65536) as u16,
            },
            Some(277..=532) => PlainRow {
                age: 255,
                amount: u16::MAX,
            },
            Some(533..=788) => PlainRow {
                age: 230,
                amount: (ordinal % 65536) as u16,
            },
            Some(2047 | 2048) => PlainRow {
                age: 243,
                amount: 7,
            },
            Some(789..=2526) => PlainRow {
                age: 0,
                amount: ((ordinal * 137 + 29) % 65536) as u16,
            },
            _ => PlainRow {
                age: ((ordinal * 73 + table * 31 + 11) % 200) as u8,
                amount: ((ordinal * 137 + table * 641 + 29) % 65536) as u16,
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
    db: Option<&'a AlignedMemory64>,
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
                    self.store
                        .db
                        .ok_or("No private cache for this loaded table")?,
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
    exact_selected_age_check_ms: f64,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum KernelMode {
    FullPredicate,
    ExactIndex,
}
impl KernelMode {
    fn pair_order(round: usize) -> [Self; 2] {
        if round.is_multiple_of(2) {
            [Self::FullPredicate, Self::ExactIndex]
        } else {
            [Self::ExactIndex, Self::FullPredicate]
        }
    }
}
/// Plain owner membership check; not an index certificate or an arithmetic proof.
fn check_exact_selected_ages(
    query: QuerySpec,
    fields: &[SelectedField],
    selected: usize,
) -> ProbeResult<()> {
    query.selection_range()?;
    if fields.len() != selected
        || fields.len() > SLOT_BUDGET
        || fields
            .iter()
            .any(|field| !field.active || !query.contains(field.age))
    {
        return Err(
            "Exact index selected age mismatch: reject complete selection without filtering".into(),
        );
    }
    Ok(())
}
enum PreparedOperation {
    Full(compact_bfv_byte_limb_core::PreparedQuery),
    Exact(compact_bfv_byte_limb_core::PreparedIndexedAggregate),
}
impl PreparedOperation {
    fn request(&self) -> &[u8] {
        match self {
            Self::Full(p) => &p.request,
            Self::Exact(p) => &p.request,
        }
    }
    fn context(&self) -> &QueryContext {
        match self {
            Self::Full(p) => p.pending.context(),
            Self::Exact(p) => p.pending.context(),
        }
    }
    fn ciphertext_payload_bytes(&self) -> ProbeResult<Vec<u8>> {
        Ok(match self {
            Self::Full(p) => p.ciphertext_payload_bytes()?,
            Self::Exact(p) => p.ciphertext_payload_bytes()?,
        })
    }
    fn finish(self, owner: &BfvOwner, wire: &[u8]) -> ProbeResult<UnverifiedAggregate> {
        Ok(match self {
            Self::Full(p) => owner.decrypt_unverified(p.pending, wire)?,
            Self::Exact(p) => {
                owner.decrypt_exact_index_unverified_for_experiment(p.pending, wire)?
            }
        })
    }
}
#[derive(Clone, Copy)]
struct Plan {
    kernel: KernelMode,
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
    // The exact operation is permitted only for these complete authenticated postings.
    // Check every actual selected age before padding, counter increment or encryption.
    if matches!(plan.kernel, KernelMode::ExactIndex) {
        let start = Instant::now();
        check_exact_selected_ages(plan.query, &fields, selected.len())?;
        stages.exact_selected_age_check_ms = ms(start);
    }
    // Both profiles always encrypt all256 slots; the owner token keeps active count.
    // FullPredicate runs its full circuit; ExactIndex always runs eight encrypted rotations/adds.
    fields.resize(
        SLOT_BUDGET,
        SelectedField {
            age: 0,
            amount: 0,
            active: false,
        },
    );
    stages.data = data_source.stats.into_inner();
    if session.data.head != session.data.snapshot.commitment()
        || session.index.head != session.index.snapshot.commitment()
    {
        return Err("Trusted live heads changed before BFV preparation".into());
    }
    let start = Instant::now();
    session.preparations.set(session.preparations.get() + 1);
    let context = QueryContext::new(
        plan.query_id,
        session.data.head.encode(),
        session.index.head.encode(),
    );
    let prepared = match plan.kernel {
        KernelMode::FullPredicate => PreparedOperation::Full(session.bfv.prepare(
            context,
            &fields,
            plan.query.predicate(),
        )?),
        KernelMode::ExactIndex => PreparedOperation::Exact(
            session
                .bfv
                .prepare_exact_index_aggregate_for_experiment(context, &fields)?,
        ),
    };
    stages.owner_bfv_prepare_serialize_ms = ms(start);
    stages.bfv_request_bytes = prepared.request().len();
    let evidence = Instant::now();
    let ciphertext_payload = prepared.ciphertext_payload_bytes()?;
    stages.freshness_evidence_ms = ms(evidence);
    let evaluated = match plan.kernel {
        KernelMode::FullPredicate => session.evaluator.evaluate(prepared.request())?,
        KernelMode::ExactIndex => session
            .evaluator
            .evaluate_exact_index_aggregate_for_experiment(prepared.request())?,
    };
    if matches!(plan.kernel, KernelMode::ExactIndex) {
        if evaluated.stats.ct_ct_multiplications != 0
            || evaluated.stats.rotations != 8
            || evaluated.stats.multiplicative_depth != 0
        {
            return Err(
                "Exact operation did not run the expected eight encrypted rotations/additions"
                    .into(),
            );
        }
    } else if evaluated.stats.ct_ct_multiplications == 0 {
        return Err("FullPredicate control skipped encrypted predicate work".into());
    }
    stages.bfv_response_bytes = evaluated.output.len();
    stages.peer_bfv = Some(evaluated.stats);
    let start = Instant::now();
    if prepared.context().data_head() != session.data.head.encode()
        || prepared.context().index_head() != session.index.head.encode()
    {
        return Err("Trusted live heads changed before BFV completion".into());
    }
    let actual = prepared.finish(session.bfv, &evaluated.output)?;
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
#[derive(Clone, Copy)]
struct SharedBytes {
    public_wire: usize,
    owner_counts: usize,
    pir_public_ram: usize,
}
fn disk_accounting(
    directory: &std::path::Path,
    catalog: &[disk::CatalogEntry],
    loader: &disk::Loader,
    shared: SharedBytes,
) -> ProbeResult<serde_json::Value> {
    let mut canonical = 0u64;
    let mut other = 0u64;
    let mut files = 0;
    for item in std::fs::read_dir(directory)? {
        let item = item?;
        let meta = item.metadata()?;
        if !meta.is_file() {
            return Err("Unexpected generated catalog directory entry".into());
        }
        if item.file_name().to_string_lossy().starts_with("table-") {
            canonical += meta.len();
        } else {
            other += meta.len();
        }
        files += 1;
    }
    let logical = catalog.len() as u64 * MAX_TABLE_ROWS as u64 * 3;
    let owner_payload = catalog.len() * (32 + 224 + 2276);
    let state = resources::sample();
    Ok(json!({
     "logical_bytes":logical,"logical_rows":catalog.len()*MAX_TABLE_ROWS,
     "actual_canonical_file_bytes":canonical,"actual_other_public_file_bytes":other,
     "actual_all_dataset_file_bytes":canonical+other,"actual_file_count":files,
     "canonical_expansion":canonical as f64/logical as f64,
     "shared_public_wire_bytes":shared.public_wire,"shared_owner_secret_image_or_count":shared.owner_counts,
     "catalog_owner_key_heads_header_payload_bytes":owner_payload,
     "catalog_struct_bytes":std::mem::size_of_val(catalog),
     "known_files_plus_secret_counts_bytes":canonical+other+(shared.owner_counts+catalog.len()*32)as u64,
     "shared_expanded_pir_public_ram_payload_bytes":shared.pir_public_ram,
     "disk_plus_current_process_working_bytes":canonical+other+state.working_set_bytes as u64,
     "disk_plus_current_process_private_bytes":canonical+other+state.private_commit_bytes as u64,
     "disk_plus_native_peak_working_bytes":canonical+other+state.native_peak_working_set_bytes as u64,
     "disk_plus_native_peak_private_bytes":canonical+other+state.native_peak_private_commit_bytes as u64,
     "disk_plus_current_working_expansion":(canonical+other+state.working_set_bytes as u64)as f64/logical as f64,
     "disk_plus_peak_private_expansion":(canonical+other+state.native_peak_private_commit_bytes as u64)as f64/logical as f64,
     "loader":loader.ledger(),"resources":state,"ntt_persisted_bytes":0,
     "bfv_native_key_payload_not_individually_partitioned":true,
     "filesystem_cache_outside_process_not_counted":true,"complete_owner_restart":false,
    }))
}
fn oracle(table: usize, query: QuerySpec) -> (Vec<u64>, u32) {
    let rows = public_rows(MAX_TABLE_ROWS, table);
    let ids: Vec<u64> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| query.contains(r.age))
        .map(|(i, _)| i as u64)
        .collect();
    let sum = ids
        .iter()
        .map(|i| u32::from(rows[*i as usize].amount))
        .sum();
    (ids, sum)
}
/// Owner-maintenance fault: roots/AEAD are valid but postings falsely classify one age.
/// This is not peer tampering and must not be mistaken for an exact-index certificate.
#[allow(clippy::too_many_arguments)]
fn reject_authenticated_age_mismatch(
    directory: &std::path::Path,
    catalog: &mut [disk::CatalogEntry],
    loader: &mut disk::Loader,
    target: usize,
    bfv: &BfvOwner,
    evaluator: &PeerEvaluator,
    pir: &Pir<'_>,
    preparations: &Cell<usize>,
) -> ProbeResult<()> {
    disk::admit(
        "before_authenticated_age_mismatch_fixture",
        target,
        24 * 1024 * 1024,
    )?;
    loader.ensure(&catalog[target], Access::Visible, pir.params)?;
    let original_heads = (
        catalog[target].data_head.clone(),
        catalog[target].index_head.clone(),
    );
    let original_cached = catalog[target].cached.clone();
    let original_data = disk::read_exact_image(
        &catalog[target].data_path,
        catalog[target].data_len,
        8 * 1024 * 1024,
    )?;
    let original_index = disk::read_exact_image(
        &catalog[target].index_path,
        catalog[target].index_len,
        8 * 1024 * 1024,
    )?;
    {
        let loaded = loader.current.as_mut().unwrap();
        let entry = &mut catalog[target];
        let page = (target * 37 % 400) as u64;
        let verified = loaded.data.lookup(page, Limits::default())?.verify(
            &entry.data_head,
            page,
            Limits::default(),
        )?;
        let mut plain = entry.owner.decrypt(&verified)?.as_bytes().to_vec();
        assert_eq!(plain[0], 250);
        plain[0] = 249;
        let data_head = entry.owner.replace_page(
            &mut loaded.data,
            &entry.data_head,
            page,
            &plain,
            Limits::default(),
        )?;
        let verified = loaded
            .index
            .lookup(0, padded_index_codec::index_limits())?
            .verify(&entry.index_head, 0, padded_index_codec::index_limits())?;
        let mut header = entry.owner.decrypt(&verified)?.as_bytes().to_vec();
        header[..compact_store::MANIFEST_BYTES].copy_from_slice(&data_head.encode());
        // Deliberately retain the old age250 posting while rebinding this fresh data head.
        let index_head = entry.owner.replace_page(
            &mut loaded.index,
            &entry.index_head,
            0,
            &header,
            padded_index_codec::index_limits(),
        )?;
        entry.data_head = data_head;
        entry.index_head = index_head;
        entry.cached = disk::capture_owner_header(&entry.owner, &loaded.index, &entry.data_head)?;
        std::fs::write(&entry.data_path, loaded.data.encode())?;
        std::fs::write(&entry.index_path, loaded.index.encode())?;
    }
    disk::persist_catalog(directory, catalog)?;
    loader.invalidate(target);
    for access in [Access::Visible, Access::Private] {
        for header in [HeaderMode::Cached, HeaderMode::Uncached] {
            let before = preparations.get();
            let attempt = loader.execute(
                &catalog[target],
                Plan {
                    kernel: KernelMode::ExactIndex,
                    access,
                    profile: Profile::Fixed256,
                    header,
                    query: QuerySpec::Equal(250),
                    query_id: nonce()?,
                },
                bfv,
                evaluator,
                pir,
                preparations,
            );
            let error = match attempt {
                Ok(_) => return Err("Mismatched indexed age was accepted".into()),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("Exact index selected age mismatch"),
                "{error}"
            );
            assert_eq!(
                preparations.get(),
                before,
                "Age mismatch reached BFV preparation"
            );
            println!(
                "{}",
                json!({"experiment":"exact-age-mismatch-rejection","access":format!("{access:?}"),
                "header":format!("{header:?}"),"table_id":target,"authenticated_but_inconsistent_index":true,
                "before_bfv_prepare":true,"rejected_without_filtering":true,"error":error})
            );
        }
    }
    // The original genuine predicate still handles its complete retrieved candidate itself.
    let control = loader.execute(
        &catalog[target],
        Plan {
            kernel: KernelMode::FullPredicate,
            access: Access::Private,
            profile: Profile::Fixed256,
            header: HeaderMode::Cached,
            query: QuerySpec::Equal(250),
            query_id: nonce()?,
        },
        bfv,
        evaluator,
        pir,
        preparations,
    )?;
    assert_eq!(
        (control.query.actual.count, control.query.actual.sum),
        (0, 0)
    );
    println!(
        "{}",
        json!({"experiment":"full-predicate-mismatch-control","kernel":"FullPredicate",
        "table_id":target,"whole_local_ms":control.whole_ms,"load":control.load,"query_stages":control.query.stages,
        "aggregate":control.query.actual,"actual_encrypted_predicate_executed":true,"computation_proof":false})
    );
    // Restore the exact original generated snapshots/heads before the independent replacement tests.
    loader.invalidate(target);
    catalog[target].data_head = original_heads.0;
    catalog[target].index_head = original_heads.1;
    catalog[target].cached = original_cached;
    std::fs::write(&catalog[target].data_path, &original_data)?;
    std::fs::write(&catalog[target].index_path, &original_index)?;
    disk::persist_catalog(directory, catalog)?;
    Ok(())
}
fn main() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|v| v == "counter-diagnostic") {
        for round in 0..8 {
            let begin = Instant::now();
            let full = resources::sample();
            let full_ms = ms(begin);
            let begin = Instant::now();
            let memory = resources::memory_sample();
            let memory_ms = ms(begin);
            println!(
                "{}",
                json!({"experiment":"disk-counter-cost","round":round,
                "full_sample_ms":full_ms,"memory_only_sample_ms":memory_ms,
                "full":full,"memory_only":memory})
            );
        }
        return Ok(());
    }
    let count: usize = args.get(1).map(|v| v.parse()).transpose()?.unwrap_or(3);
    let samples: usize = args.get(2).map(|v| v.parse()).transpose()?.unwrap_or(1);
    let threads: usize = args.get(3).map(|v| v.parse()).transpose()?.unwrap_or(8);
    let ids: Vec<usize> = args
        .get(4)
        .map(String::as_str)
        .unwrap_or("0,1,2")
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let budget: u64 = args
        .get(5)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(64 * 1024 * 1024);
    let directory =
        std::path::PathBuf::from(args.get(6).ok_or("Supply new ignored dataset directory")?);
    native::configure(args.get(7).map(String::as_str).unwrap_or("combined"))?;
    if !(3..=2000).contains(&count)
        || !(1..=2).contains(&samples)
        || !(1..=8).contains(&threads)
        || ids.len() < 2
        || ids.iter().any(|id| *id >= count)
        || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
    {
        return Err("Invalid bounded disk experiment arguments".into());
    }
    if (count as u64)
        .checked_mul(6 * 1024 * 1024)
        .is_none_or(|v| v > budget)
    {
        return Err("Dataset preflight rejected before any canonical write".into());
    }
    std::fs::create_dir(&directory)?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let monitor = resources::Monitor::start(disk::MEMORY_LIMIT);
    let setup = Instant::now();
    let params = spiral_owner_state::profile_params();
    let key_start = Instant::now();
    let original = spiral_owner_state::OwnerState::generate(&params, [0x44; 32])?;
    let image = original.owner.encode_secret_for_experiment();
    let pir_wire_bytes = original.public_wire.len();
    disk::write_new(
        &directory.join("shared-pir-public.bin"),
        &original.public_wire,
    )?;
    let restored = spiral_owner_state::OwnerState::restore(
        &params,
        [0x44; 32],
        image.as_ref(),
        &original.public_wire,
    )?;
    drop(image);
    drop(original);
    let _pir_owner = restored.owner;
    let pir_client = restored.client;
    let pir_public = restored.public;
    let pir_restore_ms = ms(key_start);
    let pir_public_ram: usize = pir_public
        .v_packing
        .iter()
        .chain(pir_public.v_expansion_left.iter().flatten())
        .chain(pir_public.v_expansion_right.iter().flatten())
        .chain(pir_public.v_conversion.iter().flatten())
        .map(|m| m.data.len() * 8)
        .sum();
    let key_start = Instant::now();
    let (bfv_owner, public_setup) = BfvOwner::generate(Geometry::Rows256)?;
    let bfv_secret_count = bfv_owner.secret_key_serialized_bytes();
    let bfv_keygen_ms = ms(key_start);
    let bfv_counts = public_setup.byte_counts()?;
    let bfv_wire = public_setup.to_bytes()?;
    let bfv_wire_bytes = bfv_wire.len();
    disk::write_new(&directory.join("shared-bfv-public.bin"), &bfv_wire)?;
    drop(public_setup);
    let key_start = Instant::now();
    let public_setup = PublicSetup::from_bytes(&bfv_wire)?;
    drop(bfv_wire);
    let evaluator = PeerEvaluator::from_public_setup(&public_setup)?;
    drop(public_setup);
    runtime_profile_gate(&bfv_owner, &evaluator)?;
    let bfv_restore_ms = ms(key_start);
    let pir = Pir {
        params: &params,
        client: &pir_client,
        public: &pir_public,
    };
    let mut catalog = disk::build_catalog(&directory, count, budget)?;
    let mut loader = disk::Loader::new(1)?;
    let shared = SharedBytes {
        public_wire: pir_wire_bytes + bfv_wire_bytes,
        owner_counts: spiral_owner_state::OWNER_STATE_BYTES + bfv_secret_count,
        pir_public_ram,
    };
    println!(
        "{}",
        json!({
         "experiment":"disk-setup","experiment_package":"private-bfv-exact-disk","shared_owner_for_both_kernels":true,"same_full_keyset_for_both_kernels":true,"fresh_new_generation_only":true,"baseline":"78584b539bcc32540271032ed4dbb52498bac0cb",
         "tables":count,"supplied_table_ids":ids,"max_canonical_bytes":budget,"samples":samples,
         "bfv_profile":bfv_owner.profile(),"bfv_public_bytes":bfv_counts,
         "bfv_secret_serialized_count":bfv_secret_count,"pir_owner_image_bytes":spiral_owner_state::OWNER_STATE_BYTES,
         "pir_public_wire_bytes":pir_wire_bytes,"bfv_keygen_ms":bfv_keygen_ms,
         "bfv_public_restore_ms":bfv_restore_ms,"pir_setup_restore_ms":pir_restore_ms,
         "setup_ms":ms(setup),"initial_loaded_tables":0,"setup_private_cache_preparations":0,
         "accounting":disk_accounting(&directory,&catalog,&loader,shared)?,
         "rayon_threads":threads,"maximum_sampled_threads":monitor.maximum_sampled_threads(),
         "server_schedule":native::name(),"cache_backend":"spiral-cache-core/pinned-parallel-trials","owner_online":true,"network_measured":false,"durable_fsync":false,"computation_proof":false,
        })
    );
    let preparations = Cell::new(0);
    let mut previous = HashMap::<(usize, String, KernelMode), [u8; 32]>::new();
    let mut shapes = HashMap::<String, (usize, usize, usize)>::new();
    let mut pair_round = 0usize;
    for sample in 0..samples {
        for case in CASES {
            for profile in [Profile::AddressOnly, Profile::Fixed256] {
                for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                    let access_order = if sample % 2 == 0 {
                        [Access::Private, Access::Visible]
                    } else {
                        [Access::Visible, Access::Private]
                    };
                    for access in access_order {
                        for kernel in KernelMode::pair_order(pair_round) {
                            for &id in &ids {
                                for repeat in 0..2 {
                                    let before = loader.current.as_ref().map(|t| t.id);
                                    let result = loader.execute(
                                        &catalog[id],
                                        Plan {
                                            kernel,
                                            access,
                                            profile,
                                            header,
                                            query: case.query,
                                            query_id: nonce()?,
                                        },
                                        &bfv_owner,
                                        &evaluator,
                                        &pir,
                                        &preparations,
                                    )?;
                                    if repeat == 0 {
                                        assert_eq!(result.load.event, "TableMiss");
                                    } else {
                                        assert_eq!(result.load.event, "TableHit");
                                    }
                                    assert_eq!(loader.current.as_ref().map(|t| t.id), Some(id));
                                    let (expected, sum) = oracle(id, case.query);
                                    assert_eq!(result.query.selected, expected);
                                    assert_eq!(
                                        (result.query.actual.count, result.query.actual.sum),
                                        (expected.len() as u32, sum)
                                    );
                                    let key = (id, case.name.to_string(), kernel);
                                    let fingerprint: [u8; 32] =
                                        sha2::Sha256::digest(&result.query.ciphertext_payload)
                                            .into();
                                    if let Some(old) = previous.insert(key, fingerprint) {
                                        assert_ne!(
                                            old, fingerprint,
                                            "Fresh ciphertexts excluding context"
                                        );
                                    }
                                    let s = &result.query.stages;
                                    let request = s.header.request_bytes
                                        + s.posting.request_bytes
                                        + s.data.request_bytes
                                        + s.bfv_request_bytes;
                                    let response = s.header.response_bytes
                                        + s.posting.response_bytes
                                        + s.data.response_bytes
                                        + s.bfv_response_bytes;
                                    let rpcs = s.header.calls + s.posting.calls + s.data.calls + 1;
                                    if matches!(profile, Profile::Fixed256) {
                                        let key = format!(
                                            "{kernel:?}/{header:?}/{access:?}/{}",
                                            case.query.kind()
                                        );
                                        if let Some(old) =
                                            shapes.insert(key, (request, response, rpcs))
                                        {
                                            assert_eq!(
                                                old,
                                                (request, response, rpcs),
                                                "Fixed256 shape changed with group cardinality/table"
                                            );
                                        }
                                    }
                                    println!(
                                        "{}",
                                        json!({
                                         "experiment":"disk-read","kernel":format!("{kernel:?}"),"sample":sample,"case":case.name,"query_kind":case.query.kind(),
                                         "table_id":id,"profile":format!("{profile:?}"),"header":format!("{header:?}"),
                                         "access":format!("{access:?}"),"repeat":repeat,"prior_loaded_table":before,
                                         "whole_local_ms":result.whole_ms,"query_only_nested_ms":result.query.total_ms,
                                         "load":result.load,"query_stages":result.query.stages,
                                         "selected_ordinals_from_real_index":result.query.selected,"aggregate":result.query.actual,
                                         "correct":true,"fresh_ciphertexts":true,"request_bytes":request,"response_bytes":response,
                                         "wire_bytes":request+response,"sequential_rpcs":rpcs,"loader":loader.ledger(),
                                         "resources":resources::sample(),"maximum_sampled_threads":monitor.maximum_sampled_threads(),
                                         "application_cache_miss_not_guaranteed_physical_disk_cold":true,"computation_proof":false,
                                        })
                                    );
                                }
                            }
                        }
                        pair_round += 1;
                    }
                }
            }
        }
    }
    reject_authenticated_age_mismatch(
        &directory,
        &mut catalog,
        &mut loader,
        ids[0],
        &bfv_owner,
        &evaluator,
        &pir,
        &preparations,
    )?;
    // A real visible miss, private native upgrade and private hit use the same table.
    let upgrade_id = ids[0];
    loader.invalidate(upgrade_id);
    for (access, expected_event) in [
        (Access::Visible, "TableMiss"),
        (Access::Private, "NativeUpgrade"),
        (Access::Private, "TableHit"),
    ] {
        let result = loader.execute(
            &catalog[upgrade_id],
            Plan {
                kernel: KernelMode::ExactIndex,
                access,
                profile: Profile::Fixed256,
                header: HeaderMode::Cached,
                query: QuerySpec::Equal(252),
                query_id: nonce()?,
            },
            &bfv_owner,
            &evaluator,
            &pir,
            &preparations,
        )?;
        assert_eq!(result.load.event, expected_event);
        let (expected, sum) = oracle(upgrade_id, QuerySpec::Equal(252));
        assert_eq!(result.query.selected, expected);
        assert_eq!(
            (result.query.actual.count, result.query.actual.sum),
            (16, sum)
        );
        println!(
            "{}",
            json!({"experiment":"disk-native-upgrade-control",
            "table_id":upgrade_id,"access":format!("{access:?}"),
            "whole_local_ms":result.whole_ms,"load":result.load,
            "query_only_nested_ms":result.query.total_ms,"query_stages":result.query.stages,
            "aggregate":result.query.actual,"correct":true,"loader":loader.ledger(),
            "resources":resources::sample(),"computation_proof":false})
        );
    }
    // Actual catalog/file failure and replacement lifecycle follows.
    let target = *ids.last().unwrap();
    let other = ids[0];
    loader.invalidate(target);
    let original_data = disk::read_exact_image(
        &catalog[target].data_path,
        catalog[target].data_len,
        8 * 1024 * 1024,
    )?;
    let original_index = disk::read_exact_image(
        &catalog[target].index_path,
        catalog[target].index_len,
        8 * 1024 * 1024,
    )?;
    for (label, is_data, damaged) in [
        (
            "truncated_data",
            true,
            original_data[..original_data.len() - 1].to_vec(),
        ),
        (
            "truncated_index",
            false,
            original_index[..original_index.len() - 1].to_vec(),
        ),
        ("same_length_tamper", true, {
            let mut b = original_data.clone();
            let i = b.len() / 2;
            b[i] ^= 128;
            b
        }),
        (
            "wrong_table_data",
            true,
            disk::read_exact_image(
                &catalog[other].data_path,
                catalog[other].data_len,
                8 * 1024 * 1024,
            )?,
        ),
        (
            "wrong_table_index",
            false,
            disk::read_exact_image(
                &catalog[other].index_path,
                catalog[other].index_len,
                8 * 1024 * 1024,
            )?,
        ),
        ("extra_file_byte", true, {
            let mut b = original_data.clone();
            b.push(0);
            b
        }),
    ] {
        loader.invalidate(target);
        let path = if is_data {
            &catalog[target].data_path
        } else {
            &catalog[target].index_path
        };
        std::fs::write(path, &damaged)?;
        let before = preparations.get();
        let attempt = loader.execute(
            &catalog[target],
            Plan {
                kernel: KernelMode::ExactIndex,
                access: Access::Private,
                profile: Profile::Fixed256,
                header: HeaderMode::Uncached,
                query: QuerySpec::Equal(250),
                query_id: nonce()?,
            },
            &bfv_owner,
            &evaluator,
            &pir,
            &preparations,
        );
        assert!(attempt.is_err(), "{label}");
        assert_eq!(preparations.get(), before);
        assert!(
            loader.current.is_none(),
            "Failed file load must publish no snapshot/cache"
        );
        std::fs::write(
            path,
            if is_data {
                &original_data
            } else {
                &original_index
            },
        )?;
        println!(
            "{}",
            json!({"experiment":"disk-rejection","case":label,
   "before_bfv_prepare":true,"failed_load_not_published":true,"loader":loader.ledger()})
        );
    }
    // The normal update timer includes real table access/write/invalidation and fresh miss.
    let update = Instant::now();
    loader.ensure(&catalog[target], Access::Visible, &params)?;
    let old_heads = (
        catalog[target].data_head.clone(),
        catalog[target].index_head.clone(),
    );
    let old_header = catalog[target].cached.clone();
    let old_sizes = (catalog[target].data_len, catalog[target].index_len);
    {
        let table = loader.current.as_mut().unwrap();
        let first = (target * 37 % 400) * PAGE_ROWS;
        let page = (first / PAGE_ROWS) as u64;
        let response = table.data.lookup(page, Limits::default())?;
        let verified = response.verify(&catalog[target].data_head, page, Limits::default())?;
        let mut bytes = catalog[target]
            .owner
            .decrypt(&verified)?
            .as_bytes()
            .to_vec();
        let old = u16::from_le_bytes([bytes[1], bytes[2]]);
        let next = old
            .checked_add(1)
            .ok_or("Owner fixture amount overflow before mutation")?;
        bytes[1..3].copy_from_slice(&next.to_le_bytes());
        let entry = &mut catalog[target];
        let new_head = entry.owner.replace_page(
            &mut table.data,
            &entry.data_head,
            page,
            &bytes,
            Limits::default(),
        )?;
        let response = table.index.lookup(0, padded_index_codec::index_limits())?;
        let verified = response.verify(&entry.index_head, 0, padded_index_codec::index_limits())?;
        let mut header_bytes = entry.owner.decrypt(&verified)?.as_bytes().to_vec();
        header_bytes[..compact_store::MANIFEST_BYTES].copy_from_slice(&new_head.encode());
        let new_index = entry.owner.replace_page(
            &mut table.index,
            &entry.index_head,
            0,
            &header_bytes,
            padded_index_codec::index_limits(),
        )?;
        let data_image = table.data.encode();
        let index_image = table.index.encode();
        assert_eq!((data_image.len(), index_image.len()), old_sizes);
        std::fs::write(&entry.data_path, &data_image)?;
        std::fs::write(&entry.index_path, &index_image)?;
        entry.data_head = new_head;
        entry.index_head = new_index;
        entry.cached = disk::capture_owner_header(&entry.owner, &table.index, &entry.data_head)?;
    }
    let catalog_length = std::fs::metadata(directory.join("catalog.jsonl"))?.len();
    disk::persist_catalog(&directory, &catalog)?;
    assert_eq!(
        catalog_length,
        std::fs::metadata(directory.join("catalog.jsonl"))?.len(),
        "Fixed head encoding prevents catalog growth per replacement"
    );
    loader.invalidate(target);
    assert!(
        loader.current.is_none(),
        "Actual replacement must invalidate decoded/NTT state"
    );
    let write_invalidate_ms = ms(update);
    let fresh = loader.execute(
        &catalog[target],
        Plan {
            kernel: KernelMode::ExactIndex,
            access: Access::Private,
            profile: Profile::Fixed256,
            header: HeaderMode::Cached,
            query: QuerySpec::Equal(250),
            query_id: nonce()?,
        },
        &bfv_owner,
        &evaluator,
        &pir,
        &preparations,
    )?;
    assert_eq!(fresh.load.event, "TableMiss");
    assert_eq!(
        (fresh.query.actual.count, fresh.query.actual.sum),
        (1, 101 + (target % 1000) as u32)
    );
    println!(
        "{}",
        json!({"experiment":"disk-owner-replacement","table_id":target,
  "write_catalog_invalidate_ms":write_invalidate_ms,"fresh_full_miss_ms":fresh.whole_ms,
  "whole_replace_invalidate_fresh_miss_ms":ms(update),"fresh_load":fresh.load,
  "aggregate":fresh.query.actual,"canonical_no_growth":true,"catalog_no_growth":true,
  "bfv_update":false,"durable_fsync":false,"write_addresses_hidden":false,
  "accounting":disk_accounting(&directory,&catalog,&loader,shared)?})
    );
    loader.invalidate(target);
    let current_data = disk::read_exact_image(
        &catalog[target].data_path,
        catalog[target].data_len,
        8 * 1024 * 1024,
    )?;
    std::fs::write(&catalog[target].data_path, &original_data)?;
    let before = preparations.get();
    assert!(
        loader
            .execute(
                &catalog[target],
                Plan {
                    kernel: KernelMode::ExactIndex,
                    access: Access::Private,
                    profile: Profile::Fixed256,
                    header: HeaderMode::Cached,
                    query: QuerySpec::Equal(250),
                    query_id: nonce()?,
                },
                &bfv_owner,
                &evaluator,
                &pir,
                &preparations
            )
            .is_err()
    );
    assert_eq!(before, preparations.get());
    assert!(loader.current.is_none());
    std::fs::write(&catalog[target].data_path, &current_data)?;
    println!(
        "{}",
        json!({"experiment":"disk-rejection","case":"old_ciphertext_at_new_head","before_bfv_prepare":true})
    );
    // A stale independently supplied trust head must reject current disk images.
    let current_head = std::mem::replace(&mut catalog[target].data_head, old_heads.0);
    let before = preparations.get();
    assert!(
        loader
            .execute(
                &catalog[target],
                Plan {
                    kernel: KernelMode::ExactIndex,
                    access: Access::Private,
                    profile: Profile::Fixed256,
                    header: HeaderMode::Uncached,
                    query: QuerySpec::Equal(250),
                    query_id: nonce()?,
                },
                &bfv_owner,
                &evaluator,
                &pir,
                &preparations
            )
            .is_err()
    );
    assert_eq!(before, preparations.get());
    assert!(loader.current.is_none());
    catalog[target].data_head = current_head;
    println!(
        "{}",
        json!({"experiment":"disk-rejection","case":"stale_trusted_catalog_head","before_bfv_prepare":true})
    );
    assert!(
        old_header
            .restore(&catalog[target].data_head, &catalog[target].index_head)
            .is_err()
    );
    println!(
        "{}",
        json!({"experiment":"disk-rejection","case":"stale_owner_header","before_bfv_prepare":true})
    );
    // Restore a real active pair after negative tests; the final physical ledger counts it.
    let final_read = loader.execute(
        &catalog[target],
        Plan {
            kernel: KernelMode::ExactIndex,
            access: Access::Private,
            profile: Profile::Fixed256,
            header: HeaderMode::Cached,
            query: QuerySpec::Equal(250),
            query_id: nonce()?,
        },
        &bfv_owner,
        &evaluator,
        &pir,
        &preparations,
    )?;
    assert_eq!(
        (final_read.query.actual.count, final_read.query.actual.sum),
        (1, 101 + (target % 1000) as u32)
    );
    println!(
        "{}",
        json!({"experiment":"disk-complete","completed":true,"correct":true,
  "full_bfv_operations":preparations.get(),"kernel_modes":["FullPredicate","ExactIndex"],"matrix_operations":samples*CASES.len()*32*ids.len(),"expected_full_operations":samples*CASES.len()*32*ids.len()+6,"expected_rejections":13,
  "final_restored_full_miss_ms":final_read.whole_ms,
  "accounting":disk_accounting(&directory,&catalog,&loader,shared)?,
  "maximum_sampled_threads":monitor.maximum_sampled_threads(),
  "network_measured":false,"computation_proof":false})
    );
    Ok(())
}
include!("protocol_helpers.rs");

#[cfg(test)]
mod disk_fixture_tests {
    use super::*;
    #[test]
    fn complete_disk_cases_cover_every_named_cardinality_and_one_data_page() {
        let expected_counts = [0usize, 1, 16, 256, 256, 256, 64, 21];
        assert_eq!(
            CASES.len(),
            expected_counts.len(),
            "Every named case needs an explicit cardinality"
        );
        for id in [0, 1, 2, 499, 999] {
            let rows = public_rows(MAX_TABLE_ROWS, id);
            for (case, count) in CASES.iter().zip(expected_counts) {
                let ordinals: Vec<u64> = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| case.query.contains(r.age))
                    .map(|(i, _)| i as u64)
                    .collect();
                assert_eq!(ordinals.len(), count, "table{id} {}", case.name);
                data_page_preflight(&ordinals).unwrap();
                if matches!(case.query, QuerySpec::Equal(255) | QuerySpec::AtLeast(255)) {
                    assert_eq!(
                        ordinals
                            .iter()
                            .map(|i| u32::from(rows[*i as usize].amount))
                            .sum::<u32>(),
                        16_776_960
                    );
                }
            }
        }
    }
    #[test]
    fn complete_ranges_use_authenticated_posting_callbacks_and_enforce_real_page_budget() {
        for table_id in [0, 1, 2, 499, 999] {
            let owner = Owner::generate([78; 16]).unwrap();
            let rows = public_rows(MAX_TABLE_ROWS, table_id);
            let bytes: Vec<u8> = rows
                .iter()
                .flat_map(|r| [r.age, r.amount as u8, (r.amount >> 8) as u8])
                .collect();
            let data = owner
                .seal(
                    Layout {
                        schema: SCHEMA,
                        row_width: 3,
                        rows_per_page: 2048,
                        row_count: MAX_TABLE_ROWS as u64,
                    },
                    &bytes,
                    Limits::default(),
                )
                .unwrap();
            let index = padded_index_codec::build(&owner, &rows, data.commitment()).unwrap();
            for case in CASES {
                let header =
                    padded_index_codec::check_binding(&owner, &index, data.commitment()).unwrap();
                let range = case.query.selection_range().unwrap();
                posting_page_preflight(&header, range).unwrap();
                let selected = padded_index_codec::select_from_header(
                    &owner,
                    &index,
                    data.commitment(),
                    range,
                    256,
                    &mut 0,
                    header,
                )
                .unwrap();
                let expected = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| case.query.contains(r.age))
                    .map(|(i, _)| i as u64)
                    .collect::<Vec<_>>();
                assert_eq!(selected, expected);
                data_page_preflight(&selected).unwrap();
            }
        }
        assert_eq!(
            data_page_preflight(&[2047, 2048]),
            Err(IndexError::PageBudget)
        );
        assert!(
            QuerySpec::ClosedRange {
                lower: 252,
                upper: 250
            }
            .selection_range()
            .is_err()
        );
    }
}

#[cfg(test)]
mod exact_age_gate_tests {
    use super::*;
    fn field(age: u8) -> SelectedField {
        SelectedField {
            age,
            amount: 65535,
            active: true,
        }
    }
    #[test]
    fn every_complete_selected_age_must_match_equal_ge_or_closed_range() {
        assert!(check_exact_selected_ages(QuerySpec::Equal(250), &[field(250)], 1).is_ok());
        assert!(
            check_exact_selected_ages(QuerySpec::AtLeast(250), &[field(250), field(255)], 2)
                .is_ok()
        );
        assert!(
            check_exact_selected_ages(
                QuerySpec::ClosedRange {
                    lower: 250,
                    upper: 252
                },
                &[field(250), field(252)],
                2
            )
            .is_ok()
        );
        assert!(
            check_exact_selected_ages(QuerySpec::Equal(250), &[field(250), field(249)], 2).is_err()
        );
        assert!(check_exact_selected_ages(QuerySpec::AtLeast(250), &[field(249)], 1).is_err());
        assert!(
            check_exact_selected_ages(
                QuerySpec::ClosedRange {
                    lower: 250,
                    upper: 252
                },
                &[field(253)],
                1
            )
            .is_err()
        );
    }
    #[test]
    fn missing_inactive_excess_and_reversed_selections_are_not_silently_filtered() {
        assert!(check_exact_selected_ages(QuerySpec::Equal(250), &[], 0).is_ok());
        assert!(check_exact_selected_ages(QuerySpec::Equal(250), &[field(250)], 2).is_err());
        assert!(
            check_exact_selected_ages(
                QuerySpec::Equal(250),
                &[SelectedField {
                    active: false,
                    ..field(250)
                }],
                1
            )
            .is_err()
        );
        assert!(
            check_exact_selected_ages(QuerySpec::Equal(250), &vec![field(250); 257], 257).is_err()
        );
        assert!(
            check_exact_selected_ages(
                QuerySpec::ClosedRange {
                    lower: 252,
                    upper: 250
                },
                &[],
                0
            )
            .is_err()
        );
    }
    #[test]
    fn paired_modes_reverse_order_without_omitting_the_original_predicate() {
        assert_eq!(
            KernelMode::pair_order(0),
            [KernelMode::FullPredicate, KernelMode::ExactIndex]
        );
        assert_eq!(
            KernelMode::pair_order(1),
            [KernelMode::ExactIndex, KernelMode::FullPredicate]
        );
    }
}
