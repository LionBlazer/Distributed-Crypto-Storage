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
    collections::{BTreeMap, BTreeSet, HashMap},
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
const PAGE_BUDGET: usize = 2;
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
include!("fixtures.rs");
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
    pages: RefCell<BTreeSet<u64>>,
    replacement_wire: Option<&'a [u8]>,
    replacement_page: Option<u64>,
}
impl Source<'_> {
    fn fetch(&self, page: u64) -> ProbeResult<Vec<u8>> {
        if self.store.head != self.store.snapshot.commitment() {
            return Err("Peer cache snapshot does not match independently trusted head".into());
        }
        if page >= self.store.head.layout().page_count()? as u64 {
            return Err("Requested page lies outside the authenticated snapshot".into());
        }
        let mut pages = self.pages.borrow_mut();
        if !pages.contains(&page) && pages.len() >= PAGE_BUDGET {
            return Err(IndexError::PageBudget.into());
        }
        pages.insert(page);
        drop(pages);
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
        Ok(if self.replacement_page == Some(page) {
            self.replacement_wire.map_or(wire, <[u8]>::to_vec)
        } else {
            wire
        })
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
    real_posting_pages: usize,
    dummy_posting_fetches: usize,
    real_data_pages: usize,
    dummy_data_fetches: usize,
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
    replacement_wire: Option<(u8, u64, &'a [u8])>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum KernelMode {
    FullPredicate,
    ExactIndex,
}
impl KernelMode {
    #[cfg(test)]
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
        pages: RefCell::new(BTreeSet::new()),
        replacement_wire: None,
        replacement_page: None,
    }
}
fn fault_source<'a>(
    mut source: Source<'a>,
    replacement: Option<(u8, u64, &'a [u8])>,
) -> Source<'a> {
    if let Some((store_id, page, wire)) = replacement
        && store_id == source.store.id
    {
        source.replacement_wire = Some(wire);
        source.replacement_page = Some(page);
    }
    source
}
fn read(plan: Plan, session: &Session<'_>) -> ProbeResult<ReadResult> {
    let total = Instant::now();
    let range = plan.query.selection_range()?;
    let layout = session.data.head.layout();
    if layout.schema != SCHEMA
        || layout.row_width != ROW_BYTES
        || layout.rows_per_page != PAGE_ROWS as u32
        || layout.row_count > MAX_TABLE_ROWS as u64
    {
        return Err("Unsupported canonical data geometry".into());
    }
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
    let real_posting = posting_page_preflight(&header, range)?;
    let (_, offsets) = header.metadata();
    // NEW explicit schedule: header retrieval is separate. Posting pages are actually fetched
    // even if page0 was already decrypted for the uncached header, never silently reused.
    drop(header);
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
        IndexHeader::from_cached(counts, offsets),
    )?;
    if posting_source.stats.borrow().calls != real_posting.len() {
        return Err(
            "Complete posting decode did not fetch every expected page exactly once".into(),
        );
    }
    stages.real_posting_pages = real_posting.len();
    if matches!(plan.profile, Profile::Fixed256) {
        while posting_source.stats.borrow().calls < PAGE_BUDGET {
            drop(posting_source.plain(session.owner, 0)?);
            stages.dummy_posting_fetches += 1;
        }
    }
    stages.index_verify_decrypt_select_ms = ms(start);
    stages.posting = posting_source.stats.into_inner();
    let real_data = data_page_preflight(&selected)?;
    let data_source = fault_source(
        source(plan.access, session.data, session.pir),
        session.replacement_wire,
    );
    let mut data_pages = BTreeMap::new();
    for page in &real_data {
        data_pages.insert(*page, data_source.plain(session.owner, *page)?);
    }
    stages.real_data_pages = real_data.len();
    if matches!(plan.profile, Profile::Fixed256) {
        while data_source.stats.borrow().calls < PAGE_BUDGET {
            drop(data_source.plain(session.owner, 0)?);
            stages.dummy_data_fetches += 1;
        }
    }
    let mut fields = SensitiveFields(Vec::with_capacity(SLOT_BUDGET));
    for ordinal in &selected {
        let address = session.data.head.layout().address_of(*ordinal)?;
        let bytes = data_pages
            .get(&address.page_index)
            .ok_or("Missing selected authenticated page")?
            .as_bytes()
            .get(address.byte_offset..address.byte_offset + ROW_BYTES as usize)
            .ok_or("Selected ordinal outside authenticated data page")?;
        fields.0.push(SelectedField {
            age: bytes[0],
            amount: u16::from_le_bytes([bytes[1], bytes[2]]),
            active: true,
        });
    }
    // The exact operation is permitted only for these complete authenticated postings.
    // Check every actual selected age before padding, counter increment or encryption.
    if matches!(plan.kernel, KernelMode::ExactIndex) {
        let start = Instant::now();
        check_exact_selected_ages(plan.query, &fields.0, selected.len())?;
        stages.exact_selected_age_check_ms = ms(start);
    }
    // Both profiles always encrypt all256 slots; the owner token keeps active count.
    // FullPredicate runs its full circuit; ExactIndex always runs eight encrypted rotations/adds.
    fields.0.resize(
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
            &fields.0,
            plan.query.predicate(),
        )?),
        KernelMode::ExactIndex => PreparedOperation::Exact(
            session
                .bfv
                .prepare_exact_index_aggregate_for_experiment(context, &fields.0)?,
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
     "shared_public_wire_bytes":shared.public_wire,"shared_cached_public_keyset_digest_bytes":64,"shared_owner_secret_image_or_count":shared.owner_counts,
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
mod multipage_run;
fn main() -> ProbeResult<()> {
    multipage_run::run()
}
include!("protocol_helpers.rs");
#[cfg(test)]
mod multipage_tests;

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
