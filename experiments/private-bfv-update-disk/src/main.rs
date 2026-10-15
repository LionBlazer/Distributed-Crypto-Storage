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
use std::cell::{Cell, RefCell};
mod disk;
mod expansion_schedule;
mod native;
#[path = "padded_index_codec.rs"]
mod padded_index_codec;
mod resources;
mod selection;
mod server_schedule;
mod update;
mod update_controls;
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
    let selection::Selection {
        selected,
        mut fields,
        ..
    } = selection::select(plan, session, &mut stages)?;
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
     "bfv_native_key_payload_not_individually_partitioned":true,"shared_cached_public_keyset_digest_bytes":64,
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

fn main() -> ProbeResult<()> {
    update::run()
}
