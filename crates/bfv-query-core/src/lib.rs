//! Experimental exact owner-online BFV roles. Outputs have no computation proof.
//! Parameters and arithmetic match the measured byte-limb probe; retrieval is external.
mod canonical;
mod exact_index;
mod indexed_insert;
mod indexed_select;
mod typed_projection;
pub use indexed_insert::{
    EvaluatedIndexedInsert, IndexedInsertStats, InsertedRow, PendingIndexedInsert,
    PreparedIndexedInsert, UnverifiedInsertedRows,
};
pub use typed_projection::{
    BYTE_SELECT_CAPACITY, PendingByteSelect, PreparedByteSelect, UnverifiedByteSelection,
};
mod indexed_update;
pub use exact_index::{PendingIndexedAggregate, PreparedIndexedAggregate};
pub use indexed_select::{
    EvaluatedIndexedSelect, IndexedSelectStats, PendingIndexedSelect, PreparedIndexedSelect,
    ProjectedRow, RowProjection, UnverifiedSelectedRows,
};
mod kernel;
mod linear_update;
pub use indexed_update::{
    EvaluatedIndexedUpdate, IndexedUpdateStats, PendingIndexedUpdate, PreparedIndexedUpdate,
    UnverifiedUpdateOutcome, UnverifiedUpdatedValues, UpdatedAmount,
};
pub use linear_update::{PublicUpdateEvaluator, PublicUpdateParameters};

use bfv_linear_circuit::{DEGREE, MODULI};
use bincode::Options;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKeyBuilder, Plaintext,
    RelinearizationKey, SecretKey,
};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize as FheSerialize,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use zeroize::Zeroizing;

pub const HEAD_BYTES: usize = 112;
pub const MAX_ROWS: usize = 256;
pub const MAX_WIRE_BYTES: u64 = 64 * 1024 * 1024;
const VERSION: u16 = 1;
const PLAINTEXT: u64 = 114_689;

#[derive(Debug)]
pub enum Error {
    GeometryLimit,
    ReversedRange,
    InvalidShape,
    ParameterProfile,
    WireLimit,
    BindingMismatch,
    AggregateBounds,
    UpdateBounds,
    SelectBounds,
    InsertBounds,
    Backend(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(message) => write!(f, "BFV experiment backend: {message}"),
            other => write!(f, "BFV experiment rejected {other:?}"),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
fn backend(error: impl std::error::Error) -> Error {
    Error::Backend(error.to_string())
}

/// Public fixed geometry; selected cardinality is never serialized in the BFV request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Geometry {
    Rows16,
    Rows256,
}
impl Geometry {
    pub const fn slots(self) -> usize {
        match self {
            Self::Rows16 => 16,
            Self::Rows256 => 256,
        }
    }
}
/// Caller-owned authenticated plaintext. Inactive or missing slots contribute zero weights.
#[derive(Clone, Copy, Debug)]
pub struct SelectedField {
    pub age: u8,
    pub amount: u16,
    pub active: bool,
}
#[derive(Clone, Copy, Debug)]
pub enum Predicate {
    Equal(u8),
    AtLeast(u8),
    ClosedRange { lower: u8, upper: u8 },
}
impl Predicate {
    fn parts(self) -> Result<(PredicateKind, u8, Option<u8>)> {
        match self {
            Self::Equal(value) => Ok((PredicateKind::Equal, value, None)),
            Self::AtLeast(value) => Ok((PredicateKind::AtLeast, value, None)),
            Self::ClosedRange { lower, upper } if lower <= upper => {
                Ok((PredicateKind::Range, lower, Some(upper)))
            }
            Self::ClosedRange { .. } => Err(Error::ReversedRange),
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum PredicateKind {
    Equal,
    AtLeast,
    Range,
}

/// Opaque trusted context supplied by the retrieval composition, not a proof of freshness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryContext {
    query_id: [u8; 16],
    data_head: Vec<u8>,
    index_head: Vec<u8>,
}
impl QueryContext {
    pub fn new(
        query_id: [u8; 16],
        data_head: [u8; HEAD_BYTES],
        index_head: [u8; HEAD_BYTES],
    ) -> Self {
        Self {
            query_id,
            data_head: data_head.to_vec(),
            index_head: index_head.to_vec(),
        }
    }
    pub fn query_id(&self) -> [u8; 16] {
        self.query_id
    }
    pub fn data_head(&self) -> &[u8] {
        &self.data_head
    }
    pub fn index_head(&self) -> &[u8] {
        &self.index_head
    }
    fn valid(&self) -> bool {
        self.data_head.len() == HEAD_BYTES && self.index_head.len() == HEAD_BYTES
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicSetup {
    version: u16,
    geometry: Geometry,
    parameters: Vec<u8>,
    relinearization_key: Vec<u8>,
    rotation_keys: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct PublicSetupBytes {
    pub parameters: usize,
    pub relinearization_key: usize,
    pub rotation_keys: usize,
    pub serialized_wire: usize,
}
#[derive(Debug, Serialize)]
pub struct ParameterProfile {
    pub degree: usize,
    pub plaintext_modulus: u64,
    pub coefficient_moduli: Vec<u64>,
    pub coefficient_moduli_bits: Vec<usize>,
    pub secret_error_distribution: &'static str,
    pub initial_level: usize,
    pub output_level: usize,
    pub optimized_ntt: bool,
    pub fused_ge: bool,
    pub additive_range: bool,
    pub security_gate: &'static str,
}
fn profile(parameters: &BfvParameters) -> ParameterProfile {
    ParameterProfile {
        degree: parameters.degree(),
        plaintext_modulus: parameters.plaintext(),
        coefficient_moduli: parameters.moduli().to_vec(),
        coefficient_moduli_bits: parameters.moduli_sizes().to_vec(),
        secret_error_distribution: "unchanged CBD(20), variance10 for secret and error",
        initial_level: 0,
        output_level: 0,
        optimized_ntt: false,
        fused_ge: false,
        additive_range: true,
        security_gate: "upstream_about128_not_independently_validated",
    }
}
fn official_parameters() -> Result<Arc<BfvParameters>> {
    static PARAMETERS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
    if let Some(parameters) = PARAMETERS.get() {
        return Ok(parameters.clone());
    }
    // The upstream catalog eagerly constructs all degrees, including N16384.
    // Build only the pinned N8192 entry; complete upstream wire equality is tested.
    let parameters = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT)
        .set_moduli(&MODULI)
        .set_variance(10)
        .build_arc()
        .map_err(backend)?;
    if parameters.degree() != DEGREE
        || parameters.plaintext() != PLAINTEXT
        || parameters.moduli() != MODULI
        || parameters.plaintext() % (2 * DEGREE as u64) != 1
        || 16 * Geometry::Rows256.slots() > parameters.degree() / 2
    {
        return Err(Error::ParameterProfile);
    }
    let _ = PARAMETERS.set(parameters);
    Ok(PARAMETERS
        .get()
        .expect("validated public parameters were initialized")
        .clone())
}
impl PublicSetup {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode(self)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let setup: Self = decode(bytes)?;
        setup.checked_parameters()?;
        Ok(setup)
    }
    pub fn byte_counts(&self) -> Result<PublicSetupBytes> {
        Ok(PublicSetupBytes {
            parameters: self.parameters.len(),
            relinearization_key: self.relinearization_key.len(),
            rotation_keys: self.rotation_keys.len(),
            serialized_wire: encode(self)?.len(),
        })
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn profile(&self) -> Result<ParameterProfile> {
        let parameters = self.checked_parameters()?;
        Ok(profile(&parameters))
    }
    fn checked_parameters(&self) -> Result<Arc<BfvParameters>> {
        let parameters = official_parameters()?;
        if self.version != VERSION || parameters.to_bytes() != self.parameters {
            return Err(Error::ParameterProfile);
        }
        Ok(parameters)
    }
}

// Public setup identity shared by the isolated operation domains; not authentication or proof.
fn keyset_id(setup: &PublicSetup) -> Result<[u8; 32]> {
    Ok(Sha256::digest(setup.to_bytes()?).into())
}

/// Holds the only BFV secret; caller still owns plaintext field buffers and trusted heads.
pub struct Owner {
    parameters: Arc<BfvParameters>,
    key: SecretKey,
    geometry: Geometry,
    keyset_id: [u8; 32],
}
/// Public-only evaluation role. It owns no storage snapshot, AEAD key, or SecretKey.
pub struct PeerEvaluator {
    kernel: kernel::Kernel,
    geometry: Geometry,
    keyset_id: [u8; 32],
}
/// One-use owner token; consuming it prevents accidental duplicate completion by this handle.
/// It is not a persistent replay ledger, proof, or verifier capability.
pub struct PendingQuery {
    context: QueryContext,
    geometry: Geometry,
    keyset_id: [u8; 32],
    active_rows: u32,
}
impl PendingQuery {
    pub fn context(&self) -> &QueryContext {
        &self.context
    }
}
pub struct PreparedQuery {
    pub pending: PendingQuery,
    pub request: Vec<u8>,
}
impl PreparedQuery {
    /// Ciphertext-only freshness evidence: excludes IDs, heads, public shape and kind.
    pub fn ciphertext_payload_bytes(&self) -> Result<Vec<u8>> {
        let request: Request = decode(&self.request)?;
        encode(&(request.age, request.lower, request.upper, request.values))
    }
}
#[derive(Debug, Serialize)]
pub struct EvaluationStats {
    pub request_decode_ms: f64,
    pub encrypted_evaluate_ms: f64,
    pub output_encode_ms: f64,
    pub ct_ct_multiplications: usize,
    pub rotations: usize,
    pub multiplicative_depth: usize,
}
pub struct EvaluatedQuery {
    pub output: Vec<u8>,
    pub stats: EvaluationStats,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ProofStatus {
    Unavailable,
}
/// Binding/bounds checked only. A malicious evaluator can still forge in-bounds arithmetic.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UnverifiedAggregate {
    pub count: u32,
    pub sum: u32,
    pub low_limb_sum: u32,
    pub high_limb_sum: u32,
    pub proof: ProofStatus,
}

#[derive(Serialize, Deserialize)]
struct Request {
    version: u16,
    context: QueryContext,
    geometry: Geometry,
    predicate: PredicateKind,
    age: Vec<u8>,
    lower: Vec<u8>,
    upper: Option<Vec<u8>>,
    values: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Response {
    version: u16,
    context: QueryContext,
    geometry: Geometry,
    count_sum: Vec<u8>,
}

impl Owner {
    pub fn generate(geometry: Geometry) -> Result<(Self, PublicSetup)> {
        let parameters = official_parameters()?;
        let key = SecretKey::random(&parameters, &mut rand::rng());
        let (relinearization_key, rotation_keys) = {
            let relin = RelinearizationKey::new(&key, &mut rand::rng()).map_err(backend)?;
            let mut builder = EvaluationKeyBuilder::new(&key).map_err(backend)?;
            for shift in rotation_steps(geometry) {
                builder.enable_column_rotation(shift).map_err(backend)?;
            }
            let rotations = builder.build(&mut rand::rng()).map_err(backend)?;
            drop(builder);
            (relin.to_bytes(), rotations.to_bytes())
        };
        let setup = PublicSetup {
            version: VERSION,
            geometry,
            parameters: parameters.to_bytes(),
            relinearization_key,
            rotation_keys,
        };
        let keyset_id = keyset_id(&setup)?;
        Ok((
            Self {
                parameters,
                key,
                geometry,
                keyset_id,
            },
            setup,
        ))
    }
    pub fn profile(&self) -> ParameterProfile {
        profile(&self.parameters)
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn secret_key_serialized_bytes(&self) -> usize {
        Zeroizing::new(self.key.to_bytes()).len()
    }
    pub fn prepare(
        &self,
        context: QueryContext,
        fields: &[SelectedField],
        predicate: Predicate,
    ) -> Result<PreparedQuery> {
        let (kind, lower, upper) = predicate.parts()?; // Reject reversed range before encryption.
        let slots = self.geometry.slots();
        if fields.len() > slots {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() || 16 * slots > self.parameters.degree() / 2 {
            return Err(Error::InvalidShape);
        }
        let age = planes(fields, None, slots);
        let lower_bits = planes(fields, Some(lower), slots);
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        let mut active_rows = 0;
        for (i, row) in fields.iter().enumerate().filter(|(_, row)| row.active) {
            values[i] = u64::from(row.amount & 255);
            values[DEGREE / 2 + i] = u64::from(row.amount >> 8);
            values[8 * slots + i] = 1;
            active_rows += 1;
        }
        let request = Request {
            version: VERSION,
            context: context.clone(),
            geometry: self.geometry,
            predicate: kind,
            age: self.encrypted(&age)?,
            lower: self.encrypted(&lower_bits)?,
            upper: upper
                .map(|bound| self.encrypted(&planes(fields, Some(bound), slots)))
                .transpose()?,
            values: self.encrypted(&values)?,
        };
        Ok(PreparedQuery {
            pending: PendingQuery {
                context,
                geometry: self.geometry,
                keyset_id: self.keyset_id,
                active_rows,
            },
            request: encode(&request)?,
        })
    }
    fn encrypted(&self, values: &[u64]) -> Result<Vec<u8>> {
        let plaintext =
            Plaintext::try_encode(values, Encoding::simd(), &self.parameters).map_err(backend)?;
        let ciphertext: Ciphertext = self
            .key
            .try_encrypt(&plaintext, &mut rand::rng())
            .map_err(backend)?;
        Ok(ciphertext.to_bytes())
    }
    pub fn decrypt_unverified(
        &self,
        pending: PendingQuery,
        output: &[u8],
    ) -> Result<UnverifiedAggregate> {
        let response: Response = decode(output)?;
        if response.version != VERSION
            || response.geometry != self.geometry
            || pending.geometry != self.geometry
            || pending.keyset_id != self.keyset_id
            || !response.context.valid()
            || response.context != pending.context
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.count_sum, &self.parameters)?;
        let plaintext = self.key.try_decrypt(&ciphertext).map_err(backend)?;
        let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?;
        let low = decoded[0];
        let high = decoded[DEGREE / 2];
        let count = decoded[8 * self.geometry.slots()];
        let sum = high
            .checked_mul(256)
            .and_then(|value| value.checked_add(low))
            .ok_or(Error::AggregateBounds)?;
        if count > u64::from(pending.active_rows)
            || count > self.geometry.slots() as u64
            || low > 255 * count
            || high > 255 * count
            || low > 255 * self.geometry.slots() as u64
            || high > 255 * self.geometry.slots() as u64
            || sum > 65_535 * count
        {
            return Err(Error::AggregateBounds);
        }
        Ok(UnverifiedAggregate {
            count: u32::try_from(count).map_err(|_| Error::AggregateBounds)?,
            sum: u32::try_from(sum).map_err(|_| Error::AggregateBounds)?,
            low_limb_sum: u32::try_from(low).map_err(|_| Error::AggregateBounds)?,
            high_limb_sum: u32::try_from(high).map_err(|_| Error::AggregateBounds)?,
            proof: ProofStatus::Unavailable,
        })
    }
}
impl PeerEvaluator {
    pub fn from_public_setup(setup: &PublicSetup) -> Result<Self> {
        let parameters = setup.checked_parameters()?;
        Ok(Self {
            kernel: kernel::Kernel::from_public(
                parameters,
                &setup.relinearization_key,
                &setup.rotation_keys,
            )?,
            geometry: setup.geometry,
            keyset_id: keyset_id(setup)?,
        })
    }
    pub fn profile(&self) -> ParameterProfile {
        profile(self.kernel.parameters())
    }
    pub fn evaluate(&self, wire: &[u8]) -> Result<EvaluatedQuery> {
        let started = Instant::now();
        let request: Request = decode(wire)?;
        if request.version != VERSION
            || request.geometry != self.geometry
            || !request.context.valid()
            || 16 * self.geometry.slots() > DEGREE / 2
            || matches!(request.predicate, PredicateKind::Range) != request.upper.is_some()
        {
            return Err(Error::InvalidShape);
        }
        let a = checked_ciphertext(&request.age, self.kernel.parameters())?;
        let lower = checked_ciphertext(&request.lower, self.kernel.parameters())?;
        let upper = request
            .upper
            .as_deref()
            .map(|wire| checked_ciphertext(wire, self.kernel.parameters()))
            .transpose()?;
        let values = checked_ciphertext(&request.values, self.kernel.parameters())?;
        let request_decode_ms = elapsed(started);
        let started = Instant::now();
        let (sums, ct_ct_multiplications, rotations) = self.kernel.evaluate(
            request.predicate,
            &a,
            &lower,
            upper.as_ref(),
            &values,
            self.geometry.slots(),
        )?;
        let encrypted_evaluate_ms = elapsed(started);
        let started = Instant::now();
        let output = encode(&Response {
            version: VERSION,
            context: request.context,
            geometry: self.geometry,
            count_sum: sums.to_bytes(),
        })?;
        Ok(EvaluatedQuery {
            output,
            stats: EvaluationStats {
                request_decode_ms,
                encrypted_evaluate_ms,
                output_encode_ms: elapsed(started),
                ct_ct_multiplications,
                rotations,
                multiplicative_depth: 5,
            },
        })
    }
}
fn checked_ciphertext(wire: &[u8], parameters: &Arc<BfvParameters>) -> Result<Ciphertext> {
    let ct = Ciphertext::from_bytes(wire, parameters).map_err(backend)?;
    if ct.len() != 2
        || ct
            .iter()
            .any(|poly| poly.representation() != &fhe_math::rq::Representation::Ntt)
        || parameters.level_of_context(ct[0].ctx()).map_err(backend)? != 0
    {
        return Err(Error::InvalidShape);
    }
    Ok(ct)
}
fn rotation_steps(geometry: Geometry) -> BTreeSet<usize> {
    let slots = geometry.slots();
    let mut shifts = BTreeSet::from([slots, 2 * slots, 4 * slots]);
    let mut shift = 1;
    while shift < slots {
        shifts.insert(shift);
        shift *= 2;
    }
    shifts
}
fn planes(fields: &[SelectedField], threshold: Option<u8>, slots: usize) -> Zeroizing<Vec<u64>> {
    let mut out = Zeroizing::new(vec![0; DEGREE]);
    for index in 0..slots {
        let value = threshold.unwrap_or_else(|| fields.get(index).map_or(0, |row| row.age));
        for bit in 0..8 {
            let bit_value = u64::from((value >> (7 - bit)) & 1);
            for group in [0, 8 * slots, DEGREE / 2, DEGREE / 2 + 8 * slots] {
                out[group + bit * slots + index] = bit_value;
            }
        }
    }
    out
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let wire = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_WIRE_BYTES)
        .serialize(value)
        .map_err(backend)?;
    if wire.len() as u64 > MAX_WIRE_BYTES {
        return Err(Error::WireLimit);
    }
    Ok(wire)
}
fn decode<T: serde::de::DeserializeOwned>(wire: &[u8]) -> Result<T> {
    if wire.len() as u64 > MAX_WIRE_BYTES {
        return Err(Error::WireLimit);
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_WIRE_BYTES)
        .reject_trailing_bytes()
        .deserialize(wire)
        .map_err(backend)
}

#[cfg(test)]
mod proof_boundary_tests {
    use super::*;

    #[test]
    fn in_bounds_forged_arithmetic_remains_explicitly_unverified() {
        let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
        let context = QueryContext::new([1; 16], [2; 112], [3; 112]);
        let fields = [
            SelectedField {
                age: 18,
                amount: 10,
                active: true,
            },
            SelectedField {
                age: 18,
                amount: 20,
                active: true,
            },
        ];
        let prepared = owner
            .prepare(context, &fields, Predicate::AtLeast(18))
            .unwrap();
        // A malicious public-only peer can echo the encrypted values without summing.
        let request: Request = decode(&prepared.request).unwrap();
        let forged = encode(&Response {
            version: VERSION,
            context: request.context,
            geometry: request.geometry,
            count_sum: request.values,
        })
        .unwrap();
        let actual = owner.decrypt_unverified(prepared.pending, &forged).unwrap();
        assert_eq!((actual.count, actual.sum), (1, 10));
        assert_ne!((actual.count, actual.sum), (2, 30));
        assert_eq!(actual.proof, ProofStatus::Unavailable);
    }
}

#[cfg(test)]
mod profile_and_level_tests {
    use super::*;

    #[test]
    fn selected_profile_matches_the_complete_upstream_parameter_wire() {
        let upstream = BfvParameters::default_parameters_128(17)
            .unwrap()
            .find(|parameters| parameters.degree() == DEGREE)
            .unwrap();
        let selected = official_parameters().unwrap();
        assert_eq!(selected.to_bytes(), upstream.to_bytes());
    }

    #[test]
    fn public_setup_rejects_any_serialized_parameter_profile_drift() {
        let (_, mut setup) = Owner::generate(Geometry::Rows16).unwrap();
        setup.parameters[0] ^= 1;
        assert!(matches!(
            PeerEvaluator::from_public_setup(&setup),
            Err(Error::ParameterProfile)
        ));
        assert!(matches!(
            PublicSetup::from_bytes(&setup.to_bytes().unwrap()),
            Err(Error::ParameterProfile)
        ));
    }

    #[test]
    fn lower_level_inputs_and_outputs_are_rejected_before_arithmetic_or_decryption() {
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
        let context = QueryContext::new([1; 16], [2; 112], [3; 112]);
        let prepared = owner
            .prepare(
                context,
                &[SelectedField {
                    age: 18,
                    amount: 1,
                    active: true,
                }],
                Predicate::AtLeast(18),
            )
            .unwrap();
        let mut request: Request = decode(&prepared.request).unwrap();
        let mut values = Ciphertext::from_bytes(&request.values, &owner.parameters).unwrap();
        values.switch_to_level(1).unwrap();
        request.values = values.to_bytes();
        assert!(matches!(
            peer.evaluate(&encode(&request).unwrap()),
            Err(Error::InvalidShape)
        ));
        let output = encode(&Response {
            version: VERSION,
            context: request.context,
            geometry: request.geometry,
            count_sum: request.values,
        })
        .unwrap();
        assert!(matches!(
            owner.decrypt_unverified(prepared.pending, &output),
            Err(Error::InvalidShape)
        ));
    }
}
