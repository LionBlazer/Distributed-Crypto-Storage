//! Genuine encrypted row projection. Exact selection and authenticated storage are caller-owned.
use super::*;

const REQUEST_MAGIC: [u8; 8] = *b"BFVSELQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVSELR1";
const SELECT_VERSION: u16 = 1;
const VALIDITY_START: usize = 2 * MAX_ROWS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RowProjection {
    Age,
    Amount,
    AgeAmount,
}
impl RowProjection {
    fn age(self) -> bool {
        self != Self::Amount
    }
    fn amount(self) -> bool {
        self != Self::Age
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Operation {
    IndexedMaskedSelect,
    ExactPublicProjection,
}

#[derive(Serialize, Deserialize)]
struct Request {
    magic: [u8; 8],
    version: u16,
    operation: Operation,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    projection: RowProjection,
    rows: Vec<u8>,
    mask: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Response {
    magic: [u8; 8],
    version: u16,
    operation: Operation,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    projection: RowProjection,
    projected: Vec<u8>,
}

/// One-use owner completion token, never serialized or sent to the peer.
/// ```compile_fail
/// use bfv_query_core::PendingIndexedSelect;
/// fn reuse(token: PendingIndexedSelect) { let moved = token; drop(token); drop(moved); }
/// ```
pub struct PendingIndexedSelect {
    context: QueryContext,
    geometry: Geometry,
    keyset_id: [u8; 32],
    projection: RowProjection,
    active: [bool; MAX_ROWS],
    operation: Operation,
}
impl PendingIndexedSelect {
    pub fn context(&self) -> &QueryContext {
        &self.context
    }
}
pub struct PreparedIndexedSelect {
    pub pending: PendingIndexedSelect,
    pub request: Vec<u8>,
}
impl PreparedIndexedSelect {
    /// Fresh ciphertexts only, excluding public metadata and context.
    pub fn ciphertext_payload_bytes(&self) -> Result<Vec<u8>> {
        let request: Request = decode(&self.request)?;
        encode(&(request.rows, request.mask))
    }
}
/// Owner-only final BFV-decoded row; absent columns were zeroed homomorphically.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ProjectedRow {
    pub slot: usize,
    pub age: Option<u8>,
    pub amount: Option<u16>,
}
/// Bounds/context checks do not prove correct computation by a malicious evaluator.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UnverifiedSelectedRows {
    pub rows: Vec<ProjectedRow>,
    pub proof: ProofStatus,
}
#[derive(Debug, Serialize)]
pub struct IndexedSelectStats {
    pub request_decode_ms: f64,
    pub encrypted_evaluate_ms: f64,
    pub output_encode_ms: f64,
    pub ct_ct_multiplications: usize,
    pub relinearizations: usize,
    pub rotations: usize,
    pub multiplicative_depth: usize,
}
pub struct EvaluatedIndexedSelect {
    pub output: Vec<u8>,
    pub stats: IndexedSelectStats,
}

impl Owner {
    /// Encrypt ORIGINAL field values, including supplied inactive values, plus a fresh
    /// encrypted active/projection mask. No projected answer is computed here.
    /// Caller must establish complete authenticated index selection before preparation.
    pub fn prepare_indexed_select_for_experiment(
        &self,
        context: QueryContext,
        fields: &[SelectedField],
        projection: RowProjection,
    ) -> Result<PreparedIndexedSelect> {
        if fields.len() > self.geometry.slots() {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        let mut rows = Zeroizing::new(vec![0u64; DEGREE]);
        let mut mask = Zeroizing::new(vec![0u64; DEGREE]);
        let mut active = [false; MAX_ROWS];
        for (slot, field) in fields.iter().enumerate() {
            rows[slot] = u64::from(field.age);
            rows[DEGREE / 2 + slot] = u64::from(field.amount);
            rows[VALIDITY_START + slot] = 1;
            active[slot] = field.active;
            if field.active {
                mask[slot] = u64::from(projection.age());
                mask[DEGREE / 2 + slot] = u64::from(projection.amount());
                mask[VALIDITY_START + slot] = 1;
            }
        }
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: SELECT_VERSION,
            operation: Operation::IndexedMaskedSelect,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            projection,
            rows: self.encrypted(&rows)?,
            mask: self.encrypted(&mask)?,
        })?;
        Ok(PreparedIndexedSelect {
            request,
            pending: PendingIndexedSelect {
                context,
                geometry: self.geometry,
                keyset_id: self.keyset_id,
                projection,
                active,
                operation: Operation::IndexedMaskedSelect,
            },
        })
    }

    /// Final BFV decryption only AFTER peer masked multiplication. No original row
    /// values are retained in this token or substituted for the decrypted answer.
    pub fn decrypt_indexed_select_unverified_for_experiment(
        &self,
        pending: PendingIndexedSelect,
        output: &[u8],
    ) -> Result<UnverifiedSelectedRows> {
        let response: Response = decode(output)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != SELECT_VERSION
            || response.operation != pending.operation
            || response.keyset_id != self.keyset_id
            || pending.keyset_id != self.keyset_id
            || response.geometry != self.geometry
            || pending.geometry != self.geometry
            || response.projection != pending.projection
            || !pending.context.valid()
            || response.context != pending.context
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.projected, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let decoded =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?);
        if decoded.len() != DEGREE {
            return Err(Error::InvalidShape);
        }
        // Validate all rows/columns/reserved slots before constructing any returned row.
        for (index, value) in decoded.iter().copied().enumerate() {
            let maximum = if index < MAX_ROWS && pending.active[index] && pending.projection.age() {
                255
            } else if (DEGREE / 2..DEGREE / 2 + MAX_ROWS).contains(&index)
                && pending.active[index - DEGREE / 2]
                && pending.projection.amount()
            {
                65535
            } else if (VALIDITY_START..VALIDITY_START + MAX_ROWS).contains(&index) {
                let expected = u64::from(pending.active[index - VALIDITY_START]);
                if value != expected {
                    return Err(Error::SelectBounds);
                }
                expected
            } else {
                0
            };
            if value > maximum {
                return Err(Error::SelectBounds);
            }
        }
        let rows = (0..MAX_ROWS)
            .filter(|slot| pending.active[*slot])
            .map(|slot| ProjectedRow {
                slot,
                age: pending.projection.age().then_some(decoded[slot] as u8),
                amount: pending
                    .projection
                    .amount()
                    .then_some(decoded[DEGREE / 2 + slot] as u16),
            })
            .collect();
        Ok(UnverifiedSelectedRows {
            rows,
            proof: ProofStatus::Unavailable,
        })
    }
}

impl PeerEvaluator {
    /// Real ciphertext-by-ciphertext masking and relinearization, returning encrypted rows.
    /// Uses only public keys; it never decrypts or receives plaintext fields/masks.
    pub fn evaluate_indexed_select_for_experiment(
        &self,
        wire: &[u8],
    ) -> Result<EvaluatedIndexedSelect> {
        let started = Instant::now();
        let request: Request = decode(wire)?;
        if request.magic != REQUEST_MAGIC
            || request.version != SELECT_VERSION
            || request.operation != Operation::IndexedMaskedSelect
            || request.keyset_id != self.keyset_id
            || request.geometry != self.geometry
            || !request.context.valid()
        {
            return Err(Error::BindingMismatch);
        }
        // Both ciphertexts bind to the SAME Arc<Params>, two components, initial level0.
        let rows = checked_ciphertext(&request.rows, self.kernel.parameters())?;
        let mask = checked_ciphertext(&request.mask, self.kernel.parameters())?;
        let request_decode_ms = elapsed(started);
        let started = Instant::now();
        let (projected, multiplications) = self.kernel.project_selected(&rows, &mask)?;
        let encrypted_evaluate_ms = elapsed(started);
        let started = Instant::now();
        let output = encode(&Response {
            magic: RESPONSE_MAGIC,
            version: SELECT_VERSION,
            operation: request.operation,
            keyset_id: self.keyset_id,
            context: request.context,
            geometry: self.geometry,
            projection: request.projection,
            projected: projected.to_bytes(),
        })?;
        Ok(EvaluatedIndexedSelect {
            output,
            stats: IndexedSelectStats {
                request_decode_ms,
                encrypted_evaluate_ms,
                output_encode_ms: elapsed(started),
                ct_ct_multiplications: multiplications,
                relinearizations: multiplications,
                rotations: 0,
                multiplicative_depth: 1,
            },
        })
    }
}

impl Owner {
    /// Prepares an already authenticated exact matching set, with every supplied row active.
    /// ORIGINAL values and presence bits are encrypted before column projection. The
    /// public column mask spans all MAX_ROWS slots, independent of the selected count.
    /// This API rejects private-active holes; use the encrypted-mask API for those.
    pub fn prepare_exact_select_for_experiment(
        &self,
        context: QueryContext,
        fields: &[SelectedField],
        projection: RowProjection,
    ) -> Result<PreparedIndexedSelect> {
        if fields.len() > self.geometry.slots() {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        if fields.iter().any(|field| !field.active) {
            return Err(Error::InvalidShape);
        }
        let mut rows = Zeroizing::new(vec![0u64; DEGREE]);
        let mut active = [false; MAX_ROWS];
        for (slot, field) in fields.iter().enumerate() {
            rows[slot] = u64::from(field.age);
            rows[DEGREE / 2 + slot] = u64::from(field.amount);
            rows[VALIDITY_START + slot] = 1;
            active[slot] = true;
        }
        let operation = Operation::ExactPublicProjection;
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: SELECT_VERSION,
            operation,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            projection,
            rows: self.encrypted(&rows)?,
            mask: Vec::new(),
        })?;
        Ok(PreparedIndexedSelect {
            request,
            pending: PendingIndexedSelect {
                context,
                geometry: self.geometry,
                keyset_id: self.keyset_id,
                projection,
                active,
                operation,
            },
        })
    }
}

/// This public mask contains only column selection, never a predicate, row count or data.
fn public_projection(
    parameters: &Arc<BfvParameters>,
    projection: RowProjection,
) -> Result<Plaintext> {
    let mut mask = vec![0; DEGREE];
    for slot in 0..MAX_ROWS {
        mask[slot] = u64::from(projection.age());
        mask[DEGREE / 2 + slot] = u64::from(projection.amount());
        mask[VALIDITY_START + slot] = 1;
    }
    Plaintext::try_encode(&mask, Encoding::simd(), parameters).map_err(backend)
}

// Pinned level-zero codec: 8192*(43+43+44+44+44)/8 = 223232 bytes/poly;
// two unseeded polys plus their protobuf overhead fit 446494 bytes. A seeded
// ciphertext is smaller. Bound incoming bytes before upstream decode or copying.
const MAX_PUBLIC_SELECT_CIPHERTEXT_BYTES: usize = 512 * 1024;

pub(super) fn encode_public_select(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    context: QueryContext,
    projection: RowProjection,
    canonical_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if !context.valid() {
        return Err(Error::BindingMismatch);
    }
    if canonical_ciphertext.len() > MAX_PUBLIC_SELECT_CIPHERTEXT_BYTES {
        return Err(Error::WireLimit);
    }
    // Malformed public polynomial encodings can reach assertions upstream.
    // They are rejection, never permission to normalize or replace the input.
    let rows = std::panic::catch_unwind(|| checked_ciphertext(canonical_ciphertext, parameters))
        .map_err(|_| Error::InvalidShape)??;
    if rows.iter().any(|poly| {
        poly.coefficients().dim() != (MODULI.len(), DEGREE)
            || poly
                .coefficients()
                .outer_iter()
                .zip(MODULI)
                .any(|(row, q)| row.iter().any(|value| *value >= q))
    }) || rows.to_bytes() != canonical_ciphertext
    {
        return Err(Error::InvalidShape);
    }
    encode(&Request {
        magic: REQUEST_MAGIC,
        version: SELECT_VERSION,
        operation: Operation::ExactPublicProjection,
        keyset_id,
        context,
        geometry,
        projection,
        rows: canonical_ciphertext.to_vec(),
        mask: Vec::new(),
    })
}

fn checked_exact_request(geometry: Geometry, keyset_id: [u8; 32], wire: &[u8]) -> Result<Request> {
    let request: Request = decode(wire)?;
    if request.magic != REQUEST_MAGIC
        || request.version != SELECT_VERSION
        || request.operation != Operation::ExactPublicProjection
        || request.keyset_id != keyset_id
        || request.geometry != geometry
        || !request.context.valid()
        || !request.mask.is_empty()
    {
        return Err(Error::BindingMismatch);
    }
    Ok(request)
}

pub(super) fn evaluate_public(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_exact_request(geometry, keyset_id, wire)?;
    let rows = checked_ciphertext(&request.rows, parameters)?;
    let mask = public_projection(parameters, request.projection)?;
    response(request, (&rows * &mask).to_bytes())
}

pub(super) fn request_context(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<QueryContext> {
    let request = checked_exact_request(geometry, keyset_id, wire)?;
    checked_ciphertext(&request.rows, parameters)?;
    Ok(request.context)
}

pub(super) fn circuit_request(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_exact_request(geometry, keyset_id, wire)?;
    let rows = checked_ciphertext(&request.rows, parameters)?;
    let mask = public_projection(parameters, request.projection)?;
    canonical::public_product_request(parameters, wire, &rows, &mask)
}

pub(super) fn restore_circuit_output(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
    output: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_exact_request(geometry, keyset_id, wire)?;
    checked_ciphertext(&request.rows, parameters)?;
    let (binding, coefficients) = bfv_product_circuit::decode_output(output).map_err(backend)?;
    if binding != <[u8; 32]>::from(Sha256::digest(wire)) {
        return Err(Error::BindingMismatch);
    }
    response(
        request,
        canonical::ciphertext(parameters, &coefficients)?.to_bytes(),
    )
}

fn response(request: Request, projected: Vec<u8>) -> Result<Vec<u8>> {
    encode(&Response {
        magic: RESPONSE_MAGIC,
        version: SELECT_VERSION,
        operation: request.operation,
        keyset_id: request.keyset_id,
        context: request.context,
        geometry: request.geometry,
        projection: request.projection,
        projected,
    })
}

#[cfg(test)]
mod public_tests;
#[cfg(test)]
mod tests;
