//! Atomic encrypted batch append; storage retrieval, authorization and writeback are external.
use super::*;
const REQUEST_MAGIC: [u8; 8] = *b"BFVINSQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVINSR1";
// Version 3 binds a nonempty positioned batch and its exact count. Older versions
// must never be interpreted as this circuit, even when the batch has one row.
const INSERT_VERSION: u16 = 3;
const VALIDITY: usize = 2 * MAX_ROWS;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Operation {
    IndexedAppend,
}
#[derive(Serialize, Deserialize)]
struct Request {
    magic: [u8; 8],
    version: u16,
    operation: Operation,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    existing_rows: u16,
    incoming_rows: u16,
    existing: Vec<u8>,
    incoming: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Response {
    magic: [u8; 8],
    version: u16,
    operation: Operation,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    existing_rows: u16,
    incoming_rows: u16,
    rows: Vec<u8>,
}
/// One-use owner binding; it contains no original field values and has no wire codec.
pub struct PendingIndexedInsert {
    context: QueryContext,
    keyset_id: [u8; 32],
    existing_rows: usize,
    incoming_rows: usize,
}
/// Validated public append shape and original query/head identity. It conveys no proof.
pub struct InsertMetadata {
    pub context: QueryContext,
    pub existing_rows: usize,
    pub incoming_rows: usize,
}
impl PendingIndexedInsert {
    pub fn context(&self) -> &QueryContext {
        &self.context
    }
}
pub struct PreparedIndexedInsert {
    pub pending: PendingIndexedInsert,
    pub request: Vec<u8>,
}
impl PreparedIndexedInsert {
    pub fn ciphertext_payload_bytes(&self) -> Result<Vec<u8>> {
        let request: Request = decode(&self.request)?;
        encode(&(request.existing, request.incoming))
    }
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct InsertedRow {
    pub slot: usize,
    pub age: u8,
    pub amount: u16,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UnverifiedInsertedRows {
    pub rows: Vec<InsertedRow>,
    pub proof: ProofStatus,
}
#[derive(Debug, Serialize)]
pub struct IndexedInsertStats {
    pub request_decode_ms: f64,
    pub encrypted_append_ms: f64,
    pub output_encode_ms: f64,
    pub ciphertext_additions: usize,
    pub rotations: usize,
    pub ct_ct_multiplications: usize,
    pub multiplicative_depth: usize,
}
pub struct EvaluatedIndexedInsert {
    pub output: Vec<u8>,
    pub stats: IndexedInsertStats,
}
fn check_geometry(geometry: Geometry, existing: usize, incoming: usize) -> Result<()> {
    if geometry != Geometry::Rows256
        || incoming == 0
        || existing
            .checked_add(incoming)
            .is_none_or(|total| total > MAX_ROWS)
    {
        return Err(Error::GeometryLimit);
    }
    Ok(())
}
impl Owner {
    /// Encrypt authenticated originals and the authorized incoming batch separately.
    /// The incoming ciphertext contains only new rows at their public append positions.
    /// The peer must add both independent ciphertexts to obtain the complete relation.
    pub fn prepare_indexed_insert_for_experiment(
        &self,
        context: QueryContext,
        existing: &[SelectedField],
        incoming: &[SelectedField],
    ) -> Result<PreparedIndexedInsert> {
        check_geometry(self.geometry, existing.len(), incoming.len())?;
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        if incoming.iter().chain(existing).any(|field| !field.active) {
            return Err(Error::InvalidShape);
        }
        let mut old = Zeroizing::new(vec![0u64; DEGREE]);
        for (slot, field) in existing.iter().enumerate() {
            old[slot] = u64::from(field.age);
            old[DEGREE / 2 + slot] = u64::from(field.amount);
            old[VALIDITY + slot] = 1;
        }
        let mut new = Zeroizing::new(vec![0u64; DEGREE]);
        for (offset, field) in incoming.iter().enumerate() {
            let slot = existing.len() + offset;
            new[slot] = u64::from(field.age);
            new[DEGREE / 2 + slot] = u64::from(field.amount);
            new[VALIDITY + slot] = 1;
        }
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: INSERT_VERSION,
            operation: Operation::IndexedAppend,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            existing_rows: existing.len() as u16,
            incoming_rows: incoming.len() as u16,
            existing: self.encrypted(&old)?,
            incoming: self.encrypted(&new)?,
        })?;
        Ok(PreparedIndexedInsert {
            request,
            pending: PendingIndexedInsert {
                context,
                keyset_id: self.keyset_id,
                existing_rows: existing.len(),
                incoming_rows: incoming.len(),
            },
        })
    }
    /// Return only final BFV-decoded peer output. Bounds/binding are not an arithmetic proof.
    pub fn decrypt_indexed_insert_unverified_for_experiment(
        &self,
        pending: PendingIndexedInsert,
        output: &[u8],
    ) -> Result<UnverifiedInsertedRows> {
        check_geometry(self.geometry, pending.existing_rows, pending.incoming_rows)?;
        let response: Response = decode(output)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != INSERT_VERSION
            || response.operation != Operation::IndexedAppend
            || response.keyset_id != self.keyset_id
            || pending.keyset_id != self.keyset_id
            || response.geometry != self.geometry
            || !pending.context.valid()
            || response.context != pending.context
            || usize::from(response.existing_rows) != pending.existing_rows
            || usize::from(response.incoming_rows) != pending.incoming_rows
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.rows, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let decoded =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?);
        if decoded.len() != DEGREE {
            return Err(Error::InvalidShape);
        }
        let count = pending.existing_rows + pending.incoming_rows;
        for (index, value) in decoded.iter().copied().enumerate() {
            let maximum = if index < count {
                255
            } else if (DEGREE / 2..DEGREE / 2 + count).contains(&index) {
                65535
            } else if (VALIDITY..VALIDITY + count).contains(&index) {
                if value != 1 {
                    return Err(Error::InsertBounds);
                }
                1
            } else {
                0
            };
            if value > maximum {
                return Err(Error::InsertBounds);
            }
        }
        let rows = (0..count)
            .map(|slot| InsertedRow {
                slot,
                age: decoded[slot] as u8,
                amount: decoded[DEGREE / 2 + slot] as u16,
            })
            .collect();
        Ok(UnverifiedInsertedRows {
            rows,
            proof: ProofStatus::Unavailable,
        })
    }
}
impl PeerEvaluator {
    /// Real addition of independently encrypted old relation and positioned incoming row.
    pub fn evaluate_indexed_insert_for_experiment(
        &self,
        wire: &[u8],
    ) -> Result<EvaluatedIndexedInsert> {
        let start = Instant::now();
        let request = checked_request(self.geometry, self.keyset_id, wire)?;
        let old = checked_ciphertext(&request.existing, self.kernel.parameters())?;
        let incoming = checked_ciphertext(&request.incoming, self.kernel.parameters())?;
        let request_decode_ms = elapsed(start);
        let start = Instant::now();
        let rows = &old + &incoming;
        let encrypted_append_ms = elapsed(start);
        let start = Instant::now();
        let output = encode(&Response {
            magic: RESPONSE_MAGIC,
            version: INSERT_VERSION,
            operation: request.operation,
            keyset_id: self.keyset_id,
            context: request.context,
            geometry: request.geometry,
            existing_rows: request.existing_rows,
            incoming_rows: request.incoming_rows,
            rows: rows.to_bytes(),
        })?;
        Ok(EvaluatedIndexedInsert {
            output,
            stats: IndexedInsertStats {
                request_decode_ms,
                encrypted_append_ms,
                output_encode_ms: elapsed(start),
                ciphertext_additions: 1,
                rotations: 0,
                ct_ct_multiplications: 0,
                multiplicative_depth: 0,
            },
        })
    }
}

fn checked_request(geometry: Geometry, keyset_id: [u8; 32], wire: &[u8]) -> Result<Request> {
    let request: Request = decode(wire)?;
    check_geometry(
        geometry,
        usize::from(request.existing_rows),
        usize::from(request.incoming_rows),
    )?;
    if request.magic != REQUEST_MAGIC
        || request.version != INSERT_VERSION
        || request.operation != Operation::IndexedAppend
        || request.keyset_id != keyset_id
        || request.geometry != geometry
        || !request.context.valid()
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
    let request = checked_request(geometry, keyset_id, wire)?;
    let old = checked_ciphertext(&request.existing, parameters)?;
    let incoming = checked_ciphertext(&request.incoming, parameters)?;
    response(request, (&old + &incoming).to_bytes())
}

pub(super) fn request_context(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<QueryContext> {
    Ok(metadata(parameters, geometry, keyset_id, wire)?.context)
}

pub(super) fn metadata(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<InsertMetadata> {
    let request = checked_request(geometry, keyset_id, wire)?;
    checked_ciphertext(&request.existing, parameters)?;
    checked_ciphertext(&request.incoming, parameters)?;
    Ok(InsertMetadata {
        context: request.context,
        existing_rows: usize::from(request.existing_rows),
        incoming_rows: usize::from(request.incoming_rows),
    })
}

pub(super) fn circuit_request(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_request(geometry, keyset_id, wire)?;
    let old = checked_ciphertext(&request.existing, parameters)?;
    let incoming = checked_ciphertext(&request.incoming, parameters)?;
    bfv_linear_circuit::encode_request(
        Sha256::digest(wire).into(),
        &canonical::coefficients(&old),
        &canonical::coefficients(&incoming),
    )
    .map_err(backend)
}

pub(super) fn restore_circuit_output(
    parameters: &Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
    wire: &[u8],
    output: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_request(geometry, keyset_id, wire)?;
    checked_ciphertext(&request.existing, parameters)?;
    checked_ciphertext(&request.incoming, parameters)?;
    let (binding, coefficients) = bfv_linear_circuit::decode_output(output).map_err(backend)?;
    if binding != <[u8; 32]>::from(Sha256::digest(wire)) {
        return Err(Error::BindingMismatch);
    }
    response(
        request,
        canonical::ciphertext(parameters, &coefficients)?.to_bytes(),
    )
}

fn response(request: Request, rows: Vec<u8>) -> Result<Vec<u8>> {
    encode(&Response {
        magic: RESPONSE_MAGIC,
        version: INSERT_VERSION,
        operation: request.operation,
        keyset_id: request.keyset_id,
        context: request.context,
        geometry: request.geometry,
        existing_rows: request.existing_rows,
        incoming_rows: request.incoming_rows,
        rows,
    })
}
#[cfg(test)]
mod tests;
