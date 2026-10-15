//! Single-row encrypted append; storage retrieval, authorization and writeback are external.
use super::*;
const REQUEST_MAGIC: [u8; 8] = *b"BFVINSQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVINSR1";
const INSERT_VERSION: u16 = 1;
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
    rows: Vec<u8>,
}
/// One-use owner binding; it contains no original field values and has no wire codec.
pub struct PendingIndexedInsert {
    context: QueryContext,
    keyset_id: [u8; 32],
    existing_rows: usize,
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
fn check_geometry(geometry: Geometry, existing: usize) -> Result<()> {
    if geometry != Geometry::Rows256 || existing >= MAX_ROWS {
        return Err(Error::GeometryLimit);
    }
    Ok(())
}
impl Owner {
    /// Encrypt actual authenticated contiguous rows and the authorized new row separately.
    /// Incoming fields are staged at256; the peer must rotate them before adding the relation.
    pub fn prepare_indexed_insert_for_experiment(
        &self,
        context: QueryContext,
        existing: &[SelectedField],
        incoming: SelectedField,
    ) -> Result<PreparedIndexedInsert> {
        check_geometry(self.geometry, existing.len())?;
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        if !incoming.active || existing.iter().any(|field| !field.active) {
            return Err(Error::InvalidShape);
        }
        let mut old = Zeroizing::new(vec![0u64; DEGREE]);
        for (slot, field) in existing.iter().enumerate() {
            old[slot] = u64::from(field.age);
            old[DEGREE / 2 + slot] = u64::from(field.amount);
            old[VALIDITY + slot] = 1;
        }
        let mut new = Zeroizing::new(vec![0u64; DEGREE]);
        new[MAX_ROWS] = u64::from(incoming.age);
        new[DEGREE / 2 + MAX_ROWS] = u64::from(incoming.amount);
        new[VALIDITY + MAX_ROWS] = 1;
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: INSERT_VERSION,
            operation: Operation::IndexedAppend,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            existing_rows: existing.len() as u16,
            existing: self.encrypted(&old)?,
            incoming: self.encrypted(&new)?,
        })?;
        Ok(PreparedIndexedInsert {
            request,
            pending: PendingIndexedInsert {
                context,
                keyset_id: self.keyset_id,
                existing_rows: existing.len(),
            },
        })
    }
    /// Return only final BFV-decoded peer output. Bounds/binding are not an arithmetic proof.
    pub fn decrypt_indexed_insert_unverified_for_experiment(
        &self,
        pending: PendingIndexedInsert,
        output: &[u8],
    ) -> Result<UnverifiedInsertedRows> {
        check_geometry(self.geometry, pending.existing_rows)?;
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
        let count = pending.existing_rows + 1;
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
    /// Real encrypted row-placement rotations and relation addition. No plaintext or secret key.
    pub fn evaluate_indexed_insert_for_experiment(
        &self,
        wire: &[u8],
    ) -> Result<EvaluatedIndexedInsert> {
        let start = Instant::now();
        let request: Request = decode(wire)?;
        check_geometry(self.geometry, usize::from(request.existing_rows))?;
        if request.magic != REQUEST_MAGIC
            || request.version != INSERT_VERSION
            || request.operation != Operation::IndexedAppend
            || request.keyset_id != self.keyset_id
            || request.geometry != self.geometry
            || !request.context.valid()
        {
            return Err(Error::BindingMismatch);
        }
        let old = checked_ciphertext(&request.existing, self.kernel.parameters())?;
        let incoming = checked_ciphertext(&request.incoming, self.kernel.parameters())?;
        let request_decode_ms = elapsed(start);
        let start = Instant::now();
        let (rows, rotations) =
            self.kernel
                .append_selected(&old, &incoming, usize::from(request.existing_rows))?;
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
            rows: rows.to_bytes(),
        })?;
        Ok(EvaluatedIndexedInsert {
            output,
            stats: IndexedInsertStats {
                request_decode_ms,
                encrypted_append_ms,
                output_encode_ms: elapsed(start),
                ciphertext_additions: 1,
                rotations,
                ct_ct_multiplications: 0,
                multiplicative_depth: 0,
            },
        })
    }
}
#[cfg(test)]
mod tests;
