//! Indexed amount addition only. Retrieval, exact selection and writeback are caller-owned.
use super::{
    DEGREE, Error, Geometry, MAX_ROWS, Owner, PeerEvaluator, ProofStatus, QueryContext, Result,
    SelectedField, backend, checked_ciphertext, decode, elapsed, encode,
};
use fhe::bfv::Encoding;
use fhe_traits::{FheDecoder, FheDecrypter, Serialize as FheSerialize};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use zeroize::Zeroizing;

const UPDATE_VERSION: u16 = 1;
const REQUEST_MAGIC: [u8; 8] = *b"BFVADDQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVADDR1";
const MAX_LIMB: u64 = 510;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum OperationTag {
    CountSum,
    IndexedAddAmount,
}
#[derive(Serialize, Deserialize)]
struct IndexedUpdateRequest {
    magic: [u8; 8],
    version: u16,
    operation: OperationTag,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    amounts: Vec<u8>,
    deltas: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct IndexedUpdateResponse {
    magic: [u8; 8],
    version: u16,
    operation: OperationTag,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    updated_limbs: Vec<u8>,
}

/// One-use owner-only completion state. It contains no secret key and has no wire codec.
/// Exact index completeness and slot-to-address mapping remain the caller's responsibility.
///
/// ```compile_fail
/// use compact_bfv_byte_limb_core::{Owner, PendingIndexedUpdate};
/// fn cannot_complete_twice(owner: &Owner, pending: PendingIndexedUpdate, wire: &[u8]) {
///     let _ = owner.decrypt_indexed_update_unverified_for_experiment(pending, wire);
///     let _ = owner.decrypt_indexed_update_unverified_for_experiment(pending, wire);
/// }
/// ```
pub struct PendingIndexedUpdate {
    context: QueryContext,
    geometry: Geometry,
    keyset_id: [u8; 32],
    active: [bool; MAX_ROWS],
}
impl PendingIndexedUpdate {
    pub fn context(&self) -> &QueryContext {
        &self.context
    }
}
pub struct PreparedIndexedUpdate {
    pub pending: PendingIndexedUpdate,
    pub request: Vec<u8>,
}
impl PreparedIndexedUpdate {
    /// Ciphertext-only randomness evidence, excluding operation/context/keyset/geometry.
    pub fn ciphertext_payload_bytes(&self) -> Result<Vec<u8>> {
        let request: IndexedUpdateRequest = decode(&self.request)?;
        encode(&(request.amounts, request.deltas))
    }
}
#[derive(Debug, Serialize)]
pub struct IndexedUpdateStats {
    pub request_decode_ms: f64,
    pub encrypted_add_ms: f64,
    pub output_encode_ms: f64,
    pub ciphertext_additions: usize,
    pub ct_ct_multiplications: usize,
    pub rotations: usize,
    pub multiplicative_depth: usize,
}
pub struct EvaluatedIndexedUpdate {
    pub output: Vec<u8>,
    pub stats: IndexedUpdateStats,
}
/// Owner-only plaintext result. Slot indices refer to the caller's private selection order.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UpdatedAmount {
    pub slot: usize,
    pub amount: u16,
    pub low_limb_sum: u16,
    pub high_limb_sum: u16,
}
/// Binding and bounds do not prove that a malicious peer performed addition.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UnverifiedUpdatedValues {
    pub rows: Vec<UpdatedAmount>,
    pub proof: ProofStatus,
}
/// Global overflow exports no partial row values and authorizes no writeback.
/// Every variant remains explicitly unverified, including an overflow claim.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum UnverifiedUpdateOutcome {
    Values(UnverifiedUpdatedValues),
    Overflow { proof: ProofStatus },
}

impl Owner {
    /// Caller supplies the complete authenticated exact matching set, not coarse candidates.
    /// Only original amount limbs and active-masked delta limbs are encrypted here.
    pub fn prepare_indexed_update_for_experiment(
        &self,
        context: QueryContext,
        fields: &[SelectedField],
        delta: u16,
    ) -> Result<PreparedIndexedUpdate> {
        let slots = self.geometry.slots();
        if fields.len() > slots {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() || slots > MAX_ROWS || 2 * slots > DEGREE {
            return Err(Error::InvalidShape);
        }
        let mut amounts = Zeroizing::new(vec![0u64; DEGREE]);
        let mut deltas = Zeroizing::new(vec![0u64; DEGREE]);
        let mut active = [false; MAX_ROWS];
        for (slot, field) in fields.iter().enumerate().filter(|(_, field)| field.active) {
            active[slot] = true;
            amounts[slot] = u64::from(field.amount & 255);
            amounts[DEGREE / 2 + slot] = u64::from(field.amount >> 8);
            deltas[slot] = u64::from(delta & 255);
            deltas[DEGREE / 2 + slot] = u64::from(delta >> 8);
        }
        let request = IndexedUpdateRequest {
            magic: REQUEST_MAGIC,
            version: UPDATE_VERSION,
            operation: OperationTag::IndexedAddAmount,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            amounts: self.encrypted(&amounts)?,
            deltas: self.encrypted(&deltas)?,
        };
        Ok(PreparedIndexedUpdate {
            pending: PendingIndexedUpdate {
                context,
                geometry: self.geometry,
                keyset_id: self.keyset_id,
                active,
            },
            request: encode(&request)?,
        })
    }

    /// Consumes one owner token, but is not a persistent replay ledger or arithmetic proof.
    /// The caller must recheck current heads and locally verify all answers before staging.
    pub fn decrypt_indexed_update_unverified_for_experiment(
        &self,
        pending: PendingIndexedUpdate,
        output: &[u8],
    ) -> Result<UnverifiedUpdateOutcome> {
        if pending.keyset_id != self.keyset_id
            || pending.geometry != self.geometry
            || !pending.context.valid()
        {
            return Err(Error::BindingMismatch);
        }
        let response: IndexedUpdateResponse = decode(output)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != UPDATE_VERSION
            || response.operation != OperationTag::IndexedAddAmount
            || response.keyset_id != self.keyset_id
            || response.geometry != self.geometry
            || response.context != pending.context
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.updated_limbs, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let decoded =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?);
        if decoded.len() != DEGREE {
            return Err(Error::InvalidShape);
        }
        let slots = self.geometry.slots();
        // Validate EVERY active, inactive and reserved position before any overflow outcome.
        for (index, value) in decoded.iter().enumerate() {
            let active = if index < slots {
                pending.active[index]
            } else if (DEGREE / 2..DEGREE / 2 + slots).contains(&index) {
                pending.active[index - DEGREE / 2]
            } else {
                false
            };
            if (active && *value > MAX_LIMB) || (!active && *value != 0) {
                return Err(Error::UpdateBounds);
            }
        }
        // Decide global overflow before allocating any owner plaintext output rows.
        let mut overflow = false;
        for slot in (0..slots).filter(|slot| pending.active[*slot]) {
            let value = reconstruct(decoded[slot], decoded[DEGREE / 2 + slot])?;
            if value > u32::from(u16::MAX) {
                overflow = true;
            }
        }
        if overflow {
            return Ok(UnverifiedUpdateOutcome::Overflow {
                proof: ProofStatus::Unavailable,
            });
        }
        let mut rows = Vec::new();
        for slot in (0..slots).filter(|slot| pending.active[*slot]) {
            let low = decoded[slot];
            let high = decoded[DEGREE / 2 + slot];
            // All slot bounds and the whole-operation overflow pass already succeeded.
            rows.push(UpdatedAmount {
                slot,
                amount: u16::try_from(reconstruct(low, high)?).map_err(|_| Error::UpdateBounds)?,
                low_limb_sum: u16::try_from(low).map_err(|_| Error::UpdateBounds)?,
                high_limb_sum: u16::try_from(high).map_err(|_| Error::UpdateBounds)?,
            });
        }
        Ok(UnverifiedUpdateOutcome::Values(UnverifiedUpdatedValues {
            rows,
            proof: ProofStatus::Unavailable,
        }))
    }
}

fn reconstruct(low: u64, high: u64) -> Result<u32> {
    let low = u32::try_from(low).map_err(|_| Error::UpdateBounds)?;
    let high = u32::try_from(high).map_err(|_| Error::UpdateBounds)?;
    // Do not truncate low to eight bits: it may contain a real carry.
    high.checked_mul(256)
        .and_then(|high| high.checked_add(low))
        .ok_or(Error::UpdateBounds)
}

impl PeerEvaluator {
    /// Public-only exact addition. It receives no plaintext amount, delta, active mask or index.
    pub fn evaluate_indexed_update(&self, wire: &[u8]) -> Result<EvaluatedIndexedUpdate> {
        let started = Instant::now();
        let request: IndexedUpdateRequest = decode(wire)?;
        if request.magic != REQUEST_MAGIC
            || request.version != UPDATE_VERSION
            || request.operation != OperationTag::IndexedAddAmount
            || request.geometry != self.geometry
            || !request.context.valid()
        {
            return Err(Error::InvalidShape);
        }
        if request.keyset_id != self.keyset_id {
            return Err(Error::BindingMismatch);
        }
        // Both decodes use this identical evaluator Arc, satisfying upstream Add's assertion.
        let amounts = checked_ciphertext(&request.amounts, self.kernel.parameters())?;
        let deltas = checked_ciphertext(&request.deltas, self.kernel.parameters())?;
        let request_decode_ms = elapsed(started);
        let started = Instant::now();
        let updated = &amounts + &deltas;
        let encrypted_add_ms = elapsed(started);
        let started = Instant::now();
        let output = encode(&IndexedUpdateResponse {
            magic: RESPONSE_MAGIC,
            version: UPDATE_VERSION,
            operation: OperationTag::IndexedAddAmount,
            keyset_id: request.keyset_id,
            context: request.context,
            geometry: self.geometry,
            updated_limbs: updated.to_bytes(),
        })?;
        Ok(EvaluatedIndexedUpdate {
            output,
            stats: IndexedUpdateStats {
                request_decode_ms,
                encrypted_add_ms,
                output_encode_ms: elapsed(started),
                ciphertext_additions: 1,
                ct_ct_multiplications: 0,
                rotations: 0,
                multiplicative_depth: 0,
            },
        })
    }
}

#[cfg(test)]
mod wire_tests;
