//! Experimental, caller-asserted exact-index aggregate; no predicate evaluation or index proof.
//!
//! Before preparation the caller must authenticate the two current heads, establish exact index
//! construction/update consistency, decode ALL complete postings with no duplicates, authenticate
//! every selected field and explicitly check its indexed age against the authorized predicate.
//! A coarse candidate set or an arbitrary `SelectedField` slice does not satisfy that contract.
//! This module cannot establish that contract from a vector, and never returns a proof.
use super::*;

const REQUEST_MAGIC: [u8; 8] = *b"BFVEXAQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVEXAR1";
const EXACT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Operation {
    ExactIndexedAggregate,
}

#[derive(Serialize, Deserialize)]
struct Request {
    magic: [u8; 8],
    version: u16,
    operation: Operation,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    values: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Response {
    magic: [u8; 8],
    version: u16,
    operation: Operation,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    count_sum: Vec<u8>,
}

/// One-use owner token for THIS operation and public keyset, not an index capability or proof.
/// Callers must recheck live heads before completion when writes may occur in flight.
///
/// ```compile_fail
/// # use bfv_query_core::PendingIndexedAggregate;
/// fn duplicate(token: PendingIndexedAggregate) { let second = token; drop(token); drop(second); }
/// ```
pub struct PendingIndexedAggregate {
    context: QueryContext,
    geometry: Geometry,
    operation: Operation,
    keyset_id: [u8; 32],
    active_rows: u32,
}
impl PendingIndexedAggregate {
    pub fn context(&self) -> &QueryContext {
        &self.context
    }
    /// Public identity of the entire unchanged serialized PublicSetup.
    pub fn keyset_id(&self) -> [u8; 32] {
        self.keyset_id
    }
}
pub struct PreparedIndexedAggregate {
    pub pending: PendingIndexedAggregate,
    pub request: Vec<u8>,
}
impl PreparedIndexedAggregate {
    /// Ciphertext-only freshness evidence; excludes context, operation and keyset digest.
    pub fn ciphertext_payload_bytes(&self) -> Result<Vec<u8>> {
        let request: Request = decode(&self.request)?;
        Ok(request.values)
    }
}

fn check_geometry(geometry: Geometry) -> Result<()> {
    if geometry != Geometry::Rows256 || 16 * geometry.slots() > DEGREE / 2 {
        return Err(Error::GeometryLimit);
    }
    Ok(())
}

impl Owner {
    /// Freshly encrypt weights AFTER the caller establishes the exact-index contract above.
    /// `age` is deliberately not inspected here: this API neither certifies selection nor filters
    /// arbitrary candidates. The caller must reject an age mismatch before invoking it.
    /// No plaintext aggregate is computed. Missing/inactive weights are freshly encrypted zeros.
    pub fn prepare_exact_index_aggregate_for_experiment(
        &self,
        context: QueryContext,
        fields: &[SelectedField],
    ) -> Result<PreparedIndexedAggregate> {
        check_geometry(self.geometry)?;
        if fields.len() > MAX_ROWS {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        let mut active_rows = 0;
        for (i, field) in fields.iter().enumerate().filter(|(_, field)| field.active) {
            values[i] = u64::from(field.amount & 255);
            values[DEGREE / 2 + i] = u64::from(field.amount >> 8);
            values[8 * MAX_ROWS + i] = 1;
            active_rows += 1;
        }
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: EXACT_VERSION,
            operation: Operation::ExactIndexedAggregate,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            values: self.encrypted(&values)?,
        })?;
        Ok(PreparedIndexedAggregate {
            pending: PendingIndexedAggregate {
                context,
                geometry: self.geometry,
                operation: Operation::ExactIndexedAggregate,
                keyset_id: self.keyset_id,
                active_rows,
            },
            request,
        })
    }

    /// Consume operation/keyset/context binding and unsigned bounds, yielding NO arithmetic proof.
    /// A public SUM tamper preserving exact COUNT remains possible, as the owning test shows.
    pub fn decrypt_exact_index_unverified_for_experiment(
        &self,
        pending: PendingIndexedAggregate,
        output: &[u8],
    ) -> Result<UnverifiedAggregate> {
        check_geometry(self.geometry)?;
        let response: Response = decode(output)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != EXACT_VERSION
            || response.operation != Operation::ExactIndexedAggregate
            || pending.operation != Operation::ExactIndexedAggregate
            || response.keyset_id != self.keyset_id
            || pending.keyset_id != self.keyset_id
            || response.geometry != self.geometry
            || pending.geometry != self.geometry
            || !response.context.valid()
            || !pending.context.valid()
            || response.context != pending.context
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.count_sum, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        // Unsigned decoding is essential: 65,280 exceeds t/2 but is less than t=114,689.
        let decoded =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?);
        if decoded.len() != DEGREE {
            return Err(Error::InvalidShape);
        }
        let low = decoded[0];
        let high = decoded[DEGREE / 2];
        let count = decoded[8 * MAX_ROWS];
        let sum = high
            .checked_mul(256)
            .and_then(|x| x.checked_add(low))
            .ok_or(Error::AggregateBounds)?;
        if count != u64::from(pending.active_rows)
            || count > MAX_ROWS as u64
            || low > 255 * count
            || high > 255 * count
            || low > 255 * MAX_ROWS as u64
            || high > 255 * MAX_ROWS as u64
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
    /// Public keys and one encrypted weight vector only. Never receives owner fields or secrets.
    pub fn evaluate_exact_index_aggregate_for_experiment(
        &self,
        wire: &[u8],
    ) -> Result<EvaluatedQuery> {
        let started = Instant::now();
        check_geometry(self.geometry)?;
        let request: Request = decode(wire)?;
        if request.magic != REQUEST_MAGIC
            || request.version != EXACT_VERSION
            || request.operation != Operation::ExactIndexedAggregate
            || request.keyset_id != self.keyset_id
            || request.geometry != self.geometry
            || !request.context.valid()
        {
            return Err(Error::BindingMismatch);
        }
        let values = checked_ciphertext(&request.values, self.kernel.parameters())?;
        let request_decode_ms = elapsed(started);
        let started = Instant::now();
        let (sums, ct_ct_multiplications, rotations) = self.kernel.aggregate_selected(&values)?;
        let encrypted_evaluate_ms = elapsed(started);
        let started = Instant::now();
        let output = encode(&Response {
            magic: RESPONSE_MAGIC,
            version: EXACT_VERSION,
            operation: request.operation,
            keyset_id: self.keyset_id,
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
                multiplicative_depth: 0,
            },
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> QueryContext {
        QueryContext::new([9; 16], [2; 112], [3; 112])
    }
    fn fields() -> [SelectedField; 2] {
        [
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
        ]
    }
    fn prepare(owner: &Owner) -> PreparedIndexedAggregate {
        owner
            .prepare_exact_index_aggregate_for_experiment(context(), &fields())
            .unwrap()
    }
    fn echo(request: Request) -> Response {
        Response {
            magic: RESPONSE_MAGIC,
            version: EXACT_VERSION,
            operation: request.operation,
            keyset_id: request.keyset_id,
            context: request.context,
            geometry: request.geometry,
            count_sum: request.values,
        }
    }
    #[test]
    fn public_sum_tamper_preserving_exact_count_remains_unverified() {
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
        let prepared = prepare(&owner);
        let honest = peer
            .evaluate_exact_index_aggregate_for_experiment(&prepared.request)
            .unwrap();
        let mut forged: Response = decode(&honest.output).unwrap();
        // Public-only malicious evaluator changes the aggregate's low slot, preserving COUNT.
        // This uses only the real public evaluation result, public parameters and an encoded one.
        let mut ciphertext =
            checked_ciphertext(&forged.count_sum, peer.kernel.parameters()).unwrap();
        let mut delta = vec![0u64; DEGREE];
        delta[0] = 1;
        let delta =
            Plaintext::try_encode(&delta, Encoding::simd(), peer.kernel.parameters()).unwrap();
        ciphertext += &delta;
        forged.count_sum = ciphertext.to_bytes();
        let actual = owner
            .decrypt_exact_index_unverified_for_experiment(
                prepared.pending,
                &encode(&forged).unwrap(),
            )
            .unwrap();
        assert_eq!((actual.count, actual.sum), (2, 31));
        assert_ne!(actual.sum, 30);
        assert_eq!(actual.proof, ProofStatus::Unavailable);
    }
    #[test]
    fn encrypted_count_must_equal_every_authorized_active_row() {
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
        let prepared = prepare(&owner);
        let honest = peer
            .evaluate_exact_index_aggregate_for_experiment(&prepared.request)
            .unwrap();
        let mut forged: Response = decode(&honest.output).unwrap();
        let mut ciphertext =
            checked_ciphertext(&forged.count_sum, peer.kernel.parameters()).unwrap();
        let mut delta = vec![0u64; DEGREE];
        delta[8 * MAX_ROWS] = 1;
        let delta =
            Plaintext::try_encode(&delta, Encoding::simd(), peer.kernel.parameters()).unwrap();
        ciphertext -= &delta;
        forged.count_sum = ciphertext.to_bytes();
        // COUNT=1 and SUM=30 pass generic unsigned bounds, but violate this exact operation.
        assert!(matches!(
            owner.decrypt_exact_index_unverified_for_experiment(
                prepared.pending,
                &encode(&forged).unwrap()
            ),
            Err(Error::AggregateBounds)
        ));
    }
    #[test]
    fn changed_context_operation_keyset_and_version_are_rejected_before_completion() {
        let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
        for mutation in 0..9 {
            let prepared = prepare(&owner);
            let mut response = echo(decode(&prepared.request).unwrap());
            match mutation {
                0 => response.context.query_id[0] ^= 1,
                1 => response.context.data_head[0] ^= 1,
                2 => response.context.index_head[0] ^= 1,
                3 => response.keyset_id[0] ^= 1,
                4 => response.geometry = Geometry::Rows16,
                5 => response.magic = REQUEST_MAGIC,
                6 => response.version += 1,
                7 => {
                    response.context.data_head.pop();
                }
                8 => {
                    response.context.index_head.pop();
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                owner.decrypt_exact_index_unverified_for_experiment(
                    prepared.pending,
                    &encode(&response).unwrap()
                ),
                Err(Error::BindingMismatch)
            ));
        }
        let prepared = prepare(&owner);
        let mut response = encode(&echo(decode(&prepared.request).unwrap())).unwrap();
        // fixed-int enum tag follows 8 magic + 2 version bytes; unknown operation is not read.
        response[10..14].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            owner
                .decrypt_exact_index_unverified_for_experiment(prepared.pending, &response)
                .is_err()
        );
    }
    #[test]
    fn malformed_metadata_operation_and_wrong_level_requests_fail_closed() {
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
        let original = prepare(&owner).request;
        for mutation in 0..7 {
            let mut request: Request = decode(&original).unwrap();
            match mutation {
                0 => request.magic = RESPONSE_MAGIC,
                1 => request.version += 1,
                2 => request.keyset_id[0] ^= 1,
                3 => request.geometry = Geometry::Rows16,
                4 => {
                    request.context.index_head.pop();
                }
                5 => request.values.clear(),
                6 => {
                    let mut ct = checked_ciphertext(&request.values, &owner.parameters).unwrap();
                    ct.switch_to_level(1).unwrap();
                    request.values = ct.to_bytes();
                }
                _ => unreachable!(),
            }
            assert!(
                peer.evaluate_exact_index_aggregate_for_experiment(&encode(&request).unwrap())
                    .is_err()
            );
        }
        let mut bad_operation = original;
        bad_operation[10..14].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            peer.evaluate_exact_index_aggregate_for_experiment(&bad_operation)
                .is_err()
        );
        let mut bad_context = context();
        bad_context.index_head.clear();
        assert!(matches!(
            owner.prepare_exact_index_aggregate_for_experiment(bad_context, &fields()),
            Err(Error::BindingMismatch)
        ));
    }
    #[test]
    fn unsigned_limb_count_bounds_and_wrong_level_output_are_enforced() {
        let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
        for (low, high, count) in [
            (511, 0, 2),
            (0, 511, 2),
            (1, 0, 0),
            (0, 0, 3),
            (114_688, 0, 2),
        ] {
            let prepared = prepare(&owner);
            let mut forged = echo(decode(&prepared.request).unwrap());
            // Public fixture construction for bounds testing, not the algorithm or a proof.
            let mut invalid = vec![0u64; DEGREE];
            invalid[0] = low;
            invalid[DEGREE / 2] = high;
            invalid[8 * MAX_ROWS] = count;
            forged.count_sum = owner.encrypted(&invalid).unwrap();
            assert!(matches!(
                owner.decrypt_exact_index_unverified_for_experiment(
                    prepared.pending,
                    &encode(&forged).unwrap()
                ),
                Err(Error::AggregateBounds)
            ));
        }
        let prepared = prepare(&owner);
        let mut response = echo(decode(&prepared.request).unwrap());
        let mut ct = checked_ciphertext(&response.count_sum, &owner.parameters).unwrap();
        ct.switch_to_level(1).unwrap();
        response.count_sum = ct.to_bytes();
        assert!(matches!(
            owner.decrypt_exact_index_unverified_for_experiment(
                prepared.pending,
                &encode(&response).unwrap()
            ),
            Err(Error::InvalidShape)
        ));
    }
}
