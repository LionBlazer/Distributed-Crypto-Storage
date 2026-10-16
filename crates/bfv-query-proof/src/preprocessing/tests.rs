//! Genuine full-profile proofs, injected private caches, and public fixture rows.
use super::*;
use crate::{Error, circuit::statement, codec, prove_with_cache, verify_with_cache};
use bfv_query_core::{
    Geometry, Owner, PublicUpdateEvaluator, QueryContext, RowProjection, SelectedField,
};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{Proof, StarkGenericConfig};

type Challenge = <Config as StarkGenericConfig>::Challenge;
struct Fixture {
    input: Vec<u8>,
    output: Vec<u8>,
    proof: Vec<u8>,
    operation: Operation,
}
impl Fixture {
    fn new(operation: Operation, cache: &PreprocessingCache) -> Self {
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let evaluator =
            PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
        let context = QueryContext::new([1; 16], [2; 112], [3; 112]);
        let fields = [SelectedField {
            age: 18,
            amount: 20,
            active: true,
        }];
        let input = match operation {
            Operation::Addition => {
                let prepared = owner
                    .prepare_indexed_update_for_experiment(context, &fields, 5)
                    .unwrap();
                evaluator.circuit_request(&prepared.request).unwrap()
            }
            Operation::PublicPolynomialProduct => {
                let prepared = owner
                    .prepare_exact_select_for_experiment(context, &fields, RowProjection::AgeAmount)
                    .unwrap();
                evaluator.select_circuit_request(&prepared.request).unwrap()
            }
        };
        // This executes actual BFV arithmetic and the genuine STARK prover. It
        // intentionally performs no successful proof verification before returning.
        let generated = prove_with_cache(&input, cache).unwrap();
        Self {
            input,
            output: generated.output,
            proof: generated.proof,
            operation,
        }
    }
    fn key(&self) -> DigestKey {
        let end = 8 + self.operation.certificate_bytes();
        let statement = statement(
            self.operation,
            &self.input,
            &self.output,
            &self.proof[8..end],
        )
        .unwrap();
        cache_key(self.operation, &statement.hashes)
    }
    fn corrupt_canonical_proof(&self) -> Vec<u8> {
        let end = 8 + self.operation.certificate_bytes();
        let (mut proof, trailing): (Proof<Config>, _) =
            codec::take_from_bytes(&self.proof[end..]).unwrap();
        assert!(trailing.is_empty());
        proof.opened_values.trace_local[0] += Challenge::ONE;
        let payload = postcard::to_allocvec(&proof).unwrap();
        let mut wire = self.proof[..end].to_vec();
        wire.extend_from_slice(&payload);
        wire
    }
}
fn operations() -> [Operation; 2] {
    [Operation::Addition, Operation::PublicPolynomialProduct]
}

#[test]
fn a_prover_seeded_public_key_never_accepts_a_corrupted_canonical_proof() {
    for operation in operations() {
        let cache = PreprocessingCache::new();
        let fixture = Fixture::new(operation, &cache);
        assert!(cache.get(fixture.key(), operation).is_some());
        let corrupted = fixture.corrupt_canonical_proof();

        // Act before any successful verification: canonical decoding succeeds,
        // the public key hits, and the actual SDK verifier must still reject.
        assert_eq!(
            verify_with_cache(&fixture.input, &fixture.output, &corrupted, &cache).unwrap_err(),
            Error::Verification
        );
        let checked =
            verify_with_cache(&fixture.input, &fixture.output, &fixture.proof, &cache).unwrap();
        assert!(checked.matches_statement(&fixture.input, &fixture.output));
        assert_eq!(
            verify_with_cache(&fixture.input, &fixture.output, &corrupted, &cache).unwrap_err(),
            Error::Verification
        );
    }
}

fn same_rejection(cache: &PreprocessingCache, input: &[u8], output: &[u8], proof: &[u8]) {
    let cold = verify_with_cache(input, output, proof, &PreprocessingCache::new()).unwrap_err();
    let warm = verify_with_cache(input, output, proof, cache).unwrap_err();
    assert_eq!(warm, cold);
    // A rejected statement may have a genuinely derived public key cached; that
    // still cannot turn its next invalid proof into successful verification.
    assert_eq!(
        verify_with_cache(input, output, proof, cache).unwrap_err(),
        cold
    );
}
#[test]
fn cold_and_warm_keys_preserve_operand_result_binding_certificate_and_operation_rejection() {
    for operation in operations() {
        let cache = PreprocessingCache::new();
        let fixture = Fixture::new(operation, &cache);
        let cold = verify_with_cache(
            &fixture.input,
            &fixture.output,
            &fixture.proof,
            &PreprocessingCache::new(),
        )
        .unwrap();
        let warm =
            verify_with_cache(&fixture.input, &fixture.output, &fixture.proof, &cache).unwrap();
        assert_eq!(cold.input_digest(), warm.input_digest());
        assert_eq!(cold.output_digest(), warm.output_digest());

        let mut operand = fixture.input.clone();
        let last = operand.len() - 8;
        let value = u64::from_le_bytes(operand[last..].try_into().unwrap());
        operand[last..]
            .copy_from_slice(&((value + 1) % bfv_linear_circuit::MODULI[4]).to_le_bytes());
        same_rejection(&cache, &operand, &fixture.output, &fixture.proof);
        let mut result = fixture.output.clone();
        let last = result.len() - 8;
        let value = u64::from_le_bytes(result[last..].try_into().unwrap());
        result[last..]
            .copy_from_slice(&((value + 1) % bfv_linear_circuit::MODULI[4]).to_le_bytes());
        same_rejection(&cache, &fixture.input, &result, &fixture.proof);
        let mut rebound = fixture.input.clone();
        let mut rebound_output = fixture.output.clone();
        rebound[8] ^= 1;
        rebound_output[8] ^= 1;
        same_rejection(&cache, &rebound, &rebound_output, &fixture.proof);
        let mut other_operation = fixture.proof.clone();
        other_operation[..8].copy_from_slice(match operation {
            Operation::Addition => Operation::PublicPolynomialProduct.proof_magic(),
            Operation::PublicPolynomialProduct => Operation::Addition.proof_magic(),
        });
        same_rejection(&cache, &fixture.input, &fixture.output, &other_operation);
        if operation == Operation::PublicPolynomialProduct {
            let mut certificate = fixture.proof.clone();
            certificate[8] ^= 1;
            same_rejection(&cache, &fixture.input, &fixture.output, &certificate);
        }
    }
}

#[test]
fn keys_with_the_wrong_public_width_or_degree_are_rederived_before_verification() {
    for operation in operations() {
        let cache = PreprocessingCache::new();
        let fixture = Fixture::new(operation, &cache);
        let digest = fixture.key();
        for wrong_width in [true, false] {
            let mut entries = cache.entries.lock().unwrap();
            let key = entries.keys.get_mut(&digest).unwrap();
            if wrong_width {
                key.width += 1
            } else {
                key.degree_bits += 1
            }
            drop(entries);
            assert!(cache.get(digest, operation).is_none());
            let checked =
                verify_with_cache(&fixture.input, &fixture.output, &fixture.proof, &cache).unwrap();
            assert!(checked.matches_statement(&fixture.input, &fixture.output));
            assert!(valid_shape(
                &cache.get(digest, operation).unwrap(),
                operation
            ));
        }
    }
}

#[test]
fn a_poisoned_optional_cache_falls_back_to_real_verification() {
    let cache = PreprocessingCache::new();
    let fixture = Fixture::new(Operation::Addition, &cache);
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _held = cache.entries.lock().unwrap();
                    panic!("public test cache poisoning");
                })
                .join()
                .is_err()
        );
    });
    assert!(cache.get(fixture.key(), fixture.operation).is_none());
    let checked =
        verify_with_cache(&fixture.input, &fixture.output, &fixture.proof, &cache).unwrap();
    assert!(checked.matches_statement(&fixture.input, &fixture.output));
    same_rejection(
        &cache,
        &fixture.input,
        &fixture.output,
        &fixture.corrupt_canonical_proof(),
    );
}
fn digest(ordinal: usize) -> DigestKey {
    let mut digest = [0; 32];
    digest[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
    digest
}
#[test]
fn duplicate_inserts_do_not_extend_the_fifo_or_protect_its_oldest_key_from_eviction() {
    let cache = PreprocessingCache::new();
    let fixture = Fixture::new(Operation::Addition, &cache);
    let key = cache.get(fixture.key(), fixture.operation).unwrap();
    let cache = PreprocessingCache::new();
    for ordinal in 0..CACHE_ENTRIES {
        cache.insert(digest(ordinal), fixture.operation, key.clone());
    }
    for _ in 0..CACHE_ENTRIES {
        cache.insert(digest(0), fixture.operation, key.clone());
    }
    cache.insert(digest(CACHE_ENTRIES), fixture.operation, key);
    assert!(cache.get(digest(0), fixture.operation).is_none());
    assert!(cache.get(digest(1), fixture.operation).is_some());
    assert!(
        cache
            .get(digest(CACHE_ENTRIES), fixture.operation)
            .is_some()
    );
    let entries = cache.entries.lock().unwrap();
    assert_eq!(entries.keys.len(), CACHE_ENTRIES);
    assert_eq!(entries.order.len(), CACHE_ENTRIES);
}
#[test]
fn concurrent_key_inserts_and_clones_preserve_the_shared_bound_and_unique_fifo() {
    let source = PreprocessingCache::new();
    let fixture = Fixture::new(Operation::Addition, &source);
    let key = source.get(fixture.key(), fixture.operation).unwrap();
    let cache = PreprocessingCache::new();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let key = &key;
                let cache = &cache;
                scope.spawn(move || {
                    for ordinal in 0..256 {
                        let current = digest(worker * 256 + ordinal);
                        cache.insert(current, Operation::Addition, key.clone());
                        if let Some(key) = cache.get(current, Operation::Addition) {
                            assert!(valid_shape(&key, Operation::Addition));
                        }
                        cache.insert(digest(usize::MAX), Operation::Addition, key.clone());
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let entries = cache.entries.lock().unwrap();
    assert_eq!(entries.keys.len(), CACHE_ENTRIES);
    assert_eq!(entries.order.len(), CACHE_ENTRIES);
    assert_eq!(
        entries
            .order
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        CACHE_ENTRIES
    );
    assert!(
        entries
            .order
            .iter()
            .all(|digest| entries.keys.contains_key(digest))
    );
}
#[test]
fn cache_identity_binds_the_operation_and_each_exact_statement_hash() {
    let hashes = [[1; 32], [2; 32], Sha256::digest([]).into()];
    let addition = cache_key(Operation::Addition, &hashes);
    assert_ne!(
        addition,
        cache_key(Operation::PublicPolynomialProduct, &hashes)
    );
    for position in 0..3 {
        let mut changed = hashes;
        changed[position][0] ^= 1;
        assert_ne!(addition, cache_key(Operation::Addition, &changed));
    }
}
