//! Exact finite raw-digest tape for ONE fixed native Query transcript.
use super::super::research_ro::Tape;
use super::{E, F, Result};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use rand_public_pp::CryptoRng;
use std::collections::BTreeMap;

const ACCEPTED: usize = 277;
const MAX_RAW: usize = 4096;

pub(in crate::gold::program) struct TapePlan {
    pub(super) tape: Tape,
    accepted: Vec<F>,
    indices: Vec<usize>,
    positions: Vec<F>,
    pub(super) row_for_query: Vec<usize>,
}
impl TapePlan {
    /// No RO query/programming: sample complete64-byte digests, preserving every
    /// rejected firstLE64 candidate. The finite raw cap is an explicit error.
    pub(in crate::gold::program) fn sample(rng: &mut impl CryptoRng) -> Result<Self> {
        let mut tape = Tape::new();
        for counter in 0..ACCEPTED as u64 {
            let mut retry = 0;
            loop {
                if tape.len() == MAX_RAW {
                    return Err("Query-tape-raw-limit");
                }
                let mut digest = [0; 64];
                rng.fill_bytes(&mut digest);
                let candidate = u64::from_le_bytes(digest[..8].try_into().unwrap());
                tape.insert((counter, retry), digest);
                if candidate < F::ORDER_U64 {
                    break;
                }
                retry += 1;
            }
        }
        Self::checked(tape)
    }

    pub(in crate::gold::program) fn checked(tape: Tape) -> Result<Self> {
        if tape.is_empty() || tape.len() > MAX_RAW {
            return Err("Query-tape-raw-limit");
        }
        let mut accepted = Vec::with_capacity(ACCEPTED);
        let mut used = 0;
        for counter in 0..ACCEPTED as u64 {
            let mut retry = 0;
            loop {
                let digest = tape.get(&(counter, retry)).ok_or("Query-tape-gap")?;
                used += 1;
                let candidate = u64::from_le_bytes(digest[..8].try_into().unwrap());
                if candidate < F::ORDER_U64 {
                    accepted.push(F::from_u64(candidate));
                    break;
                }
                retry += 1;
                if used == MAX_RAW {
                    return Err("Query-tape-raw-limit");
                }
            }
        }
        if used != tape.len() {
            return Err("Query-tape-unused-raw");
        }
        // Query:10 lookup draws, alpha/zeta/theta5 each,12 native FRI betas5
        // each, then192 low15-bit Gold index draws. Do not replace their law by
        // independently uniform indices or discard full rejected digest bytes.
        let indices = accepted[85..]
            .iter()
            .map(|x| (x.as_canonical_u64() & 32767) as usize)
            .collect::<Vec<_>>();
        if indices.len() != 192 {
            return Err("Query-tape-index-count");
        }
        let omega = F::two_adic_generator(15);
        let mut positions = Vec::new();
        let mut seen = BTreeMap::new();
        let mut row_for_query = Vec::with_capacity(192);
        for &index in &indices {
            let next = positions.len();
            let row = *seen.entry(index).or_insert_with(|| {
                let exponent = index.reverse_bits() >> (usize::BITS - 15);
                positions.push(F::GENERATOR * omega.exp_u64(exponent as u64));
                next
            });
            row_for_query.push(row);
        }
        Ok(Self {
            tape,
            accepted,
            indices,
            positions,
            row_for_query,
        })
    }
    fn extension(&self, start: usize) -> E {
        E::from_basis_coefficients_fn(|i| self.accepted[start + i])
    }
    pub(in crate::gold::program) fn lookup_alpha(&self) -> E {
        self.extension(0)
    }
    pub(in crate::gold::program) fn lookup_beta(&self) -> E {
        self.extension(5)
    }
    pub(in crate::gold::program) fn constraint_alpha(&self) -> E {
        self.extension(10)
    }
    pub(in crate::gold::program) fn z(&self) -> E {
        self.extension(15)
    }
    pub(in crate::gold::program) fn theta(&self) -> E {
        self.extension(20)
    }
    pub(in crate::gold::program) fn indices(&self) -> &[usize] {
        &self.indices
    }
    pub(in crate::gold::program) fn positions(&self) -> &[F] {
        &self.positions
    }
    pub(in crate::gold::program) fn accepted(&self) -> &[F] {
        &self.accepted
    }
}
