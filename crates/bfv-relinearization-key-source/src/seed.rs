//! Exact pinned public seeded c1 expansion, with no polynomial/NTT evaluation.
use crate::{
    COEFFICIENTS, DEGREE, Error, KEY_COMPONENTS, MODULI, Result, UnverifiedSeededRelinearizationKey,
};
use fhe_math::zq::Modulus;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

/// Ordered public NTT c1 values expanded from one canonical source's public seed.
/// This supplies neither c0 NTT links nor a same-secret/owner/computation proof.
pub struct UnverifiedExpandedSeededKey {
    keyset_id: [u8; 32],
    c1: [Vec<u64>; KEY_COMPONENTS],
}
impl UnverifiedExpandedSeededKey {
    /// Complete source setup identity; byte identity is not key authority.
    pub fn keyset_id(&self) -> [u8; 32] {
        self.keyset_id
    }
    /// Complete Q5 NTT c1 for decomposition index0..4 in original modulus order.
    pub fn c1_ntt(&self, decomposition: usize) -> Option<&[u64]> {
        self.c1.get(decomposition).map(Vec::as_slice)
    }
}
impl UnverifiedSeededRelinearizationKey<'_> {
    /// Explicit public expansion: outer ChaCha8(seed), five sequential seed_i32,
    /// SHA256(seed_i), then inner ChaCha8 and the SDK's exact Modulus::random_vec
    /// sampler in Q5 row order. These are directly NTT coefficients, not PB
    /// coefficients requiring a hidden transform. No Context or Poly is created.
    pub fn expand_c1_ntt(&self) -> Result<UnverifiedExpandedSeededKey> {
        let moduli = MODULI
            .iter()
            .map(|q| Modulus::new(*q).map_err(|_| Error::FixedParameters))
            .collect::<Result<Vec<_>>>()?;
        let mut outer = ChaCha8Rng::from_seed(self.seed());
        let c1 = core::array::from_fn(|_| {
            let mut seed = [0u8; 32];
            outer.fill(&mut seed);
            let mut inner = ChaCha8Rng::from_seed(Sha256::digest(seed).into());
            let mut values = Vec::with_capacity(COEFFICIENTS);
            for modulus in &moduli {
                values.extend(modulus.random_vec(DEGREE, &mut inner));
            }
            values
        });
        Ok(UnverifiedExpandedSeededKey {
            keyset_id: self.keyset_id(),
            c1,
        })
    }
}
