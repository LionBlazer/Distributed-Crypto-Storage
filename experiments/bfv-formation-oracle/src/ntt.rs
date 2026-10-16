//! Transparent canonical arithmetic reference for the pinned public NTT convention.
//! Unlike upstream's lazy/Shoup butterflies, every output is reduced with u128.
use crate::{DEGREE, LOG_DEGREE, Result};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub(crate) fn mul(a: u64, b: u64, modulus: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(modulus)) as u64
}
pub(crate) fn pow(mut value: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul(result, value, modulus);
        }
        value = mul(value, value, modulus);
        exponent >>= 1;
    }
    result
}

pub(crate) struct ReferenceNtt {
    modulus: u64,
    omegas: Vec<u64>,
    inverses: Vec<u64>,
    size_inverse: u64,
}
impl ReferenceNtt {
    pub(crate) fn new(modulus: u64) -> Result<Self> {
        if modulus <= 1 || !(modulus - 1).is_multiple_of(2 * DEGREE as u64) {
            return Err("pinned modulus does not support this NTT".into());
        }
        // Exact public root-selection convention in fhe-math 0.1.1 native.rs.
        // This fixed RNG only derives PUBLIC twiddles, never an encryption key.
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut root = None;
        for _ in 0..100 {
            let candidate = pow(
                rng.random_range(0..modulus),
                (modulus - 1) / (2 * DEGREE as u64),
                modulus,
            );
            if pow(candidate, 2 * DEGREE as u64, modulus) == 1
                && pow(candidate, DEGREE as u64, modulus) != 1
            {
                root = Some(candidate);
                break;
            }
        }
        let root = root.ok_or("public primitive-root search failed")?;
        let root_inverse = pow(root, modulus - 2, modulus);
        let mut powers = Vec::with_capacity(DEGREE);
        let mut inverse_powers = Vec::with_capacity(DEGREE);
        let (mut value, mut inverse_value) = (1, root_inverse);
        for _ in 0..DEGREE {
            powers.push(value);
            inverse_powers.push(inverse_value);
            value = mul(value, root, modulus);
            inverse_value = mul(inverse_value, root_inverse, modulus);
        }
        let reverse = |index: usize| index.reverse_bits() >> (usize::BITS - LOG_DEGREE);
        Ok(Self {
            modulus,
            omegas: (0..DEGREE).map(|i| powers[reverse(i)]).collect(),
            inverses: (0..DEGREE).map(|i| inverse_powers[reverse(i)]).collect(),
            size_inverse: pow(DEGREE as u64, modulus - 2, modulus),
        })
    }
    fn check(&self, values: &[u64]) -> Result<()> {
        if values.len() != DEGREE || values.iter().any(|v| *v >= self.modulus) {
            return Err("noncanonical reference NTT input".into());
        }
        Ok(())
    }
    pub(crate) fn forward(&self, values: &mut [u64]) -> Result<()> {
        self.check(values)?;
        let mut length = DEGREE / 2;
        let mut omega_index = 1;
        while length != 0 {
            for chunk in values.chunks_exact_mut(2 * length) {
                let omega = self.omegas[omega_index];
                omega_index += 1;
                let (left, right) = chunk.split_at_mut(length);
                for (x, y) in left.iter_mut().zip(right) {
                    let old_x = *x;
                    let product = mul(*y, omega, self.modulus);
                    *x = (old_x + product) % self.modulus;
                    *y = (old_x + self.modulus - product) % self.modulus;
                }
            }
            length /= 2;
        }
        Ok(())
    }
    pub(crate) fn backward(&self, values: &mut [u64]) -> Result<()> {
        self.check(values)?;
        let mut length = 1;
        let mut inverse_index = 0;
        while length < DEGREE {
            for chunk in values.chunks_exact_mut(2 * length) {
                let inverse = self.inverses[inverse_index];
                inverse_index += 1;
                let (left, right) = chunk.split_at_mut(length);
                for (x, y) in left.iter_mut().zip(right) {
                    let old_x = *x;
                    *x = (old_x + *y) % self.modulus;
                    *y = mul(old_x + self.modulus - *y, inverse, self.modulus);
                }
            }
            length *= 2;
        }
        for value in values {
            *value = mul(*value, self.size_inverse, self.modulus);
        }
        Ok(())
    }
}
