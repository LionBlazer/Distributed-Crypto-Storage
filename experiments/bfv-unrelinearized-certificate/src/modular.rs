//! Public coefficient arithmetic for the closed certificate checker.
//!
//! Horner evaluation keeps its accumulator in the ordinary residue domain. Only
//! the common point is in Montgomery form, so coefficients need no conversion.
//! This module has no private-witness or cryptographic security authority.
use crate::{Error, Result};

pub(crate) struct Modulus {
    p: u64,
    negative_inverse: u64,
    r_squared: u64,
}
impl Modulus {
    /// The strict bound makes both the product and the REDC addition fit u128.
    /// Primality is not needed here; the certificate fixes its own prime fields.
    pub(crate) fn new(p: u64) -> Result<Self> {
        if p < 3 || p.is_multiple_of(2) || p >= 1 << 62 {
            return Err(Error::Shape);
        }
        let mut inverse = 1u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2u64.wrapping_sub(p.wrapping_mul(inverse)));
        }
        let r = (1u128 << 64) % u128::from(p);
        Ok(Self {
            p,
            negative_inverse: inverse.wrapping_neg(),
            r_squared: (r * r % u128::from(p)) as u64,
        })
    }
    /// All operands in this private module are canonical. The caller validates
    /// complete input vectors before evaluation; points come from hash-to-field.
    fn reduce(&self, a: u64, b: u64) -> u64 {
        debug_assert!(a < self.p && b < self.p);
        let product = u128::from(a) * u128::from(b);
        let cancellation = (product as u64).wrapping_mul(self.negative_inverse);
        // product < p^2 < 2^124; cancellation*p < 2^126. No u128 wrap.
        let sum = product + u128::from(cancellation) * u128::from(self.p);
        debug_assert_eq!(sum as u64, 0);
        let value = (sum >> 64) as u64;
        if value >= self.p {
            value - self.p
        } else {
            value
        }
    }
    fn encode(&self, value: u64) -> u64 {
        self.reduce(value, self.r_squared)
    }
    pub(crate) fn add(&self, a: u64, b: u64) -> u64 {
        debug_assert!(a < self.p && b < self.p);
        let sum = a + b;
        if sum >= self.p { sum - self.p } else { sum }
    }
    pub(crate) fn multiply(&self, a: u64, b: u64) -> u64 {
        self.reduce(a, self.encode(b))
    }
    pub(crate) fn power(&self, point: u64, mut exponent: u64) -> u64 {
        let mut value = self.encode(1);
        let mut base = self.encode(point);
        while exponent != 0 {
            if exponent & 1 != 0 {
                value = self.reduce(value, base);
            }
            base = self.reduce(base, base);
            exponent >>= 1;
        }
        self.reduce(value, 1)
    }
    pub(crate) fn evaluate(&self, coefficients: &[u64], point: u64) -> u64 {
        let point = self.encode(point);
        coefficients.iter().rev().fold(0, |value, &coefficient| {
            self.add(self.reduce(value, point), coefficient)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::{N, QP};
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;

    #[test]
    fn every_small_residue_product_and_sum_matches_independent_big_integer_arithmetic() -> Result<()>
    {
        for p in [3u64, 5, 97] {
            let field = Modulus::new(p)?;
            for a in 0..p {
                for b in 0..p {
                    let modulus = BigUint::from(p);
                    assert_eq!(
                        field.multiply(a, b),
                        ((BigUint::from(a) * BigUint::from(b)) % &modulus)
                            .to_u64()
                            .unwrap()
                    );
                    assert_eq!(
                        field.add(a, b),
                        ((BigUint::from(a) + BigUint::from(b)) % &modulus)
                            .to_u64()
                            .unwrap()
                    );
                }
            }
        }
        Ok(())
    }
    #[test]
    fn complete_fixed_profile_polynomials_and_boundary_points_match_big_integers() -> Result<()> {
        for p in QP {
            let field = Modulus::new(p)?;
            let modulus = BigUint::from(p);
            let coefficients: Vec<_> = (0..N)
                .map(|i| match i % 4 {
                    0 => 0,
                    1 => p - 1,
                    2 => p / 2,
                    _ => (i as u64 * 7919 + 17) % p,
                })
                .collect();
            for point in [0, 1, 2, p / 2, p - 1] {
                let expected = coefficients
                    .iter()
                    .rev()
                    .fold(BigUint::from(0u64), |value, &coefficient| {
                        (value * point + coefficient) % &modulus
                    });
                assert_eq!(
                    field.evaluate(&coefficients, point),
                    expected.to_u64().unwrap()
                );
                assert_eq!(
                    field.power(point, N as u64),
                    BigUint::from(point)
                        .modpow(&BigUint::from(N), &modulus)
                        .to_u64()
                        .unwrap()
                );
                for a in [0, 1, p / 2, p - 1] {
                    assert_eq!(
                        field.multiply(a, point),
                        (BigUint::from(a) * point % &modulus).to_u64().unwrap()
                    );
                }
            }
        }
        Ok(())
    }
    #[test]
    fn unsupported_moduli_reject_before_montgomery_setup() {
        for p in [0, 1, 2, 4, 1 << 62, (1 << 62) + 1, u64::MAX] {
            assert!(Modulus::new(p).is_err());
        }
    }
}
