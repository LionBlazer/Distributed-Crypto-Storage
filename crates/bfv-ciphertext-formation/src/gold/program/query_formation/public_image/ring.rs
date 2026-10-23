//! Finite coefficient arithmetic for an isolated owning research test.
//! A is a quotient RING; it is deliberately not given a fake Field impl.
use bfv_hiding_stark::{Challenge as E, Val as F};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

pub(super) type Poly = Vec<F>;
pub(super) type Tensor = [Poly; 5];
pub(super) type Result<T> = core::result::Result<T, &'static str>;

pub(super) fn trim(mut p: Poly) -> Poly {
    while p.last() == Some(&F::ZERO) {
        p.pop();
    }
    p
}
pub(super) fn add(a: &[F], b: &[F]) -> Poly {
    let mut result = vec![F::ZERO; a.len().max(b.len())];
    for (i, &value) in a.iter().enumerate() {
        result[i] += value;
    }
    for (i, &value) in b.iter().enumerate() {
        result[i] += value;
    }
    trim(result)
}
pub(super) fn scale(a: &[F], coefficient: F) -> Poly {
    trim(a.iter().map(|&value| value * coefficient).collect())
}
pub(super) fn sub(a: &[F], b: &[F]) -> Poly {
    add(a, &scale(b, -F::ONE))
}
pub(super) fn mul(a: &[F], b: &[F]) -> Poly {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut result = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, &left) in a.iter().enumerate() {
        if left != F::ZERO {
            for (j, &right) in b.iter().enumerate() {
                result[i + j] += left * right;
            }
        }
    }
    trim(result)
}
pub(super) fn divide(a: &[F], b: &[F]) -> Result<(Poly, Poly)> {
    let denominator = trim(b.to_vec());
    let Some(&leading) = denominator.last() else {
        return Err("zero-polynomial-divisor");
    };
    let mut remainder = trim(a.to_vec());
    let mut quotient = vec![F::ZERO; remainder.len().saturating_sub(denominator.len()) + 1];
    let inverse = leading.inverse();
    while remainder.len() >= denominator.len() {
        let degree = remainder.len() - denominator.len();
        let coefficient = *remainder.last().unwrap() * inverse;
        quotient[degree] = coefficient;
        for (i, &value) in denominator.iter().enumerate() {
            remainder[degree + i] -= coefficient * value;
        }
        remainder = trim(remainder);
    }
    Ok((trim(quotient), remainder))
}
pub(super) fn rotate(p: &[F], h: F) -> Poly {
    p.iter()
        .zip(h.powers())
        .map(|(&coefficient, power)| coefficient * power)
        .collect()
}
pub(super) fn evaluate(p: &[F], point: E) -> E {
    p.iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * point + coefficient)
}

#[derive(Clone, Debug)]
pub(super) struct Ring {
    modulus: Poly,
}
impl Ring {
    pub(super) fn checked(modulus: Poly) -> Result<Self> {
        if modulus.len() < 2 || modulus.len() > 395 || modulus.last() != Some(&F::ONE) {
            return Err("monic-modulus-degree");
        }
        Ok(Self { modulus })
    }
    pub(super) fn modulus(&self) -> &[F] {
        &self.modulus
    }
    pub(super) fn degree(&self) -> usize {
        self.modulus.len() - 1
    }
    pub(super) fn reduce(&self, p: &[F]) -> Poly {
        // Monic long reduction. Large public PP polynomials are bounded4096.
        let mut p = trim(p.to_vec());
        while p.len() >= self.modulus.len() {
            let shift = p.len() - self.modulus.len();
            let coefficient = *p.last().unwrap();
            for (i, &value) in self.modulus.iter().enumerate() {
                p[shift + i] -= coefficient * value;
            }
            p = trim(p);
        }
        p
    }
    pub(super) fn multiply(&self, a: &[F], b: &[F]) -> Poly {
        self.reduce(&mul(a, b))
    }
    pub(super) fn power(&self, p: &[F], mut exponent: usize) -> Poly {
        let mut result = vec![F::ONE];
        let mut factor = self.reduce(p);
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = self.multiply(&result, &factor);
            }
            exponent >>= 1;
            if exponent != 0 {
                factor = self.multiply(&factor, &factor);
            }
        }
        result
    }
    pub(super) fn inverse(&self, p: &[F]) -> Result<Poly> {
        let (mut a, mut b) = (self.modulus.clone(), self.reduce(p));
        let (mut u, mut v) = (Vec::new(), vec![F::ONE]);
        while !b.is_empty() {
            let (quotient, remainder) = divide(&a, &b)?;
            let next = sub(&u, &mul(&quotient, &v));
            (a, b) = (b, remainder);
            (u, v) = (v, next);
        }
        if a.len() != 1 {
            return Err("nonunit-in-disclosure-ring");
        }
        Ok(self.reduce(&scale(&u, a[0].inverse())))
    }
    pub(super) fn zero_tensor(&self) -> Tensor {
        core::array::from_fn(|_| Vec::new())
    }
    pub(super) fn lift(&self, p: &[F]) -> Tensor {
        let mut output = self.zero_tensor();
        output[0] = self.reduce(p);
        output
    }
    pub(super) fn constant(&self, value: E) -> Tensor {
        core::array::from_fn(|i| trim(vec![value.as_basis_coefficients_slice()[i]]))
    }
    pub(super) fn tensor_add(&self, a: &Tensor, b: &Tensor) -> Tensor {
        core::array::from_fn(|i| add(&a[i], &b[i]))
    }
    pub(super) fn tensor_sub(&self, a: &Tensor, b: &Tensor) -> Tensor {
        core::array::from_fn(|i| sub(&a[i], &b[i]))
    }
    pub(super) fn tensor_neg(&self, a: &Tensor) -> Tensor {
        core::array::from_fn(|i| scale(&a[i], -F::ONE))
    }
    pub(super) fn tensor_mul(&self, a: &Tensor, b: &Tensor) -> Tensor {
        let mut output = self.zero_tensor();
        // E_coeff=F[u]/(u^5-3). X is the separate residue indeterminate.
        for (i, left) in a.iter().enumerate() {
            for (j, right) in b.iter().enumerate() {
                let product = self.multiply(left, right);
                let (index, coefficient) = if i + j < 5 {
                    (i + j, F::ONE)
                } else {
                    (i + j - 5, F::from_u32(3))
                };
                output[index] = add(&output[index], &scale(&product, coefficient));
            }
        }
        output
    }
    pub(super) fn tensor_scale(&self, value: &Tensor, coefficient: E) -> Tensor {
        self.tensor_mul(value, &self.constant(coefficient))
    }
}

#[test]
fn explicit_small_polynomial_and_tensor_products_keep_the_two_indeterminates() {
    // Independent literal expansion in F[X]/(X^2-3):
    // (X+1)(2X+3)=2X^2+5X+3=9+5X.
    let ring = Ring::checked(vec![-F::from_u32(3), F::ZERO, F::ONE]).unwrap();
    assert_eq!(
        ring.multiply(&[F::ONE, F::ONE], &[F::from_u32(3), F::from_u32(2)]),
        vec![F::from_u32(9), F::from_u32(5)]
    );
    // (u+X)(u-X)=u^2-3, coefficient-by-coefficient, not a collapse X=u.
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let x = ring.lift(&[F::ZERO, F::ONE]);
    let left = ring.tensor_add(&ring.constant(u), &x);
    let right = ring.tensor_sub(&ring.constant(u), &x);
    let product = ring.tensor_mul(&left, &right);
    assert_eq!(
        product,
        [vec![-F::from_u32(3)], vec![], vec![F::ONE], vec![], vec![]]
    );
    assert_eq!(
        ring.tensor_mul(&ring.constant(u.exp_u64(4)), &ring.constant(u.exp_u64(2))),
        ring.constant(u * F::from_u32(3))
    );
    assert_eq!(
        ring.inverse(&ring.reduce(&[-F::ONE, F::ZERO, F::ONE]))
            .unwrap(),
        vec![F::from_u32(2).inverse()]
    );
    assert_eq!(ring.inverse(&[]), Err("nonunit-in-disclosure-ring"));
}
