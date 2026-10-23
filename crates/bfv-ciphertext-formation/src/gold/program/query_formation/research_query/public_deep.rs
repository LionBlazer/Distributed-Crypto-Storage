//! Public-V-only whole-B sampler for the fixed Query R-DEEP image.
//!
//! Research child of cfg(test) `research_query`, not proof/admission authority.
//! Coordinates are native F/EF5 coefficients in the physical variable X on
//! 7*H32768. No original trace, original R, private witness or V|B solver enters.
use bfv_hiding_stark::{Challenge as E, Val as F};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::HasFrobenius;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField,
    batch_multiplicative_inverse,
};
use rand_public_pp::{CryptoRng, RngExt};
use std::collections::{HashMap, HashSet};

mod tests;

pub(super) type Result<T> = core::result::Result<T, &'static str>;
const K: usize = 4096;
const N: usize = 2048;
const LDE: usize = 32768;
const MAX_S: usize = 192;

#[derive(Clone, Debug)]
pub(super) struct Column {
    pub(super) rows: Vec<F>,
    pub(super) at_z: E,
    pub(super) at_hz: Option<E>,
}

/// Entirely public inputs. PP coefficients come from the independently fixed
/// public Query factory (real zero-interleaved degree<4096 PP), not a witness.
/// This arithmetic module does not authenticate a caller's factory association.
pub(super) struct PublicView<'a> {
    pub(super) s: &'a [F],
    pub(super) z: E,
    pub(super) theta: E,
    pub(super) r: &'a [Column],
    pub(super) main: &'a [Column],
    pub(super) quotient: &'a [Vec<Column>],
    pub(super) pp: &'a [Column],
    pub(super) pp_coefficients: &'a [Vec<F>],
    pub(super) aux: &'a [Column],
}

fn base(x: E) -> Option<F> {
    <E as ExtensionField<F>>::as_base(&x)
}
fn trim<T: PrimeCharacteristicRing + Copy + PartialEq>(mut p: Vec<T>) -> Vec<T> {
    while p.last() == Some(&T::ZERO) {
        p.pop();
    }
    p
}
fn base_product(a: &[F], b: &[F]) -> Vec<F> {
    let mut result = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            result[i + j] += x * y;
        }
    }
    trim(result)
}
fn evaluate(p: &[F], x: E) -> E {
    p.iter()
        .rev()
        .fold(E::ZERO, |v, &coefficient| v * x + coefficient)
}
fn divide_base_root(p: &[F], root: F) -> (Vec<F>, F) {
    let mut quotient = vec![F::ZERO; p.len() - 1];
    let mut remainder = *p.last().expect("nonempty polynomial");
    for i in (0..quotient.len()).rev() {
        quotient[i] = remainder;
        remainder = p[i] + root * remainder;
    }
    (quotient, remainder)
}
fn divide_extension_root(p: &[E], root: E) -> (Vec<E>, E) {
    if p.is_empty() {
        return (Vec::new(), E::ZERO);
    }
    let mut quotient = vec![E::ZERO; p.len() - 1];
    let mut remainder = *p.last().unwrap();
    for i in (0..quotient.len()).rev() {
        quotient[i] = remainder;
        remainder = p[i] + root * remainder;
    }
    (quotient, remainder)
}

fn minimal_polynomial(point: E) -> Result<Vec<F>> {
    if let Some(point) = base(point) {
        return Ok(vec![-point, F::ONE]);
    }
    let mut p = vec![E::ONE];
    for j in 0..5 {
        let root = point.repeated_frobenius(j);
        let mut next = vec![E::ZERO; p.len() + 1];
        for (i, &coefficient) in p.iter().enumerate() {
            next[i] -= root * coefficient;
            next[i + 1] += coefficient;
        }
        p = next;
    }
    p.into_iter()
        .map(|coefficient| base(coefficient).ok_or("minimal-polynomial-not-base"))
        .collect()
}

/// Converts an arbitrary E value into the coefficients of the unique base
/// polynomial of degree<deg(m_point) having that value at point. This explicitly
/// preserves the five Frobenius coordinates instead of identifying X with u.
struct EvaluationBasis {
    dimension: usize,
    inverse: [[F; 5]; 5],
}
impl EvaluationBasis {
    fn new(point: E) -> Result<Self> {
        if base(point).is_some() {
            return Ok(Self {
                dimension: 1,
                inverse: core::array::from_fn(|i| {
                    core::array::from_fn(|j| F::from_bool(i == 0 && j == 0))
                }),
            });
        }
        let powers: Vec<E> = point.powers().take(5).collect();
        let mut rows = [[F::ZERO; 10]; 5];
        for (index, row) in rows.iter_mut().enumerate() {
            for (column, power) in powers.iter().enumerate() {
                row[column] = <E as BasedVectorSpace<F>>::as_basis_coefficients_slice(power)[index];
            }
            row[5 + index] = F::ONE;
        }
        for column in 0..5 {
            let pivot = (column..5)
                .find(|&row| rows[row][column] != F::ZERO)
                .ok_or("nonprimitive-ood-basis")?;
            rows.swap(column, pivot);
            let inverse = rows[column][column].inverse();
            rows[column].iter_mut().for_each(|value| *value *= inverse);
            let pivot = rows[column];
            for (row, values) in rows.iter_mut().enumerate() {
                if row != column {
                    let scale = values[column];
                    for (value, &pivot) in values.iter_mut().zip(&pivot) {
                        *value -= scale * pivot;
                    }
                }
            }
        }
        Ok(Self {
            dimension: 5,
            inverse: core::array::from_fn(|i| core::array::from_fn(|j| rows[i][5 + j])),
        })
    }
    fn represent(&self, value: E) -> Result<Vec<F>> {
        if self.dimension == 1 {
            return base(value)
                .map(|value| vec![value])
                .ok_or("base-ood-requires-base-value");
        }
        let coordinates = <E as BasedVectorSpace<F>>::as_basis_coefficients_slice(&value);
        Ok(self
            .inverse
            .iter()
            .map(|row| row.iter().zip(coordinates).map(|(&a, &b)| a * b).sum())
            .collect())
    }
}

struct Completion {
    modulus: Vec<F>,
    powers: Vec<E>,
    inverse_modulus: E,
    basis: EvaluationBasis,
}
impl Completion {
    fn new(modulus: Vec<F>, point: E) -> Result<Self> {
        let value = evaluate(&modulus, point);
        if value == E::ZERO {
            return Err("overlapping-ood-minimal-polynomials");
        }
        Ok(Self {
            modulus,
            powers: point.powers().take(K).collect(),
            inverse_modulus: value.inverse(),
            basis: EvaluationBasis::new(point)?,
        })
    }
    fn value(&self, p: &[F]) -> E {
        p.iter()
            .zip(&self.powers)
            .map(|(&coefficient, &power)| power * coefficient)
            .sum()
    }
    fn complete(&self, p: &mut Vec<F>, target: E) -> Result<()> {
        let residue = self
            .basis
            .represent((target - self.value(p)) * self.inverse_modulus)?;
        let update = base_product(&self.modulus, &residue);
        p.resize(p.len().max(update.len()), F::ZERO);
        for (value, update) in p.iter_mut().zip(update) {
            *value += update;
        }
        if self.value(p) != target {
            return Err("inconsistent-ood-interpolation");
        }
        Ok(())
    }
}

struct Domain {
    s: Vec<F>,
    indices: Vec<usize>,
    lagrange: Vec<Vec<F>>,
    modulus: Vec<F>,
    z: Completion,
    hz: Completion,
}
impl Domain {
    fn checked(s: &[F], z: E, theta: E) -> Result<Self> {
        if s.len() > MAX_S {
            return Err("too-many-S-locations");
        }
        if base(theta).is_some() {
            return Err("exceptional-base-theta");
        }
        if z == E::ZERO || z.exp_power_of_2(N.ilog2() as usize) == E::ONE {
            return Err("exceptional-zero-or-original-domain-z");
        }
        if (z / E::from(F::GENERATOR)).exp_power_of_2(LDE.ilog2() as usize) == E::ONE {
            return Err("exceptional-input-domain-z");
        }
        let mut distinct = HashSet::new();
        for &point in s {
            if !distinct.insert(point.as_canonical_u64()) {
                return Err("duplicate-S-location");
            }
            if (point / F::GENERATOR).exp_power_of_2(LDE.ilog2() as usize) != F::ONE {
                return Err("S-outside-input-domain");
            }
        }
        let omega = F::two_adic_generator(LDE.ilog2() as usize);
        let lookup: HashMap<_, _> = omega
            .powers()
            .take(LDE)
            .enumerate()
            .map(|(i, x)| ((F::GENERATOR * x).as_canonical_u64(), i))
            .collect();
        let indices = s
            .iter()
            .map(|point| {
                lookup
                    .get(&point.as_canonical_u64())
                    .copied()
                    .ok_or("S-domain-index")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut roots = vec![F::ONE];
        for &point in s {
            roots = base_product(&roots, &[-point, F::ONE]);
        }
        let mut lagrange = Vec::with_capacity(s.len());
        let mut denominators = Vec::with_capacity(s.len());
        for &point in s {
            let (quotient, remainder) = divide_base_root(&roots, point);
            if remainder != F::ZERO {
                return Err("S-root-division");
            }
            let denominator = base(evaluate(&quotient, E::from(point))).unwrap();
            if denominator == F::ZERO {
                return Err("duplicate-S-location");
            }
            lagrange.push(quotient);
            denominators.push(denominator);
        }
        for (basis, inverse) in lagrange
            .iter_mut()
            .zip(batch_multiplicative_inverse(&denominators))
        {
            for coefficient in basis {
                *coefficient *= inverse;
            }
        }
        let modulus = base_product(&roots, &minimal_polynomial(z)?);
        if modulus.len() > K {
            return Err("disclosure-modulus-too-large");
        }
        let hz = z * F::two_adic_generator(N.ilog2() as usize);
        Ok(Self {
            s: s.to_vec(),
            indices,
            lagrange,
            modulus: modulus.clone(),
            z: Completion::new(roots, z)?,
            hz: Completion::new(modulus, hz)?,
        })
    }
    fn representative(&self, column: &Column, two: bool) -> Result<Vec<F>> {
        require_column(column, self.s.len(), two)?;
        let mut p = vec![F::ZERO; self.s.len()];
        for (&value, basis) in column.rows.iter().zip(&self.lagrange) {
            for (coefficient, &basis) in p.iter_mut().zip(basis) {
                *coefficient += value * basis;
            }
        }
        self.z.complete(&mut p, column.at_z)?;
        if two {
            self.hz.complete(&mut p, column.at_hz.unwrap())?;
        }
        Ok(trim(p))
    }
    fn check_public_pp(&self, column: &Column, p: &[F]) -> Result<()> {
        require_column(column, self.s.len(), false)?;
        if p.len() > K {
            return Err("public-PP-degree-bound");
        }
        let p = &p[..p
            .iter()
            .rposition(|&value| value != F::ZERO)
            .map_or(0, |last| last + 1)];
        if self.z.value(p) != column.at_z {
            return Err("public-PP-OOD-mismatch");
        }
        if p.len() <= 64 || self.s.len() * p.len() < LDE {
            if self
                .s
                .iter()
                .zip(&column.rows)
                .any(|(&point, &value)| evaluate(p, E::from(point)) != E::from(value))
            {
                return Err("public-PP-row-mismatch");
            }
        } else {
            let mut padded = p.to_vec();
            padded.resize(LDE, F::ZERO);
            let values = Radix2DitParallel::<F>::default().coset_dft(padded, F::GENERATOR);
            if self
                .indices
                .iter()
                .zip(&column.rows)
                .any(|(&index, &value)| values[index] != value)
            {
                return Err("public-PP-row-mismatch");
            }
        }
        Ok(())
    }
}

fn require_column(column: &Column, rows: usize, two: bool) -> Result<()> {
    if column.rows.len() != rows || column.at_hz.is_some() != two {
        return Err("column-disclosure-shape");
    }
    Ok(())
}

struct Accumulator {
    theta: E,
    power: E,
    count: usize,
    z: Vec<E>,
    hz: Vec<E>,
    claim_z: E,
    claim_hz: E,
}
impl Accumulator {
    fn new(theta: E) -> Self {
        Self {
            theta,
            power: E::ONE,
            count: 0,
            z: vec![E::ZERO; K],
            hz: vec![E::ZERO; K],
            claim_z: E::ZERO,
            claim_hz: E::ZERO,
        }
    }
    fn matrix(&mut self, columns: &[Column], representatives: &[Vec<F>], two: bool) {
        // EXACT native order is matrix -> POINT -> column, not column -> point.
        for point in 0..if two { 2 } else { 1 } {
            for (column, p) in columns.iter().zip(representatives) {
                let (sum, claim, value) = if point == 0 {
                    (&mut self.z, &mut self.claim_z, column.at_z)
                } else {
                    (&mut self.hz, &mut self.claim_hz, column.at_hz.unwrap())
                };
                for (sum, &coefficient) in sum.iter_mut().zip(p) {
                    if coefficient != F::ZERO {
                        *sum += self.power * coefficient;
                    }
                }
                *claim += self.power * value;
                self.power *= self.theta;
                self.count += 1;
            }
        }
    }
    fn private_matrix(&mut self, domain: &Domain, columns: &[Column], two: bool) -> Result<()> {
        let representatives = columns
            .iter()
            .map(|column| domain.representative(column, two))
            .collect::<Result<Vec<_>>>()?;
        self.matrix(columns, &representatives, two);
        Ok(())
    }
}

/// Deterministic affine law, never a verified Query/statement capability.
pub(super) struct Prepared {
    origin: Vec<E>,
    direction: Vec<E>,
    free: usize,
    openings: usize,
}
impl Prepared {
    pub(super) fn origin(&self) -> &[E] {
        &self.origin
    }
    pub(super) fn direction(&self) -> &[E] {
        &self.direction
    }
    pub(super) fn free_coefficients(&self) -> usize {
        self.free
    }
    pub(super) fn opening_count(&self) -> usize {
        self.openings
    }
    pub(super) fn instantiate(&self, u: &[E]) -> Result<Vec<E>> {
        if u.len() != self.free {
            return Err("affine-randomness-degree");
        }
        // Native base-field DFT transports all FIVE E coordinates. Product
        // length is exactly k-1, so one4096-point convolution suffices.
        let len = self.direction.len() + u.len() - 1;
        let height = len.next_power_of_two();
        let dft = Radix2DitParallel::<F>::default();
        let mut left = self.direction.clone();
        left.resize(height, E::ZERO);
        let mut right = u.to_vec();
        right.resize(height, E::ZERO);
        let left = dft.dft_algebra(left);
        let right = dft.dft_algebra(right);
        let product: Vec<E> = left.into_iter().zip(right).map(|(a, b)| a * b).collect();
        let mut result = dft.idft_algebra(product);
        result.truncate(len);
        for (coefficient, &origin) in result.iter_mut().zip(&self.origin) {
            *coefficient += origin;
        }
        Ok(result)
    }
    /// Uniformity is the ideal independent coefficient-cell premise. This
    /// diagnostic caller owns its CSPRNG; no OS/private production config is made.
    pub(super) fn sample<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Vec<E> {
        let u = (0..self.free)
            .map(|_| E::from_basis_coefficients_fn(|_| rng.random::<F>()))
            .collect::<Vec<_>>();
        self.instantiate(&u).expect("internally exact degree")
    }
}

pub(super) fn prepare(view: &PublicView<'_>) -> Result<Prepared> {
    if view.r.len() != 10
        || view.main.len() != 421
        || view.quotient.len() != 8
        || view.quotient.iter().any(|matrix| matrix.len() != 10)
        || view.pp.len() != 545
        || view.pp_coefficients.len() != 545
        || view.aux.len() != 425
    {
        return Err("fixed-Query-matrix-shape");
    }
    // All raw container extents before domain setup, interpolation or DFT work.
    for (columns, two) in [
        (view.r, false),
        (view.main, true),
        (view.pp, false),
        (view.aux, true),
    ] {
        for column in columns {
            require_column(column, view.s.len(), two)?;
        }
    }
    for matrix in view.quotient {
        for column in matrix {
            require_column(column, view.s.len(), false)?;
        }
    }
    if view.pp_coefficients.iter().any(|p| p.len() > K) {
        return Err("public-PP-degree-bound");
    }
    let domain = Domain::checked(view.s, view.z, view.theta)?;
    for (column, p) in view.pp.iter().zip(view.pp_coefficients) {
        domain.check_public_pp(column, p)?;
    }
    let mut accumulator = Accumulator::new(view.theta);
    accumulator.private_matrix(&domain, view.r, false)?;
    accumulator.private_matrix(&domain, view.main, true)?;
    for matrix in view.quotient {
        accumulator.private_matrix(&domain, matrix, false)?;
    }
    accumulator.matrix(view.pp, view.pp_coefficients, false);
    accumulator.private_matrix(&domain, view.aux, true)?;
    if accumulator.count != 2327 {
        return Err("native-opening-inventory");
    }
    let hz = view.z * F::two_adic_generator(N.ilog2() as usize);
    let (mut origin, remainder_z) = divide_extension_root(&accumulator.z, view.z);
    let (next, remainder_hz) = divide_extension_root(&accumulator.hz, hz);
    if remainder_z != accumulator.claim_z || remainder_hz != accumulator.claim_hz {
        return Err("weighted-OOD-remainder");
    }
    for (coefficient, next) in origin.iter_mut().zip(next) {
        *coefficient += next;
    }
    let lifted = domain
        .modulus
        .iter()
        .copied()
        .map(E::from)
        .collect::<Vec<_>>();
    let (direction, remainder) = divide_extension_root(&lifted, view.z);
    if remainder != E::ZERO {
        return Err("mask-direction-not-divisible");
    }
    let free = K - (domain.modulus.len() - 1);
    Ok(Prepared {
        origin,
        direction,
        free,
        openings: accumulator.count,
    })
}
