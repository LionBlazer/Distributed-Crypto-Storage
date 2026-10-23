//! Coefficient/ring regression for the joint trace/quotient disclosure lemma.
//! Uses actual Gold/EF5 and full location budgets. The polynomial AIR fixture
//! is explicitly algebra-only; it is not an owning SQL AIR or admission gate.
use crate::{Challenge as E, QUERIES, Val as F};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::HasFrobenius;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

type Poly = Vec<F>;

fn trim(mut a: Poly) -> Poly {
    while a.last() == Some(&F::ZERO) {
        a.pop();
    }
    a
}

fn add(a: &[F], b: &[F]) -> Poly {
    let mut out = vec![F::ZERO; a.len().max(b.len())];
    for (i, &x) in a.iter().enumerate() {
        out[i] += x;
    }
    for (i, &x) in b.iter().enumerate() {
        out[i] += x;
    }
    trim(out)
}

fn minus(a: &[F], b: &[F]) -> Poly {
    add(a, &b.iter().map(|&x| -x).collect::<Vec<_>>())
}

fn multiply(a: &[F], b: &[F]) -> Poly {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut out = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        if x == F::ZERO {
            continue;
        }
        for (j, &y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
    trim(out)
}

// Only full-degree reference products use FFT. Residue-ring arithmetic below
// uses independent coefficient multiplication and long division.
fn convolution(a: &[F], b: &[F]) -> Poly {
    let len = a.len() + b.len() - 1;
    let height = len.next_power_of_two();
    let padded = |p: &[F]| {
        let mut v = p.to_vec();
        v.resize(height, F::ZERO);
        RowMajorMatrix::new_col(v)
    };
    let dft = Radix2DitParallel::<F>::default();
    let left = dft.dft_batch(padded(a)).to_row_major_matrix();
    let right = dft.dft_batch(padded(b)).to_row_major_matrix();
    let product = left
        .values
        .iter()
        .zip(&right.values)
        .map(|(&a, &b)| a * b)
        .collect();
    let mut out = dft.idft_batch(RowMajorMatrix::new_col(product)).values;
    out.truncate(len);
    trim(out)
}

fn divide(a: &[F], b: &[F]) -> (Poly, Poly) {
    assert!(!b.is_empty());
    let mut r = trim(a.to_vec());
    let mut q = vec![F::ZERO; a.len().saturating_sub(b.len()) + 1];
    let inverse = b.last().unwrap().inverse();
    while r.len() >= b.len() {
        let offset = r.len() - b.len();
        let scale = *r.last().unwrap() * inverse;
        q[offset] = scale;
        for (i, &v) in b.iter().enumerate() {
            r[offset + i] -= scale * v;
        }
        r = trim(r);
    }
    (trim(q), r)
}

fn modulo(a: &[F], m: &[F]) -> Poly {
    divide(a, m).1
}

fn inverse(a: &[F], m: &[F]) -> Poly {
    let (mut old_r, mut r) = (m.to_vec(), modulo(a, m));
    let (mut old_t, mut t) = (vec![], vec![F::ONE]);
    while !r.is_empty() {
        let (q, next_r) = divide(&old_r, &r);
        let next_t = minus(&old_t, &multiply(&q, &t));
        (old_r, r) = (r, next_r);
        (old_t, t) = (t, next_t);
    }
    assert_eq!(
        old_r.len(),
        1,
        "Z must be a unit on every disclosed location"
    );
    modulo(&old_t.iter().map(|&x| x / old_r[0]).collect::<Vec<_>>(), m)
}

fn rotate(a: &[F], h: F) -> Poly {
    a.iter()
        .zip(h.powers())
        .map(|(&v, power)| v * power)
        .collect()
}

fn eval(a: &[F], x: E) -> E {
    a.iter().rev().fold(E::ZERO, |v, &c| v * x + c)
}

fn basis() -> E {
    E::from_basis_coefficients_fn(|i| F::from_bool(i == 1))
}

fn min_poly(x: E) -> Poly {
    let mut coefficients = vec![E::ONE];
    for j in 0..5 {
        let mut next = vec![E::ZERO; coefficients.len() + 1];
        for (i, &c) in coefficients.iter().enumerate() {
            next[i] -= c * x.repeated_frobenius(j);
            next[i + 1] += c;
        }
        coefficients = next;
    }
    coefficients
        .into_iter()
        .map(|c| <E as ExtensionField<F>>::as_base(&c).unwrap())
        .collect()
}

fn roots(points: &[F]) -> Poly {
    points
        .iter()
        .fold(vec![F::ONE], |p, &x| multiply(&p, &[-x, F::ONE]))
}

fn locations(n: usize) -> (F, Vec<F>, Poly, Poly) {
    let h = F::two_adic_generator(n.ilog2() as usize);
    let omega = F::two_adic_generator(n.ilog2() as usize + 4);
    // S and h*S are disjoint: their exponents are 0 and 16 modulo 32.
    let points: Vec<_> = omega
        .exp_u64(32)
        .shifted_powers(F::GENERATOR)
        .take(QUERIES)
        .collect();
    let shifted: Vec<_> = points.iter().map(|&x| h * x).collect();
    let z = basis();
    let m = multiply(&roots(&points), &min_poly(z));
    let mt = multiply(&multiply(&m, &roots(&shifted)), &min_poly(E::from(h) * z));
    assert_eq!((m.len() - 1, mt.len() - 1), (197, 394));
    assert!(mt.len() - 1 < n);
    (h, points, m, mt)
}

#[test]
fn full_location_tensor_projection_recovers_all_five_quotient_coordinates_at_both_heights() {
    // Valid algebra-only AIR: (P^2-P)*(A(hX)+u)=0 on H. P is a masked
    // constant Boolean trace. A has five separately masked base coordinates.
    for n in [512usize, 2048] {
        let (h, _, m, mt) = locations(n);
        let mut z = vec![F::ZERO; n + 1];
        z[0] = -F::ONE;
        z[n] = F::ONE;
        let z_inverse = inverse(&z, &m);
        assert_eq!(modulo(&multiply(&z, &z_inverse), &m), vec![F::ONE]);
        for bit in [false, true] {
            let r: Vec<_> = (0..n).map(|i| F::from_usize(i + 2)).collect();
            let p = add(&multiply(&z, &r), &[F::from_bool(bit)]);
            let current = modulo(&modulo(&p, &mt), &m);
            let factor = modulo(&minus(&multiply(&current, &current), &current), &m);
            // (P^2-P)/Z derived from the valid original Boolean value.
            let sign = if bit { F::ONE } else { -F::ONE };
            let numerator = add(
                &r.iter().map(|&x| sign * x).collect::<Vec<_>>(),
                &multiply(&z, &convolution(&r, &r)),
            );
            for b in 0..5 {
                let mask: Vec<_> = (0..n)
                    .map(|i| F::from_usize(i + 3).exp_u64((b + 1) as u64))
                    .collect();
                let a = add(&multiply(&z, &mask), &[F::from_usize(b + 1)]);
                let lifted = modulo(&a, &mt);
                let next = modulo(&rotate(&lifted, h), &m);
                assert_eq!(next, modulo(&rotate(&a, h), &m), "pi_h into A");
                let next = if b == 1 { add(&next, &[F::ONE]) } else { next };
                let c_bar = modulo(&multiply(&factor, &next), &m);
                let q_bar = modulo(&multiply(&c_bar, &z_inverse), &m);
                let rotated = rotate(&a, h);
                let rotated = if b == 1 {
                    add(&rotated, &[F::ONE])
                } else {
                    rotated
                };
                let full_q = convolution(&numerator, &rotated);
                assert!(full_q.len() <= 8 * n, "honest quotient degree premise");
                assert_eq!(
                    q_bar,
                    modulo(&full_q, &m),
                    "separate quotient coordinate {b}"
                );
            }
        }
    }
}

#[test]
fn rotation_is_well_defined_only_after_projection_to_the_smaller_disclosure_ring() {
    let n = 512;
    let (h, points, m, mt) = locations(n);
    let mut z = vec![F::ZERO; n + 1];
    z[0] = -F::ONE;
    z[n] = F::ONE;
    let delta = multiply(&z, &mt);
    assert!(delta.len() <= 2 * n);
    assert!(modulo(&delta, &mt).is_empty());
    let shifted_delta = rotate(&delta, h);
    assert!(
        modulo(&shifted_delta, &m).is_empty(),
        "pi_h remains well defined"
    );
    let t = E::from(h * points[QUERIES - 1]);
    assert_eq!(eval(&mt, t), E::ZERO);
    assert_ne!(
        eval(&shifted_delta, t),
        E::ZERO,
        "the invalid endomorphism on A_T would erase this difference"
    );
}

#[test]
fn collapsed_ef5_evaluation_does_not_determine_five_base_coordinate_openings() {
    let u = basis();
    let coordinates = [
        eval(&[F::ZERO, F::ONE], u),
        eval(&[-F::ONE], u),
        E::ZERO,
        E::ZERO,
        E::ZERO,
    ];
    assert_eq!(coordinates[0], u);
    assert_eq!(coordinates[1], -E::ONE);
    assert_eq!(
        coordinates
            .iter()
            .zip(u.powers())
            .map(|(&v, b)| v * b)
            .sum::<E>(),
        E::ZERO
    );
    assert!(coordinates.iter().any(|&c| c != E::ZERO));
}
