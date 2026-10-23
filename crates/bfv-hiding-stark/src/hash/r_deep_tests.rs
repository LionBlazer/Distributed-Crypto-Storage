//! Exact coefficient-space examples for the fixed-location R-DEEP lemma.
//! Actual Gold/EF5 and both native height classes; no proof or admission.
use crate::{Challenge as E, EXTENSION_DEGREE, LOG_BLOWUP, QUERIES, Val as F};
use p3_field::extension::HasFrobenius;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};

fn generator() -> E {
    E::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO })
}

fn base(point: E) -> Option<F> {
    <E as ExtensionField<F>>::as_base(&point)
}

fn coordinates(point: &E) -> &[F] {
    <E as BasedVectorSpace<F>>::as_basis_coefficients_slice(point)
}

fn product<T: PrimeCharacteristicRing + Copy>(a: &[T], b: &[T]) -> Vec<T> {
    let mut out = vec![T::ZERO; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
    out
}

fn value(poly: &[E], point: E) -> E {
    poly.iter().rev().fold(E::ZERO, |v, &c| v * point + c)
}

fn lift(poly: &[F]) -> Vec<E> {
    poly.iter().copied().map(E::from).collect()
}

fn normalize(mut poly: Vec<E>) -> Vec<E> {
    while poly.last() == Some(&E::ZERO) {
        poly.pop();
    }
    poly
}

// Exact synthetic division of P(X)-P(z), retaining the independently computed
// remainder. This does not assume the input is divisible by X-z.
fn deep(poly: &[E], point: E) -> (Vec<E>, E) {
    let mut out = vec![E::ZERO; poly.len() - 1];
    let mut remainder = *poly.last().unwrap();
    for i in (0..out.len()).rev() {
        out[i] = remainder;
        remainder = poly[i] + point * remainder;
    }
    assert_eq!(remainder, value(poly, point));
    (out, remainder)
}

fn minimal_polynomial(point: E) -> Vec<F> {
    let conjugates = if base(point).is_some() {
        1
    } else {
        EXTENSION_DEGREE
    };
    let mut poly = vec![E::ONE];
    for j in 0..conjugates {
        poly = product(&poly, &[-point.repeated_frobenius(j), E::ONE]);
    }
    poly.into_iter().map(|c| base(c).unwrap()).collect()
}

fn locations(k: usize) -> (Vec<E>, Vec<F>) {
    let omega = F::two_adic_generator(k.ilog2() as usize + LOG_BLOWUP);
    let mut points = Vec::new();
    let mut zeroes = vec![F::ONE];
    let mut point = F::GENERATOR;
    for _ in 0..QUERIES {
        points.push(E::from(point));
        zeroes = product(&zeroes, &[-point, F::ONE]);
        point *= omega;
    }
    assert_eq!(points.len(), QUERIES);
    for &point in &points {
        assert_eq!(value(&lift(&zeroes), point), E::ZERO);
    }
    (points, zeroes)
}

// Invert the actual power-basis change over Gold, rather than assuming that a
// number of random columns alone establishes surjectivity.
fn power_basis_inverse(theta: E) -> Option<[[F; 5]; 5]> {
    assert_eq!(EXTENSION_DEGREE, 5);
    let powers: Vec<_> = theta.powers().take(5).collect();
    let mut rows = [[F::ZERO; 10]; 5];
    for (r, row) in rows.iter_mut().enumerate() {
        for (c, power) in powers.iter().enumerate() {
            row[c] = coordinates(power)[r];
        }
        row[5 + r] = F::ONE;
    }
    for col in 0..5 {
        let pivot = (col..5).find(|&r| rows[r][col] != F::ZERO)?;
        rows.swap(col, pivot);
        let scale = rows[col][col].inverse();
        rows[col].iter_mut().for_each(|x| *x *= scale);
        let pivot = rows[col];
        for (r, row) in rows.iter_mut().enumerate() {
            if r != col {
                let scale = row[col];
                for (x, &p) in row.iter_mut().zip(&pivot) {
                    *x -= scale * p;
                }
            }
        }
    }
    Some(core::array::from_fn(|r| {
        core::array::from_fn(|c| rows[r][5 + c])
    }))
}

fn combine(target: &[E], vanishing: &[F], zeta: E, theta: E) -> Vec<E> {
    let inverse = power_basis_inverse(theta).unwrap();
    let mut sum = vec![E::ZERO; target.len() + vanishing.len() - 2];
    for (j, row) in inverse.iter().enumerate() {
        let coordinates: Vec<F> = target
            .iter()
            .map(|c| row.iter().zip(coordinates(c)).map(|(&a, &b)| a * b).sum())
            .collect();
        let r = lift(&product(vanishing, &coordinates));
        let (quotient, remainder) = deep(&r, zeta);
        assert_eq!(remainder, E::ZERO);
        for (out, c) in sum.iter_mut().zip(quotient) {
            *out += theta.exp_u64(j as u64) * c;
        }
    }
    normalize(sum)
}

#[test]
fn conditional_r_columns_cover_the_entire_required_affine_direction_at_native_heights() {
    let zeta = generator();
    let theta = zeta + E::from_u32(3);
    let min = minimal_polynomial(zeta);
    assert_eq!(min.len() - 1, 5);
    for k in [1024usize, 4096] {
        let (points, rows) = locations(k);
        let vanishing = product(&min, &rows);
        assert_eq!(vanishing.len() - 1, QUERIES + 5);
        let (direction, remainder) = deep(&lift(&vanishing), zeta);
        assert_eq!(remainder, E::ZERO);
        // Full remaining degree, all five extension coordinates, no reduced
        // toy height or subset of the allowed coefficient directions.
        let target: Vec<E> = (0..k - (vanishing.len() - 1))
            .map(|i| {
                E::from_basis_coefficients_fn(|j| F::from_usize(i + 2).exp_u64((j + 1) as u64))
            })
            .collect();
        let expected = normalize(product(&direction, &target));
        assert_eq!(expected.len(), k - 1);
        assert_eq!(combine(&target, &vanishing, zeta, theta), expected);
        for point in points
            .into_iter()
            .chain((1..5).map(|j| zeta.repeated_frobenius(j)))
        {
            assert_eq!(value(&expected, point), E::ZERO);
        }
        // Those extra conjugate zeros are real: the mask does NOT cover every
        // arbitrary reduced polynomial, but covers the required affine fiber.
        assert_ne!(value(&[E::ONE], zeta.repeated_frobenius(1)), E::ZERO);
    }
}

#[test]
fn rotated_opening_differences_share_the_same_direction_and_expose_bad_basefield_mixing() {
    let zeta = generator();
    let theta = zeta + E::ONE;
    let h = E::from(F::two_adic_generator(9));
    let min = minimal_polynomial(zeta);
    let rotated_min = minimal_polynomial(h * zeta);
    assert_ne!(min, rotated_min);
    let (_, rows) = locations(1024);
    let vanishing = product(&min, &rows);
    let delta = lift(&product(&vanishing, &rotated_min));
    let (current, zero) = deep(&delta, zeta);
    let (next, rotated_zero) = deep(&delta, h * zeta);
    assert_eq!((zero, rotated_zero), (E::ZERO, E::ZERO));
    let (direction, _) = deep(&lift(&vanishing), zeta);
    let (rotated_factor, _) = deep(&lift(&rotated_min), h * zeta);
    let next_direction = product(&[-zeta, E::ONE], &rotated_factor);
    for mixing in [theta, E::from_u32(2)] {
        let c0 = mixing.exp_u64(10);
        let c1 = mixing.exp_u64(27);
        let residual: Vec<_> = current
            .iter()
            .zip(&next)
            .map(|(&a, &b)| c0 * a + c1 * b)
            .collect();
        let quotient: Vec<_> = lift(&rotated_min)
            .iter()
            .zip(&next_direction)
            .map(|(&a, &b)| c0 * a + c1 * b)
            .collect();
        assert_eq!(
            normalize(product(&direction, &quotient)),
            normalize(residual.clone())
        );
        if mixing == theta {
            assert_eq!(
                combine(&quotient, &vanishing, zeta, mixing),
                normalize(residual)
            );
        } else {
            assert!(power_basis_inverse(mixing).is_none());
            assert!(quotient.iter().any(|&c| base(c).is_none()));
        }
    }
}

#[test]
fn basefield_ood_points_have_their_correct_smaller_image_and_are_not_an_extra_privacy_failure() {
    let theta = generator();
    let (_, rows) = locations(1024);
    for zeta in [E::ZERO, E::from_u32(11)] {
        let min = minimal_polynomial(zeta);
        assert_eq!(min.len(), 2);
        let vanishing = product(&min, &rows);
        let target = vec![generator(), E::ONE, generator().square()];
        assert_eq!(
            combine(&target, &vanishing, zeta, theta),
            normalize(product(&lift(&rows), &target))
        );
    }
    // The zero-point algebraic identity is valid. Native interpolation rejects
    // zeta=0, so producer abort accounting must still include that point.
    assert!(power_basis_inverse(E::ZERO).is_none());
}
