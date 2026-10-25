//! Algebra-only public fixtures, never original private DATA traces/proofs.
mod joint_data;

use super::*;
use rand_public_pp::{SeedableRng, rngs::StdRng};

fn u() -> E {
    E::from_basis_coefficients_fn(|i| F::from_bool(i == 1))
}
fn physical_index(index: usize) -> usize {
    index.reverse_bits() >> (usize::BITS - 15)
}
fn rows(count: usize) -> Vec<F> {
    let omega = F::two_adic_generator(15);
    (0..count)
        .map(|index| F::GENERATOR * omega.exp_u64(physical_index(index) as u64))
        .collect()
}
fn eval_e(p: &[E], point: E) -> E {
    p.iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * point + coefficient)
}
fn column(p: &[F], s: &[F], z: E, two: bool) -> Column {
    Column {
        rows: s
            .iter()
            .map(|&point| base(evaluate(p, E::from(point))).unwrap())
            .collect(),
        at_z: evaluate(p, z),
        at_hz: two.then(|| evaluate(p, z * F::two_adic_generator(11))),
    }
}

struct Fixture {
    s: Vec<F>,
    z: E,
    theta: E,
    r: Vec<Column>,
    main: Vec<Column>,
    quotient: Vec<Vec<Column>>,
    pp: Vec<Column>,
    pp_coefficients: Vec<Vec<F>>,
    aux: Vec<Column>,
}
impl Fixture {
    fn zero(s: Vec<F>, z: E) -> Self {
        let one = column(&[], &s, z, false);
        let two = column(&[], &s, z, true);
        Self {
            s,
            z,
            theta: u() + E::from_u32(3),
            r: vec![one.clone(); 10],
            main: vec![two.clone(); 517],
            quotient: vec![vec![one.clone(); 10]; 8],
            pp: vec![one; 668],
            pp_coefficients: vec![vec![]; 668],
            aux: vec![two; 415],
        }
    }
    fn view(&self) -> PublicView<'_> {
        PublicView {
            s: &self.s,
            z: self.z,
            theta: self.theta,
            r: &self.r,
            main: &self.main,
            quotient: &self.quotient,
            pp: &self.pp,
            pp_coefficients: &self.pp_coefficients,
            aux: &self.aux,
        }
    }
}

#[test]
fn two_base_disclosures_reconstruct_literal_linear_polynomial_and_deep_constant() {
    let z = E::from_u32(11);
    let domain = Domain::checked(&[F::from_u32(7)], z, u()).unwrap();
    // p(X)=2+3X, so p(7)=23 and p(11)=35. These are literal independent values.
    let disclosure = Column {
        rows: vec![F::from_u32(23)],
        at_z: E::from_u32(35),
        at_hz: None,
    };
    let p = domain.representative(&disclosure, false).unwrap();
    assert_eq!(p, [F::from_u32(2), F::from_u32(3)]);
    let (deep, remainder) =
        divide_extension_root(&p.iter().copied().map(E::from).collect::<Vec<_>>(), z);
    assert_eq!(deep, [E::from_u32(3)]);
    assert_eq!(remainder, E::from_u32(35));
}

#[test]
fn base_crt_preserves_all_five_frobenius_coordinates_at_both_ood_points() {
    let s = rows(2);
    let z = u() + E::from_u32(2);
    let domain = Domain::checked(&s, z, u()).unwrap();
    let p = (1..=8).map(F::from_u32).collect::<Vec<_>>();
    let disclosure = column(&p, &s, z, true);
    let representative = domain.representative(&disclosure, true).unwrap();
    assert_eq!(representative, p);
    for j in 0..5 {
        assert_eq!(
            evaluate(&representative, z.repeated_frobenius(j)),
            disclosure.at_z.repeated_frobenius(j)
        );
        let hz = z * F::two_adic_generator(11);
        assert_eq!(
            evaluate(&representative, hz.repeated_frobenius(j)),
            disclosure.at_hz.unwrap().repeated_frobenius(j)
        );
    }
    let basis = EvaluationBasis::new(z).unwrap();
    for coordinate in 0..5 {
        let value = E::from_basis_coefficients_fn(|i| F::from_bool(i == coordinate));
        assert_eq!(evaluate(&basis.represent(value).unwrap(), z), value);
    }
}

#[test]
fn literal_native_point_then_column_exponents_include_every_matrix_boundary() {
    let mut fixture = Fixture::zero(rows(2), u() + E::from_u32(2));
    let linear = |slope| vec![F::ZERO, F::from_u32(slope)];
    for (index, slope) in [(0, 2), (9, 3)] {
        fixture.r[index] = column(&linear(slope), &fixture.s, fixture.z, false);
    }
    for (index, slope) in [(0, 5), (516, 7)] {
        fixture.main[index] = column(&linear(slope), &fixture.s, fixture.z, true);
    }
    for (matrix, index, slope) in [(0, 0, 11), (7, 9, 13)] {
        fixture.quotient[matrix][index] = column(&linear(slope), &fixture.s, fixture.z, false);
    }
    for (index, slope) in [(0, 17), (667, 19)] {
        fixture.pp_coefficients[index] = linear(slope);
        fixture.pp[index] = column(&linear(slope), &fixture.s, fixture.z, false);
    }
    for (index, slope) in [(0, 23), (414, 29)] {
        fixture.aux[index] = column(&linear(slope), &fixture.s, fixture.z, true);
    }
    let theta = fixture.theta;
    let pow = |exponent| theta.exp_u64(exponent);
    let expected = E::from_u32(2)
        + pow(9) * F::from_u32(3)
        + (pow(10) + pow(527)) * F::from_u32(5)
        + (pow(526) + pow(1043)) * F::from_u32(7)
        + pow(1044) * F::from_u32(11)
        + pow(1123) * F::from_u32(13)
        + pow(1124) * F::from_u32(17)
        + pow(1791) * F::from_u32(19)
        + (pow(1792) + pow(2207)) * F::from_u32(23)
        + (pow(2206) + pow(2621)) * F::from_u32(29);
    let prepared = prepare(&fixture.view()).unwrap();
    assert_eq!(prepared.opening_count(), 2622);
    assert_eq!(prepared.origin()[0], expected);
    assert!(
        prepared.origin()[1..]
            .iter()
            .all(|&coefficient| coefficient == E::ZERO)
    );
}

fn product(a: &[E], b: &[E]) -> Vec<E> {
    let mut out = vec![E::ZERO; a.len() + b.len() - 1];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            out[i + j] += a * b;
        }
    }
    out
}
fn divide(a: &[E], b: &[E]) -> (Vec<E>, Vec<E>) {
    let mut remainder = trim(a.to_vec());
    let mut quotient = vec![E::ZERO; a.len().saturating_sub(b.len()) + 1];
    while remainder.len() >= b.len() {
        let offset = remainder.len() - b.len();
        let coefficient = *remainder.last().unwrap() / *b.last().unwrap();
        quotient[offset] = coefficient;
        for (i, &value) in b.iter().enumerate() {
            remainder[offset + i] -= coefficient * value;
        }
        remainder = trim(remainder);
    }
    (trim(quotient), remainder)
}

#[test]
fn full_4096_by_192_public_view_has_the_exact_whole_affine_mask_and_native_fft_product() {
    let s = rows(192);
    let z = u() + E::from_u32(2);
    let mut fixture = Fixture::zero(s, z);
    // Public fixed-DATA algebra fixture, no owning witness/AIR. One full-degree base poly
    // gives coherent disclosures without retaining full matrices of polynomial coefficients.
    let p = (0..K)
        .map(|i| F::from_usize(i % 17 + 1))
        .collect::<Vec<_>>();
    let mut padded = p.clone();
    padded.resize(LDE, F::ZERO);
    let evaluated = Radix2DitParallel::<F>::default().coset_dft(padded, F::GENERATOR);
    let one = Column {
        rows: (0..192)
            .map(|index| evaluated[physical_index(index)])
            .collect(),
        at_z: evaluate(&p, z),
        at_hz: None,
    };
    let mut two = one.clone();
    for (&point, &value) in fixture.s.iter().zip(&one.rows) {
        assert_eq!(
            p.iter()
                .rev()
                .fold(F::ZERO, |sum, &coefficient| sum * point + coefficient),
            value
        );
    }
    two.at_hz = Some(evaluate(&p, z * F::two_adic_generator(11)));
    fixture.r = vec![one.clone(); 10];
    fixture.main = vec![two.clone(); 517];
    fixture.quotient = vec![vec![one.clone(); 10]; 8];
    fixture.aux = vec![two; 415];
    fixture.pp[0] = one;
    fixture.pp_coefficients[0] = p.clone();
    let prepared = prepare(&fixture.view()).unwrap();
    assert_eq!(prepared.free_coefficients(), 3899);
    assert_eq!(prepared.direction().len(), 197);
    assert_eq!(prepared.origin().len(), K - 1);
    assert_ne!(eval_e(prepared.direction(), z), E::ZERO);
    let random = (0..prepared.free_coefficients())
        .map(|i| E::from_basis_coefficients_fn(|j| F::from_usize((i + 1) * (j + 2))))
        .collect::<Vec<_>>();
    let result = prepared.instantiate(&random).unwrap();
    let independent_mask = product(prepared.direction(), &random);
    assert_eq!(
        result,
        independent_mask
            .iter()
            .zip(prepared.origin())
            .map(|(&mask, &origin)| mask + origin)
            .collect::<Vec<_>>()
    );
    let mask = result
        .iter()
        .zip(prepared.origin())
        .map(|(&a, &b)| a - b)
        .collect::<Vec<_>>();
    let (quotient, remainder) = divide(&mask, prepared.direction());
    assert!(remainder.is_empty());
    assert_eq!(quotient, random);
    for &point in &fixture.s {
        assert_eq!(eval_e(&mask, E::from(point)), E::ZERO);
    }
    for j in 1..5 {
        assert_eq!(eval_e(&mask, z.repeated_frobenius(j)), E::ZERO);
    }
    let powers = |start: usize, count: usize| {
        (start..start + count)
            .map(|e| fixture.theta.exp_u64(e as u64))
            .sum::<E>()
    };
    let wz = powers(0, 527) + powers(1044, 81) + powers(1792, 415);
    let whz = powers(527, 517) + powers(2207, 415);
    let lifted = p.iter().copied().map(E::from).collect::<Vec<_>>();
    let (at_z, _) = divide_extension_root(&lifted, z);
    let (at_hz, _) = divide_extension_root(&lifted, z * F::two_adic_generator(11));
    let difference = at_z
        .iter()
        .zip(at_hz)
        .zip(prepared.origin())
        .map(|((&a, b), &origin)| wz * a + whz * b - origin)
        .collect::<Vec<_>>();
    let (preimage, remainder) = divide(&difference, prepared.direction());
    assert!(remainder.is_empty());
    assert!(preimage.len() <= prepared.free_coefficients());
    // Actual CSPRNG coefficient sampler, public deterministic fixture seed only.
    let mut rng = StdRng::from_seed([0x59; 32]);
    let sampled = prepared.sample(&mut rng);
    assert_eq!(sampled.len(), K - 1);
    let difference = sampled
        .iter()
        .zip(prepared.origin())
        .map(|(&a, &b)| a - b)
        .collect::<Vec<_>>();
    assert!(divide(&difference, prepared.direction()).1.is_empty());
}

#[test]
fn fixed_public_pp_row_and_ood_tampering_are_rejected_before_a_sampler_is_returned() {
    let mut fixture = Fixture::zero(rows(3), u() + E::from_u32(2));
    fixture.pp_coefficients[0] = vec![F::ONE, F::from_u32(2)];
    fixture.pp[0] = column(&fixture.pp_coefficients[0], &fixture.s, fixture.z, false);
    assert!(prepare(&fixture.view()).is_ok());
    fixture.pp[0].rows[1] += F::ONE;
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("public-PP-row-mismatch")
    );
    fixture.pp[0].rows[1] -= F::ONE;
    fixture.pp[0].at_z += E::ONE;
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("public-PP-OOD-mismatch")
    );
    fixture.pp_coefficients[0].resize(K + 1, F::ZERO);
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("public-PP-degree-bound")
    );
}

#[test]
fn base_ood_disclosures_must_be_base_and_duplicate_locations_never_silently_merge() {
    let mut fixture = Fixture::zero(rows(1), E::from_u32(11));
    assert!(prepare(&fixture.view()).is_ok());
    fixture.r[0].at_z = u();
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("base-ood-requires-base-value")
    );
    for unequal in [false, true] {
        let mut fixture = Fixture::zero(vec![F::GENERATOR, F::GENERATOR], u());
        if unequal {
            fixture.main[0].rows[1] = F::ONE;
        }
        assert_eq!(prepare(&fixture.view()).err(), Some("duplicate-S-location"));
    }
}

#[test]
fn exceptional_coins_locations_missing_points_and_wrong_native_widths_are_explicit_errors() {
    for z in [E::ZERO, E::ONE, E::from(F::GENERATOR)] {
        assert!(prepare(&Fixture::zero(rows(1), z).view()).is_err());
    }
    for theta in [E::ZERO, E::from_u32(3)] {
        let mut fixture = Fixture::zero(rows(1), u());
        fixture.theta = theta;
        assert_eq!(
            prepare(&fixture.view()).err(),
            Some("exceptional-base-theta")
        );
    }
    let fixture = Fixture::zero(rows(193), u());
    assert_eq!(prepare(&fixture.view()).err(), Some("too-many-S-locations"));
    let fixture = Fixture::zero(vec![F::ZERO], u());
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("S-outside-input-domain")
    );
    let mut fixture = Fixture::zero(rows(1), u());
    fixture.main[0].at_hz = None;
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("column-disclosure-shape")
    );
    let mut fixture = Fixture::zero(rows(1), u());
    fixture.r[0].at_hz = Some(E::ZERO);
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("column-disclosure-shape")
    );
    let mut fixture = Fixture::zero(rows(1), u());
    fixture.quotient[7].pop();
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("fixed-DATA-matrix-shape")
    );
    let fixture = Fixture::zero(vec![], u());
    let prepared = prepare(&fixture.view()).unwrap();
    assert_eq!(prepared.free_coefficients(), 4091);
    assert_eq!(
        prepared.instantiate(&[]).err(),
        Some("affine-randomness-degree")
    );
}
