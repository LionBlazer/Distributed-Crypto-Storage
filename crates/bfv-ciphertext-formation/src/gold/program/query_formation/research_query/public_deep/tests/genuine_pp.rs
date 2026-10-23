//! Actual PUBLIC Query PP association and public algebra only, not an AIR witness.
use super::*;
use crate::gold::program::query_formation::{public_image::QueryFoldProgram, tests::metadata};

fn base_horner(coefficients: &[F], point: F) -> F {
    coefficients
        .iter()
        .rev()
        .fold(F::ZERO, |value, &coefficient| value * point + coefficient)
}

fn extension_horner(coefficients: &[F], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * point + coefficient)
}

fn extension_polynomial_value(coefficients: &[E], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * point + coefficient)
}

/// These are intentionally PUBLIC algebra columns, not generated MAIN/AUX/R/Q.
/// The sampler receives only their disclosures. No private trace is constructed.
fn coherent_public_column(tag: usize, s: &[F], z: E, next: bool) -> Column {
    let coefficients: Vec<F> = (0..7)
        .map(|coordinate| F::from_usize((tag + 1) * (coordinate + 3) + coordinate * coordinate))
        .collect();
    Column {
        rows: s
            .iter()
            .map(|&point| base_horner(&coefficients, point))
            .collect(),
        at_z: extension_horner(&coefficients, z),
        at_hz: next.then(|| extension_horner(&coefficients, z * F::two_adic_generator(11))),
    }
}

/// Literal SDK PCS round -> matrix -> point -> column order. This reference
/// never calls the sampler's CRT, accumulator, synthetic division or direction.
fn native_openings(fixture: &Fixture) -> Vec<(&Column, bool)> {
    fn matrix<'a>(openings: &mut Vec<(&'a Column, bool)>, columns: &'a [Column], next: bool) {
        for is_next in [false, true].into_iter().take(if next { 2 } else { 1 }) {
            openings.extend(columns.iter().map(|column| (column, is_next)));
        }
    }
    let mut openings = Vec::new();
    matrix(&mut openings, &fixture.r, false);
    matrix(&mut openings, &fixture.main, true);
    for quotient in &fixture.quotient {
        matrix(&mut openings, quotient, false);
    }
    matrix(&mut openings, &fixture.pp, false);
    matrix(&mut openings, &fixture.aux, true);
    openings
}

#[test]
fn actual_query_public_pp_and_all_2327_native_deep_terms_match_at_192_physical_locations() {
    // Arrange: only complete PUBLIC Expected/factory inputs. This does NOT ask
    // for Query Prepared, original MAIN/AUX/R/Q, a private witness, Config or proof.
    let expected = metadata();
    let public_program = QueryFoldProgram::from_expected(&expected).unwrap();
    let public_pp = public_program.public_pp_coefficients();
    assert_eq!(public_pp.len(), 545);
    assert!(public_pp.iter().all(|polynomial| polynomial.len() <= 4096));
    // This factory produces the native zero-interleaved 4096-point PP, rather
    // than interpolating the original 2048-point table. Exercise a high degree.
    assert!(public_pp.iter().any(|polynomial| polynomial.len() > 2048));

    let s = rows(192);
    let z = u() + E::from_u32(2);
    let mut fixture = Fixture::zero(s, z);
    fixture.r = (0..10)
        .map(|tag| coherent_public_column(tag, &fixture.s, z, false))
        .collect();
    fixture.main = (10..431)
        .map(|tag| coherent_public_column(tag, &fixture.s, z, true))
        .collect();
    fixture.quotient = (0..8)
        .map(|matrix| {
            (0..10)
                .map(|column| {
                    coherent_public_column(431 + 10 * matrix + column, &fixture.s, z, false)
                })
                .collect()
        })
        .collect();
    fixture.aux = (511..936)
        .map(|tag| coherent_public_column(tag, &fixture.s, z, true))
        .collect();
    fixture.pp_coefficients = public_pp.to_vec();

    // Stream one native base-field LDE column at a time. Do not allocate the
    // 32768x545 PP evaluation matrix. Independently cross-check two physical
    // rows per column by literal base-field Horner, including a noninitial row.
    let mut generation_ldes = 0;
    fixture.pp = public_pp
        .iter()
        .map(|polynomial| {
            let disclosed_rows = if polynomial.len() <= 64 {
                fixture
                    .s
                    .iter()
                    .map(|&point| base_horner(polynomial, point))
                    .collect()
            } else {
                generation_ldes += 1;
                let mut padded = polynomial.clone();
                padded.resize(32768, F::ZERO);
                let values = Radix2DitParallel::<F>::default().coset_dft(padded, F::GENERATOR);
                (0..192)
                    .map(|index| values[physical_index(index)])
                    .collect::<Vec<_>>()
            };
            for index in [0, 137] {
                assert_eq!(
                    disclosed_rows[index],
                    base_horner(polynomial, fixture.s[index]),
                    "public PP physical row {index}"
                );
            }
            Column {
                rows: disclosed_rows,
                at_z: extension_horner(polynomial, z),
                at_hz: None,
            }
        })
        .collect();

    // Act: the unchanged PUBLIC-V-only sampler owns the representatives and
    // affine law. This deterministic all-coordinate tape is a test input, not a
    // cryptographic randomness or privacy assertion.
    let prepared = prepare(&fixture.view()).unwrap();
    assert_eq!(prepared.opening_count(), 2327);
    assert_eq!(prepared.origin().len(), 4095);
    assert_eq!(prepared.direction().len(), 197);
    assert_eq!(prepared.free_coefficients(), 3899);
    let tape: Vec<E> = (0..3899)
        .map(|index| {
            E::from_basis_coefficients_fn(|coordinate| {
                F::from_usize((index + 1) * (coordinate + 1) + 23)
            })
        })
        .collect();
    let sampled = prepared.instantiate(&tape).unwrap();
    assert_eq!(sampled.len(), 4095);
    assert_ne!(sampled.as_slice(), prepared.origin());

    // Assert: independent direct native (f(a)-f(x))/(a-x) arithmetic, with
    // literal theta exponents, at EVERY actual physical S location. No sampler
    // polynomial/representative is used to construct these expected values.
    let openings = native_openings(&fixture);
    assert_eq!(openings.len(), 2327);
    for (index, column, next) in [
        (0, &fixture.r[0], false),
        (9, &fixture.r[9], false),
        (10, &fixture.main[0], false),
        (430, &fixture.main[420], false),
        (431, &fixture.main[0], true),
        (851, &fixture.main[420], true),
        (852, &fixture.quotient[0][0], false),
        (931, &fixture.quotient[7][9], false),
        (932, &fixture.pp[0], false),
        (1476, &fixture.pp[544], false),
        (1477, &fixture.aux[0], false),
        (1901, &fixture.aux[424], false),
        (1902, &fixture.aux[0], true),
        (2326, &fixture.aux[424], true),
    ] {
        assert!(core::ptr::eq(openings[index].0, column));
        assert_eq!(openings[index].1, next);
    }
    let weights: Vec<E> = (0..2327)
        .map(|exponent| fixture.theta.exp_u64(exponent))
        .collect();
    let hz = z * F::two_adic_generator(11);
    for (row, &point) in fixture.s.iter().enumerate() {
        assert_eq!((point / F::GENERATOR).exp_u64(32768), F::ONE);
        let inverses = [
            (z - E::from(point)).inverse(),
            (hz - E::from(point)).inverse(),
        ];
        let direct: E = openings
            .iter()
            .zip(&weights)
            .map(|(&(column, next), &weight)| {
                let claim = if next {
                    column.at_hz.unwrap()
                } else {
                    column.at_z
                };
                weight * (claim - E::from(column.rows[row])) * inverses[usize::from(next)]
            })
            .sum();
        assert_eq!(
            extension_polynomial_value(prepared.origin(), E::from(point)),
            direct,
            "native DEEP origin at physical row {row}"
        );
        assert_eq!(
            extension_polynomial_value(&sampled, E::from(point)),
            direct,
            "native DEEP affine sample at physical row {row}"
        );
    }

    // A non-disclosed point checks that instantiate really applied the full
    // tape. Its expected multiplier is independently the product of S and the
    // four OTHER Frobenius roots, not the sampler's direction coefficients.
    let probe = E::from_u32(49);
    let direction = fixture
        .s
        .iter()
        .fold(E::ONE, |product, &point| product * (probe - E::from(point)))
        * (1..5).fold(E::ONE, |product, power| {
            product * (probe - z.repeated_frobenius(power))
        });
    assert_ne!(direction, E::ZERO);
    assert_eq!(
        extension_polynomial_value(&sampled, probe)
            - extension_polynomial_value(prepared.origin(), probe),
        direction * extension_polynomial_value(&tape, probe)
    );
    drop(openings);
    fixture.pp[0].rows[0] += F::ONE;
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("public-PP-row-mismatch")
    );
    eprintln!(
        "query_public_deep_genuine_pp pp=545 k=4096 lde=32768 S=192 openings=2327 free=3899 generation_ldes={generation_ldes} original_trace=false proof=false honest_valid_air=false privacy=false"
    );
}
