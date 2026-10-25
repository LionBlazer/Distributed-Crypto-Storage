//! Actual Word full192 fixed-location arithmetic; no original trace or proof.
use super::*;
use p3_matrix::dense::RowMajorMatrix;
const INPUT_LOG: usize = 13;
const INPUT_HEIGHT: usize = 1 << INPUT_LOG;
const QUERIES: usize = 192;
const PP_BATCH: usize = 16;
fn at_base(coefficients: &[F], point: F) -> F {
    coefficients
        .iter()
        .rev()
        .fold(F::ZERO, |value, &coefficient| value * point + coefficient)
}
fn at_extension(coefficients: &[F], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * point + coefficient)
}
fn base_rows(coefficients: &[Poly], point: F, h: F) -> [Vec<E>; 2] {
    [point, point * h].map(|x| {
        coefficients
            .iter()
            .map(|p| E::from(at_base(p, x)))
            .collect()
    })
}
fn extension_rows(coefficients: &[Poly], point: E, h: F) -> [Vec<E>; 2] {
    [point, point * h].map(|x| coefficients.iter().map(|p| at_extension(p, x)).collect())
}

/// Evaluate ALL actual public PP columns with native coset DFT, in bounded
/// column batches. Output is natural-domain order, not bit-reversed MMCS order.
/// This avoids 384 * 1024 * 714 scalar Horner evaluations over the base field.
fn public_pp_rows_from_native_dft(coefficients: &[Poly], natural: &[usize]) -> Vec<[Vec<E>; 2]> {
    assert_eq!(coefficients.len(), PP);
    assert!(coefficients.iter().all(|p| p.len() <= 1024));
    let mut rows = (0..natural.len())
        .map(|_| core::array::from_fn(|_| vec![E::ZERO; PP]))
        .collect::<Vec<[Vec<E>; 2]>>();
    // h is the original H512 generator, hence exponent step8192/512=16.
    for start in (0..PP).step_by(PP_BATCH) {
        let width = PP_BATCH.min(PP - start);
        let mut values = vec![F::ZERO; INPUT_HEIGHT * width];
        for local in 0..width {
            for (degree, &coefficient) in coefficients[start + local].iter().enumerate() {
                values[degree * width + local] = coefficient;
            }
        }
        let evaluated = Radix2DitParallel::<F>::default()
            .coset_dft_batch(RowMajorMatrix::new(values, width), F::GENERATOR)
            .to_row_major_matrix();
        assert_eq!(
            (evaluated.height(), evaluated.width()),
            (INPUT_HEIGHT, width)
        );
        for (query_rows, &index) in rows.iter_mut().zip(natural) {
            for (next, row) in query_rows.iter_mut().enumerate() {
                let physical = (index + 16 * next) % INPUT_HEIGHT;
                for (target, &value) in row[start..start + width]
                    .iter_mut()
                    .zip(&evaluated.values[physical * width..(physical + 1) * width])
                {
                    *target = E::from(value);
                }
            }
        }
    }
    rows
}

fn public_coefficients(columns: usize, degree: usize, tag: usize) -> Vec<Poly> {
    (0..columns)
        .map(|column| {
            (0..=degree)
                .map(|d| {
                    // Deterministic PUBLIC algebra fixture; dense and column-dependent,
                    // with every leading coefficient nonzero. No valid-witness claim.
                    F::from_usize(
                        ((column + 1) * (column + d + tag + 1) + (d + 1) * (d + 1) + tag * (d + 3))
                            % 257
                            + 1,
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
#[ignore = "full 192-location ring comparison requires the owning held-process resource observer"]
fn all_five_word_coordinate_polynomials_match_native_folder_on_192_rows_and_five_ood_embeddings() {
    // Arrange only actual PUBLIC Expected/PP and arbitrary public residues.
    let metadata = Metadata::sample(true);
    let program = WordFoldProgram::from_metadata(&metadata).unwrap();
    let oracle = NativeFolderOracle::new(&metadata);
    let u = E::from_basis_coefficients_fn(|b| F::from_bool(b == 1));
    let z = u + E::from_u32(2);
    assert!(<E as ExtensionField<F>>::as_base(&z).is_none());
    assert_eq!(u.exp_u64(5), E::from_u32(3));
    let omega = F::two_adic_generator(INPUT_LOG);
    let h = F::two_adic_generator(9);
    assert_eq!(omega.exp_u64(16), h);
    // These 192 actual coset points and their h-translates are disjoint.
    // Native bit-reversed index i corresponds to exponent reverse_bits(i,13).
    let natural = (0..QUERIES).map(|i| 32 * i + 1).collect::<Vec<usize>>();
    let mmcs_indices = natural
        .iter()
        .map(|i| i.reverse_bits() >> (usize::BITS - INPUT_LOG as u32))
        .collect::<Vec<_>>();
    let positions = natural
        .iter()
        .map(|&i| F::GENERATOR * omega.exp_u64(i as u64))
        .collect::<Vec<_>>();
    for (&index, &point) in mmcs_indices.iter().zip(&positions) {
        let exponent = index.reverse_bits() >> (usize::BITS - INPUT_LOG as u32);
        assert_eq!(F::GENERATOR * omega.exp_u64(exponent as u64), point);
    }
    let domain = DisclosureDomain::checked(z, &positions).unwrap();
    assert_eq!(domain.target.degree(), 197);
    assert_eq!(domain.source_degree(), 394);
    let main = public_coefficients(MAIN, 393, 11);
    let aux = public_coefficients(AUX_BASE, 393, 29);
    let residues = PublicResidues::checked(&domain, main.clone(), aux.clone()).unwrap();
    let coins = &oracle.coins;
    let pp_rows = public_pp_rows_from_native_dft(program.public_pp_coefficients(), &natural);
    // Separate sparse scalar checks fix DFT order/coset/rotation association;
    // the full oracle comparison below uses every PP column at every location.
    for query in [0, QUERIES / 2, QUERIES - 1] {
        for column in [0, 17, PP - 1] {
            for (next, point) in [positions[query], positions[query] * h]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    pp_rows[query][next][column],
                    E::from(at_base(&program.public_pp_coefficients()[column], point))
                );
            }
        }
    }

    // Act: actual symbolic ring evaluator, retaining FIVE F[X]/M coordinates.
    let quotient = program.fold(&domain, &residues, coins).unwrap();
    assert_eq!(quotient.expected_binding(), &probe::binding(&metadata));
    assert_eq!(quotient.modulus(), domain.target_modulus());
    assert_eq!(
        quotient.constraint_count(),
        program.base.len() + program.extension.len()
    );
    assert!(quotient.coordinates().iter().all(|p| p.len() <= 197));

    // Assert at192 base points: the real SDK folder gives five INJECTIVE base
    // coordinates. This is 960 separate base-field equalities, not one tensor
    // evaluation which could identify the coefficient basis with the point.
    for (query, &point) in positions.iter().enumerate() {
        let rows = EvaluatedRows {
            main: base_rows(&main, point, h),
            pp: pp_rows[query].clone(),
            aux_base: base_rows(&aux, point, h),
        };
        let direct = oracle.fold(E::from(point), &rows, 0);
        let direct_coordinates: &[F] = direct.as_basis_coefficients_slice();
        for (coordinate, polynomial) in quotient.coordinates().iter().enumerate() {
            assert_eq!(
                at_base(polynomial, point),
                direct_coordinates[coordinate],
                "base query={query} coordinate={coordinate}"
            );
        }
    }

    // At NONBASE z, keep z fixed and use all five coefficient-Frobenius maps.
    // No evaluator/interpolation helper from the ring path supplies this oracle.
    let rows = EvaluatedRows {
        main: extension_rows(&main, z, h),
        pp: extension_rows(program.public_pp_coefficients(), z, h),
        aux_base: extension_rows(&aux, z, h),
    };
    let at_z: [E; 5] = core::array::from_fn(|b| at_extension(&quotient.coordinates()[b], z));
    let bases: [E; 5] = core::array::from_fn(|j| u.repeated_frobenius(j));
    let mut determinant = E::ONE;
    for j in 0..5 {
        for previous in 0..j {
            determinant *= bases[j] - bases[previous];
        }
    }
    assert_ne!(determinant, E::ZERO); // Actual fixed-basis Vandermonde injectivity.
    for (embedding, &basis) in bases.iter().enumerate() {
        let expected_value = at_z
            .iter()
            .zip(basis.powers())
            .map(|(&value, power)| value * power)
            .sum::<E>();
        assert_eq!(
            oracle.fold(z, &rows, embedding),
            expected_value,
            "nonbase OOD coefficient embedding={embedding}"
        );
    }

    // Negative control: P_S(X)*((X-2)-u) has coordinate degree193<197.
    // It is invisible at ALL192 base points and in the j=0 collapsed OOD map,
    // yet the other coefficient embeddings distinguish it. A one-map oracle
    // could therefore pass an actually wrong five-coordinate polynomial result.
    let mut p_s = vec![F::ONE];
    for &point in &positions {
        p_s = ring::mul(&p_s, &[-point, F::ONE]);
    }
    assert_eq!(p_s.len(), 193);
    for &point in &positions {
        assert_eq!(at_base(&p_s, point), F::ZERO);
    }
    let p_s_z = at_extension(&p_s, z);
    assert_ne!(p_s_z, E::ZERO);
    for (embedding, &basis) in bases.iter().enumerate() {
        let hidden_error = p_s_z * ((z - E::from_u32(2)) - basis);
        if embedding == 0 {
            assert_eq!(hidden_error, E::ZERO);
        } else {
            assert_ne!(hidden_error, E::ZERO);
        }
    }
    eprintln!(
        "word_public_image native_folder_full_locations=true base_points=192 target_degree=197 source_degree=394 coordinate_equalities=960 OOD_embeddings=5 native_folder_calls=197 lossy_embedding_negative=true public_only=true full_sampler=false admission=false"
    );
}
