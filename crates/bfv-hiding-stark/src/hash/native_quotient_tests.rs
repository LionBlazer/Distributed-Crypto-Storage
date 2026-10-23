//! Public synthetic quotient inputs through actual fixed-suite masking/LDEs.
//! Fresh normal OS randomness; no participant data, PCS opening, FRI proof,
//! statistical randomness claim, honest-AIR divisibility claim or admission.
use super::{Challenger, Pcs, config};
use crate::{Challenge, LOG_BLOWUP, Val};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{
    Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing, batch_multiplicative_inverse,
};
use p3_matrix::Matrix;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::interpolation::{Interpolate, compute_adjusted_weights};
use p3_uni_stark::StarkGenericConfig;

fn bit_reverse(index: usize, log_height: usize) -> usize {
    index.reverse_bits() >> (usize::BITS - u32::try_from(log_height).unwrap())
}

fn horner(coefficients: &RowMajorMatrix<Val>, column: usize, z: Challenge) -> Challenge {
    coefficients
        .values
        .chunks_exact(coefficients.width())
        .rev()
        .fold(Challenge::ZERO, |value, row| value * z + row[column])
}

// Products, not divisions: valid also at a root of one normalized v_i.
fn lambdas<E: Algebra<Val>>(x_to_n: E, inverse_s_to_n: &[Val], cis: &[Val]) -> Vec<E> {
    let vanishing: Vec<_> = inverse_s_to_n
        .iter()
        .map(|&inverse| x_to_n.clone() * inverse - E::ONE)
        .collect();
    let mut suffix = vec![E::ONE; vanishing.len() + 1];
    for i in (0..vanishing.len()).rev() {
        suffix[i] = vanishing[i].clone() * suffix[i + 1].clone();
    }
    let mut prefix = E::ONE;
    vanishing
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let weight = prefix.clone() * suffix[i + 1].clone() * cis[i];
            prefix *= v.clone();
            weight
        })
        .collect()
}

// Independent coefficient reduction modulo X^N-s_i^N, not another split LDE.
fn original_chunk(source: &RowMajorMatrix<Val>, n: usize, s_to_n: Val) -> Vec<Val> {
    let mut reduced = vec![Val::ZERO; n * 5];
    let mut power = Val::ONE;
    for block in source.values.chunks_exact(n * 5) {
        for (value, &coefficient) in reduced.iter_mut().zip(block) {
            *value += power * coefficient;
        }
        power *= s_to_n;
    }
    reduced
}

#[test]
fn actual_quotient_masks_preserve_each_base_coordinate_at_all_three_closed_geometries() {
    assert_eq!(LOG_BLOWUP, 3);
    let u = Challenge::from_basis_coefficients_fn(|i| Val::from_bool(i == 1));
    let zeta = u + Challenge::from_u8(17);
    for (log_n, c) in [(9usize, 16usize), (9, 8), (11, 8)] {
        let n = 1usize << log_n;
        let log_d = log_n + LOG_BLOWUP + 1;
        let d_height = 1usize << log_d;
        let dft = Radix2DitParallel::<Val>::default();
        let quotient_domain = TwoAdicMultiplicativeCoset::new(
            Val::GENERATOR,
            log_n + usize::try_from(c.ilog2()).unwrap(),
        )
        .unwrap();
        let domains = quotient_domain.split_domains(c);
        let mut source = RowMajorMatrix::new(
            (0..c * n)
                .flat_map(|degree| {
                    (0..5).map(move |column| Val::from_usize(11 + (degree + 1) * (column + 3)))
                })
                .collect(),
            5,
        );
        let original_ood: Vec<_> = (0..5).map(|column| horner(&source, column, zeta)).collect();
        // One source clone feeds the actual native split; retain coefficients
        // for independent checks, then consume them for the whole-D reference.
        let on_u = dft
            .coset_dft_batch(source.clone(), Val::GENERATOR)
            .to_row_major_matrix();
        let inputs = quotient_domain.split_evals(c, on_u);
        let suite = config().expect("fresh normal fixed-suite OS randomness");
        let ldes = <Pcs as UnivariateStarkPcs<Challenge, Challenger>>::get_quotient_ldes(
            suite.pcs(),
            domains.iter().copied().zip(inputs),
            c,
        )
        .unwrap();
        assert_eq!(ldes.len(), c);

        let s_to_n: Vec<_> = domains
            .iter()
            .map(|domain| domain.shift().exp_u64(n as u64))
            .collect();
        let inverse_s_to_n = batch_multiplicative_inverse(&s_to_n);
        let normalization: Vec<Val> = (0..c)
            .map(|i| {
                (0..c)
                    .filter(|&j| j != i)
                    .map(|j| s_to_n[i] * inverse_s_to_n[j] - Val::ONE)
                    .product()
            })
            .collect();
        let cis = batch_multiplicative_inverse(&normalization);
        let d_domain = TwoAdicMultiplicativeCoset::new(Val::GENERATOR, log_d).unwrap();
        assert_eq!(
            d_domain.subgroup_generator().exp_u64((16 / c) as u64),
            quotient_domain.subgroup_generator()
        );
        let denominators: Vec<_> = (0..2 * n)
            .map(|row| zeta - d_domain.element(bit_reverse(row, log_d)))
            .collect();
        let adjusted = compute_adjusted_weights(zeta, &batch_multiplicative_inverse(&denominators));
        let mut mask_sum = vec![Val::ZERO; n * 10];
        let mut chunk_ood = Vec::with_capacity(c);

        for (i, lde) in ldes.iter().enumerate() {
            assert_eq!((lde.height(), lde.width()), (16 * n, 10));
            let mut coefficients = dft.coset_idft_batch(
                lde.as_view().bit_reverse_rows().to_row_major_matrix(),
                Val::GENERATOR,
            );
            assert!(
                coefficients.values[2 * n * 10..]
                    .iter()
                    .all(|value| *value == Val::ZERO)
            );
            coefficients.values.truncate(2 * n * 10);

            // Every original U_i row is in D. Native masks vanish there, so
            // these actual rows recover q_i for all TEN columns. First five
            // have the independently supplied public source-Q coefficient check.
            let mut at_original = Vec::with_capacity(n * 10);
            for row in 0..n {
                let physical = bit_reverse(16 * row + (16 / c) * i, log_d);
                at_original.extend_from_slice(&lde.row_slice(physical).unwrap());
            }
            let baseline =
                dft.coset_idft_batch(RowMajorMatrix::new(at_original, 10), domains[i].shift());
            let expected = original_chunk(&source, n, s_to_n[i]);
            for degree in 0..n {
                for column in 0..10 {
                    let at = degree * 10 + column;
                    let high = coefficients.values[(n + degree) * 10 + column];
                    let r = s_to_n[i] * high;
                    assert_eq!(coefficients.values[at] - baseline.values[at], -r);
                    assert_eq!(high, inverse_s_to_n[i] * r);
                    mask_sum[at] += cis[i] * r;
                    if column < 5 {
                        assert_eq!(baseline.values[at], expected[degree * 5 + column]);
                    }
                }
            }
            // Actual PCS barycentric OOD kernel on its bit-reversed degree
            // prefix, checked against coefficient Horner for EVERY raw column.
            let openings = lde
                .split_rows(2 * n)
                .0
                .interpolate_coset_with_precomputation(Val::GENERATOR, zeta, &adjusted);
            assert_eq!(openings.len(), 10);
            for (column, &opening) in openings.iter().enumerate() {
                assert_eq!(opening, horner(&coefficients, column, zeta));
            }
            chunk_ood.push(openings);
        }
        assert!(
            mask_sum.iter().all(|value| *value == Val::ZERO),
            "sum c_i*r_i=0 for every coefficient of all ten columns"
        );

        let ood_weights = lambdas(zeta.exp_u64(n as u64), &inverse_s_to_n, &cis);
        for (column, &expected) in original_ood.iter().enumerate() {
            let recomposed: Challenge = ood_weights
                .iter()
                .zip(&chunk_ood)
                .map(|(&weight, row)| weight * row[column])
                .sum();
            assert_eq!(
                recomposed, expected,
                "separate quotient coordinate {column} at zeta"
            );
        }

        // lambda_i depends only on X^N, whose natural D-row period is16.
        // Prefix/suffix products handle U roots and D\U without per-row inverses.
        let phase_weights: Vec<_> = (0..16)
            .map(|phase| {
                let weights = lambdas(
                    d_domain.element(phase).exp_u64(n as u64),
                    &inverse_s_to_n,
                    &cis,
                );
                assert_eq!(weights.iter().copied().sum::<Val>(), Val::ONE);
                if phase % (16 / c) == 0 {
                    for (i, &weight) in weights.iter().enumerate() {
                        assert_eq!(weight, Val::from_bool(i == phase / (16 / c)));
                    }
                } else {
                    assert!(weights.iter().all(|weight| *weight != Val::ZERO));
                }
                weights
            })
            .collect();
        source.values.resize(d_height * 5, Val::ZERO);
        let reference = dft
            .coset_dft_batch(source, Val::GENERATOR)
            .to_row_major_matrix();
        for row in 0..d_height {
            let physical = bit_reverse(row, log_d);
            for column in 0..5 {
                let recomposed: Val = phase_weights[row % 16]
                    .iter()
                    .zip(&ldes)
                    .map(|(&weight, lde)| weight * lde.get(physical, column).unwrap())
                    .sum();
                assert_eq!(
                    recomposed,
                    reference.get(row, column).unwrap(),
                    "coordinate {column}, D-row {row}, N={n}, c={c}"
                );
            }
        }
    }
}
