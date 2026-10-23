//! Actual fixed-suite R geometry and native PCS kernels, using fresh private
//! OS randomness for nonparticipant test matrices. No complete FRI proof,
//! statistical independence test, transcript simulation or admission claim.
use super::{Challenger, Pcs, config};
use crate::{Challenge, EXTENSION_DEGREE, LOG_BLOWUP, RANDOM_CODEWORDS, Val};
use p3_commit::{Pcs as PcsTrait, UnivariateStarkPcs};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PackedFieldExtension, PrimeCharacteristicRing,
    batch_multiplicative_inverse,
};
use p3_matrix::Matrix;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::interpolation::{Interpolate, compute_adjusted_weights};
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_uni_stark::StarkGenericConfig;

fn horner_column(coefficients: &RowMajorMatrix<Val>, column: usize, z: Challenge) -> Challenge {
    coefficients
        .values
        .chunks_exact(coefficients.width())
        .rev()
        .fold(Challenge::ZERO, |value, row| value * z + row[column])
}

#[test]
fn actual_randomization_has_ten_base_columns_and_matches_native_deep_kernels_at_both_heights() {
    assert_eq!((EXTENSION_DEGREE, RANDOM_CODEWORDS, LOG_BLOWUP), (5, 5, 3));
    let theta = Challenge::from_basis_coefficients_fn(|i| Val::from_bool(i == 1));
    assert_eq!(theta.exp_u64(5), Challenge::from_u8(3));
    let zeta = theta + Challenge::from_u8(11);
    let powers: Vec<_> = theta.powers().take(10).collect();
    let packed_powers =
        <Challenge as ExtensionField<Val>>::ExtensionPacking::packed_ext_powers_capped(theta, 10)
            .collect::<Vec<_>>();

    // These are the actual committed degree bounds: original N=512/2048,
    // private MAIN/AUX and randomization degree<k with k=2N.
    for log_k in [10usize, 12] {
        let k = 1usize << log_k;
        let suite = config().expect("fresh fixed-suite OS randomness");
        let pcs = suite.pcs();
        let domain = <Pcs as PcsTrait<Challenge, Challenger>>::natural_domain_for_degree(pcs, k);
        let (_cap, data) =
            <Pcs as UnivariateStarkPcs<Challenge, Challenger>>::get_opt_randomization_poly_commitment(
                pcs,
                [domain],
            )
            .unwrap()
            .expect("hiding suite constructs an actual randomization commitment");

        // The R constructor samples k rows of FIVE base coordinates for its EF5
        // polynomial plus FIVE independent random codewords, then commits through
        // the inner PCS. It does not apply the trace wrapper's extra doubling.
        let source = <Pcs as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
            pcs, &data, 0, domain,
        )
        .to_row_major_matrix();
        assert_eq!((source.height(), source.width()), (k, 10));
        assert_eq!(
            <Pcs as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain(
                pcs, &data, 0, domain,
            )
            .width(),
            5,
            "ordinary wrapper view strips exactly the appended five columns"
        );
        let dft = Radix2DitParallel::<Val>::default();
        let coefficients = dft.idft_batch(source);
        assert_eq!((coefficients.height(), coefficients.width()), (k, 10));

        let log_lde = log_k + LOG_BLOWUP;
        let lde_height = 1usize << log_lde;
        let coset = TwoAdicMultiplicativeCoset::new(Val::GENERATOR, log_lde).unwrap();
        let native_rows = <Pcs as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
            pcs, &data, 0, coset,
        )
        .bit_reverse_rows()
        .to_row_major_matrix();
        assert_eq!(
            (native_rows.height(), native_rows.width()),
            (lde_height, 10)
        );
        // Native PCS reductions use the committed bit-reversed row order.
        let points: Vec<_> = (0..lde_height)
            .map(|i| {
                let index = i.reverse_bits() >> (usize::BITS - u32::try_from(log_lde).unwrap());
                coset.element(index)
            })
            .collect();
        let denominators: Vec<_> = points.iter().map(|&x| zeta - x).collect();
        let inverse_denominators = batch_multiplicative_inverse(&denominators);

        // This is the actual PCS low-coset OOD kernel with the same prefix and
        // adjusted weights used in two_adic_pcs.rs, not a full PCS opening.
        let low_coset = native_rows.split_rows(k).0;
        let weights = compute_adjusted_weights(zeta, &inverse_denominators[..k]);
        let native_ood =
            low_coset.interpolate_coset_with_precomputation(Val::GENERATOR, zeta, &weights);
        assert_eq!(native_ood.len(), 10);
        for (column, &opening) in native_ood.iter().enumerate() {
            assert_eq!(opening, horner_column(&coefficients, column, zeta));
        }

        // Actual row-compression kernel, with R first in PCS order: theta^0..9.
        let compressed = native_rows
            .rowwise_packed_dot_product::<Challenge>(&packed_powers)
            .collect::<Vec<_>>();
        let reduced_coefficients: Vec<Challenge> = coefficients
            .values
            .as_chunks::<10>()
            .0
            .iter()
            .map(|row| row.iter().zip(&powers).map(|(&v, &power)| power * v).sum())
            .collect();
        let reduced_ood: Challenge = native_ood.iter().zip(&powers).map(|(&v, &p)| v * p).sum();

        // Independent coefficient-side synthetic division produces
        // (R_theta(X)-R_theta(zeta))/(X-zeta), degree<k-1. Native base-DFT
        // algebra lifting evaluates it on the whole committed R coset.
        let mut deep_coefficients = vec![Challenge::ZERO; lde_height];
        let mut carry = Challenge::ZERO;
        for degree in (1..k).rev() {
            carry = reduced_coefficients[degree] + zeta * carry;
            deep_coefficients[degree - 1] = carry;
        }
        assert_eq!(reduced_coefficients[0] + zeta * carry, reduced_ood);
        let deep_rows = dft
            .coset_dft_algebra_batch(RowMajorMatrix::new_col(deep_coefficients), Val::GENERATOR)
            .bit_reverse_rows()
            .to_row_major_matrix();
        assert_eq!(compressed.len(), lde_height);
        for (row, (&compressed, &inverse)) in
            compressed.iter().zip(&inverse_denominators).enumerate()
        {
            // Same native PCS first-point reduction formula. This checks its
            // assembled values against coefficients; no FRI proof is invoked.
            assert_eq!(
                (reduced_ood - compressed) * inverse,
                deep_rows.values[row],
                "R DEEP row {row} at committed log {log_k}"
            );
        }
    }
}
