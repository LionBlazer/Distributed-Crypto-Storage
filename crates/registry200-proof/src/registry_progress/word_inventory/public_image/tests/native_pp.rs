//! Genuine owning PUBLIC PP factory association, with no Word private trace.
use super::*;
use p3_commit::UnivariateStarkPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::StarkGenericConfig;

#[test]
#[ignore = "all actual Word PP714 cells/native LDE; run alone under held-process120s/1792MiB observer"]
fn actual_word_pp_coefficients_match_zero_interleaving_and_the_native_public_lde_current_and_next()
{
    let metadata = Metadata::sample(true);
    let program = WordFoldProgram::from_metadata(&metadata).unwrap();
    let air = owning_air().unwrap();
    let original = air.preprocessed_trace().unwrap();
    assert_eq!((original.height(), original.width()), (512, 714));
    let mut coefficients = vec![F::ZERO; 1024 * PP];
    for (column, polynomial) in program.public_pp_coefficients().iter().enumerate() {
        for (degree, &value) in polynomial.iter().enumerate() {
            coefficients[degree * PP + column] = value;
        }
    }
    let interleaved = Radix2DitParallel::<F>::default()
        .dft_batch(RowMajorMatrix::new(coefficients, PP))
        .to_row_major_matrix();
    for row in 0..N {
        assert_eq!(
            &interleaved.values[(2 * row) * PP..(2 * row + 1) * PP],
            &original.values[row * PP..(row + 1) * PP]
        );
        assert!(
            interleaved.values[(2 * row + 1) * PP..(2 * row + 2) * PP]
                .iter()
                .all(|&x| x == F::ZERO)
        );
    }
    drop(interleaved);
    let naive = Radix2DitParallel::<F>::default()
        .idft_batch(original)
        .to_row_major_matrix();
    let z = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1)) + E::from_u32(2);
    assert!(
        program
            .public_pp_coefficients()
            .iter()
            .enumerate()
            .any(|(column, p)| {
                let wrong = naive
                    .values
                    .as_chunks::<PP>()
                    .0
                    .iter()
                    .rev()
                    .fold(E::ZERO, |v, row| v * z + row[column]);
                at(p, z) != wrong
            })
    );
    drop(naive);
    let report = assessment::assess(&air).unwrap();
    let public = super::super::super::hash_setup::public_data(&air, &report).unwrap();
    let global = public.common.preprocessed.as_ref().unwrap();
    assert_eq!(global.matrix_to_instance, [0]);
    let meta = global.instances[0].as_ref().unwrap();
    assert_eq!((meta.width, meta.degree_bits), (714, 10));
    assert_eq!(public.common.lookups[0].len(), 34);
    // Read only actual public factory data through the native PCS method.
    // This separate test's ordinary config never commits a private matrix,
    // constructs a proof, exposes a config getter or supplies an AIR override.
    let suite = bfv_hiding_stark::hash::config().unwrap();
    let target = TwoAdicMultiplicativeCoset::<F>::new(F::GENERATOR, 13).unwrap();
    let native = <bfv_hiding_stark::hash::Pcs as UnivariateStarkPcs<
        E,
        bfv_hiding_stark::hash::Challenger,
    >>::get_evaluations_on_domain_no_random(
        suite.pcs(),
        public
            .prover_only
            .preprocessed_prover_data
            .as_ref()
            .unwrap(),
        0,
        target,
    )
    .to_row_major_matrix();
    assert_eq!((native.height(), native.width()), (8192, 714));
    let mut coefficients = vec![F::ZERO; 8192 * PP];
    for (column, p) in program.public_pp_coefficients().iter().enumerate() {
        for (degree, &value) in p.iter().enumerate() {
            coefficients[degree * PP + column] = value;
        }
    }
    let emitted = Radix2DitParallel::<F>::default()
        .coset_dft_batch(RowMajorMatrix::new(coefficients, PP), F::GENERATOR)
        .to_row_major_matrix();
    assert_eq!(emitted.values, native.values);
    // Both requested native opening rotations correspond to actual public rows.
    let h = F::two_adic_generator(9);
    let omega = F::two_adic_generator(13);
    assert_eq!(omega.exp_u64(16), h);
    for natural in [1usize, 137, 8191] {
        for next in 0..2 {
            let index = (natural + 16 * next) % 8192;
            let x = F::GENERATOR * omega.exp_u64(index as u64);
            for column in [0, super::super::super::plan::PUBLIC_ACTIVE, PP - 1] {
                assert_eq!(
                    E::from(emitted.values[index * PP + column]),
                    at(&program.public_pp_coefficients()[column], E::from(x))
                );
            }
        }
    }
    eprintln!(
        "word_public_image actual_public_PP_factory=true original_H=512 PP=714 interleaved_cells=731136 hiding_k=1024 physical_rows=8192 PP_current_next=true full_private_trace=false proof=false privacy=false admission=false"
    );
}
