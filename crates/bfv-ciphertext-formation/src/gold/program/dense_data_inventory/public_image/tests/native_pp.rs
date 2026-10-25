//! Independent native PUBLIC PP root and every zero-interleaved cell.
//! No original DATA trace, private opening, guarded Prepared or prover exists.
use super::*;
use bfv_hiding_stark::hash::{LeafHash, Mmcs as NativeMmcs, NodeCompress};
use p3_commit::Mmcs;
use p3_matrix::{bitrev::BitReversibleMatrix, dense::RowMajorMatrix};

#[test]
#[ignore = "full native DATA public PP requires the owning held-process resource observer"]
fn actual_data_pp_coefficients_reconstruct_all_interleaved_rows_and_the_native_commitment() {
    let expected = super::super::super::expected().unwrap();
    let program = DataFoldProgram::from_expected(&expected).unwrap();
    let (air, report) = native::prescreen(&expected).unwrap();
    let original = air.preprocessed_trace().unwrap();
    assert_eq!((original.height(), original.width()), (2048, 668));
    assert_eq!(program.public_pp_coefficients().len(), 668);
    assert!(
        program
            .public_pp_coefficients()
            .iter()
            .any(|p| p.len() > 2048)
    );

    // Independently run the forward native transform on the emitted coefficients,
    // then compare every cell with literal original/zero alternating ROWS. A
    // mistaken interpolation of the old H2048 table cannot pass this equality.
    let mut coefficients = vec![F::ZERO; 4096 * PP];
    for (column, polynomial) in program.public_pp_coefficients().iter().enumerate() {
        for (degree, &value) in polynomial.iter().enumerate() {
            coefficients[degree * PP + column] = value;
        }
    }
    let reconstructed = Radix2DitParallel::<F>::default()
        .dft_batch(RowMajorMatrix::new(coefficients, PP))
        .to_row_major_matrix();
    assert_eq!((reconstructed.height(), reconstructed.width()), (4096, PP));
    for (row, original_values) in original.values.as_chunks::<PP>().0.iter().enumerate() {
        assert_eq!(
            &reconstructed.values[(2 * row) * PP..(2 * row + 1) * PP],
            original_values
        );
        assert!(
            reconstructed.values[(2 * row + 1) * PP..(2 * row + 2) * PP]
                .iter()
                .all(|&value| value == F::ZERO)
        );
    }
    drop(reconstructed);
    let naive = Radix2DitParallel::<F>::default()
        .idft_batch(original)
        .to_row_major_matrix();
    let z = E::from_basis_coefficients_fn(|b| F::from_bool(b == 1)) + E::from_u32(2);
    assert!(
        program
            .public_pp_coefficients()
            .iter()
            .enumerate()
            .any(|(column, p)| {
                let incorrect = naive
                    .values
                    .as_chunks::<PP>()
                    .0
                    .iter()
                    .rev()
                    .fold(E::ZERO, |v, row| v * z + row[column]);
                ring::evaluate(p, z) != incorrect
            })
    );
    drop(naive);

    // Use the actual owner sealed PUBLIC-only native setup to obtain its real
    // cap, then drop its prover-only storage before rebuilding the MMCS from
    // our coefficients. Its seeded configuration never escapes that factory.
    let public = super::super::super::hash_setup::public_data(&air, &expected, &report).unwrap();
    let global = public.common.preprocessed.as_ref().unwrap();
    assert_eq!(global.matrix_to_instance, [0]);
    let metadata = global.instances[0].as_ref().unwrap();
    assert_eq!(
        (metadata.matrix_index, metadata.width, metadata.degree_bits),
        (0, PP, 12)
    );
    assert_eq!(public.common.lookups[0].len(), 81);
    assert_eq!(public.common.lookups[0].total_count_weight(), 4 * 243);
    let native_commitment = global.commitment.clone();
    drop(public);
    drop(air);
    let mut coefficients = vec![F::ZERO; 32768 * PP];
    for (column, polynomial) in program.public_pp_coefficients().iter().enumerate() {
        for (degree, &value) in polynomial.iter().enumerate() {
            coefficients[degree * PP + column] = value;
        }
    }
    let lde = Radix2DitParallel::<F>::default()
        .coset_dft_batch(RowMajorMatrix::new(coefficients, PP), F::GENERATOR)
        .bit_reverse_rows()
        .to_row_major_matrix();
    let mmcs = NativeMmcs::new(
        LeafHash,
        NodeCompress,
        0,
        super::super::super::hash_setup::research_public_stream(&expected, 0),
    );
    let (coefficient_commitment, native_data) = mmcs.commit(vec![lde]);
    assert_eq!(coefficient_commitment, native_commitment);
    drop(native_data);
    eprintln!(
        "data_public_image actual_native_pp_root=true PP=668 interleaved_cells=2736128 H=2048 k=4096 D=32768 original_trace=false proof=false privacy=false admission=false"
    );
}
