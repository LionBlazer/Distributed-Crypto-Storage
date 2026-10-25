//! Actual owning DATA joint V -> whole-B coefficients -> native DEEP kernels.
//! Public seeded fixtures only; no original DATA trace, Prepared, proof or key.
use super::*;
use crate::gold::program::dense_data_inventory::{
    expected,
    public_image::{DataCoins, DataFoldProgram, public_disclosures as joint},
};
use p3_field::PackedFieldExtension;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_maybe_rayon::prelude::ParallelIterator;

fn copy_columns(columns: &[joint::Column]) -> Vec<Column> {
    columns
        .iter()
        .map(|column| Column {
            rows: column.rows.clone(),
            at_z: column.at_z,
            at_hz: column.at_hz,
        })
        .collect()
}
fn actual_fixture(s: Vec<F>, z: E) -> (DataFoldProgram, joint::Disclosures, Fixture) {
    let expected = expected().unwrap();
    let program = DataFoldProgram::from_expected(&expected).unwrap();
    let coins = DataCoins {
        lookup_alpha: u() + E::from_u32(17),
        lookup_beta: u() + E::from_u32(19),
        constraint_alpha: u() + E::from_u32(23),
    };
    let mut rng = StdRng::seed_from_u64(0x8550);
    let raw = joint::sample(&program, &coins, z, &s, &mut rng).unwrap();
    assert_eq!(raw.expected_binding, expected.binding());
    assert_eq!(raw.s, s);
    assert_eq!(raw.z, z);
    assert_eq!(program.public_pp_coefficients().len(), 668);
    let fixture = Fixture {
        s,
        z,
        theta: u() + E::from_u32(3),
        r: copy_columns(&raw.r),
        main: copy_columns(&raw.main),
        quotient: raw
            .quotient
            .iter()
            .map(|chunk| copy_columns(chunk))
            .collect(),
        pp: copy_columns(&raw.pp),
        pp_coefficients: program.public_pp_coefficients().to_vec(),
        aux: copy_columns(&raw.aux),
    };
    (program, raw, fixture)
}
fn native_openings(fixture: &Fixture) -> Vec<(&Column, bool)> {
    fn matrix<'a>(opened: &mut Vec<(&'a Column, bool)>, columns: &'a [Column], next: bool) {
        for is_next in [false, true].into_iter().take(if next { 2 } else { 1 }) {
            opened.extend(columns.iter().map(|column| (column, is_next)));
        }
    }
    let mut opened = Vec::new();
    matrix(&mut opened, &fixture.r, false);
    matrix(&mut opened, &fixture.main, true);
    for chunk in &fixture.quotient {
        matrix(&mut opened, chunk, false);
    }
    matrix(&mut opened, &fixture.pp, false);
    matrix(&mut opened, &fixture.aux, true);
    opened
}
fn direct_deep(fixture: &Fixture, row: usize) -> E {
    let x = E::from(fixture.s[row]);
    let inverse = [
        (fixture.z - x).inverse(),
        (fixture.z * F::two_adic_generator(11) - x).inverse(),
    ];
    native_openings(fixture)
        .iter()
        .enumerate()
        .map(|(exponent, &(column, next))| {
            let claim = if next {
                column.at_hz.unwrap()
            } else {
                column.at_z
            };
            fixture.theta.exp_u64(exponent as u64)
                * (claim - E::from(column.rows[row]))
                * inverse[usize::from(next)]
        })
        .sum()
}
fn native_deep_rows(fixture: &Fixture) -> Vec<E> {
    let opened = native_openings(fixture);
    assert_eq!(opened.len(), 2622);
    // Literal fixed DATA boundaries, independent of the polynomial accumulator.
    for (index, column, next) in [
        (0, &fixture.r[0], false),
        (9, &fixture.r[9], false),
        (10, &fixture.main[0], false),
        (526, &fixture.main[516], false),
        (527, &fixture.main[0], true),
        (1043, &fixture.main[516], true),
        (1044, &fixture.quotient[0][0], false),
        (1123, &fixture.quotient[7][9], false),
        (1124, &fixture.pp[0], false),
        (1791, &fixture.pp[667], false),
        (1792, &fixture.aux[0], false),
        (2206, &fixture.aux[414], false),
        (2207, &fixture.aux[0], true),
        (2621, &fixture.aux[414], true),
    ] {
        assert!(core::ptr::eq(opened[index].0, column));
        assert_eq!(opened[index].1, next);
    }
    let packed =
        <E as ExtensionField<F>>::ExtensionPacking::packed_ext_powers_capped(fixture.theta, 2622)
            .collect::<Vec<_>>();
    let compressed: [Vec<E>; 2] = core::array::from_fn(|is_next| {
        let mut rows = Vec::with_capacity(fixture.s.len() * 2622);
        for row in 0..fixture.s.len() {
            rows.extend(opened.iter().map(|&(column, next)| {
                if usize::from(next) == is_next {
                    column.rows[row]
                } else {
                    F::ZERO
                }
            }));
        }
        // Genuine native packed base-row/extension-weight dot-product kernel.
        RowMajorMatrix::new(rows, 2622)
            .rowwise_packed_dot_product::<E>(&packed)
            .collect()
    });
    let claims: [E; 2] = core::array::from_fn(|is_next| {
        let mut claim = E::ZERO;
        for (index, &(column, next)) in opened.iter().enumerate() {
            if usize::from(next) == is_next {
                claim += fixture.theta.exp_u64(index as u64)
                    * if next {
                        column.at_hz.unwrap()
                    } else {
                        column.at_z
                    };
            }
        }
        claim
    });
    fixture
        .s
        .iter()
        .enumerate()
        .map(|(row, &point)| {
            (claims[0] - compressed[0][row]) / (fixture.z - E::from(point))
                + (claims[1] - compressed[1][row])
                    / (fixture.z * F::two_adic_generator(11) - E::from(point))
        })
        .collect()
}

#[test]
#[ignore = "full DATA joint V and B require the owning held-process resource observer"]
fn actual_data_joint_192_disclosures_instantiate_whole_b_matching_all_2622_native_deep_terms() {
    let omega = F::two_adic_generator(15);
    let s = (0..192)
        .map(|i| F::GENERATOR * omega.exp_u64(64 * i + i % 2))
        .collect();
    let z = u() + E::from_u32(2);
    let (program, raw, fixture) = actual_fixture(s, z);
    assert_eq!(raw.ideal_cells, 383953);
    assert!(
        program
            .public_pp_coefficients()
            .iter()
            .any(|p| p.len() > 2048)
    );
    let prepared = prepare(&fixture.view()).unwrap();
    assert_eq!(prepared.opening_count(), 2622);
    assert_eq!(prepared.origin().len(), 4095);
    assert_eq!(prepared.direction().len(), 197);
    assert_eq!(prepared.free_coefficients(), 3899);
    let tape = (0..3899)
        .map(|index| {
            E::from_basis_coefficients_fn(|coordinate| {
                F::from_usize(5 * index + 7 * coordinate + 11)
            })
        })
        .collect::<Vec<_>>();
    let sampled = prepared.instantiate(&tape).unwrap();
    assert_eq!(sampled.len(), 4095);
    assert_ne!(sampled.as_slice(), prepared.origin());
    let native = native_deep_rows(&fixture);
    assert_eq!(native.len(), 192);
    for (row, &point) in fixture.s.iter().enumerate() {
        assert_eq!(native[row], direct_deep(&fixture, row));
        assert_eq!(eval_e(prepared.origin(), E::from(point)), native[row]);
        assert_eq!(eval_e(&sampled, E::from(point)), native[row]);
    }
    let mask = sampled
        .iter()
        .zip(prepared.origin())
        .map(|(&a, &b)| a - b)
        .collect::<Vec<_>>();
    for embedding in 1..5 {
        assert_eq!(eval_e(&mask, z.repeated_frobenius(embedding)), E::ZERO);
    }
    // The independent product uses S and the four OTHER Frobenius roots, not
    // the Prepared direction. A non-disclosed probe detects actual mask use.
    let probe = E::from_u32(49);
    let direction = fixture
        .s
        .iter()
        .fold(E::ONE, |p, &point| p * (probe - E::from(point)))
        * (1..5).fold(E::ONE, |p, j| p * (probe - z.repeated_frobenius(j)));
    assert_ne!(direction, E::ZERO);
    assert_eq!(eval_e(&mask, probe), direction * eval_e(&tape, probe));
    eprintln!(
        "data_public_deep_joint S=192 openings=2622 pp_theta_offset=1124 k=4096 B_coefficients=4095 direction_coefficients=197 free=3899 actual_DATA_PP=668 native_compression=true original_trace=false proof=false privacy=false admission=false"
    );
}

#[test]
fn actual_data_base_ood_and_h_overlaps_preserve_the_whole_b_image_and_pp_guards() {
    let h = F::two_adic_generator(11);
    let (_, raw, mut fixture) =
        actual_fixture(vec![F::GENERATOR, F::GENERATOR * h], E::from_u32(49));
    assert_eq!(raw.ideal_cells, 932 * 5 + 85 * 3);
    let prepared = prepare(&fixture.view()).unwrap();
    assert_eq!(prepared.opening_count(), 2622);
    assert_eq!(prepared.direction().len(), 3);
    assert_eq!(prepared.free_coefficients(), 4093);
    let tape = vec![u() + E::from_u32(5); 4093];
    let sampled = prepared.instantiate(&tape).unwrap();
    let native = native_deep_rows(&fixture);
    for (row, &point) in fixture.s.iter().enumerate() {
        assert_eq!(native[row], direct_deep(&fixture, row));
        assert_eq!(eval_e(prepared.origin(), E::from(point)), native[row]);
        assert_eq!(eval_e(&sampled, E::from(point)), native[row]);
    }
    fixture.pp[667].rows[1] += F::ONE;
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("public-PP-row-mismatch")
    );
    fixture.pp[667].rows[1] -= F::ONE;
    fixture.pp[0].at_z += E::ONE;
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("public-PP-OOD-mismatch")
    );
    fixture.pp[0].at_z -= E::ONE;
    fixture.r[0].at_z += u();
    assert_eq!(
        prepare(&fixture.view()).err(),
        Some("base-ood-requires-base-value")
    );
}
