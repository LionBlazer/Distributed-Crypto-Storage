//! Owning DATA joint V -> literal native DEEP row reductions, without whole B.
use super::*;
use p3_field::{BasedVectorSpace, ExtensionField, PackedFieldExtension};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_maybe_rayon::prelude::ParallelIterator;
use rand_public_pp::{SeedableRng, rngs::StdRng};

fn u() -> E {
    E::from_basis_coefficients_fn(|i| F::from_bool(i == 1))
}
fn coins(alpha: E) -> DataCoins {
    DataCoins {
        lookup_alpha: u() + E::from_u32(17),
        lookup_beta: u() + E::from_u32(19),
        constraint_alpha: alpha,
    }
}
fn native_openings(view: &Disclosures) -> Vec<(&Column, bool)> {
    fn matrix<'a>(openings: &mut Vec<(&'a Column, bool)>, columns: &'a [Column], next: bool) {
        for is_next in [false, true].into_iter().take(if next { 2 } else { 1 }) {
            openings.extend(columns.iter().map(|column| (column, is_next)));
        }
    }
    let mut openings = Vec::new();
    matrix(&mut openings, &view.r, false);
    matrix(&mut openings, &view.main, true);
    for chunk in &view.quotient {
        matrix(&mut openings, chunk, false);
    }
    matrix(&mut openings, &view.pp, false);
    matrix(&mut openings, &view.aux, true);
    openings
}
fn direct_deep(view: &Disclosures, theta: E, row: usize) -> E {
    // Independent literal term-at-a-time reference; no row dot-product kernel.
    let x = E::from(view.s[row]);
    let inverses = [
        (view.z - x).inverse(),
        (view.z * F::two_adic_generator(11) - x).inverse(),
    ];
    native_openings(view)
        .iter()
        .enumerate()
        .map(|(index, &(column, next))| {
            let claim = if next {
                column.at_hz.unwrap()
            } else {
                column.at_z
            };
            theta.exp_u64(index as u64)
                * (claim - E::from(column.rows[row]))
                * inverses[usize::from(next)]
        })
        .sum()
}

#[test]
#[ignore = "full 192-location DATA joint V requires the owning held-process resource observer"]
fn actual_data_joint_view_has_2622_native_deep_terms_and_correct_native_row_compression() {
    let expected = super::super::super::expected().unwrap();
    let program = DataFoldProgram::from_expected(&expected).unwrap();
    let omega = F::two_adic_generator(15);
    let s = (0..192)
        .map(|i| F::GENERATOR * omega.exp_u64(64 * i + i % 2))
        .collect::<Vec<_>>();
    let z = u() + E::from_u32(2);
    let theta = u() + E::from_u32(3);
    let mut rng = StdRng::seed_from_u64(0x8502);
    let view = sample(&program, &coins(u() + E::from_u32(23)), z, &s, &mut rng).unwrap();
    assert_eq!(view.expected_binding, expected.binding());
    assert_eq!(view.s, s);
    assert_eq!(view.z, z);
    assert_eq!(view.ideal_cells, 932 * 394 + 85 * 197);
    assert_eq!(view.ideal_cells, 383953);
    assert_eq!(
        (
            view.r.len(),
            view.main.len(),
            view.quotient.len(),
            view.pp.len(),
            view.aux.len()
        ),
        (10, 517, 8, 668, 415)
    );
    assert!(view.quotient.iter().all(|chunk| chunk.len() == 10));
    assert!(
        view.r
            .iter()
            .chain(&view.pp)
            .chain(view.quotient.iter().flatten())
            .all(|column| column.rows.len() == 192 && column.at_hz.is_none())
    );
    assert!(
        view.main
            .iter()
            .chain(&view.aux)
            .all(|column| column.rows.len() == 192 && column.at_hz.is_some())
    );
    let openings = native_openings(&view);
    assert_eq!(openings.len(), 2622);
    // These literal DATA positions independently pin every native matrix edge.
    // The PP theta offset is 1124; the Query offset 932 belongs to another AIR.
    for (index, column, next) in [
        (0, &view.r[0], false),
        (9, &view.r[9], false),
        (10, &view.main[0], false),
        (526, &view.main[516], false),
        (527, &view.main[0], true),
        (1043, &view.main[516], true),
        (1044, &view.quotient[0][0], false),
        (1123, &view.quotient[7][9], false),
        (1124, &view.pp[0], false),
        (1791, &view.pp[667], false),
        (1792, &view.aux[0], false),
        (2206, &view.aux[414], false),
        (2207, &view.aux[0], true),
        (2621, &view.aux[414], true),
    ] {
        assert!(core::ptr::eq(openings[index].0, column));
        assert_eq!(openings[index].1, next);
    }
    let packed = <E as ExtensionField<F>>::ExtensionPacking::packed_ext_powers_capped(theta, 2622)
        .collect::<Vec<_>>();
    let compressed: [Vec<E>; 2] = core::array::from_fn(|is_next| {
        let mut rows = Vec::with_capacity(192 * 2622);
        for row in 0..192 {
            rows.extend(openings.iter().map(|&(column, next)| {
                if usize::from(next) == is_next {
                    column.rows[row]
                } else {
                    F::ZERO
                }
            }));
        }
        // This is the actual native PCS packed Gold-row/EF5-weight kernel.
        RowMajorMatrix::new(rows, 2622)
            .rowwise_packed_dot_product::<E>(&packed)
            .collect()
    });
    let claims: [E; 2] = core::array::from_fn(|is_next| {
        let mut claim = E::ZERO;
        for (index, &(column, next)) in openings.iter().enumerate() {
            if usize::from(next) == is_next {
                claim += theta.exp_u64(index as u64)
                    * if next {
                        column.at_hz.unwrap()
                    } else {
                        column.at_z
                    };
            }
        }
        claim
    });
    for (row, &point) in s.iter().enumerate() {
        let kernel = (claims[0] - compressed[0][row]) / (z - E::from(point))
            + (claims[1] - compressed[1][row]) / (z * F::two_adic_generator(11) - E::from(point));
        assert_eq!(kernel, direct_deep(&view, theta, row));
    }
    // A wrong family's PP exponent changes this actual DATA fixture's reduction.
    assert!(s.iter().enumerate().any(|(row, _)| {
        view.pp
            .iter()
            .enumerate()
            .map(|(column, value)| {
                (theta.exp_u64((1124 + column) as u64) - theta.exp_u64((932 + column) as u64))
                    * value.rows[row]
            })
            .sum::<E>()
            != E::ZERO
    }));
    eprintln!(
        "data_joint_public_v S=192 m=197 mT=394 ideal_cells=383953 native_openings=2622 pp_theta_offset=1124 native_row_compression=true original_trace=false whole_B=false proof=false privacy=false admission=false"
    );
}

#[test]
fn changing_only_data_constraint_coin_changes_the_common_quotient_offset() {
    let expected = super::super::super::expected().unwrap();
    let program = DataFoldProgram::from_expected(&expected).unwrap();
    let h = F::two_adic_generator(11);
    let s = [F::GENERATOR, F::GENERATOR * h];
    let mut rng_a = StdRng::seed_from_u64(0x8503);
    let mut rng_b = StdRng::seed_from_u64(0x8503);
    let a = sample(
        &program,
        &coins(u() + E::from_u32(23)),
        E::from_u32(49),
        &s,
        &mut rng_a,
    )
    .unwrap();
    let b = sample(
        &program,
        &coins(u() + E::from_u32(29)),
        E::from_u32(49),
        &s,
        &mut rng_b,
    )
    .unwrap();
    assert_eq!(
        (a.ideal_cells, b.ideal_cells),
        (932 * 5 + 85 * 3, 932 * 5 + 85 * 3)
    );
    assert_eq!(a.main, b.main);
    assert_eq!(a.aux, b.aux);
    assert_eq!(a.r, b.r);
    assert_eq!(a.pp, b.pp);
    let mut changed = false;
    for coordinate in 0..5 {
        let delta_z = b.quotient[0][coordinate].at_z - a.quotient[0][coordinate].at_z;
        let delta_rows = a.quotient[0][coordinate]
            .rows
            .iter()
            .zip(&b.quotient[0][coordinate].rows)
            .map(|(&a, &b)| b - a)
            .collect::<Vec<_>>();
        changed |= delta_z != E::ZERO || delta_rows.iter().any(|&v| v != F::ZERO);
        for chunk in 0..8 {
            assert_eq!(
                b.quotient[chunk][coordinate].at_z - a.quotient[chunk][coordinate].at_z,
                delta_z
            );
            assert_eq!(
                a.quotient[chunk][coordinate]
                    .rows
                    .iter()
                    .zip(&b.quotient[chunk][coordinate].rows)
                    .map(|(&a, &b)| b - a)
                    .collect::<Vec<_>>(),
                delta_rows
            );
        }
    }
    assert!(changed);
    for chunk in 0..8 {
        assert_eq!(a.quotient[chunk][5..], b.quotient[chunk][5..]);
    }
    assert_eq!(rng_a.random::<u64>(), rng_b.random::<u64>());
}
