//! Actual public fold -> joint V -> whole-B composition, without private inputs.
use super::super::{
    public_image::{
        QueryCoins, QueryFoldProgram,
        public_disclosures::{self, Column, Disclosures},
    },
    tests::metadata,
};
use super::public_deep;
use bfv_hiding_stark::{Challenge as E, Val as F};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField};
use rand_public_pp::{RngExt, SeedableRng, rngs::StdRng};

fn u() -> E {
    E::from_basis_coefficients_fn(|i| F::from_bool(i == 1))
}
fn coins(alpha: E) -> QueryCoins {
    QueryCoins {
        lookup_alpha: u() + E::from_u32(17),
        lookup_beta: u() + E::from_u32(19),
        constraint_alpha: alpha,
    }
}
fn deep_columns(columns: &[Column]) -> Vec<public_deep::Column> {
    columns
        .iter()
        .map(|column| public_deep::Column {
            rows: column.rows.clone(),
            at_z: column.at_z,
            at_hz: column.at_hz,
        })
        .collect()
}
fn value(p: &[E], x: E) -> E {
    p.iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * x + coefficient)
}

fn direct_deep(view: &Disclosures, theta: E, row: usize) -> E {
    // An evaluation-only reference, no sampler CRT/remainder/accumulator code.
    let x = E::from(view.s[row]);
    let denominators = [
        (view.z - x).inverse(),
        (view.z * F::two_adic_generator(11) - x).inverse(),
    ];
    let mut sum = E::ZERO;
    let mut exponent = 0;
    let mut matrix = |columns: &[Column], two: bool| {
        for (next, &inverse) in denominators
            .iter()
            .enumerate()
            .take(if two { 2 } else { 1 })
        {
            for column in columns {
                let claim = if next == 0 {
                    column.at_z
                } else {
                    column.at_hz.unwrap()
                };
                sum += theta.exp_u64(exponent) * (claim - E::from(column.rows[row])) * inverse;
                exponent += 1;
            }
        }
    };
    matrix(&view.r, false);
    matrix(&view.main, true);
    for chunk in &view.quotient {
        matrix(chunk, false);
    }
    matrix(&view.pp, false);
    matrix(&view.aux, true);
    assert_eq!(exponent, 2327);
    sum
}

#[test]
fn actual_joint_public_192_disclosures_prepare_and_instantiate_the_whole_native_deep_image() {
    // Arrange: public Expected, fixed coins/locations and an explicit PUBLIC
    // seed for reproducibility. No original Query Prepared/trace/witness exists.
    let expected = metadata();
    let program = QueryFoldProgram::from_expected(&expected).unwrap();
    let omega = F::two_adic_generator(15);
    let s: Vec<F> = (0..192)
        .map(|i| F::GENERATOR * omega.exp_u64(64 * i + i % 2))
        .collect();
    let z = u() + E::from_u32(2);
    let theta = u() + E::from_u32(3);
    let mut rng = StdRng::seed_from_u64(0x7902);

    // Act: sample SAME-coins joint trace/quotient V, including correlated chunks.
    let view = public_disclosures::sample(&program, &coins(u() + E::from_u32(23)), z, &s, &mut rng)
        .unwrap();
    assert_eq!(view.expected_binding, expected.binding());
    assert_eq!(view.s, s);
    assert_eq!(view.z, z);
    assert_eq!(view.ideal_cells, 846 * 394 + 85 * 197);
    assert_eq!(
        (
            view.r.len(),
            view.main.len(),
            view.quotient.len(),
            view.pp.len(),
            view.aux.len()
        ),
        (10, 421, 8, 545, 425)
    );
    assert!(view.quotient.iter().all(|chunk| chunk.len() == 10));
    assert!(
        view.r
            .iter()
            .chain(&view.pp)
            .chain(view.quotient.iter().flatten())
            .all(|c| c.rows.len() == 192 && c.at_hz.is_none())
    );
    assert!(
        view.main
            .iter()
            .chain(&view.aux)
            .all(|c| c.rows.len() == 192 && c.at_hz.is_some())
    );

    // Explicit raw-data conversion. Neither side grants proof acceptance.
    let r = deep_columns(&view.r);
    let main = deep_columns(&view.main);
    let quotient: Vec<_> = view
        .quotient
        .iter()
        .map(|chunk| deep_columns(chunk))
        .collect();
    let pp = deep_columns(&view.pp);
    let aux = deep_columns(&view.aux);
    let deep_view = public_deep::PublicView {
        s: &view.s,
        z,
        theta,
        r: &r,
        main: &main,
        quotient: &quotient,
        pp: &pp,
        pp_coefficients: program.public_pp_coefficients(),
        aux: &aux,
    };
    let prepared = public_deep::prepare(&deep_view).unwrap();
    assert_eq!(prepared.opening_count(), 2327);
    assert_eq!(prepared.free_coefficients(), 3899);
    let mask: Vec<E> = (0..3899)
        .map(|i| E::from_basis_coefficients_fn(|b| F::from_usize(5 * i + b + 11)))
        .collect();
    let b = prepared.instantiate(&mask).unwrap();
    assert_eq!(b.len(), 4095);
    assert_ne!(b.as_slice(), prepared.origin());

    // Assert: direct native evaluation at every physical S, independent of the
    // sampler polynomial representation. The conditional algebra law, rather
    // than honest global AIR validity, supplies the distribution interpretation.
    for (row, &point) in s.iter().enumerate() {
        let direct = direct_deep(&view, theta, row);
        assert_eq!(value(prepared.origin(), E::from(point)), direct);
        assert_eq!(value(&b, E::from(point)), direct);
    }
    eprintln!(
        "query_joint_public_v S=192 m=197 mT=394 ideal_cells={} native_openings=2327 original_trace=false proof=false privacy=false",
        view.ideal_cells
    );
}

#[test]
fn changing_only_constraint_coin_changes_the_correlated_quotient_offset_and_no_other_cell_image() {
    let expected = metadata();
    let program = QueryFoldProgram::from_expected(&expected).unwrap();
    let h = F::two_adic_generator(11);
    // S overlaps h*S. Base OOD is supported without treating its five
    // Frobenius coordinates as independent samples.
    let s = [F::GENERATOR, F::GENERATOR * h];
    let mut rng_a = StdRng::seed_from_u64(0x7903);
    let mut rng_b = StdRng::seed_from_u64(0x7903);
    let a = public_disclosures::sample(
        &program,
        &coins(u() + E::from_u32(23)),
        E::from_u32(49),
        &s,
        &mut rng_a,
    )
    .unwrap();
    let b = public_disclosures::sample(
        &program,
        &coins(u() + E::from_u32(29)),
        E::from_u32(49),
        &s,
        &mut rng_b,
    )
    .unwrap();
    assert_eq!(
        (a.ideal_cells, b.ideal_cells),
        (846 * 5 + 85 * 3, 846 * 5 + 85 * 3)
    );
    assert_eq!(a.main, b.main);
    assert_eq!(a.aux, b.aux);
    assert_eq!(a.r, b.r);
    assert_eq!(a.pp, b.pp);
    let mut changed = false;
    for coordinate in 0..5 {
        let delta_z = b.quotient[0][coordinate].at_z - a.quotient[0][coordinate].at_z;
        let delta_rows: Vec<F> = a.quotient[0][coordinate]
            .rows
            .iter()
            .zip(&b.quotient[0][coordinate].rows)
            .map(|(&a, &b)| b - a)
            .collect();
        changed |= delta_z != E::ZERO || delta_rows.iter().any(|&value| value != F::ZERO);
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
