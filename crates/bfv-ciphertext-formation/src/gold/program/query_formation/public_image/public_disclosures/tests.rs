//! Native geometry and finite fiber algebra; public data, not a valid AIR trace.
use super::*;
use p3_field::{BasedVectorSpace, ExtensionField};
use rand_public_pp::{SeedableRng, rngs::StdRng};

fn u() -> E {
    E::from_basis_coefficients_fn(|i| F::from_bool(i == 1))
}

fn full_positions() -> Vec<F> {
    let omega = F::two_adic_generator(15);
    // Distinct physical S, disjoint h*S, and both inside/outside U=7H16384.
    (0..192)
        .map(|i| F::GENERATOR * omega.exp_u64(64 * i + i % 2))
        .collect()
}

fn selectors(geometry: &ChunkGeometry, point: E) -> [E; 8] {
    // Independent division-free literal products, including roots of any v_i.
    core::array::from_fn(|i| {
        geometry
            .domains
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .fold(E::from(geometry.ci[i]), |product, (_, domain)| {
                product * ((point / E::from(domain.shift())).exp_u64(2048) - E::ONE)
            })
    })
}

#[test]
fn native_split_order_and_normalized_physical_vanishing_are_preserved() {
    let domain = DisclosureDomain::checked(u() + E::from_u32(17), &full_positions()).unwrap();
    let geometry = ChunkGeometry::new(&domain.target).unwrap();
    let omega = F::two_adic_generator(14);
    for (i, chunk) in geometry.domains.iter().enumerate() {
        assert_eq!(chunk.size(), 2048);
        assert_eq!(chunk.shift(), F::GENERATOR * omega.exp_u64(i as u64));
        assert_eq!(chunk.subgroup_generator(), F::two_adic_generator(11));
        let weights = selectors(&geometry, E::from(chunk.shift()));
        assert_eq!(weights, core::array::from_fn(|j| E::from_bool(i == j)));
        for &point in &full_positions() {
            assert_eq!(
                ring::evaluate(&geometry.vanishing[i], E::from(point)),
                E::from((point / chunk.shift()).exp_u64(2048) - F::ONE)
            );
        }
    }
    for point in [E::ZERO, E::from_u32(49), u()] {
        assert_eq!(selectors(&geometry, point).into_iter().sum::<E>(), E::ONE);
    }
}

#[test]
fn correlated_fiber_recomposes_all_five_coordinates_at_the_complete_192_location_budget() {
    let s = full_positions();
    let z = u() + E::from_u32(17);
    let domain = DisclosureDomain::checked(z, &s).unwrap();
    assert_eq!((domain.target.degree(), domain.source_degree()), (197, 394));
    let geometry = ChunkGeometry::new(&domain.target).unwrap();
    let q: [Poly; 5] = core::array::from_fn(|b| {
        (0..197)
            .map(|i| F::from_usize(7 * i + 11 * b + 3))
            .collect()
    });
    let mut rng = StdRng::seed_from_u64(0x7900);
    let mut cells = Cells {
        rng: &mut rng,
        count: 0,
    };
    let chunks = quotient_fiber(&domain.target, &q, &geometry, &mut cells);
    assert_eq!(cells.count, 75 * 197);
    assert_eq!(chunks.len(), 8);
    assert!(chunks.iter().all(|chunk| chunk.len() == 10));
    assert!(chunks.iter().flatten().all(|p| p.len() <= 197));
    let mut roots_seen = [false; 8];
    let mut outside_u = false;
    for point in s.iter().copied().map(E::from).chain([z]) {
        let weights = selectors(&geometry, point);
        for (b, q) in q.iter().enumerate() {
            let recomposed: E = chunks
                .iter()
                .zip(weights)
                .map(|(chunk, weight)| weight * ring::evaluate(&chunk[b], point))
                .sum();
            assert_eq!(recomposed, ring::evaluate(q, point));
        }
        let root = geometry
            .domains
            .iter()
            .position(|chunk| (point / E::from(chunk.shift())).exp_u64(2048) == E::ONE);
        if let Some(i) = root {
            roots_seen[i] = true;
            for b in 0..5 {
                assert_eq!(
                    ring::evaluate(&chunks[i][b], point),
                    ring::evaluate(&q[b], point)
                );
            }
        } else {
            outside_u = true;
        }
    }
    assert!(roots_seen.iter().any(|&seen| seen));
    assert!(outside_u);
    // The five fixed coefficient copies do not collapse at the EF5 point.
    assert_ne!(ring::evaluate(&q[0], z), ring::evaluate(&q[1], z));
}

fn rank(mut rows: Vec<Vec<F>>) -> usize {
    let mut rank = 0;
    for column in 0..rows[0].len() {
        let Some(pivot) = (rank..rows.len()).find(|&row| rows[row][column] != F::ZERO) else {
            continue;
        };
        rows.swap(rank, pivot);
        let inverse = rows[rank][column].inverse();
        rows[rank].iter_mut().for_each(|value| *value *= inverse);
        let pivot = rows[rank].clone();
        for (row, values) in rows.iter_mut().enumerate() {
            if row != rank {
                let scale = values[column];
                for (value, &pivot) in values.iter_mut().zip(&pivot) {
                    *value -= scale * pivot;
                }
            }
        }
        rank += 1;
    }
    rank
}

#[test]
fn seven_free_mask_coordinates_have_full_kernel_rank_even_at_a_zero_vanishing_factor() {
    let omega = F::two_adic_generator(14);
    for z in core::iter::once(E::from_u32(49))
        .chain((0..8).map(|i| E::from(F::GENERATOR * omega.exp_u64(i))))
    {
        let domain = DisclosureDomain::checked(z, &[]).unwrap();
        assert_eq!(domain.target.degree(), 1);
        let geometry = ChunkGeometry::new(&domain.target).unwrap();
        let mut image = Vec::new();
        for basis in 0..7 {
            let masks = geometry.masks(core::array::from_fn(|i| vec![F::from_bool(i == basis)]));
            assert!(
                ring::trim(masks.iter().enumerate().fold(Vec::new(), |sum, (i, r)| {
                    ring::add(&sum, &ring::scale(r, geometry.ci[i]))
                }))
                .is_empty()
            );
            let values: Vec<F> = masks
                .iter()
                .enumerate()
                .map(|(i, mask)| {
                    let value =
                        ring::evaluate(&domain.target.multiply(&geometry.vanishing[i], mask), z);
                    <E as ExtensionField<F>>::as_base(&value).unwrap()
                })
                .collect();
            let weights = selectors(&geometry, z);
            assert_eq!(
                values.iter().zip(weights).map(|(&v, w)| w * v).sum::<E>(),
                E::ZERO
            );
            if let Some(root) = geometry
                .domains
                .iter()
                .position(|chunk| (z / E::from(chunk.shift())).exp_u64(2048) == E::ONE)
            {
                assert_eq!(values[root], F::ZERO);
            }
            image.push(values);
        }
        assert_eq!(rank(image), 7);
    }
}

#[test]
fn invalid_physical_locations_and_exceptional_ood_reject_before_sampling_cells() {
    let expected = super::super::super::tests::metadata();
    let program = QueryFoldProgram::from_expected(&expected).unwrap();
    let coins = QueryCoins {
        lookup_alpha: u(),
        lookup_beta: u() + E::ONE,
        constraint_alpha: u() + E::TWO,
    };
    for (z, s) in [
        (u(), vec![F::GENERATOR; 2]),
        (u(), vec![F::ZERO]),
        (u(), vec![F::GENERATOR; 193]),
        (E::ZERO, vec![]),
        (E::ONE, vec![]),
        (E::from(F::GENERATOR), vec![]),
    ] {
        let mut rng = StdRng::seed_from_u64(0x7901);
        assert!(sample(&program, &coins, z, &s, &mut rng).is_err());
        let mut control = StdRng::seed_from_u64(0x7901);
        assert_eq!(rng.random::<u64>(), control.random::<u64>());
    }
}
