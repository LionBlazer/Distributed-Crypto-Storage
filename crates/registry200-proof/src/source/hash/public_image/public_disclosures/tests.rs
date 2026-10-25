//! Independent native split, literal product weights and finite-cell rank.
use super::*;
use p3_field::{BasedVectorSpace, ExtensionField};
use rand_public_pp::{SeedableRng, rngs::StdRng};

fn u() -> E {
    E::from_basis_coefficients_fn(|i| F::from_bool(i == 1))
}
fn positions() -> Vec<F> {
    let omega = F::two_adic_generator(13);
    (0..16).map(|i| F::GENERATOR * omega.exp_u64(i)).collect()
}
fn native_domains() -> Vec<TwoAdicMultiplicativeCoset<F>> {
    TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 10)
        .unwrap()
        .create_disjoint_domain(8192)
        .split_domains(16)
}
fn v(domains: &[TwoAdicMultiplicativeCoset<F>], point: E) -> [E; 16] {
    core::array::from_fn(|i| (point / E::from(domains[i].shift())).exp_u64(512) - E::ONE)
}
fn weights(domains: &[TwoAdicMultiplicativeCoset<F>], point: E) -> [E; 16] {
    // Literal division-free-in-X Lagrange products, not the sampler's ci/masks.
    core::array::from_fn(|i| {
        domains
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| {
                ((point / E::from(other.shift())).exp_u64(512) - E::ONE)
                    / E::from((domains[i].shift() / other.shift()).exp_u64(512) - F::ONE)
            })
            .product()
    })
}
fn rank(mut rows: Vec<Vec<E>>) -> usize {
    let mut found = 0;
    for column in 0..rows[0].len() {
        let Some(pivot) = (found..rows.len()).find(|&row| rows[row][column] != E::ZERO) else {
            continue;
        };
        rows.swap(found, pivot);
        let inverse = rows[found][column].inverse();
        rows[found].iter_mut().for_each(|value| *value *= inverse);
        let pivot = rows[found].clone();
        for (row, values) in rows.iter_mut().enumerate() {
            if row != found {
                let scale = values[column];
                for (value, &pivot) in values.iter_mut().zip(&pivot) {
                    *value -= scale * pivot;
                }
            }
        }
        found += 1;
    }
    found
}
fn collapse(
    chunks: &[Vec<Poly>],
    domains: &[TwoAdicMultiplicativeCoset<F>],
    point: E,
    basis: E,
) -> E {
    let w = weights(domains, point);
    chunks
        .iter()
        .zip(w)
        .map(|(chunk, weight)| {
            weight
                * chunk[..5]
                    .iter()
                    .zip(basis.powers())
                    .map(|(p, power)| ring::evaluate(p, point) * power)
                    .sum::<E>()
        })
        .sum()
}

#[test]
fn actual_sixteen_cosets_have_normalized_zero_divisors_and_rank_fifteen_at_every_cell() {
    let s = positions();
    let z = u() + E::from_u32(17);
    let domain = DisclosureDomain::checked(z, &s).unwrap();
    assert_eq!((domain.target.degree(), domain.enlarged.degree()), (21, 42));
    let geometry = ChunkGeometry::new(&domain.target).unwrap();
    let native = native_domains();
    let omega = F::two_adic_generator(13);
    let expected_ci = -F::from_u32(16).inverse();
    for (i, chunk) in native.iter().enumerate() {
        assert_eq!(chunk.size(), 512);
        assert_eq!(chunk.shift(), F::GENERATOR * omega.exp_u64(i as u64));
        assert_eq!(chunk.subgroup_generator(), F::two_adic_generator(9));
        assert_eq!(geometry.domains[i].shift(), chunk.shift());
        assert_eq!(geometry.domains[i].size(), chunk.size());
        let product: F = native
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| other.vanishing_poly_at_point(chunk.first_point()))
            .product();
        assert_eq!(geometry.ci[i], product.inverse());
        assert_eq!(geometry.ci[i], expected_ci);
        // Every v_i has a real root in S. A false all-units guard would reject
        // the complete legitimate Source location set used by this gate.
        assert_eq!(
            domain.target.inverse(&geometry.vanishing[i]),
            Err("nonunit-in-disclosure-ring")
        );
    }
    for (case, point) in s.iter().copied().map(E::from).chain([z]).enumerate() {
        let values = v(&native, point);
        let w = weights(&native, point);
        assert_eq!(w.into_iter().sum::<E>(), E::ONE);
        let global = (point / E::from(F::GENERATOR)).exp_u64(8192) - E::ONE;
        for i in 0..16 {
            assert_eq!(ring::evaluate(&geometry.vanishing[i], point), values[i]);
            assert_eq!(w[i] * values[i], global / E::from_u32(16));
        }
        if case < 16 {
            assert_eq!(w, core::array::from_fn(|i| E::from_bool(case == i)));
            assert_eq!(values.iter().filter(|&&value| value == E::ZERO).count(), 1);
        } else {
            assert!(values.iter().all(|&value| value != E::ZERO));
        }
        // Independent fifteen-variable linear map. Do not derive this matrix
        // by invoking the implementation's masks() on its own basis inputs.
        let matrix: Vec<Vec<E>> = (0..16)
            .map(|row| {
                (0..15)
                    .map(|column| {
                        if row == 15 {
                            -values[15] * (geometry.ci[column] / geometry.ci[15])
                        } else if row == column {
                            values[row]
                        } else {
                            E::ZERO
                        }
                    })
                    .collect()
            })
            .collect();
        assert_eq!(rank(matrix.clone()), 15);
        if case < 16 {
            let deleted: Vec<_> = matrix
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != case)
                .map(|(_, row)| row.clone())
                .collect();
            assert_eq!(rank(deleted), 15);
        } else {
            assert_eq!(rank(matrix[..15].to_vec()), 15);
        }
        for (column, _) in matrix[0].iter().enumerate() {
            let masks = geometry.masks(core::array::from_fn(|i| vec![F::from_bool(i == column)]));
            for row in 0..16 {
                let actual = ring::evaluate(
                    &domain
                        .target
                        .multiply(&geometry.vanishing[row], &masks[row]),
                    point,
                );
                assert_eq!(actual, matrix[row][column]);
            }
        }
        if case == 0 {
            let mut omitted_last = matrix.clone();
            omitted_last[15].fill(E::ZERO);
            assert_eq!(rank(omitted_last), 14);
        }
    }
}

#[test]
fn small_sixteen_fiber_recomposes_all_five_coordinates_and_the_native_sdk_image() {
    let s = positions();
    let z = u() + E::from_u32(17);
    let domain = DisclosureDomain::checked(z, &s).unwrap();
    let geometry = ChunkGeometry::new(&domain.target).unwrap();
    let native = native_domains();
    // Explicit compatible affine baseline q_i=q, not quotient chunks generated
    // by an honest Source trace. Native-baseline association stays unresolved.
    let q: [Poly; 5] = core::array::from_fn(|b| {
        (0..domain.target.degree())
            .map(|i| F::from_usize(7 * i + 11 * b + 3))
            .collect()
    });
    let mut rng = StdRng::seed_from_u64(0x9950);
    let mut cells = Cells {
        rng: &mut rng,
        count: 0,
    };
    let chunks = quotient_fiber(&domain.target, &q, &geometry, &mut cells);
    assert_eq!(cells.count, (15 * 5 + 16 * 5) * 21);
    assert_eq!(chunks.len(), 16);
    assert!(chunks.iter().all(|chunk| chunk.len() == 10));
    assert!(chunks.iter().flatten().all(|p| p.len() <= 21));
    for (case, point) in s.iter().copied().map(E::from).chain([z]).enumerate() {
        let w = weights(&native, point);
        for b in 0..5 {
            let reconstructed: E = chunks
                .iter()
                .zip(w)
                .map(|(chunk, weight)| weight * ring::evaluate(&chunk[b], point))
                .sum();
            assert_eq!(reconstructed, ring::evaluate(&q[b], point));
            if case < 16 {
                assert_eq!(ring::evaluate(&chunks[case][b], point), reconstructed);
            }
        }
        let claims: Vec<Vec<E>> = chunks
            .iter()
            .map(|chunk| {
                chunk[..5]
                    .iter()
                    .map(|p| ring::evaluate(p, point))
                    .collect()
            })
            .collect();
        let sdk = p3_uni_stark::recompose_quotient_from_chunks::<bfv_hiding_stark::hash::Config>(
            &native, &claims, point,
        );
        assert_eq!(sdk, collapse(&chunks, &native, point, u()));
        for basis in (0..5).map(|j| {
            use p3_field::extension::HasFrobenius;
            u().repeated_frobenius(j)
        }) {
            let expected: E = q
                .iter()
                .zip(basis.powers())
                .map(|(p, power)| ring::evaluate(p, point) * power)
                .sum();
            assert_eq!(collapse(&chunks, &native, point, basis), expected);
        }
    }
}

#[test]
fn wrong_last_sign_mixed_normalization_and_chunk_order_have_independent_negative_oracles() {
    let s = positions();
    let z = u() + E::from_u32(17);
    let domain = DisclosureDomain::checked(z, &s).unwrap();
    let geometry = ChunkGeometry::new(&domain.target).unwrap();
    let native = native_domains();
    let masks = geometry.masks(core::array::from_fn(|i| {
        if i == 0 { vec![F::ONE] } else { vec![] }
    }));
    let mut correct = vec![vec![Vec::new(); 10]; 16];
    for i in 0..16 {
        correct[i][0] = domain.target.multiply(&geometry.vanishing[i], &masks[i]);
    }
    let mut independent_last = correct.clone();
    // Replace the correlated last mask -1 with an explicit independent cell0.
    independent_last[15][0] = Vec::new();
    let mut wrong_sign = correct.clone();
    wrong_sign[15][0] = ring::scale(&wrong_sign[15][0], -F::ONE);
    let xn = domain.target.power(&[F::ZERO, F::ONE], 512);
    let mut mixed_normalization = correct.clone();
    for i in 0..16 {
        // Deliberately mix MONIC v_i with native NORMALIZED ci/mask relation.
        // A fully consistent monic rescaling would be an equivalent recipe.
        let monic = ring::sub(&xn, &[native[i].shift().exp_u64(512)]);
        mixed_normalization[i][0] = domain.target.multiply(&monic, &masks[i]);
    }
    let global = (z / E::from(F::GENERATOR)).exp_u64(8192) - E::ONE;
    let bad = [&independent_last, &wrong_sign, &mixed_normalization];
    let exact_errors = [
        global / E::from_u32(16),
        global / E::from_u32(8),
        global * (native[0].shift().exp_u64(512) - native[15].shift().exp_u64(512))
            / E::from_u32(16),
    ];
    for (bad, error) in bad.into_iter().zip(exact_errors) {
        assert_ne!(error, E::ZERO);
        // Every base row is BLIND to these errors. Testing only roots would
        // falsely approve the independently drawn last mask and wrong sign.
        for &point in &s {
            assert_eq!(collapse(bad, &native, E::from(point), u()), E::ZERO);
        }
        for basis in (0..5).map(|j| {
            use p3_field::extension::HasFrobenius;
            u().repeated_frobenius(j)
        }) {
            assert_eq!(collapse(bad, &native, z, basis), error);
        }
    }
    for point in s.iter().copied().map(E::from).chain([z]) {
        assert_eq!(collapse(&correct, &native, point, u()), E::ZERO);
    }
    let mut swapped = correct.clone();
    swapped.swap(0, 15);
    assert_eq!(
        s.iter()
            .filter(|&&point| collapse(&swapped, &native, E::from(point), u()) != E::ZERO)
            .count(),
        2
    );
    assert!(<E as ExtensionField<F>>::as_base(&z).is_none());
}
