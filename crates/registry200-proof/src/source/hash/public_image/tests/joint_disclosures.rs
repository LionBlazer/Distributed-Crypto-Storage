//! Replays explicit public cells into the UNCHANGED owning NativeOracle.
//! Child of tests.rs keeps that oracle private; no core visibility is widened.
use super::super::public_disclosures::{self as joint, Column};
use super::*;
use rand_public_pp::{RngExt, SeedableRng, rngs::StdRng};
use std::time::Instant;

fn positions() -> Vec<F> {
    let omega = F::two_adic_generator(13);
    (0..16).map(|i| F::GENERATOR * omega.exp_u64(i)).collect()
}
fn draw(rng: &mut StdRng, degree: usize) -> Poly {
    (0..degree).map(|_| rng.random::<F>()).collect()
}
fn check_column(column: &Column, polynomial: &[F], s: &[F], z: E, next: bool) {
    let values: Vec<E> = column.rows.iter().copied().map(E::from).collect();
    assert_eq!(
        values,
        s.iter()
            .map(|&point| at(polynomial, E::from(point)))
            .collect::<Vec<_>>()
    );
    assert_eq!(column.at_z, at(polynomial, z));
    assert_eq!(
        column.at_hz,
        next.then(|| at(polynomial, z * F::two_adic_generator(9)))
    );
}
fn native_weights(domains: &[TwoAdicMultiplicativeCoset<F>], point: E) -> [E; 16] {
    core::array::from_fn(|i| {
        domains
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| {
                other.vanishing_poly_at_point(point)
                    / E::from(other.vanishing_poly_at_point(domains[i].first_point()))
            })
            .product()
    })
}
fn replayed_mask_values(free: &[Vec<Poly>], ci: &[F; 16], point: E) -> [[E; 16]; 5] {
    // Independent scalar construction from the EXACT explicit free-cell stream.
    // No production ChunkGeometry::masks or quotient_fiber call is involved.
    core::array::from_fn(|b| {
        core::array::from_fn(|i| {
            if i < 15 {
                at(&free[b][i], point)
            } else {
                -free[b]
                    .iter()
                    .enumerate()
                    .map(|(j, polynomial)| at(polynomial, point) * (ci[j] / ci[15]))
                    .sum::<E>()
            }
        })
    })
}
fn changed_state_on_same_public_images() -> SourceVersionExpected {
    // A fresh Owner::seal uses fresh OS nonces. Reuse EXACT images and heads
    // so that only C_state changes, with the same independently sealed version.
    let statement = expected().statement();
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        statement.heads[i]
            .iter()
            .chain(&statement.packets[i])
            .copied()
            .collect()
    });
    let heads: [_; 2] = core::array::from_fn(|i| {
        compact_store::Commitment::decode(&statement.heads[i], crate::source::statement::limits())
            .unwrap()
    });
    let mut state = statement.open_commitment;
    state[0] += F::ONE;
    SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        crate::source::statement::encode_digest(statement.key_commitment),
        crate::source::statement::encode_digest(state),
    )
    .unwrap()
}

#[test]
fn source_joint_preflight_preserves_rng_for_named_public_association_and_geometry_failures() {
    let program = program();
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let z = u + E::from_u32(17);
    let s = positions();
    for (z, s, reason) in [
        (z, vec![s[0]; 193], "Source-joint-disclosure-count"),
        (z, vec![s[0], s[0]], "Source-joint-duplicate-locations"),
        (z, vec![F::ZERO], "Source-joint-physical-locations"),
        (E::ZERO, vec![], "Source-joint-zero-OOD"),
        (E::ONE, vec![], "Source-joint-H512-OOD"),
        (E::from(F::GENERATOR), vec![], "Source-joint-physical-OOD"),
    ] {
        let mut rng = StdRng::seed_from_u64(0x9951);
        let mut before = StdRng::seed_from_u64(0x9951);
        assert!(
            matches!(joint::sample(program, expected(), alpha(), z, &s, &mut rng), Err(error) if error == reason)
        );
        assert_eq!(
            (0..16).map(|_| rng.random::<u64>()).collect::<Vec<_>>(),
            (0..16).map(|_| before.random::<u64>()).collect::<Vec<_>>()
        );
    }
    let other = changed_state_on_same_public_images();
    assert_eq!(other.version_id(), expected().version_id());
    assert_ne!(other.statement().values(), program.public);
    for bad_public in [
        program.public[..PUBLIC - 1].to_vec(),
        other.statement().values(),
    ] {
        let malformed = SourceFoldProgram {
            base: program.base.clone(),
            public: bad_public,
            periodic: program.periodic.clone(),
            node_count: program.node_count,
        };
        let mut rng = StdRng::seed_from_u64(0x9952);
        let mut before = StdRng::seed_from_u64(0x9952);
        assert!(matches!(
            joint::sample(&malformed, expected(), alpha(), z, &s, &mut rng),
            Err("Source-joint-expected-association")
        ));
        assert_eq!(
            (0..16).map(|_| rng.random::<u64>()).collect::<Vec<_>>(),
            (0..16).map(|_| before.random::<u64>()).collect::<Vec<_>>()
        );
    }
    let mut rng = StdRng::seed_from_u64(0x9953);
    let mut before = StdRng::seed_from_u64(0x9953);
    assert!(matches!(
        joint::sample(program, &other, alpha(), z, &s, &mut rng),
        Err("Source-joint-expected-association")
    ));
    assert_eq!(
        (0..16).map(|_| rng.random::<u64>()).collect::<Vec<_>>(),
        (0..16).map(|_| before.random::<u64>()).collect::<Vec<_>>()
    );
    let domain = DisclosureDomain::checked(z, &s).unwrap();
    assert!(matches!(
        PublicResidues::checked(&domain, vec![vec![]; MAIN - 1]),
        Err("Source-public-residue-shape")
    ));
    let mut oversized = vec![vec![]; MAIN];
    oversized[0] = vec![F::ONE; domain.enlarged.degree() + 1];
    assert!(matches!(
        PublicResidues::checked(&domain, oversized),
        Err("Source-public-residue-shape")
    ));
    // Raw192 indices may repeat, but the sampler's actual disclosed S is unique.
    let raw = [s[0], s[3], s[0], s[15], s[3]];
    let unique = [s[0], s[3], s[15]];
    let reuse = [0, 1, 0, 2, 1];
    assert_eq!(raw, reuse.map(|index| unique[index]));
}

#[test]
#[ignore = "Source small16 joint/native comparison requires the owning held-process resource observer"]
fn source_joint_small16_replays_all_main_cells_and_matches_native_rows_and_five_ood_embeddings() {
    let began = Instant::now();
    let program = program();
    let native = oracle();
    let s = positions();
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let z = u + E::from_u32(17);
    let domain = DisclosureDomain::checked(z, &s).unwrap();
    assert_eq!((domain.target.degree(), domain.enlarged.degree()), (21, 42));
    assert!(s.iter().all(|point| !s.contains(&(*point * domain.h))));
    assert_eq!(program.public, expected().statement().values());
    assert_eq!(native.public, program.public);
    assert_eq!((MAIN, PUBLIC, INPUT_HEIGHT), (7161, 691, 8192));
    assert_eq!(count_nodes(&program.base), program.node_count);
    let mut rng = StdRng::seed_from_u64(0x9954);
    let mut replay = StdRng::seed_from_u64(0x9954);

    // Primary Act: the actual Source program consumes public enlarged residues.
    let v = joint::sample(program, expected(), alpha(), z, &s, &mut rng).unwrap();
    let sampled_ms = began.elapsed().as_secs_f64() * 1000.;
    v.require_expected(expected()).unwrap();
    assert_eq!(v.expected_public, program.public);
    assert_eq!(v.s, s);
    assert_eq!(v.z, z);
    assert_eq!((v.main.len(), v.r.len(), v.quotient.len()), (7166, 10, 16));
    assert!(v.quotient.iter().all(|chunk| chunk.len() == 10));
    assert!(
        v.main
            .iter()
            .all(|column| column.rows.len() == 16 && column.at_hz.is_some())
    );
    assert!(
        v.r.iter()
            .chain(v.quotient.iter().flatten())
            .all(|column| column.rows.len() == 16 && column.at_hz.is_none())
    );
    assert_eq!(v.constraint_count, program.base.len());
    assert_eq!(v.cached_nodes, program.node_count);
    assert_eq!(v.ideal_cells, (7161 + 5) * 42 + (15 * 5 + 16 * 5 + 10) * 21);
    assert_eq!(v.ideal_cells, 304_437);
    let main: Vec<Poly> = (0..MAIN).map(|_| draw(&mut replay, 42)).collect();
    for (column, polynomial) in v.main[..MAIN].iter().zip(&main) {
        check_column(column, polynomial, &s, z, true);
    }
    // Retain all five coordinates' fifteen free masks in the EXACT draw order.
    // Aggregate recomposition alone would also accept q_i=q while ignoring
    // these cells; every original Q column is checked below against its mask.
    let free: Vec<Vec<Poly>> = (0..5)
        .map(|_| (0..15).map(|_| draw(&mut replay, 21)).collect())
        .collect();
    // Independently inspect every Q/MAIN wrapper and R column by scalar Horner.
    for chunk in &v.quotient {
        for column in &chunk[5..] {
            check_column(column, &draw(&mut replay, 21), &s, z, false);
        }
    }
    for column in &v.main[MAIN..] {
        check_column(column, &draw(&mut replay, 42), &s, z, true);
    }
    for column in &v.r {
        check_column(column, &draw(&mut replay, 21), &s, z, false);
    }
    assert_eq!(
        (0..16).map(|_| rng.random::<u64>()).collect::<Vec<_>>(),
        (0..16).map(|_| replay.random::<u64>()).collect::<Vec<_>>()
    );

    let domains = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 10)
        .unwrap()
        .create_disjoint_domain(8192)
        .split_domains(16);
    let ci: [F; 16] = core::array::from_fn(|i| {
        domains
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| other.vanishing_poly_at_point(domains[i].first_point()))
            .product::<F>()
            .inverse()
    });
    assert!(ci.iter().all(|&value| value == -F::from_u32(16).inverse()));
    let mut nontrivial_masks = [false; 5];
    let base_began = Instant::now();
    for (row, &point) in s.iter().enumerate() {
        let direct = native.fold(&main, E::from(point), alpha());
        let coefficients: &[F] = direct.as_basis_coefficients_slice();
        assert_eq!(coefficients.len(), 5);
        let masks = replayed_mask_values(&free, &ci, E::from(point));
        for (i, chunk) in v.quotient.iter().enumerate() {
            let vanishing = domains[i].vanishing_poly_at_point(E::from(point));
            for (b, &coefficient) in coefficients.iter().enumerate() {
                let mask_contribution = vanishing * masks[b][i];
                nontrivial_masks[b] |= mask_contribution != E::ZERO;
                assert_eq!(
                    E::from(chunk[b].rows[row]),
                    E::from(coefficient) + mask_contribution,
                    "same-cell Q chunk={i} coordinate={b} row={row}"
                );
            }
        }
        let weights = native_weights(&domains, E::from(point));
        assert_eq!(weights, core::array::from_fn(|i| E::from_bool(i == row)));
        for (b, &coefficient) in coefficients.iter().enumerate() {
            let actual: E = v
                .quotient
                .iter()
                .zip(weights)
                .map(|(chunk, weight)| weight * chunk[b].rows[row])
                .sum();
            assert_eq!(actual, E::from(coefficient));
            assert_eq!(v.quotient[row][b].rows[row], coefficient);
        }
        let claims: Vec<Vec<E>> = v
            .quotient
            .iter()
            .map(|chunk| {
                chunk[..5]
                    .iter()
                    .map(|column| E::from(column.rows[row]))
                    .collect()
            })
            .collect();
        assert_eq!(
            p3_uni_stark::recompose_quotient_from_chunks::<bfv_hiding_stark::hash::Config>(
                &domains,
                &claims,
                E::from(point)
            ),
            direct
        );
    }
    assert!(nontrivial_masks.into_iter().all(|seen| seen));
    let base_ms = base_began.elapsed().as_secs_f64() * 1000.;
    let masks_at_z = replayed_mask_values(&free, &ci, z);
    let weights = native_weights(&domains, z);
    let coefficients: [E; 5] = core::array::from_fn(|b| {
        v.quotient
            .iter()
            .zip(weights)
            .map(|(chunk, weight)| weight * chunk[b].at_z)
            .sum()
    });
    let claims: Vec<Vec<E>> = v
        .quotient
        .iter()
        .map(|chunk| chunk[..5].iter().map(|column| column.at_z).collect())
        .collect();
    let mut corrupted = v.quotient.clone();
    corrupted[15][0].at_z += E::ONE;
    let corrupted_coefficients: [E; 5] = core::array::from_fn(|b| {
        corrupted
            .iter()
            .zip(weights)
            .map(|(chunk, weight)| weight * chunk[b].at_z)
            .sum()
    });
    for (good, bad) in v.quotient.iter().flatten().zip(corrupted.iter().flatten()) {
        assert_eq!(good.rows, bad.rows);
    }
    let ood_began = Instant::now();
    for (embedding, basis) in (0..5).map(|i| u.repeated_frobenius(i)).enumerate() {
        let actual: E = coefficients
            .iter()
            .zip(basis.powers())
            .map(|(&c, power)| c * power)
            .sum();
        // Keep z, MAIN(z,hz) and genuine periodic512 FIXED; only the coefficient
        // alpha is conjugated. This tests all five tensor copies, not Q(z) alone.
        let reference = native.fold(&main, z, alpha().repeated_frobenius(embedding));
        assert_eq!(actual, reference);
        for (i, chunk) in v.quotient.iter().enumerate() {
            let actual_chunk: E = chunk[..5]
                .iter()
                .zip(basis.powers())
                .map(|(column, power)| column.at_z * power)
                .sum();
            let mask_image: E = masks_at_z
                .iter()
                .zip(basis.powers())
                .map(|(coordinate, power)| coordinate[i] * power)
                .sum();
            assert_eq!(
                actual_chunk,
                reference + domains[i].vanishing_poly_at_point(z) * mask_image,
                "same-cell Q chunk={i} OOD coefficient_embedding={embedding}"
            );
        }
        if embedding == 0 {
            assert_eq!(
                p3_uni_stark::recompose_quotient_from_chunks::<bfv_hiding_stark::hash::Config>(
                    &domains, &claims, z
                ),
                reference
            );
        }
        // Actual V corruption: base rows unchanged; one last-chunk OOD value
        // is altered. All five coefficient embeddings must detect it.
        let damaged: E = corrupted_coefficients
            .iter()
            .zip(basis.powers())
            .map(|(&c, power)| c * power)
            .sum();
        assert_eq!(damaged - actual, weights[15]);
        assert_ne!(damaged, reference);
    }
    let other = changed_state_on_same_public_images();
    assert_eq!(other.version_id(), expected().version_id());
    assert_eq!(
        v.require_expected(&other),
        Err("Source-joint-expected-association")
    );
    eprintln!(
        "source_joint_v small16=true MAIN=7166 R=10 Q=16x10 public=691 target_degree=21 source_degree=42 ideal_cells={} constraints={} source_nodes={} cached_nodes={} sample_ms={sampled_ms:.3} native_base_ms={base_ms:.3} native_ood_ms={:.3} base_coordinate_equalities=80 same_cell_chunk_base_equalities=1280 same_cell_chunk_ood_equalities=80 coefficient_embeddings=5 public_only=true honest_trace=false proof=false privacy=false admission=false",
        v.ideal_cells,
        v.constraint_count,
        program.node_count,
        v.cached_nodes,
        ood_began.elapsed().as_secs_f64() * 1000.
    );
}
