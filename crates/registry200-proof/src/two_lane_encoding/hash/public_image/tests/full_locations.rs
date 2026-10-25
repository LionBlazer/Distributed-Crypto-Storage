//! Full192 PUBLIC Role3 arithmetic. Select only under the held-process observer.
//! Deliberately uses the unchanged independent NativeOracle without optimization.
use super::*;
use std::time::Instant;

#[test]
#[ignore = "full192 Role3 comparison requires the owning held-process resource observer"]
fn all_five_role3_coordinate_polynomials_match_native_folder_on_192_rows_and_five_ood_embeddings() {
    let began = Instant::now();
    eprintln!(
        "role3_public_image full_locations=true phase=setup_begin public_only=true proof=false"
    );
    let program = program();
    let native = oracle();
    assert_eq!((N, MAIN, PUBLIC, INPUT_HEIGHT), (512, 1656, 740, 8192));
    assert_eq!(program.public, statement().values());
    assert_eq!(native.public, program.public);
    assert_eq!(
        program.expected_binding,
        super::super::super::binding(statement())
    );
    // Compare against the current real Role3 graph, not a DATA cache constant
    // or a new caller-configurable constraint/node limit. Nonce/Expected changes
    // can alter the actual node count; never substitute a prior numeric count.
    assert_eq!(program.base.len(), 6_916);
    assert_eq!(count_nodes(&program.base), program.node_count);
    let constraint_alpha = alpha();
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let z = u + E::from_u32(2);
    assert!(<E as ExtensionField<F>>::as_base(&z).is_none());
    assert_eq!(u.exp_u64(5), E::from_u32(3));
    let omega = F::two_adic_generator(13);
    let natural = (0..192usize).map(|i| 32 * i + 1).collect::<Vec<_>>();
    let mmcs_indices = natural
        .iter()
        .map(|i| i.reverse_bits() >> (usize::BITS - 13))
        .collect::<Vec<_>>();
    let positions = natural
        .iter()
        .map(|&i| F::GENERATOR * omega.exp_u64(i as u64))
        .collect::<Vec<_>>();
    for (&index, &point) in mmcs_indices.iter().zip(&positions) {
        let exponent = index.reverse_bits() >> (usize::BITS - 13);
        assert_eq!(point, F::GENERATOR * omega.exp_u64(exponent as u64));
    }
    let domain = DisclosureDomain::checked(z, &positions).unwrap();
    assert_eq!(omega.exp_u64(16), domain.h);
    assert_eq!(
        (domain.target.degree(), domain.enlarged.degree()),
        (197, 394)
    );
    for &point in &positions {
        assert!(!positions.contains(&(point * domain.h)));
    }
    let main = public_polynomials(domain.enlarged.degree() - 1);
    assert_eq!(main.len(), 1656);
    assert!(
        main.iter()
            .all(|p| p.len() == 394 && p.last() != Some(&F::ZERO))
    );
    let input = PublicResidues::checked(&domain, main.clone()).unwrap();
    eprintln!(
        "role3_public_image full_locations=true phase=ring_fold_begin setup_ms={:.3} constraints={} source_nodes={} MAIN=1656 target_degree=197 source_degree=394 public_values=740",
        began.elapsed().as_secs_f64() * 1000.,
        program.base.len(),
        program.node_count
    );
    let ring_began = Instant::now();
    let quotient = program.fold(&domain, &input, constraint_alpha).unwrap();
    let ring_ms = ring_began.elapsed().as_secs_f64() * 1000.;
    quotient.require_statement(statement()).unwrap();
    assert_eq!(quotient.expected_public, statement().values());
    assert_eq!(quotient.expected_binding, program.expected_binding);
    assert_eq!(quotient.modulus, domain.target.modulus());
    assert_eq!(quotient.constraint_count, program.base.len());
    assert_eq!(quotient.cached_nodes, program.node_count);
    assert!(quotient.coordinates.iter().all(|p| p.len() <= 197));
    eprintln!(
        "role3_public_image full_locations=true phase=ring_fold_end ring_ms={ring_ms:.3} constraints={} cached_nodes={} source_nodes={}",
        quotient.constraint_count, quotient.cached_nodes, program.node_count
    );

    // Existing independent path: every original MAIN polynomial is evaluated
    // at x and h*x by NativeOracle::fold; the true EncodingAir and native
    // periodic512/domain selectors run inside VerifierConstraintFolder.
    let base_began = Instant::now();
    for (query, &point) in positions.iter().enumerate() {
        let direct = native.fold(&main, E::from(point), constraint_alpha);
        let direct_coordinates: &[F] = direct.as_basis_coefficients_slice();
        assert_eq!(direct_coordinates.len(), 5);
        for (coordinate, (polynomial, &value)) in quotient
            .coordinates
            .iter()
            .zip(direct_coordinates)
            .enumerate()
        {
            assert_eq!(
                at(polynomial, E::from(point)),
                E::from(value),
                "Role3 base query={query} coordinate={coordinate}"
            );
        }
        if (query + 1).is_multiple_of(32) {
            eprintln!(
                "role3_public_image full_locations=true phase=base_progress completed={} total=192 elapsed_ms={:.3}",
                query + 1,
                base_began.elapsed().as_secs_f64() * 1000.
            );
        }
    }
    let base_ms = base_began.elapsed().as_secs_f64() * 1000.;

    // Hold z, MAIN at z/h*z, all periodic values and selectors FIXED. Only the
    // coefficient extension alpha changes under each of the five embeddings.
    let ood_began = Instant::now();
    let coordinates: [E; 5] = core::array::from_fn(|i| at(&quotient.coordinates[i], z));
    let bases: [E; 5] = core::array::from_fn(|i| u.repeated_frobenius(i));
    let native_ood: [E; 5] = core::array::from_fn(|embedding| {
        native.fold(&main, z, constraint_alpha.repeated_frobenius(embedding))
    });
    let mut determinant = E::ONE;
    for (i, &basis) in bases.iter().enumerate() {
        for &previous in &bases[..i] {
            determinant *= basis - previous;
        }
        let image = coordinates
            .iter()
            .zip(basis.powers())
            .map(|(&value, power)| value * power)
            .sum::<E>();
        assert_eq!(image, native_ood[i], "Role3 OOD coefficient embedding={i}");
    }
    assert_ne!(determinant, E::ZERO);
    let ood_ms = ood_began.elapsed().as_secs_f64() * 1000.;

    // P_S*((X-2)-u) is an actual wrong five-coordinate tensor of degree<197.
    // Every coordinate error vanishes on all192 base rows. Its first collapsed
    // OOD embedding also vanishes, while all other coefficient embeddings
    // distinguish it. Reuse the five native values already computed above.
    let mut product = vec![F::ONE];
    for &point in &positions {
        product = ring::mul(&product, &[-point, F::ONE]);
    }
    assert_eq!(product.len(), 193);
    assert_ne!(at(&product, z), E::ZERO);
    let mut damaged = quotient.coordinates.clone();
    damaged[0] = ring::add(
        &damaged[0],
        &ring::mul(&product, &[-F::from_u32(2), F::ONE]),
    );
    damaged[1] = ring::sub(&damaged[1], &product);
    assert_ne!(damaged, quotient.coordinates);
    assert!(damaged.iter().all(|p| p.len() <= 197));
    for &point in &positions {
        for (bad, good) in damaged.iter().zip(&quotient.coordinates) {
            assert_eq!(at(bad, E::from(point)), at(good, E::from(point)));
        }
    }
    for (embedding, &basis) in bases.iter().enumerate() {
        let image = damaged
            .iter()
            .zip(basis.powers())
            .map(|(p, power)| at(p, z) * power)
            .sum::<E>();
        if embedding == 0 {
            assert_eq!(image, native_ood[embedding]);
        } else {
            assert_ne!(image, native_ood[embedding]);
        }
    }
    eprintln!(
        "role3_public_image native_folder_full_locations=true base_points=192 coordinate_equalities=960 OOD_embeddings=5 native_folder_calls=197 target_degree=197 source_degree=394 constraints={} source_nodes={} cached_nodes={} MAIN=1656 public_values=740 ring_ms={ring_ms:.3} base_native_ms={base_ms:.3} ood_native_ms={ood_ms:.3} total_harness_ms={:.3} lossy_embedding_negative=true public_only=true full_sampler=false full_proof=false query_execution=false admission=false",
        quotient.constraint_count,
        program.node_count,
        quotient.cached_nodes,
        began.elapsed().as_secs_f64() * 1000.
    );
}
