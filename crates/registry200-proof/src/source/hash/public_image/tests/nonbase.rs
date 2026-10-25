//! Small complete nonbase target, with all five coefficient embeddings.
use super::*;

#[test]
fn source_nonbase_fold_keeps_all_five_coefficient_embeddings() {
    let program = program();
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let z = u + E::from_u32(2);
    assert!(<E as ExtensionField<F>>::as_base(&z).is_none());
    let omega = F::two_adic_generator(13);
    let positions = (0..3)
        .map(|i| F::GENERATOR * omega.exp_u64(32 * i + 1))
        .collect::<Vec<_>>();
    let domain = DisclosureDomain::checked(z, &positions).unwrap();
    assert_eq!(omega.exp_u64(16), domain.h);
    assert_eq!((domain.target.degree(), domain.enlarged.degree()), (8, 16));
    let main = public_polynomials(domain.enlarged.degree() - 1);
    let input = PublicResidues::checked(&domain, main.clone()).unwrap();
    let quotient = program.fold(&domain, &input, alpha()).unwrap();
    assert!(quotient.coordinates.iter().all(|p| p.len() <= 8));
    quotient.require_expected(expected()).unwrap();

    for &point in &positions {
        let native = oracle().fold(&main, E::from(point), alpha());
        let native_coordinates: &[F] = native.as_basis_coefficients_slice();
        for (polynomial, &coordinate) in quotient.coordinates.iter().zip(native_coordinates) {
            assert_eq!(at(polynomial, E::from(point)), E::from(coordinate));
        }
    }
    let coordinates: [E; 5] = core::array::from_fn(|i| at(&quotient.coordinates[i], z));
    let bases: [E; 5] = core::array::from_fn(|i| u.repeated_frobenius(i));
    let mut determinant = E::ONE;
    for (i, &basis) in bases.iter().enumerate() {
        for &previous in &bases[..i] {
            determinant *= basis - previous;
        }
    }
    assert_ne!(determinant, E::ZERO);
    for (embedding, &basis) in bases.iter().enumerate() {
        let image = coordinates
            .iter()
            .zip(basis.powers())
            .map(|(&value, power)| value * power)
            .sum::<E>();
        // Sigma acts on coefficient alpha ONLY. MAIN at z/hz, periodic logic
        // and z itself stay fixed, preserving the two separate indeterminates.
        assert_eq!(
            oracle().fold(&main, z, alpha().repeated_frobenius(embedding)),
            image
        );
    }

    // An actual corrupted tensor can pass every base row AND the first scalar
    // OOD embedding. Other coefficient embeddings must detect the error.
    let mut product = vec![F::ONE];
    for &point in &positions {
        product = ring::mul(&product, &[-point, F::ONE]);
    }
    let mut damaged = quotient.coordinates.clone();
    damaged[0] = ring::add(
        &damaged[0],
        &ring::mul(&product, &[-F::from_u32(2), F::ONE]),
    );
    damaged[1] = ring::sub(&damaged[1], &product);
    assert_ne!(damaged, quotient.coordinates);
    for &point in &positions {
        for (bad, good) in damaged.iter().zip(&quotient.coordinates) {
            assert_eq!(at(bad, E::from(point)), at(good, E::from(point)));
        }
    }
    for (embedding, &basis) in bases.iter().enumerate() {
        let image = damaged
            .iter()
            .zip(basis.powers())
            .map(|(polynomial, power)| at(polynomial, z) * power)
            .sum::<E>();
        let native = oracle().fold(&main, z, alpha().repeated_frobenius(embedding));
        if embedding == 0 {
            assert_eq!(image, native);
        } else {
            assert_ne!(image, native);
        }
    }

    let duplicated = DisclosureDomain::checked(z, &[positions[0], positions[0]]).unwrap();
    assert_eq!(
        (duplicated.target.degree(), duplicated.enlarged.degree()),
        (6, 12)
    );
    let polynomial = vec![F::from_u32(5), F::from_u32(9), F::from_u32(11)];
    let alternative = ring::add(
        &polynomial,
        &ring::mul(domain.enlarged.modulus(), &[F::ONE, F::ONE]),
    );
    for next in [false, true] {
        assert_eq!(
            domain.project(&polynomial, next),
            domain.project(&alternative, next)
        );
    }
    assert_eq!(quotient.cached_nodes, program.node_count);
    eprintln!(
        "source_public_image nonbase_native=true base_points=3 base_coordinate_equalities=15 coefficient_embeddings=5 target_degree=8 source_degree=16 source_nodes={} cached_nodes={} lossy_embedding_negative=true public_only=true full192=false proof=false admission=false",
        program.node_count, quotient.cached_nodes
    );
}
