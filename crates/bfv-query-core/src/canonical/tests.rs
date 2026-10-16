//! Public fixtures compare the complete statement with actual upstream arithmetic.
use super::*;

fn source(owner: &Owner) -> Ciphertext {
    let values: Vec<_> = (0..DEGREE)
        .map(|slot| (slot as u64 * 251 + 17) % PLAINTEXT)
        .collect();
    checked_ciphertext(&owner.encrypted(&values).unwrap(), &owner.parameters).unwrap()
}

#[test]
fn public_products_match_upstream_in_every_residue_for_simd_and_coefficient_encodings() {
    let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
    let original = source(&owner);
    for encoding in [Encoding::simd(), Encoding::poly()] {
        let values: Vec<_> = (0..DEGREE)
            .map(|slot| [0, 1, 255, PLAINTEXT - 1][slot % 4])
            .collect();
        let public = Plaintext::try_encode(&values, encoding, &owner.parameters).unwrap();
        let upstream = &original * &public;

        let request = public_product_request(
            &owner.parameters,
            b"public original query and heads",
            &original,
            &public,
        )
        .unwrap();
        let (_, actual) =
            bfv_product_circuit::decode_output(&bfv_product_circuit::evaluate(&request).unwrap())
                .unwrap();

        assert_eq!(actual, coefficients(&upstream));
    }
}

#[test]
fn identical_operands_remain_bound_to_every_byte_of_the_original_request() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let original = source(&owner);
    let public = Plaintext::try_encode(&[1u64, 1, 1], Encoding::poly(), &owner.parameters).unwrap();
    let first = b"public query and both heads: one";
    let second = b"public query and both heads: two";
    let results: Vec<_> = [first, second]
        .into_iter()
        .map(|wire| {
            let request =
                public_product_request(&owner.parameters, wire, &original, &public).unwrap();
            bfv_product_circuit::decode_output(&bfv_product_circuit::evaluate(&request).unwrap())
                .unwrap()
        })
        .collect();

    assert_eq!(results[0].0, <[u8; 32]>::from(Sha256::digest(first)));
    assert_eq!(results[1].0, <[u8; 32]>::from(Sha256::digest(second)));
    assert_ne!(results[0].0, results[1].0);
    assert_eq!(results[0].1, results[1].1);
}

#[test]
fn every_ciphertext_component_must_have_the_exact_initial_ntt_context() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let original = source(&owner);
    let public = Plaintext::try_encode(&[1u64], Encoding::poly(), &owner.parameters).unwrap();
    let mut lower = original.clone();
    lower.switch_to_level(1).unwrap();
    let mut unsuitable = vec![
        lower.clone(),
        Ciphertext::new(
            vec![
                original[0].clone(),
                original[1].clone(),
                original[1].clone(),
            ],
            &owner.parameters,
        )
        .unwrap(),
    ];
    for component in 0..2 {
        let mut power_basis = original.clone();
        power_basis[component].change_representation(Representation::PowerBasis);
        unsuitable.push(power_basis);
        // Mutable upstream components can bypass Ciphertext::new's context checks.
        let mut mixed_context = original.clone();
        mixed_context[component] = lower[component].clone();
        unsuitable.push(mixed_context);
    }

    for ciphertext in unsuitable {
        assert!(matches!(
            public_product_request(&owner.parameters, b"original", &ciphertext, &public),
            Err(Error::InvalidShape)
        ));
    }
}

#[test]
fn a_public_mask_from_another_level_or_ring_is_rejected() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let original = source(&owner);
    let lower =
        Plaintext::try_encode(&[1u64], Encoding::poly_at_level(1), &owner.parameters).unwrap();
    let other_parameters = BfvParametersBuilder::new()
        .set_degree(DEGREE / 2)
        .set_plaintext_modulus(PLAINTEXT)
        .set_moduli(&MODULI)
        .set_variance(10)
        .build_arc()
        .unwrap();
    let other = Plaintext::try_encode(&[1u64], Encoding::poly(), &other_parameters).unwrap();

    assert!(matches!(
        public_product_request(&owner.parameters, b"original", &original, &lower),
        Err(Error::InvalidShape)
    ));
    assert!(public_product_request(&owner.parameters, b"original", &original, &other).is_err());
    assert!(matches!(
        public_product_request(&other_parameters, b"original", &original, &other),
        Err(Error::ParameterProfile)
    ));
}
