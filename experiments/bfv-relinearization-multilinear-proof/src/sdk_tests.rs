//! Independent upstream oracles. Secret keys are explicit PUBLIC NONSECRET
//! test material, local to this module and never sent to a stage verifier.
use bfv_relinearization_circuit::{
    DEGREE, MODULI, Request, Role, decode_request, encode_request, evaluate_with_certificate,
};
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, RelinearizationKey,
    SecretKey,
};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::sync::Arc;
fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_moduli(&MODULI)
        .set_plaintext_modulus(114689)
        .set_variance(10)
        .build_arc()
        .unwrap()
}

#[test]
fn complete_embedding_matches_actual_sdk_poly_reduction_in_every_source_target_and_last_word() {
    let params = parameters();
    let ctx = params.context_at_level(0).unwrap();
    let input = super::fixture::request(Role::Embed, [7; 32], [9; 32]).unwrap();
    let evaluated = evaluate_with_certificate(&input).unwrap();
    // The SDK short-Poly constructor replicates/reduces one full PB row into
    // every modulus. It is the actual upstream implementation, not our modulus loop.
    for (source, row) in input.input().as_chunks::<DEGREE>().0.iter().enumerate() {
        let native =
            Poly::try_convert_from(row.to_vec(), ctx, false, Representation::PowerBasis).unwrap();
        let expected = Vec::<u64>::from(&native);
        assert_eq!(
            &evaluated.output.coefficients()[source * 5 * DEGREE..(source + 1) * 5 * DEGREE],
            expected
        );
    }
    assert_eq!(
        evaluated.aux.embedding_rows().unwrap()[DEGREE - 1][2 * 5],
        2
    );
}

/// Exact ordered public K_i from actual SDK behavior, without private fields,
/// key serialization parsing or relinearizes_poly (which is crate-private).
fn exposed_keys(params: &Arc<BfvParameters>, key: &RelinearizationKey) -> Vec<[Vec<u64>; 2]> {
    let ctx = params.context_at_level(0).unwrap();
    (0..5)
        .map(|source| {
            let mut spike = vec![0u64; 5 * DEGREE];
            spike[source * DEGREE] = 1;
            let mut c2 =
                Poly::try_convert_from(spike, ctx, false, Representation::PowerBasis).unwrap();
            c2.change_representation(Representation::Ntt);
            let zero = Poly::zero(ctx, Representation::Ntt);
            let mut ct = Ciphertext::new(vec![zero.clone(), zero, c2], params).unwrap();
            key.relinearizes(&mut ct).unwrap();
            assert_eq!(ct.len(), 2);
            [Vec::<u64>::from(&ct[0]), Vec::<u64>::from(&ct[1])]
        })
        .collect()
}
fn compare_complete_relinearization(
    params: &Arc<BfvParameters>,
    key: &RelinearizationKey,
    keys: &[[Vec<u64>; 2]],
    ciphertext: Ciphertext,
    context: [u8; 32],
    prove_stages: bool,
) {
    assert_eq!(ciphertext.len(), 3);
    let ctx = params.context_at_level(0).unwrap();
    let original0 = Vec::<u64>::from(&ciphertext[0]);
    let original1 = Vec::<u64>::from(&ciphertext[1]);
    let mut c2 = ciphertext[2].clone();
    c2.change_representation(Representation::PowerBasis);
    let c2_pb = Vec::<u64>::from(&c2);
    let embed_request =
        decode_request(&encode_request(Role::Embed, [0x42; 32], context, &c2_pb).unwrap()).unwrap();
    let embedded = evaluate_with_certificate(&embed_request).unwrap();
    let mut digits = Vec::with_capacity(5);
    for (source, row) in c2_pb.as_chunks::<DEGREE>().0.iter().enumerate() {
        let mut native =
            Poly::try_convert_from(row.to_vec(), ctx, false, Representation::PowerBasis).unwrap();
        assert_eq!(
            &embedded.output.coefficients()[source * 5 * DEGREE..(source + 1) * 5 * DEGREE],
            Vec::<u64>::from(&native)
        );
        // These 25 native transforms are oracle-only provenance. The stage
        // verifier never performs them or pretends they are already proven.
        native.change_representation(Representation::Ntt);
        digits.push(Vec::<u64>::from(&native));
    }
    if prove_stages {
        // This proof is coupled to the actual encrypted product's complete c2,
        // whose output above was compared to every native Poly reduction.
        let generated = super::prove(&embed_request).unwrap();
        let checked = super::verify(&embed_request, &generated.output, &generated.proof).unwrap();
        assert!(checked.matches(&embed_request, &generated.output));
        assert_eq!(
            generated.output.coefficients(),
            embedded.output.coefficients()
        );
    }
    let mut input = vec![0u64; Role::AccumulateAndAdd.input_coefficients()];
    for target in 0..5 {
        let destination = 17 * target * DEGREE;
        let source = target * DEGREE..(target + 1) * DEGREE;
        input[destination..destination + DEGREE].copy_from_slice(&original0[source.clone()]);
        input[destination + DEGREE..destination + 2 * DEGREE]
            .copy_from_slice(&original1[source.clone()]);
        for (i, (digit, keypair)) in digits.iter().zip(keys).enumerate() {
            input[destination + (2 + i) * DEGREE..destination + (3 + i) * DEGREE]
                .copy_from_slice(&digit[source.clone()]);
            for (component, keypoly) in keypair.iter().enumerate() {
                let at = destination + (7 + 5 * component + i) * DEGREE;
                input[at..at + DEGREE].copy_from_slice(&keypoly[source.clone()]);
            }
        }
    }
    let request: Request = decode_request(
        &encode_request(Role::AccumulateAndAdd, [0x43; 32], context, &input).unwrap(),
    )
    .unwrap();
    // Expected output is ONLY the real upstream SDK key switch, never this crate's formula.
    let mut expected = ciphertext;
    key.relinearizes(&mut expected).unwrap();
    assert_eq!(expected.len(), 2);
    let native = [
        Vec::<u64>::from(&expected[0]),
        Vec::<u64>::from(&expected[1]),
    ];
    let evaluated = evaluate_with_certificate(&request).unwrap();
    let genuine = prove_stages.then(|| {
        let generated = super::prove(&request).unwrap();
        let checked = super::verify(&request, &generated.output, &generated.proof).unwrap();
        assert!(checked.matches(&request, &generated.output));
        generated
    });
    for target in 0..5 {
        for (component, poly) in native.iter().enumerate() {
            assert_eq!(
                &evaluated.output.coefficients()
                    [(2 * target + component) * DEGREE..(2 * target + component + 1) * DEGREE],
                &poly[target * DEGREE..(target + 1) * DEGREE],
                "target{target}/component{component}"
            );
            if let Some(generated) = &genuine {
                assert_eq!(
                    &generated.output.coefficients()
                        [(2 * target + component) * DEGREE..(2 * target + component + 1) * DEGREE],
                    &poly[target * DEGREE..(target + 1) * DEGREE],
                    "genuine encrypted-product target{target}/component{component}"
                );
            }
        }
    }
}

fn run_actual_sdk_cases(prove_stages: bool) {
    let params = parameters();
    let ctx = params.context_at_level(0).unwrap();
    let mut rng = StdRng::seed_from_u64(0x5055424c49435f52);
    let sk = SecretKey::random(&params, &mut rng);
    let key = RelinearizationKey::new(&sk, &mut rng).unwrap();
    let keys = exposed_keys(&params, &key);
    assert_eq!(keys.len(), 5);
    assert!(keys.iter().flatten().all(|v| v.len() == 5 * DEGREE));
    // Deliberately a local oracle identity, not a complete PublicSetup keyset ID,
    // registry authority, proof of key generation, or a production admission token.
    let mut hash = Sha256::new();
    hash.update(b"PUBLIC NONSECRET SDK oracle parameters/RK identity");
    hash.update(params.to_bytes());
    hash.update(key.to_bytes());
    let context = hash.finalize().into();
    let arbitrary = Ciphertext::new(
        (0..3)
            .map(|_| Poly::random(ctx, Representation::Ntt, &mut rng))
            .collect(),
        &params,
    )
    .unwrap();
    compare_complete_relinearization(&params, &key, &keys, arbitrary, context, false);
    let left = (0..DEGREE)
        .map(|i| (i as u64 * 13 + 7) % 114689)
        .collect::<Vec<_>>();
    let right = (0..DEGREE)
        .map(|i| (i as u64 * 29 + 11) % 114689)
        .collect::<Vec<_>>();
    let left = Plaintext::try_encode(&left, Encoding::poly(), &params).unwrap();
    let right = Plaintext::try_encode(&right, Encoding::poly(), &params).unwrap();
    let left: Ciphertext = sk.try_encrypt(&left, &mut rng).unwrap();
    let right: Ciphertext = sk.try_encrypt(&right, &mut rng).unwrap();
    let full_product = &left * &right;
    compare_complete_relinearization(&params, &key, &keys, full_product, context, prove_stages);
}

#[test]
fn actual_sdk_key_probes_and_complete_arbitrary_and_encrypted_products_match_before_any_proof() {
    run_actual_sdk_cases(false);
}
#[test]
fn actual_encrypted_product_stage_outputs_are_genuinely_proven_and_checked_against_the_sdk() {
    run_actual_sdk_cases(true);
}
