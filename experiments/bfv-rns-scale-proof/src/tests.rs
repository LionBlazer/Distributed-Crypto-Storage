use super::*;
use bfv_scale_circuit::{
    Role, decode_output, decode_request, encode_request, evaluate_with_certificate,
};
use std::sync::{Arc, OnceLock};

fn roles() -> [Role; 2] {
    [Role::Extend5To10, Role::Scale10To5]
}
struct Genuine {
    request: bfv_scale_circuit::Request,
    generated: Generated,
}
fn genuine(role: Role) -> &'static Genuine {
    static EXTEND: OnceLock<Genuine> = OnceLock::new();
    static DOWN: OnceLock<Genuine> = OnceLock::new();
    let cell = match role {
        Role::Extend5To10 => &EXTEND,
        Role::Scale10To5 => &DOWN,
    };
    cell.get_or_init(|| {
        // All material is explicitly PUBLIC NONSECRET. This cache only avoids
        // repeating a genuine complete proof inside related test examples.
        let request = fixture::request(role, [0x19; 32]).unwrap();
        let generated = prove(&request).unwrap();
        assert!(
            verify(&request, &generated.output, &generated.proof)
                .unwrap()
                .matches(&request, &generated.output)
        );
        Genuine { request, generated }
    })
}

#[test]
fn actual_sdk_multiplication_basis_and_plaintext_geometry_match_the_fixed_profile() {
    // Independently recover the multiplication basis from the SDK prime
    // generator, following pinned BfvParameters' six-prime setup. Merely using
    // the circuit's P as an oracle input would not establish its provenance.
    let mut generated = Vec::new();
    let mut upper = 1u64 << 62;
    while generated.len() != 6 {
        upper = fhe_math::zq::primes::generate_prime(62, 2 * 8192, upper).unwrap();
        if !generated.contains(&upper) && !bfv_scale_circuit::MODULI.contains(&upper) {
            generated.push(upper);
        }
    }
    let original_bits: usize = bfv_scale_circuit::MODULI
        .iter()
        .map(|q| (64 - q.leading_zeros()) as usize)
        .sum();
    let used = (original_bits + 60).div_ceil(62);
    assert_eq!(used, 5);
    assert_eq!(
        &generated[..used],
        bfv_scale_circuit::AUXILIARY_MODULI.as_slice()
    );
    assert_eq!(bfv_scale_circuit::DEGREE, 8192);
    assert_eq!(bfv_scale_circuit::PLAINTEXT, 114_689);
    assert_eq!(
        Role::Extend5To10.input_moduli(),
        bfv_scale_circuit::MODULI.as_slice()
    );
    assert_eq!(&Role::Extend5To10.output_moduli()[5..], &generated[..used]);
    assert_eq!(
        Role::Scale10To5.input_moduli(),
        Role::Extend5To10.output_moduli()
    );
    assert_eq!(
        Role::Scale10To5.output_moduli(),
        bfv_scale_circuit::MODULI.as_slice()
    );
}

#[test]
fn every_coefficient_of_both_roles_matches_the_actual_upstream_rns_scaler() {
    use fhe_math::rns::{RnsContext, RnsScaler, ScalingFactor};
    use num_bigint::BigUint;
    for role in roles() {
        let request = fixture::request(role, [7; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&request).unwrap();
        let from = Arc::new(RnsContext::new(role.input_moduli()).unwrap());
        let to = Arc::new(RnsContext::new(role.output_moduli()).unwrap());
        let factor = match role {
            Role::Extend5To10 => ScalingFactor::one(),
            Role::Scale10To5 => {
                let denominator = role
                    .output_moduli()
                    .iter()
                    .fold(BigUint::from(1u8), |product, &q| product * q);
                ScalingFactor::new(&BigUint::from(114_689u64), &denominator)
            }
        };
        let scaler = RnsScaler::new(&from, &to, factor);
        // Call the pinned SDK, not a reimplementation of its Garner/theta loop.
        for coefficient in 0..8192 {
            let rests = (0..role.input_moduli().len())
                .map(|lane| request.input()[lane * 8192 + coefficient])
                .collect::<Vec<_>>();
            let expected = scaler.scale_new(
                ndarray::ArrayView1::from(rests.as_slice()),
                role.output_moduli().len(),
            );
            for (lane, &expected) in expected.iter().enumerate() {
                assert_eq!(
                    evaluated.output.coefficients()[lane * 8192 + coefficient],
                    expected,
                    "{role:?}: modulus {lane}, coefficient {coefficient}"
                );
            }
        }
        if role == Role::Extend5To10 {
            assert_eq!(
                &evaluated.output.coefficients()[..request.input().len()],
                request.input()
            );
        }
    }
}

#[test]
fn genuine_full8192_stage_proofs_bind_both_fixed_roles_and_complete_outputs() {
    for role in roles() {
        let fixture = genuine(role);
        let checked = verify(
            &fixture.request,
            &fixture.generated.output,
            &fixture.generated.proof,
        )
        .unwrap();
        assert_eq!(checked.role(), role);
        assert!(checked.matches(&fixture.request, &fixture.generated.output));
        assert!(fixture.generated.proof.len() <= MAX_PROOF_BYTES);
        assert_eq!(
            fixture.generated.output.coefficients().len(),
            role.output_coefficients()
        );
    }
}

#[test]
fn valid_frames_cannot_replay_a_request_role_profile_or_powerbasis_tag() {
    for role in roles() {
        let fixture = genuine(role);
        // magic, profile, role, PowerBasis and opaque request identity are all
        // checked before nested SDK proof decoding or preprocessing commitment.
        for offset in [0, 8, 39, 40, 41, 42, 73] {
            let mut changed = fixture.generated.proof.clone();
            changed[offset] ^= 1;
            assert_eq!(
                verify(&fixture.request, &fixture.generated.output, &changed).unwrap_err(),
                Error::Frame,
                "header byte {offset}"
            );
        }
        let other = fixture::request(role, [0x91; 32]).unwrap();
        assert!(
            !verify(
                &fixture.request,
                &fixture.generated.output,
                &fixture.generated.proof
            )
            .unwrap()
            .matches(&other, &fixture.generated.output)
        );
        assert!(verify(&other, &fixture.generated.output, &fixture.generated.proof).is_err());
    }
}

#[test]
fn every_output_modulus_including_last_coefficient_is_bound_before_acceptance() {
    for role in roles() {
        let fixture = genuine(role);
        let original = fixture.generated.output.encode();
        let start = original.len() - role.output_coefficients() * 8;
        for (lane, &q) in role.output_moduli().iter().enumerate() {
            for coefficient in [0, 8191] {
                let mut changed = original.clone();
                let offset = start + (lane * 8192 + coefficient) * 8;
                let old = u64::from_le_bytes(changed[offset..offset + 8].try_into().unwrap());
                changed[offset..offset + 8].copy_from_slice(&((old + 1) % q).to_le_bytes());
                let output = decode_output(&changed).unwrap();
                assert!(
                    verify(&fixture.request, &output, &fixture.generated.proof).is_err(),
                    "{role:?}: output modulus {lane}, coefficient {coefficient}"
                );
            }
        }
    }
}

#[test]
fn noncanonical_last_residues_and_incomplete_vectors_fail_before_proof_work() {
    for role in roles() {
        let request = fixture::request(role, [3; 32]).unwrap();
        let mut values = request.input().to_vec();
        let last = values.len() - 1;
        values[last] = *role.input_moduli().last().unwrap();
        assert!(encode_request(role, [3; 32], &values).is_err());
        assert!(encode_request(role, [3; 32], &values[..last]).is_err());
        let mut wire = request.encode();
        wire.push(0);
        assert!(decode_request(&wire).is_err());
    }
}

#[test]
fn oversized_and_malformed_sdk_sequences_never_bypass_the_new_frame_budget() {
    let mut oversized = postcard::to_allocvec(&usize::MAX).unwrap();
    assert_eq!(
        codec::take_from_bytes::<Vec<u64>>(&oversized).unwrap_err(),
        Error::ProofResourceLimit
    );
    oversized = postcard::to_allocvec(&vec![vec![0u8; 4097]]).unwrap();
    assert_eq!(
        codec::take_from_bytes::<Vec<Vec<u8>>>(&oversized).unwrap_err(),
        Error::ProofResourceLimit
    );
    let nested = vec![vec![[0u8; 8]; 4096]; 33];
    let bytes = postcard::to_allocvec(&nested).unwrap();
    assert_eq!(
        codec::take_from_bytes::<Vec<Vec<[u8; 8]>>>(&bytes).unwrap_err(),
        Error::ProofResourceLimit
    );
}

#[test]
fn tracefree_analysis_uses_the_same_role_shape_without_preprocessing() {
    use bfv_scale_circuit::plonky3::ScaleAir;
    for role in roles() {
        let shape = ScaleAir::shape(role);
        assert!(!shape.is_prepared());
        let report = backend::analyze(role).unwrap();
        assert_eq!(report.trace_height, 8192);
        assert_eq!(report.queries, 192);
        assert_eq!(report.extension_degree, 5);
        assert_eq!(report.blowup, 8);
        assert!(report.unique_decoding_bits >= 128 && report.list_decoding_bits >= 128);
        assert!(report.constraints > 0 && report.degree <= 5);
    }
}

// Rebuild the public auxiliary header around a changed, still canonical output.
// Matching only an old transcript is deliberately not the rejection mechanism.
fn forged_output_and_rebound_aux(
    role: Role,
) -> (
    bfv_scale_circuit::Request,
    bfv_scale_circuit::Output,
    bfv_scale_circuit::Aux,
) {
    use sha2::{Digest, Sha256};
    let request = fixture::request(role, [0x53; 32]).unwrap();
    let evaluated = evaluate_with_certificate(&request).unwrap();
    let original = evaluated.output.encode();
    let mut changed = original.clone();
    let index = role.output_coefficients() - 1;
    let q = *role.output_moduli().last().unwrap();
    let offset = original.len() - 8;
    let value = (evaluated.output.coefficients()[index] + 1) % q;
    changed[offset..].copy_from_slice(&value.to_le_bytes());
    let output = decode_output(&changed).unwrap();
    let old_digest: [u8; 32] = Sha256::digest(&original).into();
    let new_digest: [u8; 32] = Sha256::digest(&changed).into();
    let mut encoded = evaluated.aux.encode();
    assert_eq!(
        &encoded[112..144],
        old_digest.as_slice(),
        "auxiliary header binds the complete canonical output wire"
    );
    encoded[112..144].copy_from_slice(&new_digest);
    let auxiliary = bfv_scale_circuit::decode_aux(&encoded).unwrap();
    (request, output, auxiliary)
}

#[test]
fn rebuilding_all_public_hashes_does_not_make_a_wrong_last_coefficient_satisfy_integer_air() {
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    for role in roles() {
        let (input, output, auxiliary) = forged_output_and_rebound_aux(role);
        let (air, values) = proof::statement(&input, &output, &auxiliary).unwrap();
        let main = RowMajorMatrix::new(vec![backend::Val::ZERO; 8192 * air.width()], air.width());
        assert!(!p3_air::check_all_constraints(&air, &main, &values, Some(1)).is_ok());
    }
}

#[test]
fn a_genuine_sdk_proof_of_prover_selected_constraints_and_preprocessing_cannot_replace_scaling() {
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    struct ProverSelected {
        base: backend::BoundAir,
        constraints: usize,
    }
    impl BaseAir<backend::Val> for ProverSelected {
        fn width(&self) -> usize {
            self.base.width()
        }
        fn preprocessed_width(&self) -> usize {
            self.base.preprocessed_width()
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<backend::Val>> {
            self.base.preprocessed_trace()
        }
        fn num_public_values(&self) -> usize {
            self.base.num_public_values()
        }
        fn max_constraint_degree(&self) -> Option<usize> {
            self.base.max_constraint_degree()
        }
        fn main_next_row_columns(&self) -> Vec<usize> {
            self.base.main_next_row_columns()
        }
        fn preprocessed_next_row_columns(&self) -> Vec<usize> {
            self.base.preprocessed_next_row_columns()
        }
    }
    impl<AB: AirBuilder<F = backend::Val>> Air<AB> for ProverSelected {
        fn eval(&self, builder: &mut AB) {
            let zero = builder.main().current(0).unwrap();
            for _ in 0..self.constraints {
                builder.assert_zero(zero);
            }
        }
    }
    for role in roles() {
        let (input, output, auxiliary) = forged_output_and_rebound_aux(role);
        let (air, values) = proof::statement(&input, &output, &auxiliary).unwrap();
        let (cfg, report) = backend::config(&air, role).unwrap();
        let attacker = ProverSelected {
            base: air,
            constraints: report.constraints,
        };
        let (preprocessed, _) = p3_uni_stark::setup_preprocessed(&cfg, &attacker, 13)
            .unwrap()
            .unwrap();
        let main = RowMajorMatrix::new(
            vec![backend::Val::ZERO; 8192 * attacker.width()],
            attacker.width(),
        );
        let forged = p3_uni_stark::prove_with_preprocessed(
            &cfg,
            &attacker,
            main,
            &values,
            Some(&preprocessed),
        )
        .unwrap();
        let frame = proof::encode_frame(&input, &auxiliary, &forged).unwrap();
        assert_eq!(
            verify(&input, &output, &frame).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn frame_length_and_trailing_payload_checks_apply_before_acceptance() {
    let fixture = genuine(Role::Extend5To10);
    assert_eq!(
        verify(&fixture.request, &fixture.generated.output, &[]).unwrap_err(),
        Error::ProofLength
    );
    let too_large = vec![0; MAX_PROOF_BYTES + 1];
    assert_eq!(
        verify(&fixture.request, &fixture.generated.output, &too_large).unwrap_err(),
        Error::ProofLength
    );
    let mut trailing = fixture.generated.proof.clone();
    trailing.push(0);
    assert_eq!(
        verify(&fixture.request, &fixture.generated.output, &trailing).unwrap_err(),
        Error::TrailingProofBytes
    );
}

#[test]
fn auxiliary_high_bits_are_rejected_before_their_public_field_conversion() {
    for role in roles() {
        let input = fixture::request(role, [0x28; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let encoded = evaluated.aux.encode();
        let row = 144 + 8191 * 315;
        for (field, offset, bit) in [
            ("v remainder", row + 8 + 15, 0x80u8),
            ("signed W bias", row + 24 + 5, 0x40),
            ("rounding remainder", row + 30 + 15, 0x80),
            ("output quotient", row + 46 + 4 * 9 + 8, 0x04),
            ("internal carry", row + 91 + 55 * 4 + 3, 0x02),
        ] {
            let mut malformed = encoded.clone();
            malformed[offset] |= bit;
            assert!(
                bfv_scale_circuit::decode_aux(&malformed).is_err(),
                "{role:?}: {field}"
            );
        }
    }
}

#[test]
fn canonical_auxiliary_forgeries_fail_after_rebuilding_the_public_preprocessing_and_digest() {
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    for role in roles() {
        let input = fixture::request(role, [0x39; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let encoded = evaluated.aux.encode();
        let row = 144 + 8191 * 315;
        // Each low-bit change remains inside its public integer range. No old
        // auxiliary hash, prover key or preprocessing commitment is reused.
        for (field, offset) in [
            ("v", 0),
            ("v remainder", 8),
            ("output quotient0", 46),
            ("output quotient1", 55),
            ("output quotient2", 64),
            ("output quotient3", 73),
            ("output quotient4", 82),
            ("first internal carry", 91),
            ("last internal carry", 91 + 55 * 4),
        ] {
            let mut forged = encoded.clone();
            forged[row + offset] ^= 1;
            let auxiliary = bfv_scale_circuit::decode_aux(&forged).unwrap();
            let (air, values) = proof::statement(&input, &evaluated.output, &auxiliary).unwrap();
            let main =
                RowMajorMatrix::new(vec![backend::Val::ZERO; 8192 * air.width()], air.width());
            assert!(
                !p3_air::check_all_constraints(&air, &main, &values, Some(1)).is_ok(),
                "{role:?}: {field}"
            );
        }
    }
}

#[test]
fn complete_trusted_input_and_modulus_order_are_bound_even_with_the_same_request_identity() {
    for role in roles() {
        let valid = genuine(role);
        for (lane, &q) in role.input_moduli().iter().enumerate() {
            for coefficient in [0, 8191] {
                let mut values = valid.request.input().to_vec();
                let index = lane * 8192 + coefficient;
                values[index] = (values[index] + 1) % q;
                let other = decode_request(
                    &encode_request(role, valid.request.binding(), &values).unwrap(),
                )
                .unwrap();
                assert!(verify(&other, &valid.generated.output, &valid.generated.proof).is_err());
            }
        }
        let mut values = valid.request.input().to_vec();
        let first = 7;
        let last = (role.input_moduli().len() - 1) * 8192 + 7;
        values.swap(first, last);
        values[first] %= role.input_moduli()[0];
        values[last] %= role.input_moduli()[role.input_moduli().len() - 1];
        assert_ne!(values, valid.request.input());
        let reordered =
            decode_request(&encode_request(role, valid.request.binding(), &values).unwrap())
                .unwrap();
        assert!(verify(&reordered, &valid.generated.output, &valid.generated.proof).is_err());
    }
}
