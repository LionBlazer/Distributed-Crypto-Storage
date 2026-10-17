use super::*;
use bfv_ntt_circuit::{
    Basis, DEGREE, Direction, Output, Request, decode_request, encode_request,
    evaluate_with_certificate,
};
use p3_challenger::CanSample;
use p3_symmetric::CryptographicHasher;
use std::sync::OnceLock;
mod attacks;
fn directions() -> [Direction; 2] {
    [Direction::Forward, Direction::Inverse]
}
struct Genuine {
    input: Request,
    generated: Generated,
}
fn representative(direction: Direction, basis: Basis) -> &'static Genuine {
    static FQ: OnceLock<Genuine> = OnceLock::new();
    static IQ: OnceLock<Genuine> = OnceLock::new();
    static FP: OnceLock<Genuine> = OnceLock::new();
    static IP: OnceLock<Genuine> = OnceLock::new();
    let cell = match (direction, basis.index()) {
        (Direction::Forward, 0) => &FQ,
        (Direction::Inverse, 0) => &IQ,
        (Direction::Forward, 9) => &FP,
        (Direction::Inverse, 9) => &IP,
        _ => panic!("only four public representatives are retained"),
    };
    cell.get_or_init(|| {
        let input = fixture::request(direction, basis, [0x71; 32]).unwrap();
        let generated = prove(&input).unwrap();
        assert!(
            verify(&input, &generated.output, &generated.proof)
                .unwrap()
                .matches(&input, &generated.output)
        );
        Genuine { input, generated }
    })
}
#[test]
fn all8192_coefficients_match_the_actual_native_sdk_for_all_twenty_fixed_targets() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    assert_eq!(
        std::any::type_name::<NttOperator>(),
        "fhe_math::ntt::native::NttOperator"
    );
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let modulus = Modulus::new(basis.modulus()).unwrap();
        let native = NttOperator::new(&modulus, DEGREE).unwrap();
        for direction in directions() {
            let input = fixture::request(direction, basis, [7; 32]).unwrap();
            let actual = evaluate_with_certificate(&input).unwrap();
            let mut expected = input.input().to_vec();
            match direction {
                Direction::Forward => native.forward(&mut expected),
                Direction::Inverse => native.backward(&mut expected),
            };
            assert_eq!(
                actual.output.coefficients(),
                expected,
                "{direction:?} basis {index}"
            );
        }
    }
}
#[test]
fn the_real_sdk_impulse_fixes_root_native_order_and_inverse_normalization() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let modulus = Modulus::new(basis.modulus()).unwrap();
        let native = NttOperator::new(&modulus, DEGREE).unwrap();
        let mut impulse = vec![0; DEGREE];
        impulse[1] = 1;
        native.forward(&mut impulse);
        let p = bfv_ntt_circuit::parameters(basis);
        assert_eq!(impulse[0], p.primitive_root());
        assert_eq!(
            modulus.pow(p.primitive_root(), DEGREE as u64),
            basis.modulus() - 1
        );
        assert_eq!(p.inverse_size(), modulus.inv(DEGREE as u64).unwrap());
        native.backward(&mut impulse);
        assert_eq!(impulse[1], 1);
        assert_eq!(impulse.iter().filter(|&&x| x != 0).count(), 1);
    }
}
#[test]
fn all_twenty_genuine_serialized_proofs_verify_without_retaining_a_proof_bank() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    // Mandatory unignored full targets. Only four public representatives survive
    // their iteration for independent negative examples; the other sixteen drop.
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let modulus = Modulus::new(basis.modulus()).unwrap();
        let native = NttOperator::new(&modulus, DEGREE).unwrap();
        for direction in directions() {
            let oracle = |input: &Request| {
                let mut expected = input.input().to_vec();
                match direction {
                    Direction::Forward => native.forward(&mut expected),
                    Direction::Inverse => native.backward(&mut expected),
                };
                expected
            };
            if index == 0 || index == 9 {
                let valid = representative(direction, basis);
                assert!(valid.generated.proof.len() <= MAX_PROOF_BYTES);
                assert_eq!(valid.generated.output.coefficients(), oracle(&valid.input));
            } else {
                let input = fixture::request(direction, basis, [0x71; 32]).unwrap();
                let generated = prove(&input).unwrap();
                let checked = verify(&input, &generated.output, &generated.proof).unwrap();
                assert!(checked.matches(&input, &generated.output));
                assert_eq!(generated.output.coefficients(), oracle(&input));
                assert!(generated.proof.len() <= MAX_PROOF_BYTES);
            }
        }
    }
}
#[test]
fn full_sha512_outputs_and_complete_statement_bytes_seed_distinct_domains() {
    use sha2::{Digest, Sha512};
    let words = [0x0102030405060708u64, 0xfedcba9876543210];
    let leaf = backend::domains().leaf_hasher().hash_iter(words);
    let node = backend::domains().node_hasher().hash_iter(words);
    let mut expected = Sha512::new();
    expected.update(b"DCS/NTT-WITNESS/v1/MERKLE-LEAF/LE64/");
    for w in words {
        expected.update(w.to_le_bytes());
    }
    let expected: [u8; 64] = expected.finalize().into();
    assert_eq!(
        leaf,
        core::array::from_fn(|i| u64::from_le_bytes(
            expected[i * 8..i * 8 + 8].try_into().unwrap()
        ))
    );
    assert_ne!(leaf, node);
    let (input, output) =
        fixture::zero_statement(Direction::Forward, Basis::new(0).unwrap()).unwrap();
    let mut values = vec![0; DEGREE];
    values[DEGREE - 1] = 1;
    let other = fixture::output(&input, &values).unwrap();
    let shape = bfv_ntt_circuit::multistark::shape(input.direction(), input.basis());
    let specs: Vec<_> = shape
        .airs()
        .iter()
        .map(|air| bfv_multilinear_stark::AirSpec::new(air, air.height().ilog2() as usize))
        .collect();
    let (config, _) = bfv_multilinear_stark::config_for(&specs, backend::domains()).unwrap();
    let profile = backend::profile_digest(input.direction(), input.basis());
    let first: backend::Challenge = config
        .challenger(profile, &input.encode(), &output.encode())
        .sample();
    // Independently reconstruct the previous exact seed, including every byte after
    // the legacy SHA256 codec header, before using the shared transcript adapter.
    let mut seed = b"DCS/NTT-WITNESS-PROOF/v1/statement/".to_vec();
    seed.extend(profile);
    seed.extend(Sha512::digest(input.encode()));
    seed.extend(Sha512::digest(output.encode()));
    let mut expected = p3_challenger::SerializingChallenger64::<backend::Val, _>::new(
        p3_challenger::HashChallenger::<u8, _, 64>::new(
            seed,
            backend::domains().transcript_hasher(),
        ),
    );
    let expected: backend::Challenge = expected.sample();
    assert_eq!(first, expected);
    let second: backend::Challenge = config
        .challenger(profile, &input.encode(), &other.encode())
        .sample();
    assert_ne!(first, second);
    let changed = decode_request(
        &encode_request(input.direction(), input.basis(), [1; 32], input.input()).unwrap(),
    )
    .unwrap();
    let changed_output = fixture::output(&changed, output.coefficients()).unwrap();
    let third: backend::Challenge = config
        .challenger(profile, &changed.encode(), &changed_output.encode())
        .sample();
    assert_ne!(first, third);
}
#[test]
fn whole_model_has_no_unassessed_term_and_uses_both_fixed_pcs_shapes() {
    // A numerical SDK report is required, not the requested phase target alone.
    for direction in directions() {
        let report = backend::analyze(direction, Basis::new(0).unwrap()).unwrap();
        assert!(report.whole_security_bits.is_finite() && report.whole_security_bits >= 144.);
        assert!(report.unassessed_components.is_empty());
        assert!(!report.terms.is_empty());
        assert_eq!(
            (report.main_pcs.variables, report.preprocessed_pcs.variables),
            (22, 21)
        );
        assert_eq!(report.lookup_padded, 1 << 22);
        assert_ne!(report.lookup_count_weight, report.lookup_contributions);
        assert_eq!(report.collision_bits, 256);
    }
}
#[test]
fn genuine_foreign_context_direction_basis_and_rebuilt_full_output_are_rejected() {
    for direction in directions() {
        for index in [0, 9] {
            let valid = representative(direction, Basis::new(index).unwrap());
            let other = representative(
                if direction == Direction::Forward {
                    Direction::Inverse
                } else {
                    Direction::Forward
                },
                valid.input.basis(),
            );
            assert!(
                verify(
                    &valid.input,
                    &other.generated.output,
                    &other.generated.proof
                )
                .is_err()
            );
            let other = representative(
                direction,
                Basis::new(if index == 0 { 9 } else { 0 }).unwrap(),
            );
            assert!(
                verify(
                    &valid.input,
                    &other.generated.output,
                    &other.generated.proof
                )
                .is_err()
            );
            let mut coefficients = valid.generated.output.coefficients().to_vec();
            coefficients[DEGREE - 1] =
                (coefficients[DEGREE - 1] + 1) % valid.input.basis().modulus();
            let output = fixture::output(&valid.input, &coefficients).unwrap();
            let decoded = proof::decode_frame(
                &valid.input,
                &valid.generated.output,
                &valid.generated.proof,
            )
            .unwrap();
            let rebound = proof::encode_frame(&valid.input, &output, &decoded).unwrap();
            assert!(verify(&valid.input, &output, &rebound).is_err());
            let input = decode_request(
                &encode_request(
                    direction,
                    valid.input.basis(),
                    [0xff; 32],
                    valid.input.input(),
                )
                .unwrap(),
            )
            .unwrap();
            let output = fixture::output(&input, valid.generated.output.coefficients()).unwrap();
            let rebound = proof::encode_frame(&input, &output, &decoded).unwrap();
            assert!(verify(&input, &output, &rebound).is_err());
        }
    }
}
#[test]
fn every_header_axis_length_cap_trailing_byte_and_wrong_machine_shape_fail_closed() {
    let valid = representative(Direction::Forward, Basis::new(0).unwrap());
    for offset in [
        0, 8, 71, 72, 103, 104, 105, 106, 107, 108, 111, 112, 175, 176, 239, 240, 247, 248, 251,
        252, 255,
    ] {
        let mut bytes = valid.generated.proof.clone();
        bytes[offset] ^= 1;
        assert!(
            verify(&valid.input, &valid.generated.output, &bytes).is_err(),
            "offset {offset}"
        );
    }
    assert_eq!(
        verify(
            &valid.input,
            &valid.generated.output,
            &vec![0; MAX_PROOF_BYTES + 1]
        )
        .unwrap_err(),
        Error::ProofLength
    );
    let mut extra = valid.generated.proof.clone();
    extra.push(0);
    assert!(verify(&valid.input, &valid.generated.output, &extra).is_err());
    let mut decoded = proof::decode_frame(
        &valid.input,
        &valid.generated.output,
        &valid.generated.proof,
    )
    .unwrap();
    decoded.sumcheck.round_polys.pop();
    let bytes = proof::encode_frame(&valid.input, &valid.generated.output, &decoded).unwrap();
    assert_eq!(
        verify(&valid.input, &valid.generated.output, &bytes).unwrap_err(),
        Error::ProofEncoding
    );
}
#[test]
fn bounded_postcard_rejects_large_declared_sequences_before_allocating_them() {
    // Generic visitor boundary, exercised independently of a genuine proof.
    let mut length = MAX_PROOF_SEQUENCE_ELEMENTS + 1;
    let mut bytes = Vec::new();
    while length >= 128 {
        bytes.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    bytes.push(length as u8);
    assert_eq!(
        codec::decode::<Vec<u8>>(&bytes).unwrap_err(),
        Error::ProofResourceLimit
    );
    let mut encoded = postcard::to_allocvec(&vec![1u64, 2]).unwrap();
    encoded.push(0);
    assert_eq!(
        codec::decode::<Vec<u64>>(&encoded).unwrap_err(),
        Error::TrailingProofBytes
    );
}
