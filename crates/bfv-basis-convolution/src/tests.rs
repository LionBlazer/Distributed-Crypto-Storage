//! PUBLIC NONSECRET caller-owned test inputs. Operational Owner tests live in core.
use super::*;
use bfv_hiding_stark::{
    Challenge, Val,
    codec::{self, Topology},
};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::cell::Cell;
use zeroize::Zeroizing;

fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn polynomial(degree: usize, representation: u8, variable_time: bool) -> Vec<u8> {
    let mut bytes = vec![8, representation, 16];
    varint(degree, &mut bytes);
    bytes.push(26);
    let packed = degree * (43 + 43 + 44 + 44 + 44) / 8;
    varint(packed, &mut bytes);
    bytes.resize(bytes.len() + packed, 0);
    if variable_time {
        bytes.extend([32, 1]);
    }
    bytes
}
fn envelope(polynomials: &[Vec<u8>], seed: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for polynomial in polynomials {
        bytes.push(10);
        varint(polynomial.len(), &mut bytes);
        bytes.extend(polynomial);
    }
    if let Some(seed) = seed {
        bytes.push(18);
        varint(seed.len(), &mut bytes);
        bytes.extend(seed);
    }
    bytes
}
fn encrypted() -> (Vec<u8>, Zeroizing<Vec<i8>>) {
    let parameters = parameters();
    let mut rng = rand::rng();
    let key = SecretKey::random(&parameters, &mut rng);
    let plaintext =
        Plaintext::try_encode(&[1u64, 0, 114688][..], Encoding::simd(), &parameters).unwrap();
    let ciphertext: Ciphertext = key.try_encrypt(&plaintext, &mut rng).unwrap();
    let wide = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
    let coefficients = Zeroizing::new(wide.iter().map(|v| i8::try_from(*v).unwrap()).collect());
    (ciphertext.to_bytes(), coefficients)
}
#[test]
fn borrowed_preflight_accepts_exact_seeded_unseeded_and_both_variable_time_policies() {
    for first in [false, true] {
        let p = polynomial(N, 2, first);
        let seeded = envelope(std::slice::from_ref(&p), Some(&[0; 32]));
        assert!(crate::preflight::validate(&seeded).is_ok());
        assert_eq!(
            CanonicalCiphertext::decode(&parameters().to_bytes(), &seeded, 0)
                .unwrap()
                .bytes(),
            seeded
        );
        for second in [false, true] {
            let unseeded = envelope(&[p.clone(), polynomial(N, 2, second)], None);
            assert!(crate::preflight::validate(&unseeded).is_ok());
            assert_eq!(
                CanonicalCiphertext::decode(&parameters().to_bytes(), &unseeded, 0)
                    .unwrap()
                    .bytes(),
                unseeded
            );
        }
    }
}
#[test]
fn borrowed_preflight_rejects_amplification_seed_degree_repr_defaults_and_last_residue_before_sdk()
{
    // No upstream math is called in this test: every attack meets the borrowed gate first.
    let tiny = polynomial(8, 3, false);
    let many = envelope(&vec![tiny; 2299], None);
    assert!(many.len() < MAX_CIPHERTEXT_BYTES);
    assert!(crate::preflight::validate(&many).is_err());
    assert!(CanonicalCiphertext::decode(&parameters().to_bytes(), &many, 0).is_err());
    for degree in [0, 8, 8191, 16384] {
        assert!(
            crate::preflight::validate(&envelope(&[polynomial(degree, 2, false)], Some(&[0; 32])))
                .is_err()
        );
    }
    for representation in [0, 1, 3, 255] {
        assert!(
            crate::preflight::validate(&envelope(
                &[polynomial(N, representation, false)],
                Some(&[0; 32])
            ))
            .is_err()
        );
    }
    let good = polynomial(N, 2, false);
    for size in [0, 1, 31, 33] {
        assert!(
            crate::preflight::validate(&envelope(
                std::slice::from_ref(&good),
                Some(&vec![0; size])
            ))
            .is_err()
        );
    }
    let valid = envelope(std::slice::from_ref(&good), Some(&[0; 32]));
    for suffix in [
        vec![24, 0],
        vec![24, 1],
        vec![18, 0],
        vec![32, 1],
        vec![128],
    ] {
        let mut bad = valid.clone();
        bad.extend(suffix);
        assert!(crate::preflight::validate(&bad).is_err());
    }
    let mut overlong = good.clone();
    overlong.splice(3..5, [128, 192, 0]);
    assert!(crate::preflight::validate(&envelope(&[overlong], Some(&[0; 32]))).is_err());
    // BOTH first and FINAL residue of EVERY packed qi row before any SDK math.
    let packed_start = good.len() - 223232;
    let mut row_offset = 0;
    for modulus in MODULI {
        let width = (64 - (modulus - 1).leading_zeros()) as usize;
        for index in [0, N - 1] {
            let mut bad = good.clone();
            for bit in 0..width {
                let at = row_offset * 8 + index * width + bit;
                if modulus & (1 << bit) != 0 {
                    bad[packed_start + at / 8] |= 1 << (at % 8);
                }
            }
            for seeded in [true, false] {
                let wire = if seeded {
                    envelope(&[bad.clone()], Some(&[0; 32]))
                } else {
                    envelope(&[good.clone(), bad.clone()], None)
                };
                assert!(crate::preflight::validate(&wire).is_err());
                assert!(CanonicalCiphertext::decode(&parameters().to_bytes(), &wire, 0).is_err());
            }
        }
        row_offset += width * N / 8;
    }
}
#[test]
fn canonical_decoder_preserves_complete_original_seeded_and_unseeded_wire() {
    let (seeded, _) = encrypted();
    let parameters = parameters();
    let original = CanonicalCiphertext::decode(&parameters.to_bytes(), &seeded, 0).unwrap();
    use fhe_traits::DeserializeParametrized;
    let ct = Ciphertext::from_bytes(&seeded, &parameters).unwrap();
    let unseeded = Ciphertext::new(ct.iter().cloned().collect(), &parameters)
        .unwrap()
        .to_bytes();
    for basis in 0..5 {
        let a = original.for_basis(basis).unwrap();
        let b = CanonicalCiphertext::decode(&parameters.to_bytes(), &unseeded, basis).unwrap();
        assert_eq!(a.coefficients(), b.coefficients());
        assert_eq!(a.b_coefficients(), b.b_coefficients());
        assert_eq!(a.evaluations(), b.evaluations());
        assert_eq!(a.bytes(), seeded);
        assert_ne!(a.bytes(), b.bytes());
    }
    assert!(original.for_basis(5).is_err());
}
#[test]
fn explicit_witness_and_fixed_air_geometry_reject_noncanonical_inputs() {
    assert!(ProverWitness::new(&vec![0; N - 1], [0; 4], [1; 4]).is_err());
    assert!(ProverWitness::new(&vec![Val::ORDER_U64; N], [0; 4], [1; 4]).is_err());
    assert!(ProverWitness::new(&vec![0; N], [Val::ORDER_U64; 4], [1; 4]).is_err());
    assert_eq!(circuit::WIDTH, 9452);
    assert_eq!(PUBLIC_VALUES, 62);
    assert_eq!(HEADER_BYTES, 308);
}
fn reframe(original: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = original[..HEADER_BYTES].to_vec();
    bytes[304..308].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
#[test]
fn genuine_component_rechecks_all_key_values_and_rejects_hostile_canonical_nested_frames() {
    let (ciphertext, coefficients) = encrypted();
    let descriptor = bfv_key_transform::SetupDescriptor {
        database: [1; 16],
        key_domain: [2; 16],
        public_setup_digest: setup_digest(),
        key_epoch: 1,
    };
    let expected_key = bfv_key_transform::Expected {
        coefficients: bfv_key_transform::input_commitment(&descriptor, &coefficients, [7; 4])
            .unwrap()
            .map(Val::from_u64),
        descriptor: descriptor.clone(),
    };
    let shat: Vec<_> = bfv_key_transform::circuit::oracle(
        &coefficients
            .iter()
            .copied()
            .map(bfv_key_transform::signed)
            .collect::<Vec<_>>(),
    )
    .iter()
    .map(|v| v.as_canonical_u64())
    .collect();
    let second_coefficients = Zeroizing::new(coefficients.to_vec());
    let key_witness = bfv_key_transform::ProverWitness::new(coefficients, [7; 4], [11; 4]).unwrap();
    let key = bfv_key_transform::prove([4; 32], &expected_key, &key_witness).unwrap();
    let key_claim = bfv_key_transform::verify([4; 32], &expected_key, key.as_bytes()).unwrap();
    let expected = Expected::new(
        key_claim.statement().clone(),
        &parameters().to_bytes(),
        &ciphertext,
        [5; 32],
        0,
    )
    .unwrap();
    let witness = ProverWitness::new(&shat, [11; 4], [13; 4]).unwrap();
    let evidence = prove([4; 32], &expected, key.as_bytes(), &witness)
        .unwrap()
        .into_bytes();
    verify([4; 32], &expected, key.as_bytes(), &evidence).unwrap();
    let (parameters, report) = bfv_hiding_stark::analyze(&expected.key().air()).unwrap();
    let _ = parameters;
    report.require_target().unwrap();
    let air = Statement {
        expected: expected.clone(),
        result: [Val::ZERO; 4],
    }
    .air();
    let (_, report) = bfv_hiding_stark::analyze(&air).unwrap();
    report.require_target().unwrap();
    let topology = Topology::checked(circuit::WIDTH, report.quotient_chunks).unwrap();
    let payload = &evidence[HEADER_BYTES..];
    let decode = || {
        codec::decode(
            payload,
            &topology,
            MAX_SEQUENCE_ELEMENTS,
            MAX_TOTAL_ELEMENTS,
        )
        .unwrap()
    };
    let proof = decode();
    assert!(matches!(
        codec::serialize(&proof, &topology, payload.len() - 1),
        Err(codec::Error::ResourceLimit)
    ));
    assert!(codec::decode(payload, &topology, MAX_SEQUENCE_ELEMENTS, 1).is_err());
    let prefix = postcard::to_allocvec(&proof.commitments).unwrap().len();
    drop(proof);
    let mut bomb = payload[..prefix].to_vec();
    varint(usize::MAX, &mut bomb);
    assert!(matches!(
        codec::decode(&bomb, &topology, MAX_SEQUENCE_ELEMENTS, MAX_TOTAL_ELEMENTS),
        Err(codec::Error::ResourceLimit)
    ));
    assert!(
        verify(
            [4; 32],
            &expected,
            key.as_bytes(),
            &reframe(&evidence, &bomb)
        )
        .is_err()
    );
    for attack in 0..12 {
        let mut proof = decode();
        match attack {
            0 => {
                proof.opened_values.trace_local.pop();
            }
            1 => {
                *proof
                    .opened_values
                    .trace_next
                    .as_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap() += Challenge::ONE;
            }
            2 => {
                proof.opened_values.quotient_chunks.pop();
            }
            3 => proof.opened_values.random = None,
            4 => {
                proof.opening_proof.0[0].pop();
            }
            5 => {
                proof.opening_proof.1.input_openings[1].opened_values[0][0].pop();
            }
            6 => {
                proof.opening_proof.1.commit_phase_openings[9]
                    .sibling_values
                    .pop();
            }
            7 => proof.opening_proof.1.final_poly.push(Challenge::ZERO),
            8 => proof.ood_pow_witness = Val::ONE,
            9 => proof.commitments.random = None,
            10 => proof.degree_bits -= 1,
            _ => {
                proof.opening_proof.1.input_openings[1]
                    .opening_proof
                    .1
                    .sibling_hashes
                    .pop();
            }
        }
        let payload = postcard::to_allocvec(&proof).unwrap();
        drop(proof);
        assert!(
            verify(
                [4; 32],
                &expected,
                key.as_bytes(),
                &reframe(&evidence, &payload)
            )
            .is_err(),
            "nested {attack}"
        );
    }
    for at in [8, 40, 87, 103, 135, 139, 164, 196, 235, 267, 269, 303] {
        let mut bad = evidence.clone();
        bad[at] ^= 1;
        assert!(verify([4; 32], &expected, key.as_bytes(), &bad).is_err());
    }
    let mut alias = evidence.clone();
    alias[296..304].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(verify([4; 32], &expected, key.as_bytes(), &alias).is_err());
    let mut trailing = evidence.clone();
    trailing.push(0);
    assert!(verify([4; 32], &expected, key.as_bytes(), &trailing).is_err());
    let touched = Cell::new(false);
    let no_factory = |candidate: &[u8]| {
        let result = crate::evidence::prove_with_factory(
            [4; 32],
            &expected,
            candidate,
            || {
                touched.set(true);
                witness.statement(expected.clone())
            },
            |_| panic!("unreachable trace"),
        );
        assert!(result.is_err());
        assert!(!touched.get());
    };
    no_factory(&[]);
    let mut broken = key.as_bytes().to_vec();
    *broken.last_mut().unwrap() ^= 1;
    no_factory(&broken);
    // SAME descriptor+Cs, but a genuinely valid foreign CsHat must not authorize this child.
    let foreign_witness =
        bfv_key_transform::ProverWitness::new(second_coefficients, [7; 4], [17; 4]).unwrap();
    let foreign_key = bfv_key_transform::prove([4; 32], &expected_key, &foreign_witness).unwrap();
    let foreign =
        bfv_key_transform::verify([4; 32], &expected_key, foreign_key.as_bytes()).unwrap();
    assert_eq!(foreign.statement().expected, key_claim.statement().expected);
    assert_ne!(
        foreign.statement().transformed,
        key_claim.statement().transformed
    );
    no_factory(foreign_key.as_bytes());
}
