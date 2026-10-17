//! PUBLIC NONSECRET generated test keys. No private key/vector/salt is printed or serialized.
use super::*;
use crate::Geometry;
use bfv_hiding_stark::{Challenge, Val};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_symmetric::Permutation;
use std::time::Instant;

fn scope() -> KeyScope {
    KeyScope {
        database: [0x42; 16],
        bfv_key_domain: [0x71; 16],
        epoch: 1,
    }
}
// Independent native stream, not the shared commitment/statement implementation.
fn native_context(anchor: &BfvKeyAnchor, output: bool) -> [Val; 8] {
    let domain: &[u8] = if output {
        b"DCS/BFV-SECRET-ODD-EVALUATIONS/v1"
    } else {
        b"DCS/BFV-SECRET-COEFFICIENTS/v1"
    };
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-KEY-TRANSFORM-CONTEXT/v1");
    h.update((domain.len() as u32).to_le_bytes());
    h.update(domain);
    h.update(bfv_key_transform::profile_digest());
    h.update(anchor.scope.database);
    h.update(anchor.scope.bfv_key_domain);
    h.update(anchor.parameter_digest);
    h.update(anchor.scope.epoch.to_le_bytes());
    if output {
        for word in anchor.coefficients {
            h.update(word.to_le_bytes());
        }
    }
    let bytes = h.finalize();
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[i * 4..i * 4 + 4].try_into().unwrap(),
        ))
    })
}
fn native_root(context: [Val; 8], salt: [u64; 4], values: &[Val]) -> [u64; 4] {
    assert_eq!(values.len(), 8192);
    let mut state = [Val::ZERO; 12];
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_12();
    state[..8].copy_from_slice(&context);
    permutation.permute_mut(&mut state);
    state[..4].copy_from_slice(&salt.map(Val::from_u64));
    state[4..8].fill(Val::ZERO);
    permutation.permute_mut(&mut state);
    for values in values.as_chunks::<8>().0 {
        state[..8].copy_from_slice(values);
        permutation.permute_mut(&mut state);
    }
    core::array::from_fn(|i| state[i].as_canonical_u64())
}
fn reframe(original: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = original[..bfv_key_transform::HEADER_BYTES].to_vec();
    bytes[204..208].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn malformed_actual_payloads(setup: &PublicSetup, expected: &BfvKeyAnchor, evidence: &[u8]) {
    use bfv_hiding_stark::codec::{self, Topology};
    let shape = Topology::checked(9932, 16).unwrap();
    let payload = &evidence[208..];
    let decode = || codec::decode(payload, &shape, 16_384, 24 * 1024 * 1024).unwrap();
    let original = decode();
    assert_eq!(postcard::to_allocvec(&original).unwrap(), payload);
    assert!(matches!(
        codec::serialize(&original, &shape, payload.len() - 1),
        Err(codec::Error::ResourceLimit)
    ));
    assert_eq!(
        codec::serialize(&original, &shape, payload.len()).unwrap(),
        payload
    );
    assert!(matches!(
        codec::decode(payload, &shape, 16_384, 1),
        Err(codec::Error::ResourceLimit)
    ));
    // Actual serde field boundary: commitments precede trace_local's sequence prefix.
    let prefix = postcard::to_allocvec(&original.commitments).unwrap().len();
    let mut bomb = payload[..prefix].to_vec();
    let mut length = usize::MAX;
    loop {
        let word = (length & 127) as u8;
        length >>= 7;
        bomb.push(word | if length != 0 { 128 } else { 0 });
        if length == 0 {
            break;
        }
    }
    assert!(matches!(
        codec::decode(&bomb, &shape, 16_384, 24 * 1024 * 1024),
        Err(codec::Error::ResourceLimit)
    ));
    assert!(
        setup
            .verify_key_transform(expected, &reframe(evidence, &bomb))
            .is_err()
    );
    drop(original);
    for attack in 0..12 {
        let mut proof = decode();
        match attack {
            0 => proof.degree_bits -= 1,
            1 => {
                proof.opened_values.trace_local.pop();
            }
            2 => {
                *proof
                    .opened_values
                    .trace_next
                    .as_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap() += Challenge::ONE;
            }
            3 => {
                proof.opened_values.quotient_chunks.pop();
            }
            4 => {
                proof.opened_values.random = None;
            }
            5 => {
                proof.opening_proof.0[0].pop();
            }
            6 => {
                proof.opening_proof.1.input_openings[1].opened_values[0][0].pop();
            }
            7 => {
                proof.opening_proof.1.input_openings[1]
                    .opening_proof
                    .1
                    .sibling_hashes
                    .pop();
            }
            8 => {
                proof.opening_proof.1.final_poly.push(Challenge::ZERO);
            }
            9 => {
                proof.opening_proof.1.commit_phase_openings[0].sibling_values[0]
                    .push(Challenge::ZERO);
            }
            10 => proof.ood_pow_witness = Val::ONE,
            _ => proof.commitments.random = None,
        }
        let payload = postcard::to_allocvec(&proof).unwrap();
        drop(proof);
        assert!(
            setup
                .verify_key_transform(expected, &reframe(evidence, &payload))
                .is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn actual_owner_produces_bounded_hiding_evidence_and_fresh_independent_verifier_checks_it() {
    let started = Instant::now();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let setup_bytes = setup.to_bytes().unwrap();
    let generated = started.elapsed();
    let anchor_started = Instant::now();
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    let expected = handle.public_anchor().clone();
    assert_eq!(
        expected.full_setup_id(),
        <[u8; 32]>::from(Sha256::digest(&setup_bytes))
    );
    let anchored = anchor_started.elapsed();
    // Test-only access to the actual upstream key, never a fixture coefficient generator.
    let coefficients = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&owner.key).coeffs);
    let shifted: Vec<_> = coefficients
        .iter()
        .map(|s| Val::from_u64(u64::try_from(s + 20).unwrap()))
        .collect();
    assert_eq!(
        native_root(
            native_context(&expected, false),
            *handle.input_salt,
            &shifted
        ),
        expected.coefficient_commitment()
    );
    let signed: Vec<_> = coefficients
        .iter()
        .map(|s| {
            if *s >= 0 {
                Val::from_u64(*s as u64)
            } else {
                -Val::from_u64(s.unsigned_abs())
            }
        })
        .collect();
    let transformed =
        Radix2DitParallel::<Val>::default().coset_dft(signed, Val::two_adic_generator(14));
    let output_salt = Zeroizing::new(bfv_key_transform::random_salt().unwrap());
    let independent_output =
        native_root(native_context(&expected, true), *output_salt, &transformed);
    drop(coefficients);
    drop(shifted);
    drop(transformed);

    let proof_started = Instant::now();
    let evidence = handle.prove().unwrap().into_bytes();
    let proved = proof_started.elapsed();
    let second_started = Instant::now();
    let second = handle
        .prove_with_output_salt(output_salt)
        .unwrap()
        .into_bytes();
    let second_proved = second_started.elapsed();
    assert_ne!(evidence, second);
    assert_eq!(&evidence[140..172], &second[140..172]);
    assert_ne!(&evidence[172..204], &second[172..204]);
    drop(handle);
    drop(owner);
    drop(setup);

    let verify_started = Instant::now();
    let independent_setup = PublicSetup::from_bytes(&setup_bytes).unwrap();
    let verified = independent_setup
        .verify_key_transform(&expected, &evidence)
        .unwrap();
    let verified_elapsed = verify_started.elapsed();
    let repeat_verify_started = Instant::now();
    let second_verified = independent_setup
        .verify_key_transform(&expected, &second)
        .unwrap();
    assert_eq!(verified.full_setup_id(), expected.full_setup_id());
    assert_eq!(
        second_verified
            .statement()
            .transformed
            .map(|v| v.as_canonical_u64()),
        independent_output
    );
    let repeat_verified_elapsed = repeat_verify_started.elapsed();
    println!(
        "{{\"stage\":\"actual_owner_key_anchor\",\"setup_bytes\":{},\"proof_frame_bytes\":{},\"second_frame_bytes\":{},\"owner_generate_ms\":{},\"anchor_ms\":{},\"generation_ms\":{},\"second_generation_ms\":{},\"fresh_verification_ms\":{},\"repeat_fresh_verification_ms\":{},\"sql_grant\":false,\"evaluation_key_consistency_proven\":false}}",
        setup_bytes.len(),
        evidence.len(),
        second.len(),
        generated.as_secs_f64() * 1000.0,
        anchored.as_secs_f64() * 1000.0,
        proved.as_secs_f64() * 1000.0,
        second_proved.as_secs_f64() * 1000.0,
        verified_elapsed.as_secs_f64() * 1000.0,
        repeat_verified_elapsed.as_secs_f64() * 1000.0
    );
    drop(second);

    for at in 0..6 {
        let mut wrong = expected.clone();
        match at {
            0 => wrong.scope.database[15] ^= 1,
            1 => wrong.scope.bfv_key_domain[15] ^= 1,
            2 => wrong.scope.epoch ^= 1 << 31,
            3 => wrong.full_setup_id[31] ^= 1,
            4 => wrong.parameter_digest[31] ^= 1,
            _ => wrong.coefficients[3] ^= 1,
        }
        assert!(
            independent_setup
                .verify_key_transform(&wrong, &evidence)
                .is_err()
        );
        let mut coherent_header = evidence.clone();
        coherent_header[40..72].copy_from_slice(&wrong.full_setup_id);
        coherent_header[72..140].copy_from_slice(&wrong.descriptor().bytes());
        for (word, bytes) in wrong
            .coefficients
            .iter()
            .zip(coherent_header[140..172].as_chunks_mut::<8>().0)
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        assert!(
            independent_setup
                .verify_key_transform(&wrong, &coherent_header)
                .is_err()
        );
    }
    for at in [8, 39, 40, 71, 87, 103, 135, 139, 140, 171, 172, 203] {
        let mut bad = evidence.clone();
        bad[at] ^= 1;
        assert!(
            independent_setup
                .verify_key_transform(&expected, &bad)
                .is_err()
        );
    }
    let mut alias = evidence.clone();
    alias[140..148].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(
        independent_setup
            .verify_key_transform(&expected, &alias)
            .is_err()
    );
    let mut trailing = evidence.clone();
    trailing.push(0);
    assert!(
        independent_setup
            .verify_key_transform(&expected, &trailing)
            .is_err()
    );
    let mut short = evidence.clone();
    short.truncate(short.len() - 1);
    assert!(
        independent_setup
            .verify_key_transform(&expected, &short)
            .is_err()
    );
    malformed_actual_payloads(&independent_setup, &expected, &evidence);

    let (other_owner, other_setup) = Owner::generate(Geometry::Rows16).unwrap();
    let other_handle = other_owner.key_anchor(&other_setup, scope()).unwrap();
    let other_expected = other_handle.public_anchor().clone();
    let other_evidence = other_handle.prove().unwrap().into_bytes();
    other_setup
        .verify_key_transform(&other_expected, &other_evidence)
        .unwrap();
    assert!(
        independent_setup
            .verify_key_transform(&expected, &other_evidence)
            .is_err()
    );
    assert!(
        other_setup
            .verify_key_transform(&expected, &other_evidence)
            .is_err()
    );
}

#[test]
fn foreign_setup_geometry_and_rotation_only_changes_reject_before_owner_secret_use() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let mut rotations = setup.rotation_keys.clone();
    let last = rotations.len() - 1;
    rotations[last] ^= 1;
    let changed = PublicSetup::from_public_material(
        setup.geometry,
        &setup.parameters,
        &setup.relinearization_key,
        &rotations,
    )
    .unwrap();
    assert!(matches!(
        owner.key_anchor(&changed, scope()),
        Err(Error::BindingMismatch)
    ));
    let changed = PublicSetup::from_public_material(
        Geometry::Rows256,
        &setup.parameters,
        &setup.relinearization_key,
        &setup.rotation_keys,
    )
    .unwrap();
    assert!(matches!(
        owner.key_anchor(&changed, scope()),
        Err(Error::BindingMismatch)
    ));
    let (foreign_owner, foreign) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        owner.key_anchor(&foreign, scope()),
        Err(Error::BindingMismatch)
    ));
    drop(foreign_owner);
}

#[test]
fn recreating_handle_mints_a_new_public_anchor_without_changing_the_original() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let first = owner.key_anchor(&setup, scope()).unwrap();
    let original = first.public_anchor().clone();
    let second = owner.key_anchor(&setup, scope()).unwrap();
    assert_eq!(first.public_anchor(), &original);
    assert_eq!(
        first.public_anchor().full_setup_id(),
        second.public_anchor().full_setup_id()
    );
    assert_ne!(
        first.public_anchor().coefficient_commitment(),
        second.public_anchor().coefficient_commitment()
    );
}
