//! PUBLIC NONSECRET generated messages and actual Owner keys; no private material is printed.
use super::*;
use crate::{Geometry, KeyScope};
use bfv_ciphertext_formation::{EncodedCommitment, EncodedOpening};
use bfv_hiding_stark::Val;
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::DeserializeParametrized;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use std::time::Instant;
fn root(context: [u64; 8], salt: [u64; 4], values: &[u64]) -> [u64; 4] {
    let p = p3_goldilocks::default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    state[..8].copy_from_slice(&context.map(Val::from_u64));
    p.permute_mut(&mut state);
    state[..4].copy_from_slice(&salt.map(Val::from_u64));
    state[4..8].fill(Val::ZERO);
    p.permute_mut(&mut state);
    for block in values.as_chunks::<8>().0 {
        state[..8].copy_from_slice(&block.map(Val::from_u64));
        p.permute_mut(&mut state);
    }
    core::array::from_fn(|i| state[i].as_canonical_u64())
}
fn scope() -> KeyScope {
    KeyScope {
        database: [0x42; 16],
        bfv_key_domain: [0x71; 16],
        epoch: 1,
    }
}
fn words() -> Zeroizing<Vec<u64>> {
    Zeroizing::new((0..8192).map(|j| (j as u64 * 37) % 114689).collect())
}
fn encoded_opening(w: Zeroizing<Vec<u64>>) -> (EncodedCommitment, EncodedOpening) {
    let context = [23; 8];
    let salt = [29; 4];
    let c = EncodedCommitment::new([31; 32], context, root(context, salt, &w)).unwrap();
    let o = EncodedOpening::new(w, salt, c.clone()).unwrap();
    (c, o)
}
#[test]
fn actual_owner_unknown_rng_ciphertext_forms_exact_scaled_words_with_fresh_public_verification() {
    let started = Instant::now();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let owner_generate_ms = started.elapsed().as_secs_f64() * 1000.0;
    let setup_bytes = setup.to_bytes().unwrap();
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    let anchor = handle.public_anchor().clone();
    let w = words();
    let encryption = Instant::now();
    let ciphertext = handle.encrypt_encoded_coefficients(&setup, &w).unwrap();
    let encryption_ms = encryption.elapsed().as_secs_f64() * 1000.0;
    let (commitment, opening) = encoded_opening(w);
    let request = [0xA1; 32];
    let mut job = handle.basis_job(&setup, request, &ciphertext).unwrap();
    let start = Instant::now();
    let key = job.prove_key().unwrap().as_bytes().to_vec();
    let key_generation_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut frames: [Vec<u8>; 5] = core::array::from_fn(|_| Vec::new());
    let mut claims = Vec::with_capacity(5);
    let mut basis_ms = [0.0; 5];
    for i in 0..5 {
        let start = Instant::now();
        frames[i] = job.prove_next_basis().unwrap().into_bytes();
        basis_ms[i] = start.elapsed().as_secs_f64() * 1000.0;
        let verified = setup
            .verify_basis_convolution(&anchor, request, &ciphertext, i, &key, &frames[i])
            .unwrap();
        claims.push(verified.statement().clone());
    }
    let claims: [bfv_basis_convolution::Statement; 5] = claims.try_into().ok().unwrap();
    let expected = FormationExpected::new(commitment, claims).unwrap();
    let p = Prerequisites {
        key: &key,
        bases: frames.each_ref().map(Vec::as_slice),
    };
    // A genuine same-Cs/different-CsHat Key is valid on its own but cannot replace this complete job.
    let foreign_key = handle.prove().unwrap();
    let foreign = setup
        .verify_key_transform(&anchor, foreign_key.as_bytes())
        .unwrap();
    assert_eq!(foreign.statement().expected, expected.key().expected);
    assert_ne!(foreign.statement().transformed, expected.key().transformed);
    let mut wrong_result = expected.bases().clone();
    wrong_result[4].result[3] += Val::ONE;
    assert!(
        bfv_basis_convolution::verify_five(anchor.full_setup_id(), &wrong_result, &key, p.bases)
            .is_err()
    );
    let wrong_key = Prerequisites {
        key: foreign_key.as_bytes(),
        bases: p.bases,
    };
    // A VALID differently committed W opening still cannot form this actual ciphertext.
    let mut changed_w = words();
    changed_w[8191] = (changed_w[8191] + 1) % 114689;
    let bad_commitment =
        EncodedCommitment::new([31; 32], [23; 8], root([23; 8], [29; 4], &changed_w)).unwrap();
    let wrong_opening = EncodedOpening::new(changed_w, [29; 4], bad_commitment.clone()).unwrap();
    let wrong_plaintext = FormationExpected::new(bad_commitment, expected.bases().clone()).unwrap();
    let wrong_witness = bfv_ciphertext_formation::ProverWitness::new(
        &wrong_opening,
        &job.shat,
        core::array::from_fn(|i| job.salts[i + 1]),
        [37; 4],
    )
    .unwrap();
    assert!(
        bfv_ciphertext_formation::prove(
            anchor.full_setup_id(),
            &wrong_plaintext,
            &p,
            &wrong_witness
        )
        .is_err()
    );
    drop(wrong_witness);
    let mut formation = job.into_formation(opening).unwrap();
    assert_eq!(formation.stage(), FormationJobStage::Ready);
    assert!(formation.prove(&expected, &wrong_key).is_err());
    assert_eq!(formation.stage(), FormationJobStage::Ready);
    for i in 0..5 {
        let mut bases = p.bases;
        bases[i] = &[];
        assert!(
            formation
                .prove(&expected, &Prerequisites { key: &key, bases })
                .is_err()
        );
        assert_eq!(formation.stage(), FormationJobStage::Ready);
    }
    // Independent SDK ring phase, not the Gold oracle and never used to choose W.
    let wide = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&owner.key).coeffs);
    let mut s = Poly::try_convert_from(
        wide.as_slice(),
        owner.parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    s.change_representation(Representation::Ntt);
    let ct = Ciphertext::from_bytes(&ciphertext, &owner.parameters).unwrap();
    let mut phase = &ct[1] * &s;
    phase += &ct[0];
    phase.change_representation(Representation::PowerBasis);
    let w = words();
    let mut noise = vec![0i64; 8192];
    for i in 0..5 {
        for j in 0..8192 {
            let q = i128::from(bfv_ciphertext_formation::Q[i]);
            let e = (i128::from(phase.coefficients()[[i, j]])
                - i128::from(bfv_ciphertext_formation::DELTA[i]) * i128::from(w[j]))
            .rem_euclid(q);
            let e = if e > q / 2 { e - q } else { e };
            assert!((-20..=20).contains(&e));
            if i == 0 {
                noise[j] = i64::try_from(e).unwrap();
            } else {
                assert_eq!(i128::from(noise[j]), e);
            }
        }
    }
    let noise_salt = *formation.noise_salt;
    let start = Instant::now();
    let evidence = formation.prove(&expected, &p).unwrap().into_bytes();
    let formation_generation_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(formation.stage(), FormationJobStage::Complete);
    assert!(formation.prove(&expected, &p).is_err());
    formation.cancel();
    assert_eq!(formation.stage(), FormationJobStage::Cancelled);
    assert!(matches!(
        formation.prove(&expected, &p),
        Err(Error::FormationJobStage)
    ));
    drop(formation);
    drop(handle);
    drop(owner);
    drop(setup);
    drop(s);
    drop(wide);
    drop(phase);
    let fresh_start = Instant::now();
    let fresh = PublicSetup::from_bytes(&setup_bytes).unwrap();
    let verified = fresh
        .verify_ciphertext_formation(&anchor, &expected, &p, &evidence)
        .unwrap();
    let fresh_ms = fresh_start.elapsed().as_secs_f64() * 1000.0;
    let signed: Vec<_> = noise
        .into_iter()
        .map(|v| {
            if v < 0 {
                Val::ORDER_U64 - v.unsigned_abs()
            } else {
                v as u64
            }
        })
        .collect();
    assert_eq!(
        root(
            verified.statement().contexts()[6].map(|v| v.as_canonical_u64()),
            noise_salt,
            &signed
        ),
        verified.statement().noise.map(|v| v.as_canonical_u64())
    );
    hostile_payloads(&fresh, &anchor, &expected, &p, &evidence);
    for at in [8, 40, 72, 103, 104, 135, 139] {
        let mut bad = evidence.clone();
        bad[at] ^= 1;
        assert!(
            fresh
                .verify_ciphertext_formation(&anchor, &expected, &p, &bad)
                .is_err()
        );
    }
    let mut alias = evidence.clone();
    alias[128..136].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(
        fresh
            .verify_ciphertext_formation(&anchor, &expected, &p, &alias)
            .is_err()
    );
    let mut trailing = evidence.clone();
    trailing.push(0);
    assert!(
        fresh
            .verify_ciphertext_formation(&anchor, &expected, &p, &trailing)
            .is_err()
    );
    let mut reordered = p.bases;
    reordered.swap(0, 4);
    assert!(
        fresh
            .verify_ciphertext_formation(
                &anchor,
                &expected,
                &Prerequisites {
                    key: &key,
                    bases: reordered
                },
                &evidence
            )
            .is_err()
    );
    for field in 0..4 {
        let mut foreign = anchor.clone();
        match field {
            0 => foreign.scope.database[15] ^= 1,
            1 => foreign.scope.bfv_key_domain[15] ^= 1,
            2 => foreign.scope.epoch ^= 1 << 31,
            _ => foreign.full_setup_id[31] ^= 1,
        };
        assert!(
            fresh
                .verify_ciphertext_formation(&foreign, &expected, &p, &evidence)
                .is_err()
        );
    }
    println!(
        "{}",
        serde_json::json!({"stage":"actual_owner_ciphertext_formation","owner_generate_ms":owner_generate_ms,"encryption_ms":encryption_ms,"key_generation_ms":key_generation_ms,"basis_generation_ms":basis_ms,"formation_generation_ms":formation_generation_ms,"fresh_setup_and_verification_ms":fresh_ms,"setup_bytes":setup_bytes.len(),"ciphertext_bytes":ciphertext.len(),"key_frame_bytes":key.len(),"basis_frame_bytes":frames.each_ref().map(Vec::len),"formation_frame_bytes":evidence.len(),"native_coefficients_per_basis":8192,"sql_grant":false,"evaluation_key_consistency_proven":false,"composed_128_claim":false})
    );
}
#[test]
fn owner_encryption_shape_guards_and_incomplete_cancelled_job_cannot_form() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    assert!(
        handle
            .encrypt_encoded_coefficients(&setup, &vec![0; 8191])
            .is_err()
    );
    let mut invalid = vec![0; 8192];
    invalid[8191] = 114689;
    assert!(
        handle
            .encrypt_encoded_coefficients(&setup, &invalid)
            .is_err()
    );
    let (_, foreign) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(
        handle
            .encrypt_encoded_coefficients(&foreign, &vec![0; 8192])
            .is_err()
    );
    let mut rotation_only = setup.clone();
    rotation_only.rotation_keys.push(0);
    assert!(matches!(
        handle.encrypt_encoded_coefficients(&rotation_only, &vec![0; 8192]),
        Err(Error::BindingMismatch)
    ));
    let w = words();
    let ciphertext = handle.encrypt_encoded_coefficients(&setup, &w).unwrap();
    let (_, opening) = encoded_opening(w);
    let job = handle.basis_job(&setup, [3; 32], &ciphertext).unwrap();
    assert!(job.into_formation(opening).is_err());
    let mut job = handle.basis_job(&setup, [3; 32], &ciphertext).unwrap();
    job.cancel();
    let (_, opening) = encoded_opening(words());
    assert!(job.into_formation(opening).is_err());
}

fn hostile_payloads(
    setup: &PublicSetup,
    anchor: &BfvKeyAnchor,
    expected: &FormationExpected,
    p: &Prerequisites<'_>,
    frame: &[u8],
) {
    use bfv_hiding_stark::{
        Challenge, Config,
        codec::{self, Topology},
    };
    let verified = setup
        .verify_ciphertext_formation(anchor, expected, p, frame)
        .unwrap();
    let air = verified.statement().air().unwrap();
    let (_, report) = bfv_hiding_stark::analyze(&air).unwrap();
    report.require_target().unwrap();
    let topology = Topology::checked(
        bfv_ciphertext_formation::circuit::WIDTH,
        report.quotient_chunks,
    )
    .unwrap();
    let payload = &frame[bfv_ciphertext_formation::HEADER_BYTES..];
    let decode = || -> p3_uni_stark::Proof<Config> {
        codec::decode(payload, &topology, 16384, 32 * 1024 * 1024).unwrap()
    };
    let reframe = |payload: &[u8]| {
        let mut b = frame[..140].to_vec();
        b[136..140].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        b.extend_from_slice(payload);
        b
    };
    let proof = decode();
    assert!(codec::serialize(&proof, &topology, payload.len() - 1).is_err());
    assert!(codec::decode(payload, &topology, 16384, 1).is_err());
    let prefix = postcard::to_allocvec(&proof.commitments).unwrap().len();
    drop(proof);
    let mut bomb = payload[..prefix].to_vec();
    let mut n = usize::MAX;
    while n >= 128 {
        bomb.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    bomb.push(n as u8);
    assert!(codec::decode(&bomb, &topology, 16384, 32 * 1024 * 1024).is_err());
    assert!(
        setup
            .verify_ciphertext_formation(anchor, expected, p, &reframe(&bomb))
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
                    .unwrap() += Challenge::ONE
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
            8 => proof.ood_pow_witness += Val::ONE,
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
            setup
                .verify_ciphertext_formation(anchor, expected, p, &reframe(&payload))
                .is_err(),
            "nested formation attack {attack}"
        );
    }
}
