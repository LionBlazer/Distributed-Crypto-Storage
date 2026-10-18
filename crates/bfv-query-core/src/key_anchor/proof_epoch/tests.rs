//! PUBLIC NONSECRET messages and generated Owner keys; only public proof frames are spooled.
use super::*;
use crate::{Geometry, KeyScope};
use bfv_basis_convolution::{Expected as BasisExpected, MODULI, N};
use bfv_ciphertext_formation::{EncodedCommitment, EncodedOpening, Prerequisites};
use bfv_hiding_stark::Val;
use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{DeserializeParametrized, Serialize};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn scope() -> KeyScope {
    KeyScope {
        database: [0x42; 16],
        bfv_key_domain: [0x71; 16],
        epoch: 1,
    }
}
fn words(index: usize) -> Zeroizing<Vec<u64>> {
    Zeroizing::new(
        (0..N)
            .map(|i| (i as u64 * 37 + index as u64 * 65535) % 114689)
            .collect(),
    )
}
fn root(context: [u64; 8], salt: [u64; 4], w: &[u64]) -> [u64; 4] {
    let perm = p3_goldilocks::default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    state[..8].copy_from_slice(&context.map(Val::from_u64));
    perm.permute_mut(&mut state);
    state[..4].copy_from_slice(&salt.map(Val::from_u64));
    state[4..8].fill(Val::ZERO);
    perm.permute_mut(&mut state);
    assert_eq!(w.len(), N);
    for block in w.as_chunks::<8>().0 {
        state[..8].copy_from_slice(&block.map(Val::from_u64));
        perm.permute_mut(&mut state);
    }
    core::array::from_fn(|i| state[i].as_canonical_u64())
}
fn encoding(index: usize, q: [u8; 32], key: &bfv_key_transform::Statement) -> EncodedCommitment {
    let mut h = Sha256::new();
    h.update(b"PUBLIC-NONSECRET/OwnerProofEpoch/operand/v1");
    h.update((index as u64).to_le_bytes());
    h.update(q);
    for word in key.public_values() {
        h.update(word.as_canonical_u64().to_le_bytes());
    }
    let context = bfv_basis_convolution::words(&h.finalize().into()).map(|v| v.as_canonical_u64());
    let salt = [37 + index as u64; 4];
    EncodedCommitment::new(
        [41 + index as u8; 32],
        context,
        root(context, salt, &words(index)),
    )
    .unwrap()
}
fn encoded_opening(index: usize, commitment: &EncodedCommitment) -> EncodedOpening {
    EncodedOpening::new(words(index), [37 + index as u64; 4], commitment.clone()).unwrap()
}
struct PublicFiles {
    path: PathBuf,
    parent: PathBuf,
    name: String,
}
impl PublicFiles {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("dcs-proof-epoch-public-{}-{stamp}", std::process::id());
        let path = parent.join(&name);
        fs::create_dir(&path).unwrap();
        let checked = fs::canonicalize(&path).unwrap();
        assert_eq!(checked, path);
        assert_eq!(checked.parent(), Some(parent.as_path()));
        assert_eq!(checked.file_name(), Some(std::ffi::OsStr::new(&name)));
        Self {
            path: checked,
            parent,
            name,
        }
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.path.join(name)).unwrap()
    }
}
impl Drop for PublicFiles {
    fn drop(&mut self) {
        if let Ok(path) = fs::canonicalize(&self.path)
            && path == self.path
            && path.parent() == Some(self.parent.as_path())
            && path.file_name() == Some(std::ffi::OsStr::new(&self.name))
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}
fn changed_b(owner: &Owner, bytes: &[u8]) -> Vec<u8> {
    let ct = Ciphertext::from_bytes(bytes, &owner.parameters).unwrap();
    let mut b = ct[0].clone();
    b.change_representation(Representation::PowerBasis);
    let mut values: Vec<_> = b.coefficients().iter().copied().collect();
    let last = 5 * N - 1;
    values[last] = (values[last] + 1) % MODULI[4];
    let mut b = Poly::try_convert_from(
        values,
        owner.parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    b.change_representation(Representation::Ntt);
    Ciphertext::new(vec![b, ct[1].clone()], &owner.parameters)
        .unwrap()
        .to_bytes()
}
fn altered_expected(
    expected: &FormationExpected,
    key: &bfv_key_transform::Statement,
    q: [u8; 32],
    ct: &[u8],
) -> FormationExpected {
    FormationExpected::new(
        expected.encoding().clone(),
        core::array::from_fn(|i| bfv_basis_convolution::Statement {
            expected: BasisExpected::new(
                key.clone(),
                expected.ciphertext().parameter_bytes(),
                ct,
                q,
                i,
            )
            .unwrap(),
            result: expected.bases()[i].result,
        }),
    )
    .unwrap()
}
fn actual_sdk_phase_covers_every_coefficient(owner: &Owner, ct: &[u8], w: &[u64]) {
    let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&owner.key).coeffs);
    let mut s = Poly::try_convert_from(
        secret.as_slice(),
        owner.parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    s.change_representation(Representation::Ntt);
    let ct = Ciphertext::from_bytes(ct, &owner.parameters).unwrap();
    let mut phase = &ct[1] * &s;
    phase += &ct[0];
    phase.change_representation(Representation::PowerBasis);
    let mut noise = Zeroizing::new(vec![0i128; N]);
    for (basis, q) in MODULI.into_iter().enumerate() {
        let q = i128::from(q);
        for (i, &word) in w.iter().enumerate() {
            let e = (i128::from(phase.coefficients()[[basis, i]])
                - i128::from(bfv_ciphertext_formation::DELTA[basis]) * i128::from(word))
            .rem_euclid(q);
            let e = if e > q / 2 { e - q } else { e };
            assert!((-20..=20).contains(&e), "basis{basis} coefficient{i}");
            if basis == 0 {
                noise[i] = e;
            } else {
                assert_eq!(noise[i], e);
            }
        }
    }
}

#[test]
fn one_epoch_forms_two_distinct_requests_with_one_key_and_fresh_verification_after_private_drop() {
    // Arrange actual public ciphertexts; no Source fixture or query API is involved.
    let files = PublicFiles::new();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let setup_bytes = setup.to_bytes().unwrap();
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    let anchor = handle.public_anchor().clone();
    let ciphertexts: [Vec<u8>; 2] = core::array::from_fn(|i| {
        handle
            .encrypt_encoded_coefficients(&setup, &words(i))
            .unwrap()
    });
    for (i, ct) in ciphertexts.iter().enumerate() {
        actual_sdk_phase_covers_every_coefficient(&owner, ct, &words(i));
    }
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    files.write("key", epoch.prove_key().unwrap().as_bytes());
    let key_pointer = epoch.key_evidence().unwrap().as_bytes().as_ptr();
    let key_bytes = files.read("key");
    let key = setup
        .verify_key_transform(&anchor, &key_bytes)
        .unwrap()
        .statement()
        .clone();
    assert!(epoch.material.witness.is_none());
    assert!(epoch.prove_key().is_err());
    let requests = [[0x51; 32], [0x61; 32]];
    assert_ne!(requests[0], requests[1]);
    let commitments: [EncodedCommitment; 2] =
        core::array::from_fn(|i| encoding(i, requests[i], &key));
    assert!(
        epoch
            .begin_operand(
                requests[0],
                OperandInput {
                    ciphertext: &[],
                    encoding: commitments[0].clone()
                }
            )
            .is_err()
    );
    assert_eq!(epoch.stage(), ProofEpochStage::Ready);

    // A cancelled real partial proof and an abandoned job cannot destroy the shared Key opening.
    {
        let q = [0x41; 32];
        let mut job = epoch
            .begin_operand(
                q,
                OperandInput {
                    ciphertext: &ciphertexts[0],
                    encoding: commitments[0].clone(),
                },
            )
            .unwrap();
        let proof = job.prove_next_basis().unwrap();
        setup
            .verify_basis_convolution(&anchor, q, &ciphertexts[0], 0, &key_bytes, proof.as_bytes())
            .unwrap();
        files.write("cancelled-basis", proof.as_bytes());
        job.cancel();
        assert_eq!(job.stage(), EpochOperandStage::Cancelled);
        assert!(job.current.is_none() && job.input.is_none() && job.request.is_none());
        assert!(job.prove_next_basis().is_err());
        assert!(
            job.begin_formation(encoded_opening(0, &commitments[0]))
                .is_err()
        );
    }
    {
        let abandoned = epoch
            .begin_operand(
                [0x42; 32],
                OperandInput {
                    ciphertext: &ciphertexts[0],
                    encoding: commitments[0].clone(),
                },
            )
            .unwrap();
        assert_eq!(abandoned.stage(), EpochOperandStage::Basis(0));
        drop(abandoned);
    }
    assert_eq!(
        epoch.material.statement.public_values(),
        key.public_values()
    );
    assert_eq!(epoch.material.shat.len(), N);
    assert_eq!(
        epoch.key_evidence().unwrap().as_bytes().as_ptr(),
        key_pointer
    );
    let foreign_frame = handle.prove().unwrap();
    let foreign = setup
        .verify_key_transform(&anchor, foreign_frame.as_bytes())
        .unwrap()
        .statement()
        .clone();
    assert_eq!(foreign.expected, key.expected);
    assert_ne!(foreign.transformed, key.transformed);
    drop(foreign_frame);

    let mut saved = Vec::with_capacity(2); // Public statements only, never a bank of proofs.
    for (i, &q) in requests.iter().enumerate() {
        let mut job = epoch
            .begin_operand(
                q,
                OperandInput {
                    ciphertext: &ciphertexts[i],
                    encoding: commitments[i].clone(),
                },
            )
            .unwrap();
        assert!(
            job.begin_formation(encoded_opening(i, &commitments[i]))
                .is_err()
        );
        let mut statements = Vec::with_capacity(5);
        for basis in 0..5 {
            assert_eq!(job.stage(), EpochOperandStage::Basis(basis));
            let proof = job.prove_next_basis().unwrap();
            let checked = setup
                .verify_basis_convolution(
                    &anchor,
                    q,
                    &ciphertexts[i],
                    basis,
                    &key_bytes,
                    proof.as_bytes(),
                )
                .unwrap();
            assert_eq!(
                checked.statement().expected.key().public_values(),
                key.public_values()
            );
            assert_eq!(checked.statement().expected.request(), q);
            files.write(&format!("{i}-basis-{basis}"), proof.as_bytes());
            statements.push(checked.statement().clone());
        }
        let expected =
            FormationExpected::new(commitments[i].clone(), statements.try_into().ok().unwrap())
                .unwrap();
        assert!(job.prove_next_basis().is_err());
        let mut wrong_w = words(i);
        wrong_w[N - 1] = (wrong_w[N - 1] + 1) % 114689;
        let old = &commitments[i];
        let wrong_commitment = EncodedCommitment::new(
            old.producer_identity(),
            old.context(),
            root(old.context(), [37 + i as u64; 4], &wrong_w),
        )
        .unwrap();
        let wrong_opening =
            EncodedOpening::new(wrong_w, [37 + i as u64; 4], wrong_commitment).unwrap();
        assert!(matches!(
            job.begin_formation(wrong_opening),
            Err(Error::BindingMismatch)
        ));
        assert_eq!(job.stage(), EpochOperandStage::AwaitingFormation);
        job.begin_formation(encoded_opening(i, &commitments[i]))
            .unwrap();
        let frames: [Vec<u8>; 5] = core::array::from_fn(|b| files.read(&format!("{i}-basis-{b}")));
        let bases = frames.each_ref().map(Vec::as_slice);
        for wrong in [
            altered_expected(&expected, &foreign, q, &ciphertexts[i]),
            altered_expected(&expected, &key, requests[1 - i], &ciphertexts[i]),
            altered_expected(&expected, &key, q, &ciphertexts[1 - i]),
            altered_expected(&expected, &key, q, &changed_b(&owner, &ciphertexts[i])),
        ] {
            assert!(matches!(
                job.prove_formation(&wrong, bases),
                Err(Error::BindingMismatch)
            ));
            assert_eq!(job.stage(), EpochOperandStage::FormationReady);
        }
        for field in 0..3 {
            let mut producer = old.producer_identity();
            let mut context = old.context();
            let mut digest = old.root();
            match field {
                0 => producer[31] ^= 1,
                1 => context[7] ^= 1,
                _ => digest[3] = (digest[3] + 1) % Val::ORDER_U64,
            };
            let wrong = FormationExpected::new(
                EncodedCommitment::new(producer, context, digest).unwrap(),
                expected.bases().clone(),
            )
            .unwrap();
            assert!(matches!(
                job.prove_formation(&wrong, bases),
                Err(Error::BindingMismatch)
            ));
        }
        for b in 0..5 {
            let mut missing = bases;
            missing[b] = &[];
            assert!(job.prove_formation(&expected, missing).is_err());
        }
        let mut reordered = bases;
        reordered.swap(0, 4);
        assert!(job.prove_formation(&expected, reordered).is_err());
        let cancelled = files.read("cancelled-basis");
        let mut stale = bases;
        stale[0] = &cancelled;
        assert!(job.prove_formation(&expected, stale).is_err());
        if i == 1 {
            let earlier: [Vec<u8>; 5] =
                core::array::from_fn(|b| files.read(&format!("0-basis-{b}")));
            assert!(
                job.prove_formation(&expected, earlier.each_ref().map(Vec::as_slice))
                    .is_err()
            );
        }
        assert_eq!(job.stage(), EpochOperandStage::FormationReady);
        let proof = job.prove_formation(&expected, bases).unwrap();
        setup
            .verify_ciphertext_formation(
                &anchor,
                &expected,
                &Prerequisites {
                    key: &key_bytes,
                    bases,
                },
                proof.as_bytes(),
            )
            .unwrap();
        files.write(&format!("{i}-formation"), proof.as_bytes());
        assert_eq!(job.stage(), EpochOperandStage::Complete);
        assert!(job.current.is_none() && job.input.is_none() && job.request.is_none());
        assert!(job.prove_next_basis().is_err());
        assert!(
            job.begin_formation(encoded_opening(i, &commitments[i]))
                .is_err()
        );
        assert!(job.prove_formation(&expected, bases).is_err());
        job.cancel();
        assert_eq!(job.stage(), EpochOperandStage::Cancelled);
        assert!(job.prove_formation(&expected, bases).is_err());
        drop(job);
        assert_eq!(epoch.stage(), ProofEpochStage::Ready);
        assert_eq!(
            epoch.material.statement.public_values(),
            key.public_values()
        );
        assert_eq!(epoch.material.shat.len(), N);
        assert_eq!(
            epoch.key_evidence().unwrap().as_bytes().as_ptr(),
            key_pointer
        );
        assert_eq!(epoch.key_evidence().unwrap().as_bytes(), key_bytes);
        saved.push(expected);
    }
    epoch.cancel();
    assert_eq!(epoch.stage(), ProofEpochStage::Cancelled);
    assert!(epoch.material.shat.is_empty());
    assert!(epoch.material.output_salt.iter().all(|v| *v == 0));
    assert!(epoch.key_evidence().is_err());
    assert!(epoch.prove_key().is_err());
    assert!(
        epoch
            .begin_operand(
                requests[0],
                OperandInput {
                    ciphertext: &ciphertexts[0],
                    encoding: commitments[0].clone()
                }
            )
            .is_err()
    );
    drop(epoch);
    drop(handle);
    drop(owner);
    drop(setup);

    // Fresh public verification after every private producer and Owner has ended.
    let fresh = PublicSetup::from_bytes(&setup_bytes).unwrap();
    assert_eq!(
        fresh
            .verify_key_transform(&anchor, &files.read("key"))
            .unwrap()
            .statement()
            .public_values(),
        key.public_values()
    );
    for (i, expected) in saved.iter().enumerate() {
        let frames: [Vec<u8>; 5] = core::array::from_fn(|b| files.read(&format!("{i}-basis-{b}")));
        let proof = files.read(&format!("{i}-formation"));
        let p = Prerequisites {
            key: &key_bytes,
            bases: frames.each_ref().map(Vec::as_slice),
        };
        fresh
            .verify_ciphertext_formation(&anchor, expected, &p, &proof)
            .unwrap();
        for (b, frame) in frames.iter().enumerate() {
            fresh
                .verify_basis_convolution(
                    &anchor,
                    requests[i],
                    &ciphertexts[i],
                    b,
                    &key_bytes,
                    frame,
                )
                .unwrap();
            assert!(
                fresh
                    .verify_basis_convolution(
                        &anchor,
                        requests[1 - i],
                        &ciphertexts[i],
                        b,
                        &key_bytes,
                        frame
                    )
                    .is_err()
            );
        }
        assert!(
            fresh
                .verify_ciphertext_formation(&anchor, &saved[1 - i], &p, &proof)
                .is_err()
        );
        for at in [8, 40, 72, 104, 136] {
            let mut bad = proof.clone();
            bad[at] ^= 1;
            assert!(
                fresh
                    .verify_ciphertext_formation(&anchor, expected, &p, &bad)
                    .is_err()
            );
        }
    }
}

#[test]
fn original_setup_and_prekey_guards_leave_no_ready_epoch_or_imported_opening() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    let mut rotated = setup.clone();
    rotated.rotation_keys.push(0);
    assert!(matches!(
        handle.proof_epoch(&rotated),
        Err(Error::BindingMismatch)
    ));
    let (other, foreign) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        handle.proof_epoch(&foreign),
        Err(Error::BindingMismatch)
    ));
    drop(other);
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    let commitment =
        EncodedCommitment::new([1; 32], [2; 8], root([2; 8], [3; 4], &words(0))).unwrap();
    assert_eq!(epoch.stage(), ProofEpochStage::AwaitingKey);
    assert!(epoch.key_evidence().is_err());
    assert!(matches!(
        epoch.begin_operand(
            [4; 32],
            OperandInput {
                ciphertext: &[],
                encoding: commitment.clone()
            }
        ),
        Err(Error::ProofEpochStage)
    ));
    epoch.cancel();
    epoch.cancel();
    assert_eq!(epoch.stage(), ProofEpochStage::Cancelled);
    assert!(epoch.material.shat.is_empty() && epoch.material.witness.is_none());
    assert!(epoch.material.output_salt.iter().all(|v| *v == 0));
    assert!(epoch.prove_key().is_err());
    assert!(
        epoch
            .begin_operand(
                [4; 32],
                OperandInput {
                    ciphertext: &[],
                    encoding: commitment
                }
            )
            .is_err()
    );
}
