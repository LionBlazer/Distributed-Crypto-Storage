//! Generated keys and explicit PUBLIC NONSECRET messages only. No persisted private files.
use super::*;
use crate::{Geometry, KeyScope};
use fhe::bfv::{Ciphertext, Encoding, Plaintext};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize};

fn identity() -> OwnerStateIdentity {
    OwnerStateIdentity {
        scope: KeyScope {
            database: [11; 16],
            bfv_key_domain: [12; 16],
            epoch: 7,
        },
        record_id: [13; 32],
    }
}
fn authority() -> OwnerStateAuthority {
    OwnerStateAuthority::new(Zeroizing::new([17; 32]))
}
fn message() -> Vec<u64> {
    (0..bfv_fixed_geometry::DEGREE)
        .map(|i| (19 * i as u64) % 114689)
        .collect()
}
fn encrypt(owner: &Owner, m: &[u64]) -> Vec<u8> {
    let pt = Plaintext::try_encode(m, Encoding::poly(), &owner.parameters).unwrap();
    let ct: Ciphertext = owner.key.try_encrypt(&pt, &mut rand::rng()).unwrap();
    ct.to_bytes()
}
fn decrypt(owner: &Owner, ct: &[u8]) -> Vec<u64> {
    let ct = Ciphertext::from_bytes(ct, &owner.parameters).unwrap();
    let pt = owner.key.try_decrypt(&ct).unwrap();
    Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap()
}

#[test]
fn encrypted_owner_restore_decrypts_every_original_coefficient_after_owner_drop() {
    let id = identity();
    let a = authority();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let m = message();
    let ct = encrypt(&owner, &m);
    let record = owner.backup_private_state(&setup, &id, &a).unwrap();
    let second = owner.backup_private_state(&setup, &id, &a).unwrap();
    assert_ne!(record.as_bytes(), second.as_bytes()); // fresh AEAD nonce, same semantic state
    assert!(
        owner
            .backup_private_state(
                &{
                    let mut s = setup.clone();
                    s.rotation_keys.push(0);
                    s
                },
                &id,
                &a
            )
            .is_err()
    );
    drop(owner);
    let parsed = EncryptedOwnerState::from_bytes(record.as_bytes()).unwrap();
    let restored = Owner::restore_private_state(&setup, &id, &a, &parsed).unwrap();
    assert_eq!(decrypt(&restored, &ct), m);
    let (other, foreign) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(Owner::restore_private_state(&foreign, &id, &a, &parsed).is_err());
    assert!(other.backup_private_state(&setup, &id, &a).is_err());
}

#[test]
fn encrypted_records_reject_wrong_authority_pins_role_tamper_truncation_and_resource_aliases() {
    let id = identity();
    let a = authority();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let record = owner.backup_private_state(&setup, &id, &a).unwrap();
    assert!(matches!(
        Owner::restore_private_state(
            &setup,
            &id,
            &OwnerStateAuthority::new(Zeroizing::new([18; 32])),
            &record
        ),
        Err(Error::OwnerStateAuthentication)
    ));
    for field in 0..4 {
        let mut wrong = id.clone();
        match field {
            0 => wrong.scope.database[15] ^= 1,
            1 => wrong.scope.bfv_key_domain[15] ^= 1,
            2 => wrong.scope.epoch += 1,
            _ => wrong.record_id[31] ^= 1,
        }
        assert!(matches!(
            Owner::restore_private_state(&setup, &wrong, &a, &record),
            Err(Error::BindingMismatch)
        ));
    }
    for at in [588, OWNER_STATE_HEADER_BYTES, record.as_bytes().len() - 1] {
        let mut raw = record.as_bytes().to_vec();
        raw[at] ^= 1;
        let bad = EncryptedOwnerState::from_bytes(&raw).unwrap();
        assert!(matches!(
            Owner::restore_private_state(&setup, &id, &a, &bad),
            Err(Error::OwnerStateAuthentication)
        ));
    }
    for cut in [
        0,
        8,
        OWNER_STATE_HEADER_BYTES - 1,
        record.as_bytes().len() - 1,
    ] {
        assert!(EncryptedOwnerState::from_bytes(&record.as_bytes()[..cut]).is_err());
    }
    let mut trailing = record.as_bytes().to_vec();
    trailing.push(0);
    assert!(EncryptedOwnerState::from_bytes(&trailing).is_err());
    assert!(matches!(
        EncryptedOwnerState::from_bytes(&vec![0; MAX_OWNER_STATE_BYTES + 1]),
        Err(Error::WireLimit)
    ));
    for at in [8, 10, 11, 616] {
        let mut bad = record.as_bytes().to_vec();
        bad[at] = 255;
        assert!(EncryptedOwnerState::from_bytes(&bad).is_err());
    }
    let anchor = owner.key_anchor(&setup, id.scope.clone()).unwrap();
    let anchor_record = anchor.backup_private_state(&setup, &id, &a).unwrap();
    let mut noncanonical = anchor_record.as_bytes().to_vec();
    noncanonical[292..300].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
    assert!(EncryptedOwnerState::from_bytes(&noncanonical).is_err());
    assert!(Owner::restore_private_state(&setup, &id, &a, &anchor_record).is_err());
    assert!(
        owner
            .restore_key_anchor(&setup, anchor.public_anchor(), &id, &a, &record)
            .is_err()
    );
}

#[test]
fn authenticated_malformed_secret_is_rejected_before_any_sdk_secret_decode() {
    let id = identity();
    let a = authority();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let record = owner.backup_private_state(&setup, &id, &a).unwrap();
    let plain = open(
        Pins {
            role: Role::Owner,
            setup: &setup,
            identity: &id,
            anchor: None,
            key: None,
        },
        &a,
        &record,
    )
    .unwrap();
    for attack in 0..5 {
        let mut bad = Zeroizing::new(plain.to_vec());
        match attack {
            0 => bad[8..12].copy_from_slice(&8191u32.to_le_bytes()),
            1 => bad[16] = 41,
            2 => *bad.last_mut().unwrap() = 255,
            3 => bad.push(20),
            _ => bad[12] = 1,
        }
        // This is the exact validator immediately preceding GuardedProto and SDK decode.
        assert!(secret_words(&bad).is_err());
        if bad.len() == SECRET_BYTES {
            let sealed = seal(
                Pins {
                    role: Role::Owner,
                    setup: &setup,
                    identity: &id,
                    anchor: None,
                    key: None,
                },
                &a,
                &bad,
            )
            .unwrap();
            assert!(matches!(
                Owner::restore_private_state(&setup, &id, &a, &sealed),
                Err(Error::InvalidShape)
            ));
        }
    }
    let mut boundaries = Zeroizing::new(plain.to_vec());
    boundaries[16..].fill(0);
    assert!(secret_words(&boundaries).unwrap().iter().all(|v| *v == -20));
    boundaries[16..].fill(40);
    assert!(secret_words(&boundaries).unwrap().iter().all(|v| *v == 20));
}

#[test]
fn restored_anchor_reopens_exact_input_root_and_rejects_authenticated_wrong_salt() {
    let id = identity();
    let a = authority();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let anchor = owner.key_anchor(&setup, id.scope.clone()).unwrap();
    let pin = anchor.public_anchor().clone();
    let record = anchor.backup_private_state(&setup, &id, &a).unwrap();
    let foreign = owner.key_anchor(&setup, id.scope.clone()).unwrap();
    assert!(
        owner
            .restore_key_anchor(&setup, foreign.public_anchor(), &id, &a, &record)
            .is_err()
    );
    let mut plain = open(
        Pins {
            role: Role::Anchor,
            setup: &setup,
            identity: &id,
            anchor: Some(&pin),
            key: None,
        },
        &a,
        &record,
    )
    .unwrap();
    // Select a guaranteed different canonical salt even when an original word happens to be zero.
    let old = open(
        Pins {
            role: Role::Anchor,
            setup: &setup,
            identity: &id,
            anchor: Some(&pin),
            key: None,
        },
        &a,
        &record,
    )
    .unwrap();
    let old_word = u64::from_le_bytes(old[16..24].try_into().unwrap());
    plain[16..24].copy_from_slice(&((old_word + 1) % 0xffff_ffff_0000_0001u64).to_le_bytes());
    let bad = seal(
        Pins {
            role: Role::Anchor,
            setup: &setup,
            identity: &id,
            anchor: Some(&pin),
            key: None,
        },
        &a,
        &plain,
    )
    .unwrap();
    assert!(matches!(
        owner.restore_key_anchor(&setup, &pin, &id, &a, &bad),
        Err(Error::BindingMismatch)
    ));
    plain[16..24].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
    let noncanonical = seal(
        Pins {
            role: Role::Anchor,
            setup: &setup,
            identity: &id,
            anchor: Some(&pin),
            key: None,
        },
        &a,
        &plain,
    )
    .unwrap();
    assert!(matches!(
        owner.restore_key_anchor(&setup, &pin, &id, &a, &noncanonical),
        Err(Error::InvalidShape)
    ));
    drop(foreign);
    drop(anchor);
    let restored = owner
        .restore_key_anchor(&setup, &pin, &id, &a, &record)
        .unwrap();
    assert_eq!(restored.public_anchor(), &pin);
    // A public decoded anchor alone remains insufficient: a different Owner cannot restore it.
    let (other, _) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(
        other
            .restore_key_anchor(&setup, &pin, &id, &a, &record)
            .is_err()
    );
}

#[cfg(feature = "formation-proofs")]
#[test]
fn restored_ready_epoch_preserves_full_key_and_proves_new_basis_formation_after_original_drop() {
    use crate::{OperandInput, ProofEpochStage};
    use bfv_ciphertext_formation::{EncodedCommitment, EncodedOpening, Expected, Prerequisites};
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let id = identity();
    let a = authority();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let anchor = owner.key_anchor(&setup, id.scope.clone()).unwrap();
    let public = anchor.public_anchor().clone();
    let m = message();
    let w = Zeroizing::new(m.iter().map(|m| m * 78307 % 114689).collect::<Vec<_>>());
    let ciphertext = anchor.encrypt_encoded_coefficients(&setup, &w).unwrap();
    let mut epoch = anchor.proof_epoch(&setup).unwrap();
    assert!(matches!(
        epoch.backup_ready_state(&setup, &id, &a),
        Err(Error::ProofEpochStage)
    ));
    let key_frame = epoch.prove_key().unwrap().as_bytes().to_vec();
    let key = setup
        .verify_key_transform(&public, &key_frame)
        .unwrap()
        .statement()
        .clone();
    let owner_record = owner.backup_private_state(&setup, &id, &a).unwrap();
    let anchor_record = anchor.backup_private_state(&setup, &id, &a).unwrap();
    let epoch_record = epoch.backup_ready_state(&setup, &id, &a).unwrap();
    let mut noncanonical = epoch_record.as_bytes().to_vec();
    noncanonical[580..588].copy_from_slice(&bfv_hiding_stark::Val::ORDER_U64.to_le_bytes());
    assert!(EncryptedOwnerState::from_bytes(&noncanonical).is_err());
    let mut rotated = setup.clone();
    rotated.rotation_keys.push(0);
    assert!(epoch.backup_ready_state(&rotated, &id, &a).is_err());
    epoch.cancel();
    assert!(epoch.backup_ready_state(&setup, &id, &a).is_err());
    drop(epoch);
    drop(anchor);
    drop(owner);

    let restored = Owner::restore_private_state(&setup, &id, &a, &owner_record).unwrap();
    assert_eq!(decrypt(&restored, &ciphertext), m);
    let restored_anchor = restored
        .restore_key_anchor(&setup, &public, &id, &a, &anchor_record)
        .unwrap();
    let mut wrong = key.clone();
    wrong.transformed[3] += bfv_hiding_stark::Val::ONE;
    assert!(
        restored_anchor
            .restore_ready_epoch(&setup, &wrong, &id, &a, &epoch_record)
            .is_err()
    );
    let mut plain = open(
        Pins {
            role: Role::Epoch,
            setup: &setup,
            identity: &id,
            anchor: Some(&public),
            key: Some(&key),
        },
        &a,
        &epoch_record,
    )
    .unwrap();
    let old = u64::from_le_bytes(plain[8..16].try_into().unwrap());
    plain[8..16].copy_from_slice(&((old + 1) % bfv_hiding_stark::Val::ORDER_U64).to_le_bytes());
    let bad = seal(
        Pins {
            role: Role::Epoch,
            setup: &setup,
            identity: &id,
            anchor: Some(&public),
            key: Some(&key),
        },
        &a,
        &plain,
    )
    .unwrap();
    assert!(
        restored_anchor
            .restore_ready_epoch(&setup, &key, &id, &a, &bad)
            .is_err()
    );
    let mut wrong_proof = open(
        Pins {
            role: Role::Epoch,
            setup: &setup,
            identity: &id,
            anchor: Some(&public),
            key: Some(&key),
        },
        &a,
        &epoch_record,
    )
    .unwrap();
    *wrong_proof.last_mut().unwrap() ^= 1;
    let bad = seal(
        Pins {
            role: Role::Epoch,
            setup: &setup,
            identity: &id,
            anchor: Some(&public),
            key: Some(&key),
        },
        &a,
        &wrong_proof,
    )
    .unwrap();
    assert!(
        restored_anchor
            .restore_ready_epoch(&setup, &key, &id, &a, &bad)
            .is_err()
    );
    let mut epoch = restored_anchor
        .restore_ready_epoch(&setup, &key, &id, &a, &epoch_record)
        .unwrap();
    assert_eq!(epoch.stage(), ProofEpochStage::Ready);
    assert_eq!(epoch.key_evidence().unwrap().as_bytes(), key_frame);
    assert_eq!(
        setup
            .verify_key_transform(&public, epoch.key_evidence().unwrap().as_bytes())
            .unwrap()
            .statement()
            .public_values(),
        key.public_values()
    );
    let q = [83; 32];
    let context = [89; 8];
    let salt = [97; 4];
    let fields = w
        .iter()
        .copied()
        .map(bfv_hiding_stark::Val::from_u64)
        .collect::<Vec<_>>();
    let root = bfv_key_transform::circuit::digest(
        context.map(bfv_hiding_stark::Val::from_u64),
        salt.map(bfv_hiding_stark::Val::from_u64),
        &fields,
    )
    .map(|v| v.as_canonical_u64());
    let commitment = EncodedCommitment::new([101; 32], context, root).unwrap();
    let mut job = epoch
        .begin_operand(
            q,
            OperandInput {
                ciphertext: &ciphertext,
                encoding: commitment.clone(),
            },
        )
        .unwrap();
    let mut frames = Vec::new();
    let mut statements = Vec::new();
    for basis in 0..5 {
        let proof = job.prove_next_basis().unwrap();
        let checked = setup
            .verify_basis_convolution(&public, q, &ciphertext, basis, &key_frame, proof.as_bytes())
            .unwrap();
        assert_eq!(
            checked.statement().expected.key().public_values(),
            key.public_values()
        );
        statements.push(checked.statement().clone());
        frames.push(proof.into_bytes());
    }
    let expected = Expected::new(commitment.clone(), statements.try_into().ok().unwrap()).unwrap();
    job.begin_formation(EncodedOpening::new(w, salt, commitment).unwrap())
        .unwrap();
    let bases: [&[u8]; 5] = core::array::from_fn(|i| frames[i].as_slice());
    let proof = job.prove_formation(&expected, bases).unwrap();
    drop(job);
    drop(epoch);
    drop(restored_anchor);
    drop(restored);
    let fresh = PublicSetup::from_bytes(&setup.to_bytes().unwrap()).unwrap();
    fresh
        .verify_ciphertext_formation(
            &public,
            &expected,
            &Prerequisites {
                key: &key_frame,
                bases,
            },
            proof.as_bytes(),
        )
        .unwrap();
}

#[cfg(feature = "formation-proofs")]
#[test]
fn restored_ready_epoch_rejects_a_genuine_same_anchor_proof_with_a_different_output_root() {
    let id = identity();
    let a = authority();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let anchor = owner.key_anchor(&setup, id.scope.clone()).unwrap();
    let public = anchor.public_anchor();
    let mut epoch = anchor.proof_epoch(&setup).unwrap();
    let original = epoch.prove_key().unwrap().as_bytes().to_vec();
    let key = setup
        .verify_key_transform(public, &original)
        .unwrap()
        .statement()
        .clone();
    let record = epoch.backup_ready_state(&setup, &id, &a).unwrap();
    drop(epoch);

    // This separately genuine proof has the SAME independent input anchor but
    // a fresh output salt. Its full Key33 must not replace the saved private root.
    let foreign = anchor.prove().unwrap();
    let checked = setup
        .verify_key_transform(public, foreign.as_bytes())
        .unwrap();
    assert_eq!(checked.statement().expected, key.expected);
    assert_ne!(checked.statement().transformed, key.transformed);
    let mut plain = open(
        Pins {
            role: Role::Epoch,
            setup: &setup,
            identity: &id,
            anchor: Some(public),
            key: Some(&key),
        },
        &a,
        &record,
    )
    .unwrap();
    plain.truncate(48);
    plain[40..44].copy_from_slice(&(foreign.as_bytes().len() as u32).to_le_bytes());
    plain.extend_from_slice(foreign.as_bytes());
    let substituted = seal(
        Pins {
            role: Role::Epoch,
            setup: &setup,
            identity: &id,
            anchor: Some(public),
            key: Some(&key),
        },
        &a,
        &plain,
    )
    .unwrap();

    // The authenticated original salt still reopens the original full Key33.
    // Actual verification accepts the foreign proof above, but Ready rejects
    // its different transformed root instead of adopting a same-anchor receipt.
    assert!(matches!(
        anchor.restore_ready_epoch(&setup, &key, &id, &a, &substituted),
        Err(Error::BindingMismatch)
    ));
    let mut changed_setup = setup.clone();
    changed_setup.rotation_keys.push(0);
    assert!(matches!(
        anchor.restore_ready_epoch(&changed_setup, &key, &id, &a, &record),
        Err(Error::BindingMismatch)
    ));
    let restored = anchor
        .restore_ready_epoch(&setup, &key, &id, &a, &record)
        .unwrap();
    assert_eq!(restored.stage(), crate::ProofEpochStage::Ready);
    assert_eq!(restored.key_evidence().unwrap().as_bytes(), original);
}
