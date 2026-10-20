//! PUBLIC NONSECRET fixtures. Genuine proof verification, no simulated SQL result.
use super::*;
use bfv_query_core::{Geometry, KeyScope, Owner, OwnerStateAuthority, OwnerStateIdentity};
use compact_query::{PlainRow, RowIds, TableId};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use peer_runtime::RawBundle;
use registry200_proof::lifecycle::{circuit::commitment, statement as ls};

// Reuse the existing genuine signed Bootstrap/Begin producer without changing
// its owning tests or exposing a fixture/private Source getter in production.
use crate::private_predicate::source::locking::joint::tests::fixture;

fn bfv<'a>(
    owner: &'a Owner,
    setup: &'a bfv_query_core::PublicSetup,
    anchor: &'a bfv_query_core::BfvKeyAnchor,
) -> BfvContext<'a> {
    BfvContext {
        owner,
        setup,
        anchor,
    }
}
fn bump(word: &mut u64) {
    *word = if *word == Val::ORDER_U64 - 1 {
        0
    } else {
        *word + 1
    };
}

#[test]
fn encrypted_compute_prepared_has_exact_bounded_role_and_no_trailing_alias() {
    // Grammar is deliberately not authentication. No fake proof/SQL receipt is minted.
    let mut bytes = vec![0; JOINT_RECOVERY_BYTES];
    bytes[..8].copy_from_slice(b"DCSJRC01");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10] = 1;
    bytes[136..140].copy_from_slice(
        &((JOINT_RECOVERY_BYTES - JOINT_RECOVERY_HEADER_BYTES) as u32).to_le_bytes(),
    );
    assert_eq!(JOINT_RECOVERY_HEADER_BYTES, 144);
    assert_eq!(JOINT_RECOVERY_BYTES, 1242);
    assert_eq!(
        EncryptedJointRecovery::from_bytes(&bytes)
            .unwrap()
            .as_bytes(),
        bytes
    );
    for at in [0, 8, 10, 11, 136, 140] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(EncryptedJointRecovery::from_bytes(&bad).is_err());
    }
    for len in [
        0,
        8,
        JOINT_RECOVERY_HEADER_BYTES - 1,
        JOINT_RECOVERY_BYTES - 1,
    ] {
        assert!(EncryptedJointRecovery::from_bytes(&bytes[..len]).is_err());
    }
    bytes.push(0);
    assert!(EncryptedJointRecovery::from_bytes(&bytes).is_err());
}

#[test]
fn genuine_compute_prepared_restores_after_owner_drop_and_rejects_authenticated_false_openings() {
    // Arrange genuine owner ingest and independently validated Joint history.
    let source_owner = crate::private_predicate::SourceOwner::new(
        [0x21; 16],
        [0x42; 16],
        Zeroizing::new([0x63; 32]),
    )
    .unwrap();
    let table = source_owner
        .seal_partition(
            &TableId::from_bytes([0x19; 32]).unwrap(),
            &[
                PlainRow {
                    age: 0,
                    amount: 65535,
                },
                PlainRow { age: 1, amount: 0 },
                PlainRow {
                    age: 128,
                    amount: 255,
                },
                PlainRow {
                    age: 255,
                    amount: 65534,
                },
            ],
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let heads = table.read_heads();
    let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    let object = *bundle.target_version().unwrap().object();
    drop(table);
    let fetched = || FetchedSource {
        object,
        bundle: &bundle,
        heads: &heads,
    };
    let loaded = source_owner.load(fetched()).unwrap();
    let spec = Application::new([0x3a; 32], 7, 8, &loaded.draft).unwrap();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let owner_id = OwnerStateIdentity {
        scope: KeyScope {
            database: spec.database,
            bfv_key_domain: [0x88; 16],
            epoch: 1,
        },
        record_id: [0x97; 32],
    };
    let owner_wrapping = OwnerStateAuthority::new(Zeroizing::new([0x86; 32]));
    let handle = owner.key_anchor(&setup, owner_id.scope.clone()).unwrap();
    let anchor = handle.public_anchor().clone();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let key = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap()
        .statement()
        .clone();
    let descriptor = Descriptor::checked(
        ApplicationDescriptor::from_application(&spec).unwrap(),
        object,
        &setup,
        &anchor,
        &key,
    )
    .unwrap();
    let built = fixture::sealed_begin(&source_owner, &loaded, descriptor, &setup);
    drop(loaded);
    let parent = JointLockingParent::from_verified(
        &built.parent,
        &built.binding,
        bfv(&owner, &setup, &anchor),
        &epoch,
    )
    .unwrap();
    let compiled = CompiledLockingSelect::compile(
        "SELECT amount FROM records WHERE age IN (0, 255) LIMIT 2 FOR UPDATE SKIP LOCKED",
        Zeroizing::new([0xc6; 32]),
        [0xe7; 32],
        [0xf8; 16],
    )
    .unwrap();
    let identity = JointRecoveryIdentity::new([0x75; 32]);
    let wrapping = JointRecoveryKey::new(Zeroizing::new([0x64; 32]));

    let owned_parent =
        JointControlParent::from_verified(&built.parent, &built.binding, &built.context).unwrap();
    let owned_control = JointRegistryOpening::from_private_parts(
        &owned_parent,
        built.registry.clone(),
        fixture::CONTROLLERS,
        [fixture::ENROLL_SALT, built.registry_salt],
    )
    .unwrap()
    .for_acquire(&owned_parent, 1, 1)
    .unwrap();
    // Act: preserve the full owned parent stamp and capture the real Link while
    // it exists. No raw-control getter or second private extraction is exposed.
    let RecoverableJointLockingPreparation::Prepared(recoverable) = source_owner
        .prepare_joint_locking_owned_recoverable(
            bfv(&owner, &setup, &anchor),
            &mut epoch,
            fetched(),
            &compiled,
            owned_control,
            JointOwnedRecovery::new(&owned_parent, &identity, &wrapping),
        )
        .unwrap()
    else {
        panic!("Uncontended actual Acquire must prepare");
    };
    let (prepared, record) = recoverable.into_parts();
    let (inputs, life, link, outer, candidates) = prepared.into_parts();
    let (provenance, pending, proofs) = inputs.into_parts();
    let exact_request = pending.request.clone();
    let exact_next = life.statement().next;
    let exact_result = life.statement().result;
    assert_eq!(*candidates._completion.projection, 2);
    let owner_record = owner
        .backup_private_state(&setup, &owner_id, &owner_wrapping)
        .unwrap();
    let anchor_record = handle
        .backup_private_state(&setup, &owner_id, &owner_wrapping)
        .unwrap();
    let epoch_record = epoch
        .backup_ready_state(&setup, &owner_id, &owner_wrapping)
        .unwrap();
    drop(candidates);
    drop(pending);
    drop(compiled);
    drop(epoch);
    drop(handle);
    drop(owner);
    drop(source_owner);
    // The independent public premise buffers survive, not any private mask or DATA bank.
    let owner =
        Owner::restore_private_state(&setup, &owner_id, &owner_wrapping, &owner_record).unwrap();
    let handle = owner
        .restore_key_anchor(&setup, &anchor, &owner_id, &owner_wrapping, &anchor_record)
        .unwrap();
    let epoch = handle
        .restore_ready_epoch(&setup, &key, &owner_id, &owner_wrapping, &epoch_record)
        .unwrap();
    let public = || JointRecoveryInputs {
        request: &outer,
        provenance: &provenance,
        encrypted_request: &exact_request,
        proofs: proofs.as_input_evidence(),
        lifecycle: life.as_bytes(),
        link: link.as_bytes(),
    };
    let parsed = EncryptedJointRecovery::from_bytes(record.as_bytes()).unwrap();
    let recovered = parsed
        .restore_compute_prepared(
            &identity,
            &wrapping,
            bfv(&owner, &setup, &anchor),
            &epoch,
            &parent,
            public(),
        )
        .unwrap();
    let (restored_pending, restored) = recovered.into_parts();
    assert_eq!(restored_pending.request, exact_request);
    restored_pending.operand_ciphertexts().unwrap();
    let staged = &restored._staged;
    let life_expected = &staged._association.lifecycle().expected;
    let fields = commitment::registry_fields_opening(
        life_expected,
        &restored._completion.table,
        &restored._completion.row_ids,
        &staged.controllers,
        &staged.next,
        staged.salts[1].map(Val::from_u64),
    );
    assert_eq!(ls::digest(&fields), exact_next);
    let result = commitment::ResultFieldsOpening {
        operation: registry200_proof::lifecycle::circuit::model::Operation::Acquire,
        outcome: 0,
        transaction: staged.actor.transaction,
        flags: *restored._completion.flags,
        salt: (*restored._completion.result_salt).map(Val::from_u64),
    };
    assert_eq!(
        ls::digest(&commitment::result_fields_opening(
            life.statement(),
            &result
        )),
        exact_result
    );
    assert_eq!(*restored._completion.projection, 2);
    assert_eq!(restored._outer_request, outer.encode().unwrap());
    assert_eq!(
        staged
            ._association
            .query()
            .expected
            .bfv()
            .key()
            .public_values(),
        key.public_values()
    );
    drop(restored_pending);
    drop(restored);

    // AEAD keys are public NONSECRET fixtures here. These are AUTHENTIC, canonical
    // but false payloads, not bad-tag tests. Every altered valid projection must
    // fail the actual Cmd160 opening even though Result144 does not bind it.
    let association = codec::association(&parent, &public()).unwrap();
    for projection in [1, 3] {
        let mut payload = codec::open(&identity, &wrapping, association, &record).unwrap();
        payload.link.projection = projection;
        let false_record = codec::seal(&identity, &wrapping, association, &payload).unwrap();
        let authenticated = codec::open(&identity, &wrapping, association, &false_record).unwrap();
        assert_eq!(authenticated.link.projection, projection);
        assert!(
            predicate_acquire::circuit::Witness::new(
                link.expected(),
                codec::copy_opening(&authenticated.link)
            )
            .is_err()
        );
        assert!(
            false_record
                .restore_compute_prepared(
                    &identity,
                    &wrapping,
                    bfv(&owner, &setup, &anchor),
                    &epoch,
                    &parent,
                    public()
                )
                .is_err()
        );
    }
    for attack in 0..13 {
        let mut payload = codec::open(&identity, &wrapping, association, &record).unwrap();
        match attack {
            0 => payload.link.flags[0][3] ^= true,
            1 => bump(&mut payload.link.salts[0][3]),
            2 => bump(&mut payload.link.salts[1][3]),
            3 => bump(&mut payload.link.salts[2][3]),
            4 => payload.link.mask[31] ^= 0x80,
            5 => {
                payload.controllers[0][31] ^= 1;
                payload.link.controller = payload.controllers[0];
            }
            6 => payload.old.transactions[0].snapshot[31] ^= 1,
            7 => payload.next.transactions[0].snapshot[31] ^= 1,
            8 => bump(&mut payload.salts[0][3]),
            9 => bump(&mut payload.salts[1][3]),
            10 => bump(&mut payload.salts[2][3]),
            11 => payload.ids[3][31] ^= 1,
            _ => payload.table[31] ^= 1,
        }
        let false_record = codec::seal(&identity, &wrapping, association, &payload).unwrap();
        codec::open(&identity, &wrapping, association, &false_record).unwrap();
        assert!(
            false_record
                .restore_compute_prepared(
                    &identity,
                    &wrapping,
                    bfv(&owner, &setup, &anchor),
                    &epoch,
                    &parent,
                    public()
                )
                .is_err(),
            "authenticated false opening {attack}"
        );
    }
    assert!(
        record
            .restore_compute_prepared(
                &identity,
                &JointRecoveryKey::new(Zeroizing::new([0x65; 32])),
                bfv(&owner, &setup, &anchor),
                &epoch,
                &parent,
                public()
            )
            .is_err()
    );
    assert!(
        record
            .restore_compute_prepared(
                &JointRecoveryIdentity::new([0x76; 32]),
                &wrapping,
                bfv(&owner, &setup, &anchor),
                &epoch,
                &parent,
                public()
            )
            .is_err()
    );
    let mut corrupted = record.as_bytes().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let corrupted = EncryptedJointRecovery::from_bytes(&corrupted).unwrap();
    assert!(
        corrupted
            .restore_compute_prepared(
                &identity,
                &wrapping,
                bfv(&owner, &setup, &anchor),
                &epoch,
                &parent,
                public()
            )
            .is_err()
    );
    let mut changed_request = exact_request.clone();
    *changed_request.last_mut().unwrap() ^= 1;
    let mut wrong = public();
    wrong.encrypted_request = &changed_request;
    assert!(
        record
            .restore_compute_prepared(
                &identity,
                &wrapping,
                bfv(&owner, &setup, &anchor),
                &epoch,
                &parent,
                wrong
            )
            .is_err()
    );
    let mut no_premise = public();
    no_premise.proofs.formations[1] = &[];
    assert!(
        record
            .restore_compute_prepared(
                &identity,
                &wrapping,
                bfv(&owner, &setup, &anchor),
                &epoch,
                &parent,
                no_premise
            )
            .is_err()
    );
    // Re-seal against altered public proof bytes to force the genuine input
    // verifier, rather than crediting only the AEAD association mismatch.
    let mut bad_key = proofs.frames()[0].to_vec();
    bad_key[0] ^= 1;
    let mut wrong = public();
    wrong.proofs.key = &bad_key;
    let changed_association = codec::association(&parent, &wrong).unwrap();
    let payload = codec::open(&identity, &wrapping, association, &record).unwrap();
    let false_record = codec::seal(&identity, &wrapping, changed_association, &payload).unwrap();
    assert!(
        false_record
            .restore_compute_prepared(
                &identity,
                &wrapping,
                bfv(&owner, &setup, &anchor),
                &epoch,
                &parent,
                wrong
            )
            .is_err()
    );
    // A genuinely self-verified Key on this same anchor, with fresh CsHat,
    // remains foreign to the independently pinned full33 installation.
    let mut fresh = handle.proof_epoch(&setup).unwrap();
    fresh.prove_key().unwrap();
    let foreign = setup
        .verify_key_transform(&anchor, fresh.key_evidence().unwrap().as_bytes())
        .unwrap();
    assert_eq!(
        &foreign.statement().public_values()[..29],
        &key.public_values()[..29]
    );
    assert_ne!(
        &foreign.statement().public_values()[29..],
        &key.public_values()[29..]
    );
    assert!(
        record
            .restore_compute_prepared(
                &identity,
                &wrapping,
                bfv(&owner, &setup, &anchor),
                &fresh,
                &parent,
                public()
            )
            .is_err()
    );
    drop(fresh);
    // Copies of authentic ciphertext are intentionally restorable; no global
    // exactly-once or current-lock claim is manufactured from a move-only handle.
    let second = record
        .restore_compute_prepared(
            &identity,
            &wrapping,
            bfv(&owner, &setup, &anchor),
            &epoch,
            &parent,
            public(),
        )
        .unwrap();
    assert_eq!(second.into_parts().0.request, exact_request);
}
