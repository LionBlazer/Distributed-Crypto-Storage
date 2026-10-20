//! PUBLIC NONSECRET keys/data only. No forged parent, accepting callback or FHE answer.
use super::*;
use crate::private_predicate::SourceOwner;
use bfv_query_core::{BfvKeyAnchor, Geometry, KeyScope, Owner, PublicSetup};
use compact_query::{PlainRow, RowIds, TableId};
use peer_runtime::RawBundle;
use registry200_proof::admission::CanonicalSource;
use zeroize::Zeroizing;
pub(super) mod fixture;
mod full_acquire;
pub(super) mod full_acquire_fixture;

fn context<'a>(
    owner: &'a Owner,
    setup: &'a PublicSetup,
    anchor: &'a BfvKeyAnchor,
) -> BfvContext<'a> {
    BfvContext {
        owner,
        setup,
        anchor,
    }
}
fn control(
    registry: &Registry,
    controllers: [[u8; 32]; 2],
    salts: [[u64; 4]; 2],
) -> LockingControl {
    LockingControl::new(
        registry.clone(),
        controllers,
        salts,
        LockingActor::new(1, 1, registry.revision, 1).unwrap(),
    )
    .unwrap()
}

#[test]
fn owner_original_setup_check_rejects_foreign_same_geometry_without_encrypting() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    owner.require_public_setup(&setup).unwrap();
    let (_, foreign) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(owner.require_public_setup(&foreign).is_err());
    let (_, other_geometry) = Owner::generate(Geometry::Rows256).unwrap();
    assert!(owner.require_public_setup(&other_geometry).is_err());
    owner
        .require_public_setup(&PublicSetup::from_bytes(&setup.to_bytes().unwrap()).unwrap())
        .unwrap();
}

#[test]
fn genuine_joint_parent_rejects_foreign_pins_then_produces_new_g_input16_after_history_drop() {
    // Arrange actual canonical ingest, actual BFV epoch and independently pinned descriptor.
    let source_owner =
        SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
    let rows = [
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
    ];
    let table = source_owner
        .seal_partition(
            &TableId::from_bytes([0x19; 32]).unwrap(),
            &rows,
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
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: spec.database,
                bfv_key_domain: [0x88; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let anchor = handle.public_anchor().clone();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let checked = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    let key_values = checked.statement().public_values();
    let descriptor = Descriptor::checked(
        ApplicationDescriptor::from_application(&spec).unwrap(),
        object,
        &setup,
        &anchor,
        checked.statement(),
    )
    .unwrap();
    let built = fixture::sealed_begin(&source_owner, &loaded, descriptor, &setup);
    // History, ingress and all native parent-proof buffers have already dropped.
    let parent = JointLockingParent::from_verified(
        &built.parent,
        &built.binding,
        context(&owner, &setup, &anchor),
        &epoch,
    )
    .unwrap();
    assert_eq!(
        parent.head().genesis,
        built.binding.journal_genesis().id().unwrap()
    );
    assert_ne!(
        built.binding.journal_genesis().application_commitment,
        spec.id()
    );
    assert!(
        spec.require_genesis(built.binding.journal_genesis())
            .is_err(),
        "no old-app relabel"
    );

    let mut foreign_g = built.binding.journal_genesis().clone();
    foreign_g.timestamp += 1;
    let foreign_binding = JointBinding::new(
        spec.network,
        built.binding.rules().clone(),
        built.binding.work_genesis().clone(),
        foreign_g,
        built.binding.application_descriptor().clone(),
        built.binding.setup_claim().clone(),
    )
    .unwrap();
    assert!(
        JointLockingParent::from_verified(
            &built.parent,
            &foreign_binding,
            context(&owner, &setup, &anchor),
            &epoch
        )
        .is_err()
    );
    let (foreign_owner, foreign_setup) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(
        JointLockingParent::from_verified(
            &built.parent,
            &built.binding,
            context(&foreign_owner, &setup, &anchor),
            &epoch
        )
        .is_err()
    );
    assert!(
        JointLockingParent::from_verified(
            &built.parent,
            &built.binding,
            context(&owner, &foreign_setup, &anchor),
            &epoch
        )
        .is_err()
    );
    let awaiting = handle.proof_epoch(&setup).unwrap();
    assert!(
        JointLockingParent::from_verified(
            &built.parent,
            &built.binding,
            context(&owner, &setup, &anchor),
            &awaiting
        )
        .is_err()
    );
    drop(awaiting);
    // A genuine independently self-verified Key from the SAME anchor but fresh
    // CsHat is still foreign to the full independently pinned ALL33 descriptor.
    let mut fresh_epoch = handle.proof_epoch(&setup).unwrap();
    fresh_epoch.prove_key().unwrap();
    let fresh = setup
        .verify_key_transform(&anchor, fresh_epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    assert_eq!(&fresh.statement().public_values()[..29], &key_values[..29]);
    assert_ne!(&fresh.statement().public_values()[29..], &key_values[29..]);
    assert!(
        JointLockingParent::from_verified(
            &built.parent,
            &built.binding,
            context(&owner, &setup, &anchor),
            &fresh_epoch
        )
        .is_err()
    );
    drop(fresh_epoch);
    drop(foreign_owner);
    drop(foreign_setup);

    let compiled=CompiledLockingSelect::compile("SELECT age, amount FROM records WHERE age IN (0, 255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED",
        Zeroizing::new([0xc6;32]),[0xe7;32],[0xf8;16]).unwrap();
    for actor in [
        LockingActor::new(1, 2, built.registry.revision, 1).unwrap(),
        LockingActor::new(1, 1, built.registry.revision + 1, 1).unwrap(),
        LockingActor::new(1, 1, built.registry.revision, 2).unwrap(),
    ] {
        assert!(
            LockingControl::new(
                built.registry.clone(),
                fixture::CONTROLLERS,
                [fixture::ENROLL_SALT, built.registry_salt],
                actor
            )
            .is_err()
        );
    }
    let good_salts = [fixture::ENROLL_SALT, built.registry_salt];
    for case in 0..4 {
        let mut registry = built.registry.clone();
        let mut controllers = fixture::CONTROLLERS;
        let mut salts = good_salts;
        match case {
            0 => controllers[0][31] ^= 1,
            1 => salts[0][3] += 1,
            2 => salts[1][3] += 1,
            _ => registry.transactions[0].snapshot[31] ^= 1,
        }
        let error = match source_owner.prepare_joint_locking(
            context(&owner, &setup, &anchor),
            &mut epoch,
            fetched(),
            &compiled,
            &parent,
            control(&registry, controllers, salts),
        ) {
            Err(error) => error,
            Ok(_) => panic!("foreign private opening {case} accepted"),
        };
        assert!(
            matches!(error,crate::Error::InvalidInput(ref text) if text=="Private control opening differs from the validated parent")
        );
        assert_eq!(epoch.stage(), ProofEpochStage::Ready);
    }
    let mut wrong_object = object;
    wrong_object[31] ^= 1;
    assert!(
        source_owner
            .prepare_joint_locking(
                context(&owner, &setup, &anchor),
                &mut epoch,
                FetchedSource {
                    object: wrong_object,
                    bundle: &bundle,
                    heads: &heads
                },
                &compiled,
                &parent,
                control(&built.registry, fixture::CONTROLLERS, good_salts)
            )
            .is_err()
    );
    let mut broken = bundle.clone();
    *broken.index.last_mut().unwrap() ^= 1;
    assert!(
        source_owner
            .prepare_joint_locking(
                context(&owner, &setup, &anchor),
                &mut epoch,
                FetchedSource {
                    object,
                    bundle: &broken,
                    heads: &heads
                },
                &compiled,
                &parent,
                control(&built.registry, fixture::CONTROLLERS, good_salts)
            )
            .is_err()
    );
    drop(loaded);

    // Act: the shared actual producer encrypts ALL originals and proves the old
    // same-q input16 plus actual new-G Lifecycle and private-mask Link.
    let owned_parent =
        JointControlParent::from_verified(&built.parent, &built.binding, &built.context).unwrap();
    let owned_control = JointRegistryOpening::from_private_parts(
        &owned_parent,
        built.registry.clone(),
        fixture::CONTROLLERS,
        good_salts,
    )
    .unwrap()
    .for_acquire(&owned_parent, 1, 1)
    .unwrap();
    let JointLockingPreparation::Prepared(prepared) = source_owner
        .prepare_joint_locking_owned(
            context(&owner, &setup, &anchor),
            &mut epoch,
            fetched(),
            &compiled,
            &owned_parent,
            owned_control,
        )
        .unwrap()
    else {
        panic!("uncontended Acquire must prepare")
    };
    assert_eq!(prepared.request().lane(), Lane::Acquire);
    let request = prepared.request().inner();
    assert_eq!(request.genesis, parent.head().genesis);
    assert_eq!(request.parent, parent.head().block);
    assert_eq!(request.application, spec.id());
    assert_eq!(
        request.query,
        registry200_journal::intent_query(
            &spec,
            request.genesis,
            request.parent,
            request.nonce,
            request.enrollment,
            registry200_journal::Operation::Transition
        )
    );
    assert_eq!(
        prepared.lifecycle().statement().expected.genesis,
        request.genesis
    );
    assert_eq!(
        prepared.lifecycle().statement().expected.source.request,
        request.query
    );
    assert_eq!(
        prepared
            .link()
            .expected()
            .query()
            .expected
            .source_claim()
            .request,
        request.query
    );
    assert_eq!(prepared.inputs().provenance().query(), request.query);
    for encoding in prepared.inputs().provenance().encodings() {
        assert_eq!(encoding.expected.bfv().key().public_values(), key_values);
    }
    assert_eq!(prepared.inputs().proofs().frames().len(), 15);
    let (inputs, life, link, outer, candidates) = prepared.into_parts();
    let original = inputs.request().to_vec();
    let (provenance, pending, proofs) = inputs.into_parts();
    assert_eq!(pending.request, original);
    let expected_link = link.expected().clone();
    drop(epoch);
    drop(handle);
    drop(owner);
    drop(source_owner);
    drop(compiled);
    drop(candidates);
    drop(built);
    // Assert fresh actual public verification after every private producer owner drops.
    provenance
        .verify_inputs(&proofs.as_input_evidence())
        .unwrap();
    let canonical = CanonicalSource::checked_claim(&life.statement().expected.source).unwrap();
    let expected =
        registry200_proof::admission::Expected::checked_claim(&life.statement().expected).unwrap();
    let verified = registry200_proof::wire::verify(&expected, life.as_bytes()).unwrap();
    assert_eq!(
        verified.next_root(),
        registry200_proof::source::statement::encode_digest(life.statement().next)
    );
    predicate_acquire::verify(
        &expected_link,
        &predicate_acquire::Prerequisites {
            query: proofs.frames()[2],
            lifecycle: life.as_bytes(),
        },
        link.as_bytes(),
    )
    .unwrap();
    assert_eq!(canonical.claim().request, outer.inner().query);
}
