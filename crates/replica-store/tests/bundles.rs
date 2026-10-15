//! Generic related ciphertext objects; public synthetic payloads, no SQL policy.
use compact_store::{EncryptedSnapshot, Layout, Limits, Owner};
use replica_store::*;

fn sealed(value: u8) -> EncryptedSnapshot {
    Owner::generate(*b"public-bundle001")
        .unwrap()
        .seal(
            Layout {
                schema: *b"PUBLIC-BYTES-001",
                row_width: 1,
                rows_per_page: 16,
                row_count: 64,
            },
            &[value; 64],
            Limits::default(),
        )
        .unwrap()
}
fn peer(store: &mut ReplicaStore, id: u64, domain: u64, quota: usize) {
    store
        .register_peer(PeerConfig {
            id: PeerId(id),
            failure_domain: FailureDomainId(domain),
            quota_bytes: quota,
        })
        .unwrap();
}
fn target(
    object: u64,
    image: &EncryptedSnapshot,
    copies: usize,
    bundle: Option<u64>,
) -> ReplicaTarget {
    ReplicaTarget {
        object: ObjectId(object),
        expected: image.commitment().clone(),
        copies,
        bundle: bundle.map(BundleId),
    }
}
fn seed(store: &mut ReplicaStore, peer: u64, object: u64, image: &EncryptedSnapshot) {
    store
        .seed(
            PeerId(peer),
            ObjectId(object),
            image.commitment(),
            &image.encode(),
        )
        .unwrap();
}
fn store() -> ReplicaStore {
    ReplicaStore::new(Bounds::default()).unwrap()
}

#[test]
fn per_object_redundancy_and_tempting_partial_quotas_do_not_count_as_complete_bundles() {
    let first = sealed(1);
    let second = sealed(2);
    let charge = first.encoded_len() + RECORD_METADATA_BYTES;
    let mut s = store();
    peer(&mut s, 1, 1, charge * 2);
    peer(&mut s, 2, 2, charge);
    peer(&mut s, 3, 3, charge);
    peer(&mut s, 4, 4, charge * 2 - 1);
    seed(&mut s, 1, 1, &first);
    seed(&mut s, 1, 2, &second);
    seed(&mut s, 2, 1, &first);
    seed(&mut s, 3, 2, &second);
    let before = (1..=4)
        .map(|id| s.usage(PeerId(id)).unwrap())
        .collect::<Vec<_>>();
    let targets = [
        target(1, &first, 2, Some(7)),
        target(2, &second, 2, Some(7)),
    ];

    assert!(matches!(
        s.plan_repair(&targets),
        Err(Error::InsufficientDomainsOrCapacity)
    ));

    assert_eq!(
        (1..=4)
            .map(|id| s.usage(PeerId(id)).unwrap())
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(
        s.ciphertext(PeerId(2), ObjectId(2)),
        Err(Error::MissingReplica)
    );
    assert_eq!(
        s.ciphertext(PeerId(3), ObjectId(1)),
        Err(Error::MissingReplica)
    );
}

#[test]
fn complementary_sources_form_two_complete_copies_without_a_complete_source_bundle() {
    let first = sealed(3);
    let second = sealed(4);
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    seed(&mut s, 1, 1, &first);
    seed(&mut s, 2, 2, &second);
    let targets = [
        target(1, &first, 2, Some(8)),
        target(2, &second, 2, Some(8)),
    ];

    let report = s
        .repair_local(s.plan_repair(&targets).unwrap(), &targets)
        .unwrap();

    assert_eq!(report.copied.len(), 2);
    assert!(
        report.copied.iter().any(|c| c.object == ObjectId(2)
            && c.source == PeerId(2)
            && c.destination == PeerId(1))
    );
    assert!(
        report.copied.iter().any(|c| c.object == ObjectId(1)
            && c.source == PeerId(1)
            && c.destination == PeerId(2))
    );
    for id in 1..=2 {
        assert_eq!(
            s.ciphertext(PeerId(id), ObjectId(1)).unwrap(),
            first.encode()
        );
        assert_eq!(
            s.ciphertext(PeerId(id), ObjectId(2)).unwrap(),
            second.encode()
        );
    }
    assert!(s.plan_repair(&targets).unwrap().copies().is_empty());
}

#[test]
fn mixed_copy_policies_duplicate_objects_and_member_bounds_reject_before_placement() {
    let image = sealed(5);
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    seed(&mut s, 1, 1, &image);
    seed(&mut s, 1, 2, &image);
    let before = s.usage(PeerId(1)).unwrap();
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 1, Some(1)), target(2, &image, 2, Some(1))]),
        Err(Error::InvalidTargets)
    ));
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 1, Some(1)), target(1, &image, 1, Some(2))]),
        Err(Error::InvalidTargets)
    ));
    let limited = ReplicaStore::new(Bounds {
        max_objects: 1,
        ..Bounds::default()
    })
    .unwrap();
    assert!(matches!(
        limited.plan_repair(&[target(1, &image, 1, Some(1)), target(2, &image, 1, Some(1))]),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(s.usage(PeerId(1)).unwrap(), before);
}

#[test]
fn aggregate_bundle_charges_are_reserved_across_the_entire_multi_bundle_batch() {
    let image = sealed(6);
    let charge = image.encoded_len() + RECORD_METADATA_BYTES;
    let mut s = store();
    peer(&mut s, 1, 1, charge * 4);
    peer(&mut s, 2, 2, charge * 4 - 1);
    for object in 1..=4 {
        seed(&mut s, 1, object, &image);
    }
    let targets = [
        target(1, &image, 2, Some(1)),
        target(2, &image, 2, Some(1)),
        target(3, &image, 2, Some(2)),
        target(4, &image, 2, Some(2)),
    ];
    assert!(matches!(
        s.plan_repair(&targets),
        Err(Error::InsufficientDomainsOrCapacity)
    ));
    assert_eq!(s.usage(PeerId(2)).unwrap().charged_bytes, 0);
    for object in 1..=4 {
        assert_eq!(
            s.ciphertext(PeerId(2), ObjectId(object)),
            Err(Error::MissingReplica)
        );
    }
}

#[test]
fn bad_second_member_rolls_back_a_verified_first_member_and_preserves_sources() {
    let first = sealed(7);
    let second = sealed(8);
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    seed(&mut s, 1, 1, &first);
    seed(&mut s, 1, 2, &second);
    let targets = [
        target(1, &first, 2, Some(3)),
        target(2, &second, 2, Some(3)),
    ];
    let before = s.usage(PeerId(2)).unwrap();
    let result = s.repair_with(
        s.plan_repair(&targets).unwrap(),
        &targets,
        |_, object, out| {
            let bytes = if object == ObjectId(1) {
                first.encode()
            } else {
                second.encode()
            };
            out.copy_from_slice(&bytes);
            if object == ObjectId(2) {
                *out.last_mut().unwrap() ^= 1;
            }
            Ok(out.len())
        },
    );
    assert_eq!(result, Err(Error::NoAvailableSource(ObjectId(2))));
    assert_eq!(s.usage(PeerId(2)).unwrap(), before);
    assert_eq!(
        s.ciphertext(PeerId(2), ObjectId(1)),
        Err(Error::MissingReplica)
    );
    assert_eq!(
        s.ciphertext(PeerId(2), ObjectId(2)),
        Err(Error::MissingReplica)
    );
    assert_eq!(
        s.ciphertext(PeerId(1), ObjectId(1)).unwrap(),
        first.encode()
    );
    assert_eq!(
        s.ciphertext(PeerId(1), ObjectId(2)).unwrap(),
        second.encode()
    );
}

#[test]
fn complete_holders_in_one_declared_domain_still_count_as_only_one_bundle_copy() {
    let image = sealed(9);
    let mut s = store();
    for id in 1..=3 {
        peer(&mut s, id, 1, 4096);
    }
    for id in 1..=2 {
        seed(&mut s, id, 1, &image);
        seed(&mut s, id, 2, &image);
    }
    let targets = [target(1, &image, 2, Some(4)), target(2, &image, 2, Some(4))];
    assert!(matches!(
        s.plan_repair(&targets),
        Err(Error::InsufficientDomainsOrCapacity)
    ));
    assert_eq!(s.usage(PeerId(3)).unwrap().charged_bytes, 0);
}

#[test]
fn independent_none_keeps_separate_placement_and_bundle_changes_invalidate_current_targets() {
    let image = sealed(10);
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    seed(&mut s, 1, 1, &image);
    seed(&mut s, 2, 2, &image);
    let independent = [target(1, &image, 1, None), target(2, &image, 1, None)];
    assert!(s.plan_repair(&independent).unwrap().copies().is_empty());
    let grouped = [target(1, &image, 1, Some(5)), target(2, &image, 1, Some(5))];
    let plan = s.plan_repair(&grouped).unwrap();
    assert!(!plan.copies().is_empty());
    assert_eq!(
        s.repair_with(plan, &independent, |_, _, _| panic!(
            "policy mismatch must precede receive"
        )),
        Err(Error::CurrentTargetsChanged)
    );
    assert_eq!(
        s.ciphertext(PeerId(1), ObjectId(2)),
        Err(Error::MissingReplica)
    );
}

#[test]
fn complete_bundle_staging_limit_and_absent_member_fail_without_partial_writes() {
    let image = sealed(11);
    let mut s = ReplicaStore::new(Bounds {
        max_staged_bytes: image.encoded_len() * 2 - 1,
        ..Bounds::default()
    })
    .unwrap();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    seed(&mut s, 1, 1, &image);
    seed(&mut s, 1, 2, &image);
    let targets = [target(1, &image, 2, Some(6)), target(2, &image, 2, Some(6))];
    assert!(matches!(s.plan_repair(&targets), Err(Error::ResourceLimit)));
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 2, Some(6)), target(3, &image, 2, Some(6))]),
        Err(Error::NoAvailableSource(ObjectId(3)))
    ));
    assert_eq!(s.usage(PeerId(2)).unwrap().charged_bytes, 0);
}

#[test]
fn bundle_placement_is_deterministic_for_equivalent_reordered_target_lists() {
    let image = sealed(12);
    let mut s = store();
    peer(&mut s, 2, 2, 4096);
    peer(&mut s, 1, 1, 4096);
    for object in 1..=3 {
        seed(&mut s, 1, object, &image);
    }
    let targets = [
        target(1, &image, 2, Some(9)),
        target(2, &image, 2, None),
        target(3, &image, 2, Some(9)),
    ];
    let reverse = targets.iter().rev().cloned().collect::<Vec<_>>();
    assert_eq!(
        s.plan_repair(&targets).unwrap().copies(),
        s.plan_repair(&reverse).unwrap().copies()
    );
}
