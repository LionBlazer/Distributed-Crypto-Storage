//! Public, non-secret synthetic payloads; all owner keys are ephemeral fixture keys.
use compact_store::{EncryptedSnapshot, Layout, Limits, Owner};
use replica_store::*;

fn sealed(value: u8) -> EncryptedSnapshot {
    Owner::generate(*b"public-replica01")
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
fn target(object: u64, image: &EncryptedSnapshot, copies: usize) -> ReplicaTarget {
    ReplicaTarget {
        object: ObjectId(object),
        expected: image.commitment().clone(),
        copies,
    }
}
fn store() -> ReplicaStore {
    ReplicaStore::new(Bounds::default()).unwrap()
}

#[test]
fn disappearing_peer_is_repaired_from_actual_survivor_ciphertext() {
    let image = sealed(7);
    let bytes = image.encode();
    let mut s = store();
    for id in 1..=3 {
        peer(&mut s, id, id, 4096);
    }
    for id in 1..=2 {
        s.seed(PeerId(id), ObjectId(1), image.commitment(), &bytes)
            .unwrap();
    }
    s.set_available(PeerId(1), false).unwrap();
    let targets = [target(1, &image, 2)];

    let report = s
        .repair_local(s.plan_repair(&targets).unwrap(), &targets)
        .unwrap();

    assert_eq!(
        report.copied,
        vec![CompletedCopy {
            object: ObjectId(1),
            source: PeerId(2),
            destination: PeerId(3),
            canonical_bytes: bytes.len()
        }]
    );
    assert_eq!(s.ciphertext(PeerId(3), ObjectId(1)).unwrap(), bytes);
    assert_eq!(
        s.ciphertext(PeerId(1), ObjectId(1)),
        Err(Error::Unavailable)
    );
    assert_eq!(
        s.usage(PeerId(1)).unwrap().charged_bytes,
        bytes.len() + RECORD_METADATA_BYTES
    );
}

#[test]
fn two_peer_labels_in_one_failure_domain_do_not_satisfy_two_independent_domains() {
    let image = sealed(8);
    let bytes = image.encode();
    let mut s = store();
    peer(&mut s, 1, 10, 4096);
    peer(&mut s, 2, 10, 4096);
    for id in 1..=2 {
        s.seed(PeerId(id), ObjectId(1), image.commitment(), &bytes)
            .unwrap();
    }

    assert!(matches!(
        s.plan_repair(&[target(1, &image, 2)]),
        Err(Error::InsufficientDomainsOrCapacity)
    ));

    assert_eq!(s.ciphertext(PeerId(1), ObjectId(1)).unwrap(), bytes);
    assert_eq!(s.ciphertext(PeerId(2), ObjectId(1)).unwrap(), bytes);
    // Domain labels are placement inputs. These assertions do not attest real operators.
}

#[test]
fn quota_charges_full_canonical_crypto_metadata_and_record_identity() {
    let image = sealed(9);
    let bytes = image.encode();
    let mut s = store();
    peer(&mut s, 1, 1, bytes.len()); // Full image alone still excludes record identity.
    assert_eq!(
        s.seed(PeerId(1), ObjectId(1), image.commitment(), &bytes),
        Err(Error::Quota)
    );
    assert_eq!(s.usage(PeerId(1)).unwrap().charged_bytes, 0);
    s.set_quota(PeerId(1), bytes.len() + RECORD_METADATA_BYTES)
        .unwrap();
    s.seed(PeerId(1), ObjectId(1), image.commitment(), &bytes)
        .unwrap();
    let usage = s.usage(PeerId(1)).unwrap();
    assert_eq!(
        (
            usage.canonical_bytes,
            usage.record_metadata_bytes,
            usage.charged_bytes
        ),
        (bytes.len(), 8, bytes.len() + 8)
    );
    assert!(usage.canonical_bytes > 64); // Payload is only64B; manifest/nonces/tags count.
    assert_eq!(
        s.set_quota(PeerId(1), usage.charged_bytes - 1),
        Err(Error::Quota)
    );
    assert_eq!(s.usage(PeerId(1)).unwrap(), usage);
}

#[test]
fn whole_batch_reserves_capacity_before_any_destination_changes() {
    let image = sealed(10);
    let bytes = image.encode();
    let charge = bytes.len() + 8;
    let mut s = store();
    peer(&mut s, 1, 1, charge * 2);
    peer(&mut s, 2, 2, charge * 2 - 1);
    for object in 1..=2 {
        s.seed(PeerId(1), ObjectId(object), image.commitment(), &bytes)
            .unwrap();
    }
    let before = s.usage(PeerId(2)).unwrap();
    assert!(matches!(
        s.plan_repair(&[target(2, &image, 2), target(1, &image, 2)]),
        Err(Error::InsufficientDomainsOrCapacity)
    ));
    assert_eq!(s.usage(PeerId(2)).unwrap(), before);
    for object in 1..=2 {
        assert_eq!(
            s.ciphertext(PeerId(2), ObjectId(object)),
            Err(Error::MissingReplica)
        );
    }
}

#[test]
fn all_sources_offline_reports_loss_without_deleting_their_charged_ciphertext() {
    let image = sealed(11);
    let bytes = image.encode();
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    s.seed(PeerId(1), ObjectId(1), image.commitment(), &bytes)
        .unwrap();
    s.set_available(PeerId(1), false).unwrap();
    let before = s.usage(PeerId(1)).unwrap();
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 2)]),
        Err(Error::NoAvailableSource(ObjectId(1)))
    ));
    assert_eq!(s.usage(PeerId(1)).unwrap(), before);
}

#[test]
fn wrong_head_tamper_and_truncation_never_install_a_replica() {
    let image = sealed(12);
    let bytes = image.encode();
    let other = sealed(13);
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    assert!(
        s.seed(PeerId(1), ObjectId(1), other.commitment(), &bytes)
            .is_err()
    );
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        s.seed(PeerId(1), ObjectId(1), image.commitment(), &corrupt)
            .is_err()
    );
    assert!(
        s.seed(
            PeerId(1),
            ObjectId(1),
            image.commitment(),
            &bytes[..bytes.len() - 1]
        )
        .is_err()
    );
    assert_eq!(s.usage(PeerId(1)).unwrap().charged_bytes, 0);
    assert_eq!(
        s.ciphertext(PeerId(1), ObjectId(1)),
        Err(Error::MissingReplica)
    );
}

#[test]
fn short_corrupt_and_stale_transport_sources_are_skipped_before_destination_publication() {
    let current = sealed(14);
    let bytes = current.encode();
    let stale = sealed(15).encode();
    let mut s = store();
    for id in 1..=4 {
        peer(&mut s, id, 1, 4096);
        s.seed(PeerId(id), ObjectId(1), current.commitment(), &bytes)
            .unwrap();
    }
    peer(&mut s, 5, 2, 4096);
    let targets = [target(1, &current, 2)];
    let plan = s.plan_repair(&targets).unwrap();
    let report = s
        .repair_with(plan, &targets, |id, _, out| {
            if id == PeerId(1) {
                let n = out.len() - 1;
                out[..n].copy_from_slice(&bytes[..n]);
                return Ok(n);
            }
            out.copy_from_slice(if id == PeerId(3) { &stale } else { &bytes });
            if id == PeerId(2) {
                *out.last_mut().unwrap() ^= 1;
            }
            Ok(out.len())
        })
        .unwrap();
    assert_eq!(report.copied[0].source, PeerId(4));
    assert_eq!(
        report
            .rejected_sources
            .iter()
            .map(|r| r.peer)
            .collect::<Vec<_>>(),
        [PeerId(1), PeerId(2), PeerId(3)]
    );
    assert_eq!(s.ciphertext(PeerId(5), ObjectId(1)).unwrap(), bytes);
}

#[test]
fn later_object_transport_failure_aborts_an_already_staged_first_copy() {
    let image = sealed(16);
    let bytes = image.encode();
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    for object in 1..=2 {
        s.seed(PeerId(1), ObjectId(object), image.commitment(), &bytes)
            .unwrap();
    }
    let targets = [target(1, &image, 2), target(2, &image, 2)];
    let plan = s.plan_repair(&targets).unwrap();
    let before = s.usage(PeerId(2)).unwrap();
    assert_eq!(
        s.repair_with(plan, &targets, |_, object, out| {
            if object == ObjectId(2) {
                return Err(Error::Transport);
            }
            out.copy_from_slice(&bytes);
            Ok(out.len())
        }),
        Err(Error::NoAvailableSource(ObjectId(2)))
    );
    assert_eq!(s.usage(PeerId(2)).unwrap(), before);
    for object in 1..=2 {
        assert_eq!(
            s.ciphertext(PeerId(2), ObjectId(object)),
            Err(Error::MissingReplica)
        );
        assert_eq!(s.ciphertext(PeerId(1), ObjectId(object)).unwrap(), bytes);
    }
}

#[test]
fn changed_current_head_or_inventory_rejects_a_plan_without_fetch_or_writes() {
    let image = sealed(17);
    let bytes = image.encode();
    let other = sealed(18);
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    s.seed(PeerId(1), ObjectId(1), image.commitment(), &bytes)
        .unwrap();
    let targets = [target(1, &image, 2)];
    let plan = s.plan_repair(&targets).unwrap();
    assert_eq!(
        s.repair_with(plan, &[target(1, &other, 2)], |_, _, _| panic!(
            "must reject before transport"
        )),
        Err(Error::CurrentTargetsChanged)
    );
    let plan = s.plan_repair(&targets).unwrap();
    s.set_available(PeerId(2), false).unwrap();
    let before = s.usage(PeerId(2)).unwrap();
    assert_eq!(
        s.repair_with(plan, &targets, |_, _, _| panic!("stale plan transport")),
        Err(Error::StalePlan)
    );
    assert_eq!(s.usage(PeerId(2)).unwrap(), before);
}

#[test]
fn foreign_store_equal_generation_and_heads_cannot_replay_placement_or_bypass_quota() {
    let image = sealed(19);
    let bytes = image.encode();
    let targets = [target(1, &image, 2)];
    let mut a = store();
    let mut b = store();
    peer(&mut a, 1, 1, 4096);
    peer(&mut a, 2, 2, 4096);
    peer(&mut b, 1, 1, 4096);
    peer(&mut b, 99, 2, 0);
    for s in [&mut a, &mut b] {
        s.seed(PeerId(1), ObjectId(1), image.commitment(), &bytes)
            .unwrap();
    }
    let plan = a.plan_repair(&targets).unwrap();
    let before = b.usage(PeerId(99)).unwrap();
    assert_eq!(
        b.repair_with(plan, &targets, |_, _, _| panic!(
            "foreign plan must not fetch"
        )),
        Err(Error::StalePlan)
    );
    assert_eq!(b.usage(PeerId(99)).unwrap(), before);
    assert_eq!(b.ciphertext(PeerId(1), ObjectId(1)).unwrap(), bytes);
    assert_eq!(
        b.ciphertext(PeerId(99), ObjectId(1)),
        Err(Error::MissingReplica)
    );
}

#[test]
fn stale_local_version_is_repaired_but_last_available_current_copy_cannot_be_removed() {
    let old = sealed(20);
    let current = sealed(21);
    let bytes = current.encode();
    let mut s = store();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    s.seed(PeerId(1), ObjectId(1), old.commitment(), &old.encode())
        .unwrap();
    s.seed(PeerId(2), ObjectId(1), current.commitment(), &bytes)
        .unwrap();
    assert_eq!(
        s.remove_current(PeerId(2), ObjectId(1), current.commitment()),
        Err(Error::LastAvailableReplica)
    );
    let targets = [target(1, &current, 2)];
    let report = s
        .repair_local(s.plan_repair(&targets).unwrap(), &targets)
        .unwrap();
    assert_eq!(
        (report.copied[0].source, report.copied[0].destination),
        (PeerId(2), PeerId(1))
    );
    s.remove_current(PeerId(2), ObjectId(1), current.commitment())
        .unwrap();
    assert_eq!(
        s.remove_current(PeerId(1), ObjectId(1), current.commitment()),
        Err(Error::LastAvailableReplica)
    );
    assert_eq!(s.ciphertext(PeerId(1), ObjectId(1)).unwrap(), bytes);
}

#[test]
fn target_and_staging_limits_fail_before_any_replica_mutates() {
    let image = sealed(22);
    let bytes = image.encode();
    let mut s = ReplicaStore::new(Bounds {
        max_objects: 1,
        max_peers: 2,
        max_staged_bytes: bytes.len() - 1,
        ..Bounds::default()
    })
    .unwrap();
    peer(&mut s, 1, 1, 4096);
    peer(&mut s, 2, 2, 4096);
    s.seed(PeerId(1), ObjectId(1), image.commitment(), &bytes)
        .unwrap();
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 3)]),
        Err(Error::InvalidTargets)
    ));
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 2), target(2, &image, 2)]),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        s.plan_repair(&[target(1, &image, 2)]),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(s.usage(PeerId(2)).unwrap().charged_bytes, 0);
    assert_eq!(
        s.seed(PeerId(2), ObjectId(2), image.commitment(), &bytes),
        Err(Error::ResourceLimit)
    );
}
