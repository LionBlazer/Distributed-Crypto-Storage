//! Genuine input16/Source/Life/Link, no output118 or network-QC claim.
use super::*;
use crate::private_predicate::source::locking::joint::vault::durable::acquire::live;

#[test]
fn dropping_original_live_banks_preserves_fsynced_compute_and_requires_exact_full_restore() {
    let (mut rig, mut vault) = begun();
    let material = rig.backups.as_ref().unwrap().material();
    let before = vault.cursor().unwrap();
    let live::Preparation::Prepared(work, original) = vault
        .prepare_acquire_original(before, rig.fetched(), &material, SQL, 1, 1)
        .unwrap()
    else {
        panic!("Actual uncontended Acquire must prepare its original input16")
    };
    let cursor = vault.cursor().unwrap();
    let invocation = work.invocation_id();
    let request = work.encrypted_request().to_vec();
    let key33 = work.provenance().encodings()[0]
        .expected
        .bfv()
        .key()
        .public_values();

    // Actual Source/query/Lifecycle/Link verification, not an AEAD or hash flag.
    original.require_work(&vault, &work).unwrap();
    assert_eq!(vault.cursor().unwrap(), cursor);
    assert_eq!(
        vault.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    assert_eq!(cursor.generation(), before.generation());
    assert_ne!(cursor.digest(), before.digest());
    assert!(vault.acquire_draft(cursor).is_err());
    assert!(vault.submission(cursor).is_err());
    let ingress = vault.evidence_ingress().unwrap();
    // Explicitly unproved public garbage: no fake checked product is created.
    let malformed = ingress.retain_public_blob(&[0x19; 256]).unwrap();
    let malformed = bfv_product_evidence::CatalogId::from_blob(malformed).unwrap();
    let length = vault.wal.length;
    let used = rig.quota().usage().unwrap().total_bytes();
    assert!(
        live::require_inventory(&vault, vault.saved.acquire.as_ref().unwrap(), malformed).is_err()
    );
    assert_eq!(vault.cursor().unwrap(), cursor);
    assert_eq!(vault.wal.length, length);
    assert_eq!(rig.quota().usage().unwrap().total_bytes(), used);
    drop(ingress);

    // Losing this exclusive live call leaves the synced original Compute intact.
    // No checked stream/catalog/completion is fabricated for this owning test.
    drop(original);
    drop(work);
    drop(vault);
    rig.fresh_quota();
    let vault = open_acquire(&rig).unwrap();
    assert_eq!(vault.cursor().unwrap(), cursor);
    let work = vault
        .acquire_work(
            cursor,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
        )
        .unwrap();
    assert_eq!(work.invocation_id(), invocation);
    assert_eq!(work.encrypted_request(), request);
    assert_eq!(
        work.provenance().encodings()[0]
            .expected
            .bfv()
            .key()
            .public_values(),
        key33
    );
    assert_eq!(
        vault.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    assert!(vault.acquire_draft(cursor).is_err());
    let length = vault.wal.length;
    let used = rig.quota().usage().unwrap().total_bytes();
    assert!(matches!(
        vault.acquire_work(
            before,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material()
        ),
        Err(OwnerVaultError::Cas)
    ));
    assert_eq!(vault.cursor().unwrap(), cursor);
    assert_eq!(vault.wal.length, length);
    assert_eq!(rig.quota().usage().unwrap().total_bytes(), used);
    let wrong = super::super::super::super::JointRecoveryKey::new(Zeroizing::new([0xfe; 32]));
    let mut wrong_material = rig.backups.as_ref().unwrap().material();
    wrong_material.recovery_key = &wrong;
    assert!(
        vault
            .acquire_work(cursor, rig.fetched(), &wrong_material)
            .is_err()
    );
    assert_eq!(vault.cursor().unwrap(), cursor);
    assert_eq!(vault.wal.length, length);
    assert_eq!(rig.quota().usage().unwrap().total_bytes(), used);
}
