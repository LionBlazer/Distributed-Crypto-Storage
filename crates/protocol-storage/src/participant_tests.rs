//! PUBLIC NON-SECRET bytes and actual owned files. These exercise storage
//! ownership/accounting, not cryptographic proof, consensus or SQL permission.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

const NAMESPACE: [u8; 32] = [71; 32];
struct Workspace {
    base: PathBuf,
    root: PathBuf,
}
impl Workspace {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let base = parent.join(format!(
                "dcs-public-participant-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&base) {
                Ok(()) => {
                    let base = base.canonicalize().unwrap();
                    return Self {
                        root: base.join("participant"),
                        base,
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("owned participant directory: {error}"),
            }
        }
        panic!("bounded owned-directory attempts exhausted")
    }
    fn create(&self, limit: u64) -> ParticipantQuota {
        ParticipantQuota::create_new(&self.root, NAMESPACE, limit).unwrap()
    }
    fn reopen(&self, limit: u64) -> ParticipantQuota {
        ParticipantQuota::open_existing(&self.root, NAMESPACE, limit).unwrap()
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        // Only fixed newly owned directories, with no recursive deletion or
        // symlink traversal. Tests remove any deliberately created subdirectory.
        for directory in [
            self.root.join("control"),
            self.root.join("depot"),
            self.root.join("custody"),
            self.root.clone(),
            self.base.clone(),
        ] {
            if fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.file_type().is_dir())
                && directory.canonicalize().ok().as_ref() == Some(&directory)
            {
                if let Ok(entries) = fs::read_dir(&directory) {
                    for entry in entries.take(MAX_TRACKED_FILES + 2).flatten() {
                        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
                let _ = fs::remove_dir(&directory);
            }
        }
    }
}
fn create_file(path: &Path, bytes: &[u8]) {
    let mut file = File::create_new(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn control_file(quota: &ParticipantQuota, id: u8, kind: ControlFile, bytes: &[u8]) -> PathBuf {
    let path = quota.control_file([id; 32], kind);
    let budget = quota.control_budget();
    let mut permit = budget.preflight_file(&path, bytes.len() as u64).unwrap();
    create_file(permit.path(), bytes);
    permit.register_file().unwrap();
    path
}
fn custody_file(quota: &ParticipantQuota, id: u8, kind: CustodyFile, bytes: &[u8]) -> PathBuf {
    let path = quota.custody_file([id; 32], kind);
    let budget = quota.custody_budget();
    let mut permit = budget.preflight_file(&path, bytes.len() as u64).unwrap();
    create_file(permit.path(), bytes);
    permit.register_file().unwrap();
    path
}
fn identity(bytes: &[u8]) -> BlobId {
    BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap()
}
fn limits() -> StoreLimits {
    StoreLimits::new(1024, 8).unwrap()
}
fn blob_path(directory: &Path, id: BlobId) -> PathBuf {
    let digest: String = id
        .sha256()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    directory.join(format!("{digest}-{:016x}.blob", id.bytes()))
}
fn stage_path(directory: &Path, id: BlobId) -> PathBuf {
    let blob = blob_path(directory, id);
    directory.join(format!(
        "{}-0000000000000007.part",
        blob.file_stem().unwrap().to_str().unwrap()
    ))
}
fn actual_file_bytes(root: &Path) -> u64 {
    [
        root.to_owned(),
        root.join("control"),
        root.join("depot"),
        root.join("custody"),
    ]
    .into_iter()
    .flat_map(|directory| {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>()
    })
    .map(|path| fs::symlink_metadata(path).unwrap())
    .filter(|metadata| metadata.file_type().is_file())
    .map(|metadata| metadata.len())
    .sum()
}

#[test]
fn participant_clones_and_concurrent_reservations_share_one_global_allowance() {
    let owned = Workspace::new();
    let quota = owned.create(536);
    let baseline = quota.usage().unwrap().total_bytes();
    assert_eq!(baseline, actual_file_bytes(&owned.root));
    let allowance = 536 - baseline;
    assert_eq!(allowance, 400);
    let budget = quota.depot_budget();
    let control = quota.control_budget();
    let custody = quota.custody_budget();
    let start = Arc::new(Barrier::new(9));
    let ready = Arc::new(Barrier::new(9));
    let release = Arc::new(Barrier::new(9));
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for ordinal in 0..8 {
            let budget = budget.clone();
            let control = control.clone();
            let custody = custody.clone();
            let start = start.clone();
            let ready = ready.clone();
            let release = release.clone();
            workers.push(scope.spawn(move || {
                start.wait();
                let lease = match ordinal % 3 {
                    0 => budget.reserve(100),
                    1 => control.reserve(100),
                    _ => custody.reserve(100),
                };
                ready.wait();
                release.wait();
                lease.is_ok()
            }));
        }
        start.wait();
        ready.wait();
        assert_eq!(quota.usage().unwrap().total_bytes(), 536);
        assert!(matches!(
            quota.control_budget().reserve(1),
            Err(Error::ResourceLimit)
        ));
        assert!(matches!(
            quota.custody_budget().reserve(1),
            Err(Error::ResourceLimit)
        ));
        release.wait();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|success| *success)
                .count(),
            4
        );
    });
    assert_eq!(quota.usage().unwrap().total_bytes(), baseline);
}

#[test]
fn control_cap_is_shared_and_independent_of_larger_depot_and_local_capacity() {
    assert!(matches!(
        ByteBudget::new(MAX_SHARED_BYTES + 1),
        Err(Error::InvalidConfig)
    ));
    for limit in [10_000_000_000, 20_000_000_000, 30_000_000_000] {
        let owned = Workspace::new();
        let quota = owned.create(limit);
        let control = quota.control_budget();
        let baseline = control.used().unwrap();
        // Scalar leases, not allocated payloads or sparse gigabyte files.
        let depot = quota.depot_budget().reserve(MAX_SHARED_BYTES + 1).unwrap();
        let full_control = control.reserve(MAX_SHARED_BYTES - baseline).unwrap();
        assert_eq!(control.used().unwrap(), MAX_SHARED_BYTES);
        assert!(matches!(
            control.clone().reserve(1),
            Err(Error::ResourceLimit)
        ));
        let remaining = limit - quota.usage().unwrap().total_bytes();
        let custody = quota.custody_budget().reserve(remaining).unwrap();
        assert!(matches!(
            quota.depot_budget().reserve(1),
            Err(Error::ResourceLimit)
        ));
        assert_eq!(quota.usage().unwrap().total_bytes(), limit);
        drop(custody);
        drop(full_control);
        drop(depot);
        assert_eq!(quota.usage().unwrap().total_bytes(), baseline);
        drop(control);
        drop(quota);
        assert_eq!(owned.reopen(limit).usage().unwrap().total_bytes(), baseline);
    }
    let owned = Workspace::new();
    assert!(matches!(
        ParticipantQuota::create_new(&owned.root, NAMESPACE, MAX_PARTICIPANT_BYTES + 1),
        Err(Error::InvalidConfig)
    ));
    assert!(!owned.root.exists());
}

#[test]
fn scoped_paths_and_existing_files_are_checked_before_any_creation_or_open() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let budget = quota.control_budget();
    let baseline = quota.usage().unwrap();
    let wrong_class = quota.custody_file([1; 32], CustodyFile::Metadata);
    let outside = owned.base.join(format!("{}.wal", "01".repeat(32)));
    let wrong_name = owned.root.join("control").join("legacy.wal");
    for path in [&wrong_class, &outside, &wrong_name] {
        assert!(budget.preflight_file(path, 4).is_err());
        assert!(!path.exists());
        assert!(budget.check_existing_file(path).is_err());
    }
    assert_eq!(quota.usage().unwrap(), baseline);
    let path = control_file(&quota, 2, ControlFile::Wal, b"WAL1");
    let original_header = fs::read(owned.root.join("participant-v1.profile")).unwrap();
    assert!(ParticipantQuota::create_new(&owned.root, NAMESPACE, 1024).is_err());
    assert_eq!(
        fs::read(owned.root.join("participant-v1.profile")).unwrap(),
        original_header
    );
    assert!(
        matches!(budget.preflight_file(&path,4),Err(Error::Io(error)) if error.kind()==std::io::ErrorKind::AlreadyExists)
    );
    // An ordinary AlreadyExists refusal neither installs a pending slot nor poisons.
    drop(budget.reserve(1).unwrap());
    budget.check_existing_file(&path).unwrap();
    let untracked = quota.control_file([3; 32], ControlFile::Floor);
    create_file(&untracked, b"UNPERMITTED");
    assert!(matches!(
        budget.register_file(&untracked),
        Err(Error::CorruptFile)
    ));
    assert!(matches!(
        budget.check_existing_file(&untracked),
        Err(Error::Poisoned)
    ));
    fs::remove_file(&untracked).unwrap();
    assert!(matches!(
        EvidenceStore::open(quota.depot_directory(), budget.clone(), limits()),
        Err(Error::InvalidConfig)
    ));
}

#[test]
fn pending_file_permit_precharges_extent_and_promotes_without_double_charge() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let budget = quota.control_budget();
    let baseline = quota.usage().unwrap();
    let path = quota.control_file([4; 32], ControlFile::Journal);
    let mut permit = budget.preflight_file(&path, 8).unwrap();
    assert!(!path.exists());
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        baseline.total_bytes() + 8
    );
    assert_eq!(
        quota.usage().unwrap().tracked_files(),
        baseline.tracked_files() + 1
    );
    assert!(budget.preflight_file(&path, 8).is_err());
    create_file(permit.path(), b"JOURNAL1");
    let mut charge = permit.register_file().unwrap();
    drop(permit);
    assert_eq!(charge.bytes().unwrap(), 8);
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        baseline.total_bytes() + 8
    );
    charge.grow(12).unwrap(); // charge BEFORE append
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"WAL1").unwrap();
    file.sync_all().unwrap();
    drop(file);
    drop(charge);
    assert_eq!(budget.register_file(&path).unwrap().bytes().unwrap(), 12);
    let absent = quota.control_file([5; 32], ControlFile::Metadata);
    drop(budget.preflight_file(&absent, 7).unwrap());
    assert!(!absent.exists());
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        baseline.total_bytes() + 12
    );
}

#[test]
fn surviving_partial_creation_or_uncertain_sync_keeps_charge_and_poison_until_restart() {
    for promoted in [false, true] {
        let owned = Workspace::new();
        let quota = owned.create(1024);
        let budget = quota.control_budget();
        let baseline = quota.usage().unwrap().total_bytes();
        let path = quota.control_file([6; 32], ControlFile::Wal);
        let mut permit = budget.preflight_file(&path, 16).unwrap();
        create_file(permit.path(), b"PARTIAL");
        if promoted {
            let charge = permit.register_file().unwrap();
            // PUBLIC interruption at a write/sync return boundary; actual bytes
            // survived and no rollback/removal result is available to the owner.
            charge.mark_io_failed();
        }
        drop(permit);
        assert_eq!(quota.usage().unwrap().total_bytes(), baseline + 16);
        assert_eq!(fs::read(&path).unwrap(), b"PARTIAL");
        assert!(matches!(budget.reserve(0), Err(Error::Poisoned)));
        drop(quota);
        assert!(matches!(
            ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024),
            Err(Error::Io(_))
        ));
        drop(budget);
        let reopened = owned.reopen(1024);
        assert_eq!(reopened.usage().unwrap().total_bytes(), baseline + 7);
        drop(reopened.control_budget().reserve(1).unwrap());
    }
}

#[test]
fn zero_extent_permit_transfers_an_exact_lease_and_preserves_failed_lease_ownership() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let budget = quota.control_budget();
    let baseline = quota.usage().unwrap().total_bytes();
    let path = quota.control_file([7; 32], ControlFile::Journal);
    let mut initial = budget.reserve(8).unwrap();
    let permit = budget.preflight_file(&path, 0).unwrap();
    create_file(permit.path(), b"PARTIAL");
    assert!(matches!(
        initial.retain_file(&path),
        Err(Error::CorruptFile)
    ));
    assert_eq!(initial.bytes(), 8);
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"!").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let charge = initial.retain_file(&path).unwrap();
    assert_eq!(initial.bytes(), 0);
    drop(permit);
    drop(initial);
    assert_eq!(charge.bytes().unwrap(), 8);
    assert_eq!(quota.usage().unwrap().total_bytes(), baseline + 8);
    drop(budget.reserve(1).unwrap()); // successful promotion did not poison
    let second = quota.control_file([8; 32], ControlFile::Journal);
    let mut failed = budget.reserve(9).unwrap();
    let pending = budget.preflight_file(&second, 0).unwrap();
    create_file(pending.path(), b"BAD");
    assert!(failed.retain_file(&second).is_err());
    failed.retain_conservatively();
    drop(pending);
    assert_eq!(quota.usage().unwrap().total_bytes(), baseline + 8 + 9);
    assert!(matches!(budget.reserve(0), Err(Error::Poisoned)));
}

#[test]
fn every_descendant_handle_keeps_exclusive_participant_ownership_alive() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let budget = quota.depot_budget();
    let lease = budget.reserve(1).unwrap();
    drop(quota);
    drop(budget);
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024),
        Err(Error::Io(_))
    ));
    drop(lease);
    let quota = owned.reopen(1024);
    let budget = quota.control_budget();
    let path = quota.control_file([9; 32], ControlFile::Floor);
    let mut permit = budget.preflight_file(&path, 4).unwrap();
    create_file(permit.path(), b"FLOR");
    let charge = permit.register_file().unwrap();
    drop(permit);
    drop(quota);
    drop(budget);
    assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
    drop(charge);
    let quota = owned.reopen(1024);
    let path = quota.control_file([10; 32], ControlFile::Metadata);
    let permit = quota.control_budget().preflight_file(&path, 2).unwrap();
    drop(quota);
    assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
    drop(permit);
    let quota = owned.reopen(1024);
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    drop(quota);
    let id = identity(b"DATA");
    let mut stage = store.stage(id).unwrap();
    stage.write_chunk(b"DATA").unwrap();
    assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
    stage.finish().unwrap();
    let mut reader = store.reader(id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
    reader.finish().unwrap();
    assert_eq!(bytes, b"DATA");
    drop(store);
    let _reopened = owned.reopen(1024);
}

#[test]
fn restart_inventories_control_depot_and_custody_before_returning_any_handles() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let baseline = quota.usage().unwrap().total_bytes();
    let wal = control_file(&quota, 11, ControlFile::Wal, b"WAL12345");
    control_file(&quota, 12, ControlFile::Floor, b"FLO1");
    custody_file(&quota, 13, CustodyFile::Object, b"OBJECT123");
    custody_file(&quota, 14, CustodyFile::Metadata, b"META1");
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let id = identity(b"PUBLIC");
    let mut stage = store.stage(id).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.finish().unwrap();
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        actual_file_bytes(&owned.root)
    );
    drop(store);
    drop(quota);
    let quota = owned.reopen(1024);
    let usage = quota.usage().unwrap();
    assert_eq!(usage.control_bytes(), baseline + 12);
    assert_eq!(usage.depot_bytes(), 6);
    assert_eq!(usage.custody_bytes(), 14);
    assert_eq!(usage.total_bytes(), actual_file_bytes(&owned.root));
    assert_eq!(usage.tracked_files(), 8);
    quota.control_budget().check_existing_file(&wal).unwrap();
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let mut reader = store.reader(id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    reader.finish().unwrap();
    assert_eq!(bytes, b"PUBLIC");
    assert!(EvidenceStore::open_depot(quota.depot_budget(), limits()).is_err());
}

#[test]
fn namespace_capacity_header_and_unknown_entries_fail_before_stage_cleanup() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let directory = quota.depot_directory();
    drop(quota);
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, [72; 32], 1024),
        Err(Error::Identity)
    ));
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1025),
        Err(Error::Identity)
    ));
    let header = owned.root.join("participant-v1.profile");
    let original = fs::read(&header).unwrap();
    let mut damaged = original.clone();
    damaged[8] ^= 1;
    fs::write(&header, &damaged).unwrap();
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024),
        Err(Error::Identity)
    ));
    assert_eq!(fs::read(&header).unwrap(), damaged);
    fs::write(&header, &original[..original.len() - 1]).unwrap();
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024),
        Err(Error::CorruptFile)
    ));
    fs::write(&header, &original).unwrap();
    let lock = owned.root.join("participant.lock");
    fs::write(&lock, b"NOT-EMPTY").unwrap();
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024),
        Err(Error::CorruptFile)
    ));
    fs::write(&lock, b"").unwrap();
    let id = identity(b"PUBLIC");
    let stage = stage_path(&directory, id);
    create_file(&stage, b"PUB");
    for unknown in [
        owned.root.join("extra"),
        owned.root.join("custody").join("legacy.object2"),
    ] {
        create_file(&unknown, b"UNKNOWN");
        assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"UNKNOWN");
        assert_eq!(fs::read(&stage).unwrap(), b"PUB");
        fs::remove_file(unknown).unwrap();
    }
    fs::write(&stage, b"TOO-LONG").unwrap();
    assert!(matches!(
        ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024),
        Err(Error::CorruptFile)
    ));
    assert_eq!(fs::read(&stage).unwrap(), b"TOO-LONG");
    fs::write(&stage, b"PUB").unwrap();
    let quota = owned.reopen(1024);
    assert!(!stage.exists());
    drop(quota);
    let child = owned.root.join("control").join("nested");
    fs::create_dir(&child).unwrap();
    assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
    fs::remove_dir(child).unwrap();
}

#[test]
fn exact_quota_recovers_real_two_hardlink_names_before_retained_blob_accounting() {
    let owned = Workspace::new();
    let quota = owned.create(142);
    let directory = quota.depot_directory();
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let id = identity(b"PUBLIC");
    let mut stage = store.stage(id).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.finish().unwrap();
    drop(store);
    drop(quota);
    let blob = blob_path(&directory, id);
    let stage = stage_path(&directory, id);
    fs::hard_link(&blob, &stage).unwrap(); // actual surviving alias, no StagedBlob Drop
    let quota = owned.reopen(142);
    assert!(!stage.exists());
    assert_eq!(quota.usage().unwrap().total_bytes(), 142);
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    assert!(matches!(store.stage(id), Err(Error::ResourceLimit)));
    assert!(!stage.exists());
    assert_eq!(fs::read(blob).unwrap(), b"PUBLIC");
    let mut reader = store.reader(id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    reader.finish().unwrap();
    assert_eq!(bytes, b"PUBLIC");
}

#[test]
fn participant_lost_ack_retry_and_quota_refusal_preserve_original_immutable_bytes() {
    let owned = Workspace::new();
    let quota = owned.create(148);
    let id = identity(b"PUBLIC");
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let mut stage = store.stage(id).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.fail_after_link_for_test();
    assert!(matches!(stage.finish(), Err(Error::Io(_))));
    assert_eq!(quota.usage().unwrap().total_bytes(), 142);
    let mut retry = store.stage(id).unwrap();
    retry.write_chunk(b"PUBLIC").unwrap();
    assert_eq!(retry.finish().unwrap(), id);
    assert_eq!(quota.usage().unwrap().total_bytes(), 142);
    assert!(matches!(
        store.stage(identity(b"TOO-LONG")),
        Err(Error::ResourceLimit)
    ));
    let path = blob_path(&quota.depot_directory(), id);
    assert_eq!(fs::read(&path).unwrap(), b"PUBLIC");
    drop(store);
    drop(quota);
    let quota = owned.reopen(148);
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let mut reader = store.reader(id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    reader.finish().unwrap();
    assert_eq!(bytes, b"PUBLIC");
    drop(store);
    drop(quota);
    fs::remove_file(path).unwrap();
    let quota = owned.reopen(148);
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    assert!(matches!(store.reader(id), Err(Error::Io(_)))); // no availability/verified receipt persisted
}

#[test]
fn successful_stage_cleanup_does_not_unpoison_an_uncertain_scoped_sync() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let baseline = quota.usage().unwrap().total_bytes();
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let mut stage = store.stage(identity(b"PUBLIC")).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.fail_sync_for_test();
    assert!(matches!(stage.finish(), Err(Error::Io(_))));
    assert_eq!(quota.usage().unwrap().total_bytes(), baseline);
    assert!(matches!(
        quota.depot_budget().reserve(0),
        Err(Error::Poisoned)
    ));
    drop(store);
    drop(quota);
    let quota = owned.reopen(1024);
    drop(quota.depot_budget().reserve(1).unwrap());
}

#[test]
fn shared_poison_blocks_an_already_staged_writer_before_more_payload_io() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let baseline = quota.usage().unwrap().total_bytes();
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let mut stage = store.stage(identity(b"PUBLIC")).unwrap();
    quota
        .control_budget()
        .reserve(1)
        .unwrap()
        .retain_conservatively();
    assert!(matches!(stage.write_chunk(b"PUBLIC"), Err(Error::Poisoned)));
    assert!(matches!(stage.finish(), Err(Error::Poisoned)));
    assert_eq!(quota.usage().unwrap().total_bytes(), baseline + 1); // stage was actually removed
    assert_eq!(fs::read_dir(quota.depot_directory()).unwrap().count(), 1); // lock only
}

#[test]
fn unexpected_retained_file_changes_poison_the_shared_inventory_before_opening() {
    for missing in [false, true] {
        let owned = Workspace::new();
        let quota = owned.create(1024);
        let path = control_file(&quota, 16, ControlFile::Journal, b"JOURNAL1");
        // Actual local-file corruption/loss, not an invalid remote DTO.
        if missing {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, b"DIFFERENT-LENGTH").unwrap();
        }
        assert!(quota.control_budget().check_existing_file(&path).is_err());
        assert!(matches!(
            quota.depot_budget().reserve(0),
            Err(Error::Poisoned)
        ));
    }
}

#[test]
fn global_file_slots_include_pending_files_and_recover_the_one_publication_alias() {
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let directory = quota.depot_directory();
    let mut store = EvidenceStore::open_depot(quota.depot_budget(), limits()).unwrap();
    let budget = quota.control_budget();
    for number in 0..MAX_TRACKED_FILES - 4 {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(number as u64).to_le_bytes());
        let path = quota.control_file(id, ControlFile::Metadata);
        let mut permit = budget.preflight_file(&path, 0).unwrap();
        drop(File::create_new(permit.path()).unwrap());
        permit.register_file().unwrap();
    }
    assert_eq!(
        quota.usage().unwrap().tracked_files(),
        MAX_TRACKED_FILES - 1
    );
    let id = identity(b"P");
    let mut stage = store.stage(id).unwrap();
    assert!(matches!(
        budget.preflight_file(quota.control_file([255; 32], ControlFile::Wal), 0),
        Err(Error::ResourceLimit)
    ));
    stage.write_chunk(b"P").unwrap();
    stage.finish().unwrap();
    drop(store);
    drop(budget);
    drop(quota);
    let blob = blob_path(&directory, id);
    let stage = stage_path(&directory, id);
    fs::hard_link(&blob, &stage).unwrap();
    let quota = owned.reopen(1024);
    assert!(!stage.exists());
    assert_eq!(quota.usage().unwrap().tracked_files(), MAX_TRACKED_FILES);
    assert!(matches!(
        quota
            .custody_budget()
            .preflight_file(quota.custody_file([255; 32], CustodyFile::Metadata), 0),
        Err(Error::ResourceLimit)
    ));
}

#[cfg(unix)]
#[test]
fn symlinked_class_file_and_directory_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;
    let owned = Workspace::new();
    let quota = owned.create(1024);
    let path = quota.control_file([15; 32], ControlFile::Wal);
    let external = owned.base.join("external");
    create_file(&external, b"PUBLIC");
    symlink(&external, &path).unwrap();
    assert!(quota.control_budget().check_existing_file(&path).is_err());
    assert!(quota.control_budget().preflight_file(&path, 6).is_err());
    assert_eq!(fs::read(&external).unwrap(), b"PUBLIC");
    fs::remove_file(&path).unwrap();
    drop(quota);
    fs::remove_dir(owned.root.join("custody")).unwrap();
    symlink(&owned.base, owned.root.join("custody")).unwrap();
    assert!(ParticipantQuota::open_existing(&owned.root, NAMESPACE, 1024).is_err());
    fs::remove_file(owned.root.join("custody")).unwrap();
}
