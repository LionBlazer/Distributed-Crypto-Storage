//! PUBLIC NON-SECRET byte fixtures and real owned local files. These are storage
//! lifecycle tests, not proof verification, network finality or SQL admission.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct OwnedDirectory {
    path: PathBuf,
}
impl OwnedDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let path = parent.join(format!(
                "dcs-public-evidence-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Self {
                        path: path.canonicalize().unwrap(),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("owned test directory: {error}"),
            }
        }
        panic!("bounded owned-directory attempts exhausted")
    }
    fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
    fn evidence(&self) -> PathBuf {
        let path = self.path("evidence");
        fs::create_dir(&path).unwrap();
        path
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        // No recursive deletion or symlink traversal; only this newly created
        // test directory and its immediate evidence directory are owned here.
        for directory in [self.path("evidence"), self.path.clone()] {
            if let Ok(metadata) = fs::symlink_metadata(&directory)
                && metadata.file_type().is_dir()
                && directory.canonicalize().ok().as_ref() == Some(&directory)
            {
                if let Ok(entries) = fs::read_dir(&directory) {
                    for entry in entries.flatten() {
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
fn id(bytes: &[u8]) -> BlobId {
    BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap()
}
fn limits() -> StoreLimits {
    StoreLimits::new(1024 * 1024, 8).unwrap()
}
fn create_file(path: &Path, bytes: &[u8]) {
    let mut file = File::create_new(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn public_blob_path(directory: &Path, identity: BlobId) -> PathBuf {
    let digest: String = identity
        .sha256()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    directory.join(format!("{digest}-{:016x}.blob", identity.bytes()))
}
fn abandoned_stage_path(directory: &Path, identity: BlobId) -> PathBuf {
    let blob = public_blob_path(directory, identity);
    directory.join(format!(
        "{}-0000000000000007.part",
        blob.file_stem().unwrap().to_str().unwrap()
    ))
}

#[test]
fn actual_file_growth_is_precharged_and_reopen_does_not_forget_or_double_charge() {
    let owned = OwnedDirectory::new();
    let path = owned.path("journal");
    let budget = ByteBudget::new(16).unwrap();
    let mut initial = budget.reserve(8).unwrap();
    create_file(&path, b"PUBLIC01");
    let mut charge = initial.retain_file(&path).unwrap();
    assert_eq!(initial.bytes(), 0);
    assert_eq!(budget.used().unwrap(), 8);
    charge.grow(12).unwrap();
    assert_eq!(budget.used().unwrap(), 12); // BEFORE the actual append
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"WAL1").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(charge.grow(17), Err(Error::ResourceLimit)));
    assert_eq!(fs::metadata(&path).unwrap().len(), 12);
    drop(charge);
    drop(initial);
    assert_eq!(budget.used().unwrap(), 12);
    let reopened = budget.register_file(&path).unwrap();
    assert_eq!(reopened.bytes().unwrap(), 12);
    assert_eq!(budget.used().unwrap(), 12);
    let restarted = ByteBudget::new(16).unwrap();
    restarted.register_file(&path).unwrap();
    assert_eq!(restarted.used().unwrap(), 12);
}

#[test]
fn failed_creation_or_retention_keeps_real_partial_bytes_charged_after_owner_drop() {
    let owned = OwnedDirectory::new();
    let budget = ByteBudget::new(16).unwrap();
    let mut reserved = budget.reserve(16).unwrap();
    let path = owned.path("partial");
    // Actual bytes reached disk before a PUBLIC simulated interruption at the
    // creation/sync return boundary. No generic rollback can be assumed.
    let interrupted = (|| -> std::io::Result<()> {
        let mut file = File::create_new(&path)?;
        file.write_all(b"PARTIAL")?;
        file.sync_all()?;
        Err(std::io::Error::other(
            "PUBLIC test: interruption after sync",
        ))
    })();
    assert!(interrupted.is_err());
    assert!(matches!(
        reserved.retain_file(&path),
        Err(Error::CorruptFile)
    ));
    assert_eq!(reserved.bytes(), 16);
    assert!(matches!(
        reserved.retain_file(owned.path("missing")),
        Err(Error::Io(_))
    ));
    assert_eq!(reserved.bytes(), 16);
    reserved.retain_conservatively(); // explicit failed-owner branch, not `?`
    assert_eq!(budget.used().unwrap(), 16);
    assert_eq!(fs::read(&path).unwrap(), b"PARTIAL");
    let restarted = ByteBudget::new(16).unwrap();
    restarted.register_file(&path).unwrap();
    assert_eq!(restarted.used().unwrap(), 7);
}

#[test]
fn complete_stream_publication_and_fresh_reopen_preserve_all_original_bytes() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let bytes: Vec<_> = (0..65_539).map(|i| (i % 251) as u8).collect();
    let identity = id(&bytes);
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    let mut stage = store.stage(identity).unwrap();
    for chunk in bytes.chunks(997) {
        stage.write_chunk(chunk).unwrap();
    }
    assert_eq!(stage.finish().unwrap(), identity);
    assert_eq!(budget.used().unwrap(), bytes.len() as u64);
    drop(store);
    let restarted = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut store = EvidenceStore::open(&directory, restarted.clone(), limits()).unwrap();
    let mut reader = store.reader(identity).unwrap();
    let mut received = Vec::new();
    reader.read_to_end(&mut received).unwrap();
    assert_eq!(reader.remaining(), 0);
    reader.finish().unwrap();
    assert_eq!(received, bytes);
    assert_eq!(restarted.used().unwrap(), identity.bytes());
}

#[test]
fn malformed_uploads_and_incomplete_reads_never_publish_an_identity() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let budget = ByteBudget::new(128).unwrap();
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    let identity = id(b"PUBLIC");
    let mut short = store.stage(identity).unwrap();
    short.write_chunk(b"PUB").unwrap();
    assert!(matches!(short.finish(), Err(Error::Encoding)));
    assert_eq!(budget.used().unwrap(), 0);
    let mut wrong = store.stage(identity).unwrap();
    wrong.write_chunk(b"WRONG!").unwrap();
    assert!(matches!(wrong.finish(), Err(Error::Identity)));
    assert!(!public_blob_path(&directory, identity).exists());
    let mut oversized = store.stage(identity).unwrap();
    assert!(matches!(
        oversized.write_chunk(b"TOO-LONG"),
        Err(Error::ResourceLimit)
    ));
    oversized.cancel().unwrap();
    let mut valid = store.stage(identity).unwrap();
    valid.write_chunk(b"PUBLIC").unwrap();
    valid.finish().unwrap();
    let mut reader = store.reader(identity).unwrap();
    let mut one = [0];
    reader.read_exact(&mut one).unwrap();
    assert!(matches!(reader.finish(), Err(Error::Encoding)));
    assert!(matches!(
        BlobId::new([0; 32], MAX_BLOB_BYTES + 1),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn identical_upload_is_idempotent_and_existing_corruption_is_never_overwritten() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let budget = ByteBudget::new(64).unwrap();
    let mut store =
        EvidenceStore::open(&directory, budget.clone(), StoreLimits::new(32, 1).unwrap()).unwrap();
    let identity = id(b"ORIGINAL");
    for _ in 0..2 {
        let mut stage = store.stage(identity).unwrap();
        stage.write_chunk(b"ORIGINAL").unwrap();
        assert_eq!(stage.finish().unwrap(), identity);
        assert_eq!(budget.used().unwrap(), identity.bytes());
    }
    let path = public_blob_path(&directory, identity);
    fs::write(&path, b"DAMAGED!").unwrap(); // actual same-length custody corruption
    let mut repair = store.stage(identity).unwrap();
    repair.write_chunk(b"ORIGINAL").unwrap();
    assert!(matches!(repair.finish(), Err(Error::Identity)));
    assert_eq!(fs::read(&path).unwrap(), b"DAMAGED!");
    let mut reader = store.reader(identity).unwrap();
    let mut damaged = Vec::new();
    reader.read_to_end(&mut damaged).unwrap();
    assert!(matches!(reader.finish(), Err(Error::Identity)));
    drop(store);
    assert!(matches!(
        EvidenceStore::open(&directory, ByteBudget::new(64).unwrap(), limits()),
        Err(Error::Identity)
    ));
}

#[test]
fn cleanup_failure_preserves_charge_and_restart_removes_only_abandoned_stage() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let budget = ByteBudget::new(64).unwrap();
    let identity = id(b"PUBLIC-STAGE");
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    let mut stage = store.stage(identity).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.fail_cleanup_for_test();
    assert!(matches!(stage.cancel(), Err(Error::Io(_))));
    assert_eq!(budget.used().unwrap(), identity.bytes());
    assert!(!public_blob_path(&directory, identity).exists());
    drop(store);
    let restarted = ByteBudget::new(64).unwrap();
    let store = EvidenceStore::open(&directory, restarted.clone(), limits()).unwrap();
    assert_eq!(restarted.used().unwrap(), 0);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1); // only owned lock
    drop(store);
    assert_eq!(budget.used().unwrap(), identity.bytes()); // old failed owner never forgot bytes
}

#[test]
fn sync_failure_returns_no_committed_identity_and_cleans_the_real_stage() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let budget = ByteBudget::new(64).unwrap();
    let identity = id(b"PUBLIC");
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    let mut stage = store.stage(identity).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.fail_sync_for_test();
    assert!(matches!(stage.finish(), Err(Error::Io(_))));
    assert_eq!(budget.used().unwrap(), 0);
    assert!(!public_blob_path(&directory, identity).exists());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
}

#[test]
fn lost_response_after_real_publication_reopens_and_retries_exact_original_bytes() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let budget = ByteBudget::new(64).unwrap();
    let identity = id(b"PUBLIC");
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    let mut stage = store.stage(identity).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.fail_after_link_for_test();
    assert!(matches!(stage.finish(), Err(Error::Io(_))));
    assert_eq!(
        fs::read(public_blob_path(&directory, identity)).unwrap(),
        b"PUBLIC"
    );
    assert_eq!(budget.used().unwrap(), identity.bytes());
    drop(store);
    let restarted = ByteBudget::new(64).unwrap();
    let mut store = EvidenceStore::open(&directory, restarted.clone(), limits()).unwrap();
    let mut retry = store.stage(identity).unwrap();
    retry.write_chunk(b"PUBLIC").unwrap();
    assert_eq!(retry.finish().unwrap(), identity);
    assert_eq!(restarted.used().unwrap(), identity.bytes());
    let mut reader = store.reader(identity).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    reader.finish().unwrap();
    assert_eq!(bytes, b"PUBLIC");
}

#[test]
fn real_two_hardlink_crash_survivor_recovers_at_exact_quota_without_double_charge() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let identity = id(b"PUBLIC");
    let blob = public_blob_path(&directory, identity);
    let stage = abandoned_stage_path(&directory, identity);
    create_file(&blob, b"PUBLIC");
    fs::hard_link(&blob, &stage).unwrap(); // actual two names, no Stage Drop cleanup
    assert!(blob.exists() && stage.exists());
    let budget = ByteBudget::new(identity.bytes()).unwrap();
    budget.register_file(&blob).unwrap();
    assert_eq!(budget.used().unwrap(), identity.bytes());
    // Pre-registration makes the old double-charge fail regardless of read_dir
    // order. Only one physical retained payload exists at this crash boundary.
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    assert!(!stage.exists());
    assert_eq!(budget.used().unwrap(), identity.bytes());
    let mut reader = store.reader(identity).unwrap();
    let mut original = Vec::new();
    reader.read_to_end(&mut original).unwrap();
    reader.finish().unwrap();
    assert_eq!(original, b"PUBLIC");
    assert_eq!(fs::read(&blob).unwrap(), b"PUBLIC");
}

#[test]
fn full_quota_removes_bounded_abandoned_copies_but_preserves_corrupt_stage_and_blob() {
    for corrupt in [false, true] {
        let owned = OwnedDirectory::new();
        let directory = owned.evidence();
        let identity = id(b"PUBLIC");
        let blob = public_blob_path(&directory, identity);
        let stage = abandoned_stage_path(&directory, identity);
        create_file(&blob, b"PUBLIC");
        let abandoned: &[u8] = if corrupt { b"TOO-LONG" } else { b"PUB" };
        create_file(&stage, abandoned); // distinct actual file, not another hard link
        let budget = ByteBudget::new(identity.bytes()).unwrap();
        budget.register_file(&blob).unwrap();
        if corrupt {
            assert!(matches!(
                EvidenceStore::open(&directory, budget.clone(), limits()),
                Err(Error::CorruptFile)
            ));
            assert_eq!(fs::read(&stage).unwrap(), abandoned); // no truncation or overwrite
        } else {
            let _store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
            assert!(!stage.exists());
        }
        assert_eq!(fs::read(&blob).unwrap(), b"PUBLIC");
        assert_eq!(budget.used().unwrap(), identity.bytes());
    }
}

#[test]
fn journal_and_blobs_share_exact_quota_before_writes_and_restore() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let journal = owned.path("journal");
    create_file(&journal, b"JOURNAL1");
    let budget = ByteBudget::new(16).unwrap();
    budget.register_file(&journal).unwrap();
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    let identity = id(b"EVIDENCE");
    let mut stage = store.stage(identity).unwrap();
    stage.write_chunk(b"EVIDENCE").unwrap();
    stage.finish().unwrap();
    assert_eq!(budget.used().unwrap(), 16);
    assert!(matches!(store.stage(id(b"X")), Err(Error::ResourceLimit)));
    assert_eq!(fs::read(&journal).unwrap(), b"JOURNAL1");
    assert_eq!(
        fs::read(public_blob_path(&directory, identity)).unwrap(),
        b"EVIDENCE"
    );
    drop(store);
    let restarted = ByteBudget::new(16).unwrap();
    restarted.register_file(&journal).unwrap();
    let _store = EvidenceStore::open(&directory, restarted.clone(), limits()).unwrap();
    assert_eq!(restarted.used().unwrap(), 16);
}

#[test]
fn exclusive_store_and_missing_unknown_or_changed_files_fail_closed() {
    let owned = OwnedDirectory::new();
    let directory = owned.evidence();
    let budget = ByteBudget::new(128).unwrap();
    let mut store = EvidenceStore::open(&directory, budget.clone(), limits()).unwrap();
    assert!(matches!(
        EvidenceStore::open(&directory, budget.clone(), limits()),
        Err(Error::Io(_))
    ));
    assert!(matches!(store.reader(id(b"ABSENT")), Err(Error::Io(_))));
    let identity = id(b"PUBLIC");
    let mut stage = store.stage(identity).unwrap();
    stage.write_chunk(b"PUBLIC").unwrap();
    stage.finish().unwrap();
    drop(store);
    fs::remove_file(public_blob_path(&directory, identity)).unwrap();
    let mut restored =
        EvidenceStore::open(&directory, ByteBudget::new(128).unwrap(), limits()).unwrap();
    // A directory scan does not know the application manifest. Independently
    // required references still have to resolve; there is no cached success.
    assert!(matches!(restored.reader(identity), Err(Error::Io(_))));
    drop(restored);
    let unknown = directory.join("unrecognized");
    create_file(&unknown, b"PUBLIC");
    let stage = abandoned_stage_path(&directory, identity);
    create_file(&stage, b"PUB");
    assert!(matches!(
        EvidenceStore::open(&directory, ByteBudget::new(128).unwrap(), limits()),
        Err(Error::Encoding)
    ));
    assert_eq!(fs::read(&unknown).unwrap(), b"PUBLIC");
    assert_eq!(fs::read(&stage).unwrap(), b"PUB"); // unknown entry prevents any recovery deletion
}
