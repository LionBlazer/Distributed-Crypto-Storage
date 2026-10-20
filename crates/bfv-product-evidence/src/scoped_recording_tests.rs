//! PUBLIC NONSECRET storage/association negatives only. No test constructs a
//! CheckedProduct or scoped mathematical payload. The genuine combined4 owns
//! the stream -> Kernel -> QC -> private completion positive.
use crate::{CatalogId, ProductStore, replay::require_recording_origin};
use protocol_storage::{BlobId, ParticipantQuota};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-scoped-recording-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("owned public fixture directory: {e}"),
            }
        }
        panic!("bounded public directory attempts exhausted")
    }
    fn root(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Known direct fixture files only; no recursive traversal or symlinks.
        for root in [self.root("a"), self.root("b")] {
            for p in [
                root.join("control"),
                root.join("depot"),
                root.join("custody"),
                root,
            ] {
                if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_dir())
                    && p.canonicalize().ok().as_ref() == Some(&p)
                {
                    if let Ok(entries) = fs::read_dir(&p) {
                        for e in entries.flatten() {
                            if e.file_type().is_ok_and(|t| t.is_file()) {
                                let _ = fs::remove_file(e.path());
                            }
                        }
                    }
                    let _ = fs::remove_dir(p);
                }
            }
        }
        let _ = fs::remove_dir(&self.0);
    }
}
#[test]
fn equal_public_catalog_ids_do_not_substitute_another_store_or_ledger() {
    let dir = Directory::new();
    let a = ParticipantQuota::create_new(dir.root("a"), [0x21; 32], 1_000_000).unwrap();
    let b = ParticipantQuota::create_new(dir.root("b"), [0x22; 32], 1_000_000).unwrap();
    let first = ProductStore::open(a.depot_budget()).unwrap().into_shared();
    let second = ProductStore::open(b.depot_budget()).unwrap().into_shared();
    // These are deliberately UNVERIFIED identifiers, not catalog/proof positives.
    let id = CatalogId::from_blob(BlobId::new([0x31; 32], 256).unwrap()).unwrap();
    let other = CatalogId::from_blob(BlobId::new([0x32; 32], 256).unwrap()).unwrap();
    assert!(require_recording_origin(&first, id, &first.clone(), id).is_ok());
    assert!(require_recording_origin(&first, id, &second, id).is_err());
    assert!(require_recording_origin(&first, other, &first, id).is_err());
}
#[test]
fn a_prior_read_never_authorizes_truncated_or_missing_retained_bytes() {
    let dir = Directory::new();
    let quota = ParticipantQuota::create_new(dir.root("a"), [0x23; 32], 1_000_000).unwrap();
    let store = ProductStore::open(quota.depot_budget())
        .unwrap()
        .into_shared();
    let bytes = b"public original proof-byte reader fixture; not a proof";
    let id = store.retain_public_blob(bytes).unwrap();
    assert_eq!(store.read_public_blob(id, bytes.len()).unwrap(), bytes);
    let name: String = id.sha256().iter().map(|b| format!("{b:02x}")).collect();
    let path = quota
        .depot_directory()
        .join(format!("{name}-{:016x}.blob", id.bytes()));
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(id.bytes() - 1).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(store.read_public_blob(id, bytes.len()).is_err());
    fs::remove_file(path).unwrap();
    assert!(store.read_public_blob(id, bytes.len()).is_err());
}
