//! PUBLIC NON-SECRET byte fixtures. These owning format/storage tests do not
//! claim cryptographic success; the separate OS-peer test exercises real proofs.
use super::*;
use crate::catalog::{PARTS, RECORDS};
use protocol_storage::{BlobId, MAX_BLOB_BYTES, ParticipantQuota};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-product-evidence-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("owned directory: {e}"),
            }
        }
        panic!("bounded exclusive directory allocation exhausted")
    }
    fn root(&self) -> PathBuf {
        self.0.join("participant")
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        // Only known newly created directories and regular direct children;
        // no recursive deletion, unknown subtree or symlink traversal.
        let root = self.root();
        for p in [
            root.join("control"),
            root.join("depot"),
            root.join("custody"),
            root,
            self.0.clone(),
        ] {
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_dir())
                && p.canonicalize().ok().as_ref() == Some(&p)
            {
                if let Ok(entries) = fs::read_dir(&p) {
                    for entry in entries.flatten() {
                        if entry.file_type().is_ok_and(|k| k.is_file()) {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
                let _ = fs::remove_dir(p);
            }
        }
    }
}
fn id(bytes: &[u8]) -> BlobId {
    BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap()
}
fn catalog(two: bool) -> CatalogClaim {
    let setup_len = if two { MAX_BLOB_BYTES + 1 } else { 1 };
    CatalogClaim {
        setup_len,
        setup: if two {
            vec![BlobId::new([1; 32], MAX_BLOB_BYTES).unwrap(), id(b"S")]
        } else {
            vec![id(b"S")]
        },
        parts: core::array::from_fn(|i| id(&(i as u32).to_le_bytes())),
        binding: [0x31; 64],
        graph: [0x42; 64],
    }
}
fn blob_path(directory: &std::path::Path, id: BlobId) -> PathBuf {
    let hash: String = id.sha256().iter().map(|b| format!("{b:02x}")).collect();
    directory.join(format!("{hash}-{:016x}.blob", id.bytes()))
}

#[test]
fn canonical_catalog_has_only_fixed_roles_and_one_or_two_exact_setup_chunks() {
    for two in [false, true] {
        let c = catalog(two);
        let bytes = c.encode().unwrap();
        assert!(bytes.len() <= MAX_CATALOG_BYTES);
        let actual = CatalogClaim::decode(&bytes).unwrap();
        assert_eq!(actual.setup, c.setup);
        assert_eq!(actual.parts, c.parts);
        assert_eq!(actual.binding, c.binding);
        assert_eq!(actual.graph, c.graph);
        assert_eq!(actual.encode().unwrap(), bytes);
        assert_eq!(actual.parts.len(), PARTS);
    }
    let mut c = catalog(true);
    c.setup.swap(0, 1);
    assert!(c.encode().is_err(), "noncanonical setup chunk order");
}

#[test]
fn catalog_rejects_missing_extra_duplicate_reordered_roles_and_noncanonical_headers() {
    let bytes = catalog(false).encode().unwrap();
    for offset in [0, 8, 40, 240, 242, 255, 256, 258] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(
            CatalogClaim::decode(&bad).is_err(),
            "metadata byte {offset}"
        );
    }
    assert!(CatalogClaim::decode(&bytes[..bytes.len() - 44]).is_err());
    let mut extra = bytes.clone();
    extra.extend_from_slice(&bytes[256..300]);
    assert!(CatalogClaim::decode(&extra).is_err());
    let mut duplicate = bytes.clone();
    duplicate[300..344].copy_from_slice(&bytes[256..300]);
    assert!(CatalogClaim::decode(&duplicate).is_err());
    let mut reversed = bytes.clone();
    reversed[256..300].copy_from_slice(&bytes[300..344]);
    reversed[300..344].copy_from_slice(&bytes[256..300]);
    assert!(CatalogClaim::decode(&reversed).is_err());
    for len in [0u64, 64 * 1024 * 1024 + 1] {
        let mut bad = bytes.clone();
        bad[232..240].copy_from_slice(&len.to_le_bytes());
        assert!(CatalogClaim::decode(&bad).is_err());
    }
}

#[test]
fn role_byte_caps_are_checked_before_opening_or_allocating_referenced_blobs() {
    let mut c = catalog(false);
    c.parts[4] = BlobId::new([0x51; 32], wire_source_cap() as u64 + 1).unwrap();
    assert!(c.encode().is_err());
    let bytes = catalog(false).encode().unwrap();
    // One setup entry, then the Source at part4; modify ONLY its extent.
    let mut bomb = bytes.clone();
    let start = 256 + 5 * 44;
    bomb[start + 4..start + 12].copy_from_slice(&(wire_source_cap() as u64 + 1).to_le_bytes());
    assert!(matches!(
        CatalogClaim::decode(&bomb),
        Err(Error::ResourceLimit)
    ));
    assert!(
        CatalogId::from_blob(BlobId::new([0; 32], MAX_CATALOG_BYTES as u64 + 1).unwrap()).is_err()
    );
    assert_eq!(catalog(false).parts[RECORDS..].len(), 118);
}
fn wire_source_cap() -> usize {
    registry200_proof::coefficient_encoding::wire::MAX_SOURCE
}

#[test]
fn public_bytes_reopen_exactly_and_missing_or_corrupt_refs_are_never_cached_success() {
    let owned = OwnedDirectory::new();
    let q = ParticipantQuota::create_new(owned.root(), [0x61; 32], 1024 * 1024).unwrap();
    let directory = q.depot_directory();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    let bytes: Vec<_> = (0..65_539).map(|i| (i % 251) as u8).collect();
    let blob = store.put(&bytes).unwrap();
    assert_eq!(store.read(blob, bytes.len()).unwrap(), bytes);
    let used = q.usage().unwrap().total_bytes();
    drop(store);
    drop(q);
    let q = ParticipantQuota::open_existing(owned.root(), [0x61; 32], 1024 * 1024).unwrap();
    assert_eq!(q.usage().unwrap().total_bytes(), used);
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    assert_eq!(store.read(blob, bytes.len()).unwrap(), bytes);
    drop(store);
    drop(q);
    let p = blob_path(&directory, blob);
    let mut file = fs::OpenOptions::new().write(true).open(&p).unwrap();
    file.write_all(b"X").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        matches!(
            ParticipantQuota::open_existing(owned.root(), [0x61; 32], 1024 * 1024),
            Err(protocol_storage::Error::Identity)
        ),
        "complete root inventory rehash rejects corruption"
    );
    fs::remove_file(p).unwrap();
    let q = ParticipantQuota::open_existing(owned.root(), [0x61; 32], 1024 * 1024).unwrap();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    assert!(
        store.read(blob, bytes.len()).is_err(),
        "a prior read never authorizes a missing blob"
    );
}

#[test]
fn quota_failure_preserves_published_bytes_and_cannot_publish_a_catalog() {
    let owned = OwnedDirectory::new();
    let q = ParticipantQuota::create_new(owned.root(), [0x71; 32], 512).unwrap();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    let bytes = [0x23; 200];
    let blob = store.put(&bytes).unwrap();
    let used = q.usage().unwrap().total_bytes();
    assert!(matches!(
        store.put(&[0x24; 200]),
        Err(Error::Storage(protocol_storage::Error::ResourceLimit))
    ));
    assert_eq!(q.usage().unwrap().total_bytes(), used);
    assert_eq!(store.read(blob, bytes.len()).unwrap(), bytes);
    assert!(store.put(&catalog(false).encode().unwrap()).is_err());
    drop(store);
    drop(q);
    let q = ParticipantQuota::open_existing(owned.root(), [0x71; 32], 512).unwrap();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    assert_eq!(store.read(blob, bytes.len()).unwrap(), bytes);
}

#[test]
fn terminal_check_requires_empty_payload_actual_eof_and_successful_io() {
    use crate::record::require_end;
    assert!(require_end(&[], &mut std::io::Cursor::new([])).is_ok());
    assert!(require_end(&[0], &mut std::io::Cursor::new([])).is_err());
    assert!(require_end(&[], &mut std::io::Cursor::new([0])).is_err());
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("PUBLIC failure"))
        }
    }
    assert!(matches!(
        require_end(&[], &mut FailedRead),
        Err(Error::Io(_))
    ));
}

#[test]
fn public_catalog_claim_exposes_canonical_roles_without_verifying_referenced_bytes() {
    let owned = OwnedDirectory::new();
    let q = ParticipantQuota::create_new(owned.root(), [0x81; 32], 64 * 1024).unwrap();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    for two in [false, true] {
        // These are explicitly unverified PUBLIC metadata fixtures. Referenced
        // setup/proof blobs do not exist; successful parsing is not a receipt.
        let expected = catalog(two);
        let original = expected.encode().unwrap();
        let id = CatalogId::from_blob(store.retain_public_blob(&original).unwrap()).unwrap();
        let actual = store.catalog_claim(id).unwrap();
        assert_eq!(actual.setup_parts(), expected.setup.as_slice());
        assert_eq!(actual.setup_bytes(), expected.setup_len);
        assert_eq!(actual.provenance(), expected.parts[0]);
        assert_eq!(actual.request(), expected.parts[1]);
        assert_eq!(actual.response(), expected.parts[2]);
        assert_eq!(actual.source(), expected.parts[4]);
        assert_eq!(actual.query_child(), expected.parts[6]);
        assert_ne!(
            actual.query_child(),
            expected.parts[5],
            "SourceAllOriginal is a distinct child"
        );
        assert_eq!(actual.graph_identity(), expected.graph);
        assert_eq!(actual.encode().unwrap(), original);
        assert!(matches!(store.read_public_blob(actual.source(), 4),
            Err(Error::Storage(protocol_storage::Error::Io(e)))
                if e.kind() == std::io::ErrorKind::NotFound));
    }
    let mut trailing = catalog(false).encode().unwrap();
    trailing.push(0);
    let id = CatalogId::from_blob(store.retain_public_blob(&trailing).unwrap()).unwrap();
    assert!(
        matches!(store.catalog_claim(id), Err(Error::Encoding)),
        "valid content identity does not make a noncanonical catalog acceptable"
    );
}

#[test]
fn public_blob_caps_reject_without_file_or_ledger_changes_then_valid_bytes_still_reopen() {
    let owned = OwnedDirectory::new();
    let q = ParticipantQuota::create_new(owned.root(), [0x91; 32], 1024 * 1024).unwrap();
    let directory = q.depot_directory();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    let names = || {
        let mut names = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let before_names = names();
    let before_used = q.usage().unwrap().total_bytes();
    let missing = id(b"PUBLIC missing blob");
    for cap in [0, MAX_BLOB_BYTES as usize + 1, usize::MAX] {
        assert!(
            matches!(
                store.read_public_blob(missing, cap),
                Err(Error::ResourceLimit)
            ),
            "invalid cap must reject before trying the missing path"
        );
    }
    assert!(
        matches!(
            store.read_public_blob(missing, 1),
            Err(Error::ResourceLimit)
        ),
        "declared extent larger than caller cap must reject before file I/O"
    );
    assert!(matches!(
        store.retain_public_blob(&[]),
        Err(Error::ResourceLimit)
    ));
    let oversized = vec![0; MAX_BLOB_BYTES as usize + 1];
    assert!(
        matches!(
            store.retain_public_blob(&oversized),
            Err(Error::ResourceLimit)
        ),
        "oversized bytes must reject before hashing or staging"
    );
    drop(oversized);
    assert_eq!(names(), before_names);
    assert_eq!(q.usage().unwrap().total_bytes(), before_used);

    let bytes = b"PUBLIC non-secret storage fixture";
    let blob = store.retain_public_blob(bytes).unwrap();
    assert_eq!(store.read_public_blob(blob, bytes.len()).unwrap(), bytes);
    let used = q.usage().unwrap().total_bytes();
    assert_eq!(used, before_used + bytes.len() as u64);
    assert_eq!(store.retain_public_blob(bytes).unwrap(), blob);
    assert_eq!(
        q.usage().unwrap().total_bytes(),
        used,
        "same depot deduplicates exact public bytes"
    );
    drop(store);
    drop(q);
    let q = ParticipantQuota::open_existing(owned.root(), [0x91; 32], 1024 * 1024).unwrap();
    let mut store = ProductStore::open(q.depot_budget()).unwrap();
    assert_eq!(q.usage().unwrap().total_bytes(), used);
    assert_eq!(store.read_public_blob(blob, bytes.len()).unwrap(), bytes);
}

#[test]
fn public_reference_enumeration_has_every_fixed_role_ordinal_and_original_byte_cap() {
    for two in [false, true] {
        let original = catalog(two);
        let claim = CatalogClaim::decode(&original.encode().unwrap()).unwrap();
        let count = if two { 140 } else { 139 };
        let setup_count = if two { 2 } else { 1 };
        let expected_ids: Vec<_> = original
            .setup
            .iter()
            .chain(&original.parts)
            .copied()
            .collect();
        let references: Vec<_> = claim.references().collect();
        assert_eq!(references.len(), count);
        assert_eq!(claim.setup_parts().len(), setup_count);
        // Independent fixed wire grammar: setup, public bindings, Key, Source,
        // both children, all ten Basis, both Formation, claims, all118 records.
        let groups = [
            (1u16, setup_count, MAX_BLOB_BYTES as usize),
            (2, 1, bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES),
            (3, 1, bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES),
            (4, 1, bfv_query_core::MAX_PRIVATE_COEFFICIENT_RESPONSE_BYTES),
            (5, 1, bfv_mul_relin_proof::input_frame_limit(0).unwrap()),
            (
                6,
                1,
                registry200_proof::coefficient_encoding::wire::MAX_SOURCE,
            ),
            (
                7,
                2,
                registry200_proof::coefficient_encoding::wire::MAX_CHILD,
            ),
            (8, 10, bfv_mul_relin_proof::input_frame_limit(3).unwrap()),
            (9, 2, bfv_mul_relin_proof::input_frame_limit(13).unwrap()),
            (10, 1, bfv_mul_relin_proof::MAX_CLAIMS_BYTES),
            (
                11,
                118,
                bfv_mul_relin_proof::RECORD_HEADER + bfv_mul_relin_proof::MAX_PROOF_BYTES,
            ),
        ];
        let mut ordered = references.iter().zip(&expected_ids);
        for (role, entries, cap) in groups {
            for ordinal in 0..entries {
                let (reference, expected_id) = ordered.next().expect("every fixed role is present");
                assert_eq!(
                    (
                        reference.role(),
                        reference.ordinal(),
                        reference.blob_id(),
                        reference.byte_cap()
                    ),
                    (role, ordinal as u16, *expected_id, cap)
                );
                assert!(reference.blob_id().bytes() > 0);
                assert!(reference.blob_id().bytes() <= reference.byte_cap() as u64);
                assert!(reference.byte_cap() <= MAX_BLOB_BYTES as usize);
            }
        }
        assert!(
            ordered.next().is_none(),
            "no extra proof premise references"
        );
        assert_eq!(references[0].blob_id(), claim.setup_parts()[0]);
        if two {
            assert_eq!(references[0].blob_id().bytes(), MAX_BLOB_BYTES);
            assert_eq!(references[1].blob_id().bytes(), 1);
        }
        let mut iterator = claim.references();
        for remaining in (1..=count).rev() {
            assert_eq!(iterator.len(), remaining);
            assert_eq!(iterator.size_hint(), (remaining, Some(remaining)));
            assert!(iterator.next().is_some());
        }
        assert_eq!(iterator.len(), 0);
        assert!(iterator.next().is_none());
        assert!(iterator.next().is_none());
        assert!(iterator.next_back().is_none());
        let reversed: Vec<_> = claim
            .references()
            .rev()
            .map(|r| (r.role(), r.ordinal(), r.blob_id(), r.byte_cap()))
            .collect();
        let expected_reverse: Vec<_> = references
            .iter()
            .rev()
            .map(|r| (r.role(), r.ordinal(), r.blob_id(), r.byte_cap()))
            .collect();
        assert_eq!(reversed, expected_reverse);
    }
}
