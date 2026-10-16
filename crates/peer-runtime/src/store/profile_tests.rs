//! Observable disk lifecycle, complete custody and salted deduplication.
use super::{test_support::Directory, *};
use compact_store::{Layout, Owner};
fn fixture() -> RawBundle {
    let owner = Owner::generate([91; 16]).unwrap();
    let snapshot = owner
        .seal(
            Layout {
                schema: [92; 16],
                row_width: 1,
                rows_per_page: 8,
                row_count: 3,
            },
            &[1, 2, 3],
            Limits::default(),
        )
        .unwrap();
    RawBundle::from_snapshots(&snapshot, &snapshot).unwrap()
}
fn tree(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}
#[test]
fn legacy_unknown_and_mixed_workspaces_reject_without_changing_any_file_or_pending() {
    for name in [
        "write.pending",
        "old.bundle",
        "old.journal",
        "unknown",
        "peer.lock",
        "custody-v2.profile",
    ] {
        let directory = Directory::new();
        fs::create_dir_all(&directory.0).unwrap();
        fs::write(directory.0.join(name), b"old public fixture").unwrap();
        let before = tree(&directory.0);
        assert!(Store::open(&directory.0, 65536).is_err());
        assert_eq!(tree(&directory.0), before, "{name}");
    }
    for mutation in 0..5 {
        let directory = Directory::new();
        let mut store = Store::open(&directory.0, 65536).unwrap();
        let raw = fixture();
        let object = store.put(raw).unwrap().id;
        drop(store);
        fs::write(
            directory.0.join(workspace::PENDING),
            b"partial current write",
        )
        .unwrap();
        match mutation {
            0 => {
                fs::write(directory.0.join("write.pending"), b"legacy pending").unwrap();
            }
            1 => {
                fs::write(
                    directory.0.join("custody-v2.profile"),
                    b"wrong or partial profile",
                )
                .unwrap();
            }
            2 => {
                let mut bytes = fs::read(directory.0.join(filename(&object))).unwrap();
                bytes[8] ^= 1;
                fs::write(directory.0.join(filename(&object)), bytes).unwrap();
            }
            3 => {
                fs::write(
                    directory.0.join(format!("{}.journal2", "ab".repeat(32))),
                    b"DCSJL001 legacy",
                )
                .unwrap();
            }
            _ => {
                let path = directory.0.join(filename(&object));
                let mut bytes = fs::read(&path).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(path, bytes).unwrap();
            }
        }
        let before = tree(&directory.0);
        assert!(Store::open(&directory.0, 65536).is_err());
        assert_eq!(tree(&directory.0), before, "mutation {mutation}");
    }
}
#[test]
fn known_current_pending_recovers_even_when_its_header_was_never_fully_written() {
    for pending in [vec![], vec![1], b"DCSOBJ02".to_vec(), vec![7; 128]] {
        let directory = Directory::new();
        let mut store = Store::open(&directory.0, 65536).unwrap();
        let raw = fixture();
        let id = store.put(raw.clone()).unwrap().id;
        drop(store);
        fs::write(directory.0.join(workspace::PENDING), pending).unwrap();
        let mut reopened = Store::open(&directory.0, 65536).unwrap();
        assert!(!directory.0.join(workspace::PENDING).exists());
        assert_eq!(reopened.get(&id).unwrap(), raw);
    }
}
#[test]
fn same_heads_distinct_nonces_keep_distinct_objects_and_retention_protects_every_id() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 65536).unwrap();
    let first = fixture();
    let mut second = first.clone();
    second.nonce[0] ^= 1;
    let one = store.put(first.clone()).unwrap().id;
    let two = store.put(second.clone()).unwrap().id;
    assert_ne!(one, two);
    assert_eq!(store.put(first.clone()).unwrap().id, one);
    assert_eq!(store.objects.len(), 2);
    drop(store);
    let mut store = Store::open(&directory.0, 65536).unwrap();
    assert_eq!(store.get(&one).unwrap(), first);
    assert_eq!(store.get(&two).unwrap(), second);
    let pair = head_pair_id(&first.data_head, &first.index_head);
    let history = BTreeSet::from([pair]);
    store.prune_journal_objects(&history, &history).unwrap();
    assert_eq!(store.objects.len(), 2);
    store
        .prune_journal_objects(&history, &BTreeSet::new())
        .unwrap();
    assert!(store.objects.is_empty());
}
#[test]
fn same_id_tampering_or_old_version_never_gets_a_deduplicated_ack() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 65536).unwrap();
    let raw = fixture();
    let id = store.put(raw.clone()).unwrap().id;
    for field in 0..3 {
        let mut bad = raw.clone();
        match field {
            0 => *bad.data.last_mut().unwrap() ^= 1,
            1 => *bad.index.last_mut().unwrap() ^= 1,
            _ => bad.version = 1,
        }
        assert!(matches!(store.put(bad), Err(RemoteError::Integrity)));
        assert_eq!(store.get(&id).unwrap(), raw);
    }
    let before = fs::read(directory.0.join(filename(&id))).unwrap();
    let mut corrupted = before.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(directory.0.join(filename(&id)), &corrupted).unwrap();
    assert!(store.put(raw).is_err());
    assert_eq!(
        fs::read(directory.0.join(filename(&id))).unwrap(),
        corrupted
    );
}
#[test]
fn disk_profile_and_object_envelope_bytes_are_in_the_exact_quota() {
    let raw = fixture();
    let size = objects::encode_disk(&raw).unwrap().len() as u64;
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, size + PROFILE_BYTES as u64 - 1).unwrap();
    assert!(matches!(
        store.put(raw.clone()),
        Err(RemoteError::ResourceLimit)
    ));
    store.configure(size + PROFILE_BYTES as u64).unwrap();
    let info = store.put(raw).unwrap();
    assert_eq!(info.stored_bytes, size);
    assert_eq!(store.used(), size + PROFILE_BYTES as u64);
}

#[test]
fn insufficient_profile_quota_rejects_before_even_creating_the_state_directory() {
    for quota in [0, 1, PROFILE_BYTES as u64 - 1] {
        let directory = Directory::new();
        assert!(Store::open(&directory.0, quota).is_err());
        assert!(!directory.0.exists());
    }
}
