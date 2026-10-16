//! Complete compute admission through actual files, not remembered custody.
use super::{test_support::Directory, *};

fn fixture() -> RawBundle {
    // These plaintext values and freshly generated keys are non-secret fixtures.
    let owner = compact_store::Owner::generate([82; 16]).unwrap();
    let image = |schema, value| {
        owner
            .seal(
                compact_store::Layout {
                    schema: [schema; 16],
                    row_width: 1,
                    rows_per_page: 3,
                    row_count: 7,
                },
                &[value; 7],
                Limits::default(),
            )
            .unwrap()
    };
    RawBundle::from_snapshots(&image(83, 1), &image(84, 2)).unwrap()
}

fn class<T>(result: Result<T, RemoteError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(RemoteError::Integrity) => "integrity",
        Err(RemoteError::Io(_)) => "io",
        Err(RemoteError::NotFound) => "not found",
        Err(RemoteError::ResourceLimit) => "limit",
        Err(other) => panic!("Unexpected admission error: {other}"),
    }
}

fn owned_audit(bytes: &[u8]) -> Result<CheckedObject, RemoteError> {
    CheckedObject::audit(objects::decode_disk(bytes).map_err(error)?)
}

#[test]
fn borrowed_disk_audit_matches_owned_errors_and_checks_both_complete_images() {
    let original = fixture();
    let bytes = objects::encode_disk(&original).unwrap();
    let version = objects::audit_disk_version(&bytes).unwrap();
    assert!(version == original.target_version().unwrap());
    assert_eq!(owned_audit(&bytes).unwrap().into_raw(), original);

    for fault in 0..14 {
        let mut raw = original.clone();
        match fault {
            0 => raw.version = 1,
            1 => {
                raw.data_head.pop();
            }
            2 => {
                raw.index_head.pop();
            }
            3 => *raw.data.last_mut().unwrap() ^= 1,
            4 => *raw.index.last_mut().unwrap() ^= 1,
            5 => raw.data.push(0),
            6 => raw.index[compact_store::MANIFEST_BYTES..compact_store::MANIFEST_BYTES + 8]
                .copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => {}
        }
        let mut hostile = objects::encode_disk(&raw).unwrap();
        match fault {
            7 => hostile[0] ^= 1,
            8 => hostile[8] ^= 1,
            9 => hostile.push(0),
            10 => {
                hostile.pop();
            }
            11 | 12 => {
                let fourth = objects::DISK_HEADER_BYTES
                    + 34
                    + 3 * 8
                    + raw.data_head.len()
                    + raw.index_head.len()
                    + raw.data.len();
                let length = if fault == 11 {
                    raw.index.len() as u64 + 1
                } else {
                    u64::MAX
                };
                hostile[fourth..fourth + 8].copy_from_slice(&length.to_le_bytes());
            }
            13 => {
                // Parse the fourth field before rejecting even an invalid version.
                hostile[objects::DISK_HEADER_BYTES..objects::DISK_HEADER_BYTES + 2]
                    .copy_from_slice(&1u16.to_le_bytes());
                hostile.pop();
            }
            _ => {}
        }
        let expected = class(owned_audit(&hostile));
        assert_ne!(expected, "ok", "fault {fault}");
        assert_eq!(
            class(objects::audit_disk_version(&hostile)),
            expected,
            "fault {fault}"
        );
    }
}

#[test]
fn compute_admission_preserves_the_whole_file_cap_and_namespace_preflight() {
    let mut bytes = objects::encode_disk(&fixture()).unwrap();
    bytes.resize(peer_transport::MAX_FRAME_BYTES + 1, 0);
    assert_eq!(class(objects::audit_disk_version(&bytes)), "io");
    assert_eq!(class(owned_audit(&bytes)), "io");
    bytes[0] ^= 1;
    let borrowed = objects::audit_disk_version(&bytes)
        .err()
        .unwrap()
        .to_string();
    let owned = owned_audit(&bytes).err().unwrap().to_string();
    assert_eq!(borrowed, owned);
    assert!(borrowed.contains("Unsupported object namespace"));
}

#[test]
fn compute_audit_rereads_each_file_and_repair_clears_unavailability() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
    let original = fixture();
    let id = *original.target_version().unwrap().object();
    store.put(original.clone()).unwrap();
    let path = directory.0.join(filename(&id));
    let good = fs::read(&path).unwrap();
    for index in [false, true] {
        assert_eq!(class(store.audit_version(&id)), "ok");
        let mut damaged = original.clone();
        let image = if index {
            &mut damaged.index
        } else {
            &mut damaged.data
        };
        *image.last_mut().unwrap() ^= 1;
        fs::write(&path, objects::encode_disk(&damaged).unwrap()).unwrap();
        assert_eq!(class(store.audit_version(&id)), "integrity");
        assert!(store.invalid.contains(&id));
        assert!(!store.objects()[0].available);
        assert_eq!(class(store.get(&id)), "integrity");
        fs::write(&path, &good).unwrap();
        assert_eq!(class(store.audit_version(&id)), "ok");
        assert!(!store.invalid.contains(&id));
        assert!(store.objects()[0].available);
        assert_eq!(store.get(&id).unwrap(), original);
    }
}

#[test]
fn compute_audit_distinguishes_unknown_names_from_missing_or_substituted_known_files() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
    let original = fixture();
    let id = *original.target_version().unwrap().object();
    let bytes = objects::encode_disk(&original).unwrap();
    store.put(original.clone()).unwrap();
    let unknown = [91; 32];
    fs::write(directory.0.join(filename(&unknown)), &bytes).unwrap();
    assert_eq!(class(store.audit_version(&unknown)), "not found");
    assert!(!store.invalid.contains(&unknown));
    let path = directory.0.join(filename(&id));
    fs::remove_file(&path).unwrap();
    assert_eq!(class(store.audit_version(&id)), "io");
    assert!(store.invalid.contains(&id));
    assert!(!store.objects()[0].available);

    for changed_heads in [false, true] {
        let mut replacement = if changed_heads {
            fixture()
        } else {
            original.clone()
        };
        replacement.nonce[0] ^= 1;
        let replacement_bytes = objects::encode_disk(&replacement).unwrap();
        // Both images authenticate independently, but the requested address differs.
        assert_eq!(class(objects::audit_disk_version(&replacement_bytes)), "ok");
        fs::write(&path, replacement_bytes).unwrap();
        assert_eq!(class(store.audit_version(&id)), "integrity");
        assert_eq!(class(store.get(&id)), "integrity");
        *replacement.index.last_mut().unwrap() ^= 1;
        fs::write(&path, objects::encode_disk(&replacement).unwrap()).unwrap();
        assert_eq!(class(store.audit_version(&id)), "integrity");
    }
    fs::write(path, bytes).unwrap();
    assert_eq!(class(store.audit_version(&id)), "ok");
    assert!(store.objects()[0].available);
}
