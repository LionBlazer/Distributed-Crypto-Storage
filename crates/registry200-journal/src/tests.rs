//! Canonical application/request tests; signatures and cryptographic admission have integration tests.

fn source_claim() -> registry200_proof::source::Statement {
    use compact_store::{Layout, Owner};
    use registry200_proof::source::{self, statement::limits};
    // PUBLIC NONSECRET geometry fixture; checked metadata alone proves no logical index.
    let owner = Owner::generate([0x31; 16]).unwrap();
    let data = owner
        .seal(
            Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &[0; 12],
            limits(),
        )
        .unwrap();
    let index = owner
        .seal(
            Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &[0; 2336],
            limits(),
        )
        .unwrap();
    source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&data.encode(), &index.encode()],
        [data.commitment(), index.commitment()],
        [0xA4; 32],
        [0; 32],
        [0; 32],
    )
    .unwrap()
}

use crate::{Application, ApplicationDescriptor, Control, Operation, Request};
#[test]
fn descriptor_reconstructs_exact_original_application_and_rejects_mutated_heads() {
    let source = source_claim();
    let app = Application::new([9; 32], 7, 8, &source).unwrap();
    let descriptor = ApplicationDescriptor::from_application(&app).unwrap();
    let bytes = descriptor.encode();
    assert_eq!(bytes.len(), 312);
    let rebuilt = ApplicationDescriptor::decode(&bytes)
        .unwrap()
        .application()
        .unwrap();
    assert_eq!(rebuilt.id(), app.id());
    assert_eq!(rebuilt.initial_shards(), app.initial_shards());
    for at in [0, 56, 168] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(ApplicationDescriptor::decode(&bad).is_err());
    }
    for at in [167, 279] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        let foreign = ApplicationDescriptor::decode(&changed)
            .unwrap()
            .application()
            .unwrap();
        assert_ne!(foreign.id(), app.id());
        assert_ne!(foreign.initial_shards(), app.initial_shards());
        let original = genesis(&app);
        app.require_genesis(&original).unwrap();
        assert_eq!(
            foreign.require_genesis(&original),
            Err(version_journal::Error::WrongDomain)
        );
        assert!(crate::RegistryVerifier::new(foreign, &original).is_err());
    }
    let mut bad = bytes;
    bad[48..56].copy_from_slice(&7u64.to_le_bytes());
    assert!(ApplicationDescriptor::decode(&bad).is_err());
}
#[test]
fn control_heads_bind_both_complete_manifests_and_reserved_bytes() {
    let app = Application::new([9; 32], 7, 8, &source_claim()).unwrap();
    for control in [
        Control::Pending,
        Control::Active {
            enrollment: [0; 32],
            registry: [0; 32],
        },
    ] {
        let heads = control.heads(&app);
        assert_eq!(Control::decode(&app, heads).unwrap(), control);
        for at in [0, 24, 26, 63, 96, 111] {
            for page in 0..2 {
                let mut bad = heads;
                if page == 0 {
                    bad.data[at] ^= 1
                } else {
                    bad.index[at] ^= 1
                };
                assert!(Control::decode(&app, bad).is_err());
            }
        }
    }
}
#[test]
fn request_is_fixed_full_packet_canonical_and_bootstrap_command_is_unused() {
    let s = source_claim();
    let app = Application::new([9; 32], 7, 8, &s).unwrap();
    let mut r = Request {
        operation: Operation::Bootstrap,
        genesis: [1; 32],
        parent: [2; 32],
        application: app.id(),
        nonce: [3; 32],
        query: [4; 32],
        enrollment: [0; 32],
        opening: [0; 32],
        command: [0; 32],
        packets: s.packets,
    };
    let b = r.encode().unwrap();
    assert_eq!(b.len(), 2716);
    assert_eq!(Request::decode(&b).unwrap().encode().unwrap(), b);
    let mut trailing = b.clone();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    let mut reserved = b;
    reserved[15] = 1;
    assert!(Request::decode(&reserved).is_err());
    r.command[0] = 1;
    assert!(r.encode().is_err());
    r.command = [0; 32];
    r.packets[1].pop();
    assert!(r.encode().is_err());
}

#[test]
fn changed_cached_database_is_rejected_before_any_journal_creation() {
    let app = Application::new([9; 32], 7, 8, &source_claim()).unwrap();
    let good = genesis(&app);
    app.require_genesis(&good).unwrap();
    let mut bad = app;
    bad.database[15] ^= 1;
    let mut crafted = good;
    crafted.database = bad.database;
    crafted.initial_shards = bad.initial_shards();
    crafted.validate().unwrap();
    assert_eq!(
        bad.require_genesis(&crafted),
        Err(version_journal::Error::WrongDomain)
    );
    assert!(crate::RegistryVerifier::new(bad, &crafted).is_err());
}

fn genesis(app: &Application) -> version_journal::Genesis {
    use version_journal::{Genesis, ProtocolProfile, Target};
    // RFC8032 PUBLIC NONSECRET verifying key, not a secret fixture/export.
    let pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let owner = core::array::from_fn(|i| u8::from_str_radix(&pk[2 * i..2 * i + 2], 16).unwrap());
    Genesis {
        network_id: app.network,
        database: app.database,
        owner,
        application_commitment: app.id(),
        timestamp: 1000,
        profile: ProtocolProfile {
            initial_target: Target([255; 32]),
            pow_limit: Target([255; 32]),
            block_spacing_secs: 10,
            retarget_interval: 100,
            max_future_secs: 60,
            confirmation_depth: 1,
            max_headers: 128,
            max_shards: 2,
            max_updates: 2,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: 4096,
            max_proof_bytes: registry200_proof::wire::maximum_bundle_bytes() as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: app.initial_shards(),
    }
}
