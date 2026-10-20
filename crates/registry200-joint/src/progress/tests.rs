//! Validated Source/Bootstrap/Control; the README links the execution record.
use super::*;
use bfv_query_core::{
    EncryptedOwnerState, Geometry, KeyScope, Owner, OwnerStateAuthority, OwnerStateIdentity,
};
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_storage::{BlobId, ParticipantQuota};
use registry200_journal::{
    ApplicationDescriptor, Control, Operation, Request as InnerRequest, intent_query,
};
use registry200_proof::{
    Val, admission::CanonicalSource, lifecycle, registry_progress as core, source,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Journal, ProtocolProfile, ShardUpdate, Target,
};
use zeroize::Zeroizing;
const CONTROLLERS: [[u8; 32]; 2] = [[0x41; 32], [0x42; 32]];
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-progress-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("create owned fixture directory: {e}"),
            }
        }
        panic!("bounded directory attempts exhausted")
    }
    fn root(&self) -> PathBuf {
        self.0.join("participant")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
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
}
// Explicitly PUBLIC NONSECRET test custody. The wrapping authority below is
// public; these in-memory encrypted records are never production key custody.
struct TestOwnerMaterial {
    identity: OwnerStateIdentity,
    anchor: bfv_query_core::BfvKeyAnchor,
    key: bfv_key_transform::Statement,
    owner: EncryptedOwnerState,
    anchor_record: EncryptedOwnerState,
    ready: EncryptedOwnerState,
}
fn test_authority() -> OwnerStateAuthority {
    OwnerStateAuthority::new(Zeroizing::new([0x5a; 32]))
}
struct Fixture {
    descriptor: Descriptor,
    setup: bfv_query_core::PublicSetup,
    source: source::Statement,
    plain: [u8; 2348],
    material: TestOwnerMaterial,
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let key = [0x71; 32]; // Explicit public nonsecret AEAD fixture authority.
        let owner = compact_store::Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(key));
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let stored = owner
            .seal(
                compact_store::Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                source::statement::limits(),
            )
            .unwrap();
        let suffix: Vec<u8> = include_str!("../../tests/fixtures/index-v3-four-row-suffix.hex")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .flat_map(str::split_whitespace)
            .map(|w| u8::from_str_radix(w, 16).unwrap())
            .collect();
        assert_eq!(suffix.len(), 2224);
        let mut index = stored.commitment().encode().to_vec();
        index.extend(suffix);
        let indexed = owner
            .seal(
                compact_store::Layout {
                    schema: source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &index,
                source::statement::limits(),
            )
            .unwrap();
        let ckey = source::commitment::digest(&source::commitment::key_fields(
            &stored.commitment().encode(),
            key,
            [Val::ONE; 4],
        ));
        let source = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&stored.encode(), &indexed.encode()],
            [stored.commitment(), indexed.commitment()],
            [0; 32],
            source::statement::encode_digest(ckey),
            [0; 32],
        )
        .unwrap();
        let spec = registry200_journal::Application::new([0x77; 32], 11, 12, &source).unwrap();
        let (bfv, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let identity = OwnerStateIdentity {
            scope: KeyScope {
                database: [0x42; 16],
                bfv_key_domain: [0x91; 16],
                epoch: 1,
            },
            record_id: [0x5b; 32],
        };
        let anchor = bfv.key_anchor(&setup, identity.scope.clone()).unwrap();
        let mut epoch = anchor.proof_epoch(&setup).unwrap();
        let key_frame = epoch.prove_key().unwrap();
        let checked = setup
            .verify_key_transform(anchor.public_anchor(), key_frame.as_bytes())
            .unwrap();
        let descriptor = Descriptor::checked(
            ApplicationDescriptor::from_application(&spec).unwrap(),
            [0x51; 32],
            &setup,
            anchor.public_anchor(),
            checked.statement(),
        )
        .unwrap();
        let authority = test_authority();
        let material = TestOwnerMaterial {
            identity: identity.clone(),
            anchor: anchor.public_anchor().clone(),
            key: checked.statement().clone(),
            owner: bfv
                .backup_private_state(&setup, &identity, &authority)
                .unwrap(),
            anchor_record: anchor
                .backup_private_state(&setup, &identity, &authority)
                .unwrap(),
            ready: epoch
                .backup_ready_state(&setup, &identity, &authority)
                .unwrap(),
        };
        for record in [&material.owner, &material.anchor_record, &material.ready] {
            assert!(record.as_bytes().len() <= bfv_query_core::MAX_OWNER_STATE_BYTES);
        }
        drop(epoch);
        drop(anchor);
        drop(bfv);
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        Fixture {
            descriptor,
            setup,
            source,
            plain,
            material,
        }
    })
}
fn genesis(d: &Descriptor) -> Genesis {
    let s = d.source_spec().unwrap();
    Genesis {
        network_id: s.network,
        database: s.database,
        owner: SigningKey::from_bytes(&[0x64; 32])
            .verifying_key()
            .to_bytes(),
        application_commitment: d.id(),
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
            max_updates: 1,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: 4096,
            max_proof_bytes: MANIFEST_BYTES as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: s.initial_shards(),
    }
}
fn id(b: &[u8]) -> BlobId {
    BlobId::new(Sha256::digest(b).into(), b.len() as u64).unwrap()
}

#[test]
fn progress_metadata_has_distinct_domains_complete_pins_and_fixed_bounded_roles() {
    let f = fixture();
    let bytes = f.descriptor.encode();
    assert_eq!(bytes.len(), DESCRIPTOR_BYTES);
    let d = Descriptor::decode(&bytes).unwrap();
    let g = genesis(&d);
    let a = Application::new(d.clone(), &g).unwrap();
    assert!(d.source_spec().unwrap().require_genesis(&g).is_err());
    assert!(crate::Descriptor::decode(&bytes).is_err());
    for at in [352, 384, 416, 479, 620 + 29 * 8, 620 + 32 * 8] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if let Ok(other) = Descriptor::decode(&changed) {
            assert_ne!(other.id(), d.id());
            assert!(Application::new(other, &g).is_err());
        }
    }
    let mut malformed = bytes;
    malformed[620 + 32 * 8..620 + 33 * 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(Descriptor::decode(&malformed).is_err());
    let source = id(b"unproved source");
    let child = id(b"unproved child");
    let catalog = bfv_product_evidence::CatalogId::from_blob(id(&[0x63; 256])).unwrap();
    for m in [
        Manifest::bootstrap([0; 32], source, child).unwrap(),
        Manifest::control([0; 32], [0; 32], source, child).unwrap(),
        Manifest::predicate([0; 32], [0; 32], catalog, child).unwrap(),
    ] {
        let wire = m.encode();
        assert_eq!(wire.len(), 192);
        let decoded = Manifest::decode(&wire).unwrap();
        assert_eq!(decoded.encode(), wire);
        assert!(crate::Manifest::decode(&wire).is_err());
        assert_eq!(decoded.references().len(), 2);
        let refs: Vec<_> = decoded.references().collect();
        assert_eq!(refs[1].ordinal(), 1);
        assert_eq!(refs[1].byte_cap(), core::bootstrap::MAX_FRAME);
        assert_eq!(
            refs[0].byte_cap(),
            if m.lane() == Lane::Predicate {
                bfv_product_evidence::MAX_CATALOG_BYTES
            } else {
                registry200_proof::wire::frame::MAX_SOURCE_BYTES
            }
        );
        let mut bad = wire;
        bad[41] = 1;
        assert!(Manifest::decode(&bad).is_err());
    }
    let too_big = BlobId::new([3; 32], core::bootstrap::MAX_FRAME as u64 + 1).unwrap();
    assert!(Manifest::control([0; 32], [0; 32], source, too_big).is_err());
    let mut inner = InnerRequest {
        operation: Operation::Bootstrap,
        genesis: a.genesis(),
        parent: a.genesis(),
        application: a.source_spec().id(),
        nonce: [1; 32],
        query: [0; 32],
        enrollment: [0; 32],
        opening: [0; 32],
        command: [0; 32],
        packets: f.source.packets.clone(),
    };
    inner.query = intent_query(
        a.source_spec(),
        a.genesis(),
        inner.parent,
        inner.nonce,
        inner.enrollment,
        inner.operation,
    );
    let r = Request::new(&a, Lane::Bootstrap, inner.clone()).unwrap();
    assert_eq!(r.encode().unwrap().len(), REQUEST_BYTES);
    assert!(crate::Request::decode(&r.encode().unwrap()).is_err());
    inner.nonce[0] ^= 1;
    assert!(Request::new(&a, Lane::Bootstrap, inner).is_err());
    let m = Manifest::bootstrap([0; 32], source, child).unwrap();
    let first = OperationId::new(&a, &r, &m).unwrap();
    let other = Manifest::bootstrap([0; 32], source, id(b"another unproved child")).unwrap();
    assert_ne!(first, OperationId::new(&a, &r, &other).unwrap());
}

#[test]
fn progress_setup_claim_rejects_legacy_namespaces_and_noncanonical_extents() {
    for bytes in [
        1u64,
        protocol_storage::MAX_BLOB_BYTES,
        protocol_storage::MAX_BLOB_BYTES + 1,
        MAX_SETUP_BYTES as u64,
    ] {
        let mut b = b"DCSPST02".to_vec();
        b.extend([7; 32]);
        b.extend(bytes.to_le_bytes());
        let count = bytes.div_ceil(protocol_storage::MAX_BLOB_BYTES) as usize;
        b.push(count as u8);
        b.extend([0; 7]);
        for i in 0..count {
            b.extend([i as u8; 32]);
            b.extend(
                (bytes - i as u64 * protocol_storage::MAX_BLOB_BYTES)
                    .min(protocol_storage::MAX_BLOB_BYTES)
                    .to_le_bytes(),
            );
        }
        let claim = SetupClaim::decode(&b).unwrap();
        assert_eq!(claim.encode(), b);
        assert_eq!(claim.parts().len(), count);
        assert!(crate::SetupClaim::decode(&b).is_err());
        let mut wrong = b.clone();
        wrong[88] ^= 1;
        assert!(SetupClaim::decode(&wrong).is_err());
        let mut old = b;
        old[..8].copy_from_slice(b"DCSJSP01");
        assert!(SetupClaim::decode(&old).is_err());
    }
}

#[test]
fn depot_pins_the_whole_progress_descriptor_and_hashes_original_setup_before_sdk_reopen() {
    let f = fixture();
    let g = genesis(&f.descriptor);
    let dir = Directory::new();
    let namespace = [0xb6; 32];
    let application = f.descriptor.id();
    let capacity = 10_000_000_000;
    let quota = ParticipantQuota::create_new(dir.root(), namespace, capacity).unwrap();
    let depot = ProgressDepot::open(quota.depot_budget(), &f.descriptor).unwrap();
    let ingress = depot.ingress();
    let same = ProgressDepot::share(ingress.recording_store(), &f.descriptor).unwrap();
    let shared = same.ingress();
    let before = quota.usage().unwrap().total_bytes();
    let shared_blob = shared
        .retain_public_blob(b"one store, one retained charge")
        .unwrap();
    assert_eq!(
        ingress
            .retain_public_blob(b"one store, one retained charge")
            .unwrap(),
        shared_blob
    );
    assert_eq!(
        quota.usage().unwrap().total_bytes() - before,
        shared_blob.bytes()
    );
    assert_eq!(
        ingress
            .read_public_blob(shared_blob, shared_blob.bytes() as usize)
            .unwrap(),
        b"one store, one retained charge"
    );
    assert!(
        matches!(ProgressDepot::open(quota.depot_budget(),&f.descriptor),
        Err(Error::Storage(bfv_product_evidence::Error::Storage(protocol_storage::Error::Io(ref e))))if e.kind()==std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(
        quota.usage().unwrap().total_bytes() - before,
        shared_blob.bytes()
    );
    let claim = depot.retain_setup(&f.setup).unwrap();
    assert_eq!(claim.application_id(), application);
    let mut other = f.descriptor.encode();
    other[352] ^= 1;
    let other = Descriptor::decode(&other).unwrap();
    assert!(matches!(
        depot.require_descriptor(&other),
        Err(Error::Domain)
    ));
    let different = ProgressDepot::share(shared.recording_store(), &other).unwrap();
    assert!(matches!(
        different.load_setup(&other, &claim),
        Err(Error::Domain)
    ));
    drop(different);
    let fake = ingress
        .retain_public_blob(b"hash-valid bytes are not original setup")
        .unwrap();
    let mut b = b"DCSPST02".to_vec();
    b.extend(application);
    b.extend(fake.bytes().to_le_bytes());
    b.push(1);
    b.extend([0; 7]);
    b.extend(fake.sha256());
    b.extend(fake.bytes().to_le_bytes());
    let wrong = SetupClaim::decode(&b).unwrap();
    assert!(matches!(
        depot.load_setup(&f.descriptor, &wrong),
        Err(Error::Domain)
    ));
    let v = ProgressVerifier::new(f.descriptor.clone(), &g, &claim, depot).unwrap();
    let blob = ingress
        .retain_public_blob(b"later public evidence in the same actual store")
        .unwrap();
    assert_eq!(
        ingress
            .read_public_blob(blob, blob.bytes() as usize)
            .unwrap(),
        b"later public evidence in the same actual store"
    );
    assert!(matches!(
        ingress.read_public_blob(blob, 0),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        shared.read_public_blob(blob, protocol_storage::MAX_BLOB_BYTES as usize + 1),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        ingress.retain_public_blob(&[]),
        Err(Error::ResourceLimit)
    ));
    let used = quota.usage().unwrap().total_bytes();
    drop(v);
    drop(ingress);
    drop(same);
    drop(quota);
    // This last shared handle still owns the SAME actual root lock, even after
    // the original wrapper/quota handles drop. A new quota is not a handoff.
    assert!(
        matches!(ParticipantQuota::open_existing(dir.root(),namespace,capacity),
        Err(protocol_storage::Error::Io(ref e))if e.kind()==std::io::ErrorKind::WouldBlock)
    );
    drop(shared);
    let quota = ParticipantQuota::open_existing(dir.root(), namespace, capacity).unwrap();
    let depot = ProgressDepot::open(quota.depot_budget(), &f.descriptor).unwrap();
    let ingress = depot.ingress();
    let _fresh = ProgressVerifier::new(
        f.descriptor.clone(),
        &g,
        &SetupClaim::decode(&claim.encode()).unwrap(),
        depot,
    )
    .unwrap();
    assert_eq!(
        ingress
            .read_public_blob(blob, blob.bytes() as usize)
            .unwrap(),
        b"later public evidence in the same actual store"
    );
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
}

fn enrollment(f: &Fixture, a: &Application) -> [u8; 32] {
    let e = lifecycle::statement::Expected::bootstrap(&f.source, a.genesis(), a.genesis(), [0; 32])
        .unwrap();
    source::statement::encode_digest(source::commitment::digest(
        &lifecycle::circuit::commitment::enrollment_fields_opening(
            &e,
            &f.plain[124..156].try_into().unwrap(),
            &CONTROLLERS,
            [Val::from_u8(3); 4],
        ),
    ))
}
fn body(a: &Application, r: &Request, m: &Manifest, old: Control) -> Body {
    let mut t = AuthorizedTransition {
        parent: r.inner().parent,
        request: r.encode().unwrap(),
        proof: m.encode(),
        updates: vec![ShardUpdate {
            id: a.source_spec().control_id,
            old: old.heads(a.source_spec()),
            new: Control::Active {
                enrollment: r.inner().enrollment,
                registry: m.next_root(),
            }
            .heads(a.source_spec()),
        }],
        owner_signature: [0; 64],
    };
    t.sign(a.genesis(), &SigningKey::from_bytes(&[0x64; 32]));
    Body::Transition(t)
}
fn operation(
    f: &Fixture,
    a: &Application,
    j: &Journal,
    ingress: &ProgressEvidenceIngress,
    bootstrap: bool,
    enroll: [u8; 32],
    old: [u8; 32],
) -> (Body, OperationId, Manifest) {
    let parent = j.best_validated();
    let op = if bootstrap {
        Operation::Bootstrap
    } else {
        Operation::Transition
    };
    let nonce = if bootstrap { [0xa1; 32] } else { [0xa2; 32] };
    let q = intent_query(
        a.source_spec(),
        a.genesis(),
        parent.block,
        nonce,
        enroll,
        op,
    );
    let mut source = f.source.clone();
    source.request = q;
    source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &source,
        [Val::TWO; 4],
        &f.plain,
    ));
    let source = CanonicalSource::checked_claim(&source).unwrap();
    let raw = source::prove(
        &source,
        &source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        ),
    )
    .unwrap();
    let source_id = ingress.retain_public_blob(raw.as_bytes()).unwrap();
    let (manifest, command) = if bootstrap {
        let e = core::BootstrapExpected::new(&source, a.genesis(), parent.block, enroll).unwrap();
        let w = core::BootstrapWitness::new(
            &e,
            Zeroizing::new(f.plain),
            Zeroizing::new(CONTROLLERS),
            Zeroizing::new([[2; 4], [3; 4], [6; 4]]),
        )
        .unwrap();
        let proof = core::prove_bootstrap(&e, &w, raw.as_bytes()).unwrap();
        (
            Manifest::bootstrap(
                proof.statement().next(),
                source_id,
                ingress.retain_public_blob(proof.as_bytes()).unwrap(),
            )
            .unwrap(),
            [0; 32],
        )
    } else {
        let draft = core::transition::Expected::control(
            &source,
            a.genesis(),
            parent.block,
            enroll,
            old,
            [0; 32],
        )
        .unwrap();
        let c = lifecycle::circuit::model::Command::control(
            lifecycle::circuit::model::Operation::Begin,
            1,
            1,
            0,
        );
        let command =
            core::transition::command_commitment(&draft, &c, 0, &CONTROLLERS, [4; 4]).unwrap();
        let e = core::transition::Expected::control(
            &source,
            a.genesis(),
            parent.block,
            enroll,
            old,
            command,
        )
        .unwrap();
        let w = core::transition::Witness::control(
            &e,
            Zeroizing::new(f.plain),
            Zeroizing::new(CONTROLLERS),
            Zeroizing::new(core::circuit::State::default()),
            Zeroizing::new(c),
            Zeroizing::new([[2; 4], [3; 4], [6; 4], [4; 4], [7; 4], [8; 4]]),
        )
        .unwrap();
        let proof = core::transition::prove(
            &e,
            &w,
            &core::transition::Prerequisites {
                source: raw.as_bytes(),
                query: None,
            },
        )
        .unwrap();
        (
            Manifest::control(
                proof.statement().next(),
                proof.statement().result(),
                source_id,
                ingress.retain_public_blob(proof.as_bytes()).unwrap(),
            )
            .unwrap(),
            command,
        )
    };
    let r = Request::new(
        a,
        if bootstrap {
            Lane::Bootstrap
        } else {
            Lane::Control
        },
        InnerRequest {
            operation: op,
            genesis: a.genesis(),
            parent: parent.block,
            application: a.source_spec().id(),
            nonce,
            query: q,
            enrollment: enroll,
            opening: source::statement::encode_digest(source.claim().open_commitment),
            command,
            packets: source.claim().packets.clone(),
        },
    )
    .unwrap();
    let id = OperationId::new(a, &r, &manifest).unwrap();
    let b = body(
        a,
        &r,
        &manifest,
        if bootstrap {
            Control::Pending
        } else {
            Control::Active {
                enrollment: enroll,
                registry: old,
            }
        },
    );
    (b, id, manifest)
}
fn header(j: &Journal, b: &Body) -> version_journal::Header {
    let parent = match b {
        Body::Transition(t) => t.parent,
        Body::Empty => j.best_validated().block,
    };
    let mut h = j
        .candidate(parent, b, 1001 + j.best_validated().height)
        .unwrap();
    h.mine(16).unwrap();
    h
}

#[test]
fn genuine_new_genesis_bootstrap_and_control_require_actual_proofs_and_own_intent_before_import() {
    let f = fixture();
    let g = genesis(&f.descriptor);
    let a = Application::new(f.descriptor.clone(), &g).unwrap();
    let dir = Directory::new();
    let quota = ParticipantQuota::create_new(dir.root(), [0xb6; 32], 10_000_000_000).unwrap();
    let depot = ProgressDepot::open(quota.depot_budget(), &f.descriptor).unwrap();
    let ingress = depot.ingress();
    assert_eq!(ingress.application_id(), a.id());
    let claim = depot.retain_setup(&f.setup).unwrap();
    let v = ProgressVerifier::new(f.descriptor.clone(), &g, &claim, depot).unwrap();
    let mut journal = Journal::new(g.clone()).unwrap();
    let enroll = enrollment(f, &a);
    let (boot, expected, manifest) = operation(f, &a, &journal, &ingress, true, enroll, [0; 32]);
    let h = header(&journal, &boot);
    let wire = boot.encode(journal.profile()).unwrap();
    let wrong_manifest =
        Manifest::bootstrap([0; 32], manifest.reference(0), manifest.reference(1)).unwrap();
    let request = match &boot {
        Body::Transition(t) => Request::decode(&t.request).unwrap(),
        _ => unreachable!(),
    };
    let wrong = OperationId::new(&a, &request, &wrong_manifest).unwrap();
    let old_head = journal.best_validated();
    let accounted = journal.accounted_bytes();
    assert!(
        v.prepare_import(&mut journal, h.clone(), &wire, 2000, wrong)
            .is_err()
    );
    assert_eq!(journal.best_validated(), old_head);
    assert_eq!(journal.accounted_bytes(), accounted);
    let (pending, checked) = v
        .prepare_import(&mut journal, h, &wire, 2000, expected)
        .unwrap();
    assert_eq!(checked.next_root(), manifest.next_root());
    assert!(checked.product().is_none());
    pending.commit();
    assert!(checked.transition_step().is_none());
    let boot_root = checked.next_root();
    drop(checked);
    let (begin, expected, manifest) =
        operation(f, &a, &journal, &ingress, false, enroll, boot_root);
    let h = header(&journal, &begin);
    let wire = begin.encode(journal.profile()).unwrap();
    let (pending, checked) = v
        .prepare_import(&mut journal, h, &wire, 2000, expected)
        .unwrap();
    assert!(
        !checked
            .transition_step()
            .unwrap()
            .statement()
            .expected()
            .is_predicate()
    );
    assert_eq!(
        checked.transition_step().unwrap().statement().values(),
        checked.transition_statement().unwrap().values()
    );
    assert_eq!(checked.result_root(), manifest.result_root());
    assert_ne!(checked.next_root(), boot_root);
    assert!(checked.product().is_none());
    pending.commit();
    assert_eq!(journal.best_validated().height, 2);
    let root = checked.next_root();
    drop(checked);

    // Keep the genuine Begin child and its exact original q/old root. Only
    // replace Source with hash-valid non-proof bytes and sign that exact Body.
    // Skipping Source verification would accept the still-genuine child.
    let begin_request = Request::decode(match &begin {
        Body::Transition(t) => &t.request,
        _ => unreachable!(),
    })
    .unwrap();
    let bad_source = ingress.retain_public_blob(b"not a Source proof").unwrap();
    let bad_manifest = Manifest::control(
        manifest.next_root(),
        manifest.result_root(),
        bad_source,
        manifest.reference(1),
    )
    .unwrap();
    let expected_bad = OperationId::new(&a, &begin_request, &bad_manifest).unwrap();
    let bad = body(
        &a,
        &begin_request,
        &bad_manifest,
        Control::Active {
            enrollment: enroll,
            registry: boot_root,
        },
    );
    let bad_h = header(&journal, &bad);
    let bad_wire = bad.encode(journal.profile()).unwrap();
    let head = journal.best_validated();
    let accounted = journal.accounted_bytes();
    assert!(
        v.prepare_import(&mut journal, bad_h, &bad_wire, 2000, expected_bad)
            .is_err()
    );
    assert_eq!(journal.best_validated(), head);
    assert_eq!(journal.accounted_bytes(), accounted);

    // Hash-valid garbage is NOT a full product. This is a rejection case only;
    // a genuine new-G Predicate16+118 positive remains a separate integration gate.
    let unproved = bfv_product_evidence::CatalogId::from_blob(
        ingress.retain_public_blob(&[0x63; 256]).unwrap(),
    )
    .unwrap();
    let mut inner = Request::decode(match &begin {
        Body::Transition(t) => &t.request,
        _ => unreachable!(),
    })
    .unwrap()
    .inner()
    .clone();
    inner.parent = journal.best_validated().block;
    inner.nonce = [0xb3; 32];
    inner.query = intent_query(
        a.source_spec(),
        a.genesis(),
        inner.parent,
        inner.nonce,
        enroll,
        Operation::Transition,
    );
    let request = Request::new(&a, Lane::Predicate, inner).unwrap();
    let m = Manifest::predicate([0; 32], [0; 32], unproved, manifest.reference(1)).unwrap();
    let expected = OperationId::new(&a, &request, &m).unwrap();
    let b = body(
        &a,
        &request,
        &m,
        Control::Active {
            enrollment: enroll,
            registry: root,
        },
    );
    let h = header(&journal, &b);
    let wire = b.encode(journal.profile()).unwrap();
    let head = journal.best_validated();
    let accounted = journal.accounted_bytes();
    assert!(
        v.prepare_import(&mut journal, h, &wire, 2000, expected)
            .is_err()
    );
    assert_eq!(journal.best_validated(), head);
    assert_eq!(journal.accounted_bytes(), accounted);
}

#[path = "predicate_tests.rs"]
mod predicate;
