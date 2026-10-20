//! PUBLIC NONSECRET fixtures. Format checks grant no computation or SQL authority.
use super::*;
use bfv_query_core::{Geometry, KeyScope, Owner};
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_storage::{BlobId, ParticipantQuota};
use registry200_journal::{
    ApplicationDescriptor, Control, Operation, Request as InnerRequest, intent_query,
};
use registry200_proof::{Val, admission, control_kind, lifecycle, source};
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

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-joint-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("create owned directory: {e}"),
            }
        }
        panic!("bounded directory allocation exhausted")
    }
    fn root(&self) -> PathBuf {
        self.0.join("participant")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let root = self.root();
        // Only exact owned canonical directories and regular direct children;
        // no recursive removal or traversal of unexpected links/subtrees.
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
struct Fixture {
    descriptor: Descriptor,
    setup: bfv_query_core::PublicSetup,
    source: source::Statement,
    mathematical: lifecycle::circuit::Witness,
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let key = [0x71; 32]; // Public test AEAD key, never participant material.
        let owner = compact_store::Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(key));
        let limits = source::statement::limits();
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
                limits,
            )
            .unwrap();
        let suffix: Vec<u8> =
            include_str!("../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
                .lines()
                .filter(|l| !l.starts_with('#'))
                .flat_map(str::split_whitespace)
                .map(|x| u8::from_str_radix(x, 16).unwrap())
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
                limits,
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
        let spec = registry200_journal::Application::new([0x19; 32], 7, 8, &source).unwrap();
        let (bfv, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let anchor = bfv
            .key_anchor(
                &setup,
                KeyScope {
                    database: spec.database,
                    bfv_key_domain: [0x88; 16],
                    epoch: 1,
                },
            )
            .unwrap();
        let proof = anchor.prove().unwrap();
        let key_claim = setup
            .verify_key_transform(anchor.public_anchor(), proof.as_bytes())
            .unwrap();
        let descriptor = Descriptor::checked(
            ApplicationDescriptor::from_application(&spec).unwrap(),
            [0x51; 32],
            &setup,
            anchor.public_anchor(),
            key_claim.statement(),
        )
        .unwrap();
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        Fixture {
            descriptor,
            setup,
            source,
            mathematical: lifecycle::circuit::Witness {
                plain,
                controllers: [[0x41; 32], [0x42; 32]],
                salts: [
                    [Val::TWO; 4],
                    [Val::from_u8(3); 4],
                    [Val::from_u8(4); 4],
                    [Val::from_u8(5); 4],
                    [Val::from_u8(6); 4],
                    [Val::from_u8(7); 4],
                ],
                old: lifecycle::circuit::model::Registry::default(),
                command: None,
            },
        }
    })
}
fn genesis(d: &Descriptor) -> Genesis {
    let source = d.source_spec().unwrap();
    Genesis {
        network_id: source.network,
        database: source.database,
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
        initial_shards: source.initial_shards(),
    }
}
fn id(bytes: &[u8]) -> BlobId {
    BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap()
}

#[test]
fn descriptor_pins_new_genesis_full_setup_all_key33_and_original_source_spec() {
    let f = fixture();
    let bytes = f.descriptor.encode();
    assert_eq!(bytes.len(), 896);
    let d = Descriptor::decode(&bytes).unwrap();
    assert_eq!(d.encode(), bytes);
    let g = genesis(&d);
    Application::new(d.clone(), &g).unwrap();
    assert!(
        d.source_spec().unwrap().require_genesis(&g).is_err(),
        "old verifier must stay strict"
    );
    for at in [0, 8, 39, 40, 884, 895] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(Descriptor::decode(&bad).is_err(), "grammar offset {at}");
    }
    for at in [352, 384, 416, 479, 620 + 29 * 8, 620 + 32 * 8] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if let Ok(foreign) = Descriptor::decode(&changed) {
            assert_ne!(foreign.id(), d.id());
            assert!(Application::new(foreign, &g).is_err());
        }
    }
    let mut noncanonical = bytes;
    noncanonical[620 + 32 * 8..620 + 33 * 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(Descriptor::decode(&noncanonical).is_err());
    for case in 0..4 {
        let mut other = g.clone();
        match case {
            0 => other.network_id[0] ^= 1,
            1 => other.database[0] ^= 1,
            2 => other.application_commitment = d.source_spec().unwrap().id(),
            _ => other.initial_shards[0].heads.data[111] ^= 1,
        }
        assert!(Application::new(d.clone(), &other).is_err());
    }
}

#[test]
fn manifest_has_exact_lane_roles_canonical_roots_and_preio_caps() {
    let next = [0; 32];
    let pair = id(b"unproved pair");
    let link = id(b"unproved link");
    let c = bfv_product_evidence::CatalogId::from_blob(id(&[0x63; 256])).unwrap(); // Explicitly unproved catalog bytes.
    for m in [
        Manifest::bootstrap(next, pair).unwrap(),
        Manifest::control(next, next, pair, link).unwrap(),
        Manifest::acquire(next, next, c, pair, link).unwrap(),
    ] {
        let bytes = m.encode();
        assert_eq!(bytes.len(), 232);
        let decoded = Manifest::decode(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes);
        let expected = match m.lane() {
            Lane::Bootstrap => vec![(
                ManifestRole::LifecyclePair,
                pair,
                registry200_proof::wire::maximum_bundle_bytes(),
            )],
            Lane::Control => vec![
                (
                    ManifestRole::LifecyclePair,
                    pair,
                    registry200_proof::wire::maximum_bundle_bytes(),
                ),
                (
                    ManifestRole::ControlKind,
                    link,
                    control_kind::wire::MAX_FRAME,
                ),
            ],
            Lane::Acquire => vec![
                (
                    ManifestRole::ProductCatalog,
                    c.blob_id(),
                    bfv_product_evidence::MAX_CATALOG_BYTES,
                ),
                (
                    ManifestRole::LifecycleChild,
                    pair,
                    registry200_proof::wire::frame::MAX_CHILD_BYTES,
                ),
                (
                    ManifestRole::PredicateAcquire,
                    link,
                    registry200_proof::predicate_acquire::wire::MAX_FRAME,
                ),
            ],
        };
        assert_eq!(decoded.references().len(), expected.len());
        for (ordinal, (reference, expected)) in decoded.references().zip(&expected).enumerate() {
            assert_eq!(reference.ordinal(), ordinal);
            assert_eq!(
                (reference.role(), reference.blob_id(), reference.byte_cap()),
                *expected
            );
        }
        let mut backwards = decoded.references().rev();
        for expected in expected.iter().rev() {
            let reference = backwards.next().unwrap();
            assert_eq!(
                (reference.role(), reference.blob_id(), reference.byte_cap()),
                *expected
            );
        }
        assert_eq!(backwards.len(), 0);
        assert!(backwards.next().is_none());
        assert!(backwards.next().is_none());
        assert_eq!(
            decoded.encode(),
            bytes,
            "reference access cannot change canonical bytes"
        );
        for at in [0, 8, 39, 41, 47] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(Manifest::decode(&bad).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Manifest::decode(&trailing).is_err());
        for n in [0, 8, 111, 231] {
            assert!(Manifest::decode(&bytes[..n]).is_err());
        }
        let mut invalid_root = bytes.clone();
        invalid_root[48..56].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        assert!(Manifest::decode(&invalid_root).is_err());
    }
    let mut bootstrap = Manifest::bootstrap(next, pair).unwrap().encode();
    bootstrap[192..224].copy_from_slice(link.sha256());
    bootstrap[224..232].copy_from_slice(&link.bytes().to_le_bytes());
    assert!(
        Manifest::decode(&bootstrap).is_err(),
        "unused proof reference must be all zero"
    );
    let too_large = BlobId::new(
        [0x55; 32],
        registry200_proof::wire::maximum_bundle_bytes() as u64 + 1,
    )
    .unwrap();
    assert!(Manifest::bootstrap(next, too_large).is_err());
    assert!(
        Manifest::control(
            next,
            next,
            pair,
            BlobId::new([1; 32], control_kind::wire::MAX_FRAME as u64 + 1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn request_binds_outer_application_and_unchanged_inner_intent_without_q_rewriting() {
    let f = fixture();
    let g = genesis(&f.descriptor);
    let app = Application::new(f.descriptor.clone(), &g).unwrap();
    let spec = app.source_spec();
    let mut inner = InnerRequest {
        operation: Operation::Bootstrap,
        genesis: app.genesis(),
        parent: [0x21; 32],
        application: spec.id(),
        nonce: [0x22; 32],
        query: [0; 32],
        enrollment: [0; 32],
        opening: [0; 32],
        command: [0; 32],
        packets: f.source.packets.clone(),
    };
    inner.query = intent_query(
        spec,
        app.genesis(),
        inner.parent,
        inner.nonce,
        inner.enrollment,
        inner.operation,
    );
    let request = Request::new(&app, Lane::Bootstrap, inner.clone()).unwrap();
    let bytes = request.encode().unwrap();
    assert_eq!(bytes.len(), 2764);
    Request::decode(&bytes)
        .unwrap()
        .require_application(&app)
        .unwrap();
    assert!(Request::new(&app, Lane::Control, inner.clone()).is_err());
    for case in 0..4 {
        let mut other = inner.clone();
        match case {
            0 => other.nonce[31] ^= 1,
            1 => other.genesis[31] ^= 1,
            2 => other.query[31] ^= 1,
            _ => other.application = app.id(),
        }
        assert!(Request::new(&app, Lane::Bootstrap, other).is_err());
    }
    for at in [0, 8, 9, 15] {
        let mut bad = bytes.clone();
        bad[at] = 0xff;
        assert!(Request::decode(&bad).is_err());
    }
    let mut foreign = bytes.clone();
    foreign[47] ^= 1;
    assert!(
        Request::decode(&foreign)
            .unwrap()
            .require_application(&app)
            .is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
}

#[test]
fn setup_claim_enforces_one_or_two_exact_chunks_without_sdk_or_unbounded_allocation() {
    for n in [
        1usize,
        32 * 1024 * 1024,
        32 * 1024 * 1024 + 1,
        MAX_SETUP_BYTES,
    ] {
        let mut b = b"DCSJSP01".to_vec();
        b.extend_from_slice(&[7; 32]);
        b.extend_from_slice(&(n as u64).to_le_bytes());
        let count = n.div_ceil(32 * 1024 * 1024);
        b.push(count as u8);
        b.extend_from_slice(&[0; 7]);
        for i in 0..count {
            let len = (n - i * 32 * 1024 * 1024).min(32 * 1024 * 1024);
            b.extend_from_slice(&[i as u8; 32]);
            b.extend_from_slice(&(len as u64).to_le_bytes());
        }
        let claim = SetupClaim::decode(&b).unwrap();
        assert_eq!(claim.encode(), b);
        assert_eq!(claim.application_id(), [7; 32]);
        assert_eq!(claim.bytes(), n as u64);
        assert_eq!(claim.parts().len(), count);
        assert_eq!(
            claim.parts().iter().map(|id| id.bytes()).sum::<u64>(),
            n as u64
        );
        for (i, part) in claim.parts().iter().enumerate() {
            assert_eq!(*part.sha256(), [i as u8; 32]);
            assert_eq!(
                part.bytes(),
                (n - i * 32 * 1024 * 1024).min(32 * 1024 * 1024) as u64
            );
        }
        assert_eq!(
            claim.encode(),
            b,
            "readonly getters do not authenticate or rewrite the setup claim"
        );
        for at in [0, 48, 49, 55, 88] {
            let mut bad = b.clone();
            bad[at] ^= 0xff;
            assert!(SetupClaim::decode(&bad).is_err());
        }
        let mut bad = b.clone();
        bad[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(SetupClaim::decode(&bad).is_err());
        let mut trailing = b;
        trailing.push(0);
        assert!(SetupClaim::decode(&trailing).is_err());
    }
}

#[test]
fn setup_and_future_ingress_share_one_depot_reopen_and_never_accept_a_hash_as_setup() {
    let f = fixture();
    let dir = Directory::new();
    let namespace = f.descriptor.id();
    let capacity = 10_000_000_000;
    let quota = ParticipantQuota::create_new(dir.root(), namespace, capacity).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let claim = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let fake = ingress
        .retain_public_blob(b"not an original public setup")
        .unwrap();
    let mut wrong = b"DCSJSP01".to_vec();
    wrong.extend_from_slice(&namespace);
    wrong.extend_from_slice(&fake.bytes().to_le_bytes());
    wrong.push(1);
    wrong.extend_from_slice(&[0; 7]);
    wrong.extend_from_slice(fake.sha256());
    wrong.extend_from_slice(&fake.bytes().to_le_bytes());
    let wrong = SetupClaim::decode(&wrong).unwrap();
    assert!(
        matches!(depot.load_setup(&f.descriptor, &wrong), Err(Error::Domain)),
        "CAS validity must not bypass the independently pinned full-setup hashes"
    );
    let g = genesis(&f.descriptor);
    let verifier = JointVerifier::new(f.descriptor.clone(), &g, &claim, depot).unwrap();
    let bytes = b"public bytes arriving AFTER the verifier took ownership";
    let blob = ingress.retain_public_blob(bytes).unwrap();
    assert_eq!(ingress.read_public_blob(blob, bytes.len()).unwrap(), bytes);
    assert!(matches!(
        ingress.read_public_blob(blob, 0),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        ingress.retain_public_blob(&[]),
        Err(Error::ResourceLimit)
    ));
    let unproved = [0x63; 256];
    let catalog =
        bfv_product_evidence::CatalogId::from_blob(ingress.retain_public_blob(&unproved).unwrap())
            .unwrap();
    let before_catalog_read = quota.usage().unwrap().total_bytes();
    assert!(
        matches!(
            ingress.catalog_claim(catalog),
            Err(Error::Storage(bfv_product_evidence::Error::Encoding))
        ),
        "hash-valid public bytes must still pass the actual canonical catalog parser"
    );
    assert_eq!(
        ingress
            .read_public_blob(catalog.blob_id(), unproved.len())
            .unwrap(),
        unproved
    );
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        before_catalog_read,
        "catalog metadata access uses the same ledger without retaining any new file"
    );
    let used = quota.usage().unwrap().total_bytes();
    drop(verifier);
    drop(ingress);
    drop(quota);
    let quota = ParticipantQuota::open_existing(dir.root(), namespace, capacity).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let reopened_ingress = depot.ingress();
    let _fresh = JointVerifier::new(
        f.descriptor.clone(),
        &g,
        &SetupClaim::decode(&claim.encode()).unwrap(),
        depot,
    )
    .unwrap();
    assert!(matches!(
        reopened_ingress.catalog_claim(catalog),
        Err(Error::Storage(bfv_product_evidence::Error::Encoding))
    ));
    assert_eq!(
        reopened_ingress
            .read_public_blob(catalog.blob_id(), unproved.len())
            .unwrap(),
        unproved
    );
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
}

fn make_body(
    f: &Fixture,
    app: &Application,
    journal: &Journal,
    ingress: &JointEvidenceIngress,
    bootstrap: bool,
    enrollment: [u8; 32],
    old: [u8; 32],
) -> Body {
    use lifecycle::{
        circuit::{
            commitment,
            model::{Command, Operation as Op},
        },
        statement::{Expected, Phase, digest},
    };
    let head = journal.best_validated();
    let mut mathematical = f.mathematical.clone();
    let operation = if bootstrap {
        Operation::Bootstrap
    } else {
        Operation::Transition
    };
    let nonce = if bootstrap { [0xa1; 32] } else { [0xa2; 32] };
    let q = intent_query(
        app.source_spec(),
        app.genesis(),
        head.block,
        nonce,
        enrollment,
        operation,
    );
    let mut source = f.source.clone();
    source.request = q;
    source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &source,
        mathematical.salts[0],
        &mathematical.plain,
    ));
    let source = admission::CanonicalSource::checked_claim(&source).unwrap();
    let witness = source::circuit::Witness::new(
        [0x71; 32],
        [Val::ONE; 4],
        mathematical.salts[0],
        [255, 0, 255, 128],
    );
    let source_bytes = source::prove(&source, &witness).unwrap().into_bytes();
    let mut e = if bootstrap {
        Expected::bootstrap(source.claim(), app.genesis(), head.block, enrollment).unwrap()
    } else {
        Expected::transition(
            source.claim(),
            app.genesis(),
            head.block,
            enrollment,
            old,
            [0; 32],
        )
        .unwrap()
    };
    if !bootstrap {
        mathematical.salts[2] = f.mathematical.salts[4];
        mathematical.salts[4] = [Val::from_u8(9); 4];
        mathematical.command = Some(Command::control(Op::Begin, 1, 1, 0));
        let command = digest(&commitment::command_fields(
            &e,
            &mathematical,
            mathematical.command.as_ref().unwrap(),
        ));
        e.phase = Phase::Transition {
            old: source::statement::decode_digest(old).unwrap(),
            command,
        };
    }
    let checked = admission::Expected::checked_claim(&e).unwrap();
    let prepared = lifecycle::PreparedWitness::new(&checked, mathematical.clone()).unwrap();
    let life = lifecycle::prove(&checked, &prepared, &source_bytes).unwrap();
    let statement = life.statement();
    let next = source::statement::encode_digest(statement.next);
    let result = source::statement::encode_digest(statement.result);
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    let manifest = if bootstrap {
        Manifest::bootstrap(next, pair).unwrap()
    } else {
        let expected = control_kind::Expected::new(statement).unwrap();
        let fields =
            commitment::command_fields(&e, &mathematical, mathematical.command.as_ref().unwrap());
        let opening = control_kind::circuit::Opening::new(
            fields
                .into_iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let witness = control_kind::circuit::Witness::new(&expected, opening).unwrap();
        let kind = control_kind::prove(
            &expected,
            &witness,
            &control_kind::Prerequisites {
                lifecycle: life.as_bytes(),
            },
        )
        .unwrap();
        Manifest::control(
            next,
            result,
            pair,
            ingress.retain_public_blob(kind.as_bytes()).unwrap(),
        )
        .unwrap()
    };
    let inner = InnerRequest {
        operation,
        genesis: app.genesis(),
        parent: head.block,
        application: app.source_spec().id(),
        nonce,
        query: q,
        enrollment,
        opening: source::statement::encode_digest(source.claim().open_commitment),
        command: match e.phase {
            Phase::Bootstrap => [0; 32],
            Phase::Transition { command, .. } => source::statement::encode_digest(command),
        },
        packets: source.claim().packets.clone(),
    };
    let old_heads = app
        .source_spec()
        .control(journal.validated_shards(head).unwrap())
        .unwrap();
    let mut body = AuthorizedTransition {
        parent: head.block,
        request: Request::new(
            app,
            if bootstrap {
                Lane::Bootstrap
            } else {
                Lane::Control
            },
            inner,
        )
        .unwrap()
        .encode()
        .unwrap(),
        updates: vec![ShardUpdate {
            id: app.source_spec().control_id,
            old: old_heads,
            new: Control::Active {
                enrollment,
                registry: next,
            }
            .heads(app.source_spec()),
        }],
        proof: manifest.encode(),
        owner_signature: [0; 64],
    };
    body.sign(app.genesis(), &SigningKey::from_bytes(&[0x64; 32]));
    Body::Transition(body)
}

#[test]
fn real_source_bootstrap_and_non_acquire_begin_are_signed_admitted_and_freshly_replayed() {
    let f = fixture();
    let g = genesis(&f.descriptor);
    let app = Application::new(f.descriptor.clone(), &g).unwrap();
    let dir = Directory::new();
    let capacity = 10_000_000_000;
    let namespace = f.descriptor.id();
    let quota = ParticipantQuota::create_new(dir.root(), namespace, capacity).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let claim = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let verifier = JointVerifier::new(f.descriptor.clone(), &g, &claim, depot).unwrap();
    let mut journal = Journal::new(g.clone()).unwrap();
    let e = lifecycle::statement::Expected::bootstrap(
        &f.source,
        app.genesis(),
        journal.genesis_head().block,
        [0; 32],
    )
    .unwrap();
    let enrollment = source::statement::encode_digest(source::commitment::digest(
        &lifecycle::circuit::commitment::enrollment_fields(&e, &f.mathematical),
    ));
    let boot = make_body(f, &app, &journal, &ingress, true, enrollment, [0; 32]);
    journal
        .verify_candidate(journal.best_validated().block, &boot, &verifier)
        .unwrap();
    let mut header = journal
        .candidate(journal.best_validated().block, &boot, 1001)
        .unwrap();
    header.mine(1).unwrap();
    let boot_wire = boot.encode(journal.profile()).unwrap();
    journal
        .import_block(header.clone(), &boot_wire, 1001, &verifier)
        .unwrap();
    let old = match Control::decode(
        app.source_spec(),
        app.source_spec()
            .control(journal.validated_shards(journal.best_validated()).unwrap())
            .unwrap(),
    )
    .unwrap()
    {
        Control::Active { registry, .. } => registry,
        _ => panic!("bootstrap must activate"),
    };
    let begin = make_body(f, &app, &journal, &ingress, false, enrollment, old);
    // An honestly re-signed Control body with missing Kind must not gain admission.
    let Body::Transition(ref honest) = begin else {
        unreachable!()
    };
    let mut hostile = honest.clone();
    let original = Manifest::decode(&hostile.proof).unwrap();
    let fake = ingress.retain_public_blob(b"not a Kind proof").unwrap();
    hostile.proof = Manifest::control(
        original.next_root(),
        original.result_root(),
        original.reference(0).unwrap(),
        fake,
    )
    .unwrap()
    .encode();
    hostile.sign(app.genesis(), &SigningKey::from_bytes(&[0x64; 32]));
    assert!(matches!(
        journal.verify_candidate(
            journal.best_validated().block,
            &Body::Transition(hostile),
            &verifier
        ),
        Err(version_journal::Error::RejectedComputationProof)
    ));
    journal
        .verify_candidate(journal.best_validated().block, &begin, &verifier)
        .unwrap();
    let mut second = journal
        .candidate(journal.best_validated().block, &begin, 1002)
        .unwrap();
    second.mine(1).unwrap();
    let begin_wire = begin.encode(journal.profile()).unwrap();
    journal
        .import_block(second.clone(), &begin_wire, 1002, &verifier)
        .unwrap();
    let expected = journal.best_validated();
    let shards = journal.validated_shards(expected).unwrap().to_vec();
    let used = quota.usage().unwrap().total_bytes();
    drop(verifier);
    drop(ingress);
    drop(quota);
    let quota = ParticipantQuota::open_existing(dir.root(), namespace, capacity).unwrap();
    let fresh = JointVerifier::new(
        f.descriptor.clone(),
        &g,
        &SetupClaim::decode(&claim.encode()).unwrap(),
        JointDepot::open(quota.depot_budget()).unwrap(),
    )
    .unwrap();
    let mut replay = Journal::new(g).unwrap();
    replay
        .import_block(header, &boot_wire, 1001, &fresh)
        .unwrap();
    replay
        .import_block(second, &begin_wire, 1002, &fresh)
        .unwrap();
    assert_eq!(replay.best_validated(), expected);
    assert_eq!(
        replay.validated_shards(expected).unwrap(),
        shards.as_slice()
    );
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
    // This proves local signed mathematical admission/reopen, not finality,
    // a private Acquire/product path, delegated rights or a live SQL lease.
}

#[test]
fn genuine_source_pending_import_drops_unpublished_and_known_state_still_reads_actual_proof() {
    let f = fixture();
    let g = genesis(&f.descriptor);
    let app = Application::new(f.descriptor.clone(), &g).unwrap();
    let dir = Directory::new();
    let quota =
        ParticipantQuota::create_new(dir.root(), f.descriptor.id(), 10_000_000_000).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let claim = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let verifier = JointVerifier::new(f.descriptor.clone(), &g, &claim, depot).unwrap();
    let mut journal = Journal::new(g).unwrap();
    let e = lifecycle::statement::Expected::bootstrap(
        &f.source,
        app.genesis(),
        journal.genesis_head().block,
        [0; 32],
    )
    .unwrap();
    let enrollment = source::statement::encode_digest(source::commitment::digest(
        &lifecycle::circuit::commitment::enrollment_fields(&e, &f.mathematical),
    ));
    let body = make_body(f, &app, &journal, &ingress, true, enrollment, [0; 32]);
    let mut header = journal
        .candidate(journal.genesis_head().block, &body, 1001)
        .unwrap();
    header.mine(1).unwrap();
    let wire = body.encode(journal.profile()).unwrap();
    let snapshot = |j: &Journal| {
        (
            j.header_count(),
            j.accounted_bytes(),
            j.best_header(),
            j.best_validated(),
            j.ancestry_floor(),
        )
    };
    let before = snapshot(&journal);
    let used = quota.usage().unwrap();

    // Real signed Source/Life verification precedes an unpublished Drop.
    let pending = journal
        .prepare_import(header.clone(), &wire, 1001, &verifier)
        .unwrap();
    drop(pending);
    assert_eq!(snapshot(&journal), before);
    assert_eq!(quota.usage().unwrap(), used);
    journal
        .prepare_import(header.clone(), &wire, 1001, &verifier)
        .unwrap()
        .commit();
    let checked = snapshot(&journal);
    assert_eq!(journal.best_validated().block, header.id());
    journal
        .prepare_import(header.clone(), &wire, 1001, &verifier)
        .unwrap()
        .commit();
    assert_eq!(snapshot(&journal), checked);

    // Corrupt the SAME retained premise after success. A known state must not
    // make fresh preparation accept a hash/old application result as proof.
    let Body::Transition(body) = body else {
        unreachable!()
    };
    let pair = Manifest::decode(&body.proof).unwrap().reference(0).unwrap();
    let hex: String = pair.sha256().iter().map(|b| format!("{b:02x}")).collect();
    let path = quota
        .depot_directory()
        .join(format!("{hex}-{:016x}.blob", pair.bytes()));
    let original = fs::read(&path).unwrap();
    let mut corrupt = original.clone();
    let at = corrupt.len() - 1;
    corrupt[at] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert!(matches!(
        journal.prepare_import(header, &wire, 1001, &verifier),
        Err(version_journal::Error::RejectedComputationProof)
    ));
    assert_eq!(snapshot(&journal), checked);
    assert_eq!(quota.usage().unwrap(), used);
    fs::write(path, original).unwrap(); // Repair only this explicit public-fixture fault.
    // This is real Bootstrap math, not a substitute for the full Acquire OS gate.
}

#[test]
fn recording_ingress_keeps_the_same_depot_and_ledger_after_the_joint_owner_moves() {
    let directory = Directory::new();
    let namespace = [0xd1; 32];
    let quota = ParticipantQuota::create_new(directory.root(), namespace, 1024 * 1024).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let recorder = ingress.recording_store();
    let before = quota.usage().unwrap();
    let public = b"PUBLIC joint ingress, not a proof or completed catalog";
    let id = recorder.retain_public_blob(public).unwrap();
    assert_eq!(ingress.read_public_blob(id, public.len()).unwrap(), public);
    assert_eq!(ingress.retain_public_blob(public).unwrap(), id);
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        before.total_bytes() + public.len() as u64
    );
    assert!(JointDepot::open(quota.depot_budget()).is_err());
    drop(depot);
    drop(ingress);
    drop(quota);
    assert!(ParticipantQuota::open_existing(directory.root(), namespace, 1024 * 1024).is_err());
    assert_eq!(recorder.read_public_blob(id, public.len()).unwrap(), public);
    drop(recorder);
    let quota = ParticipantQuota::open_existing(directory.root(), namespace, 1024 * 1024).unwrap();
    let reopened = JointDepot::open(quota.depot_budget()).unwrap();
    assert_eq!(
        reopened
            .ingress()
            .read_public_blob(id, public.len())
            .unwrap(),
        public
    );
    // No cryptographic operation or accepted application state is manufactured.
}
