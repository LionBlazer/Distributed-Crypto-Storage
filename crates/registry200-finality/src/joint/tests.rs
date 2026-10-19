//! PUBLIC NONSECRET keys/openings. Actual application proofs and actual Work QCs.
use super::*;
use crate::joint::{CANDIDATE_BYTES, profile_digest};
use bfv_query_core::{Geometry, KeyScope, Owner};
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_storage::ParticipantQuota;
use registry200_joint::{
    Application, Descriptor, JointDepot, JointEvidenceIngress, Manifest, Request, SetupClaim,
};
use registry200_journal::{
    ApplicationDescriptor, Control, Operation, Request as InnerRequest, intent_query,
};
use registry200_proof::{Val, admission, control_kind, lifecycle, source};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Journal, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits, NetworkSeed, QuorumCertificate, SignedVote, Step, VoteContext,
    WorkTicket,
    consensus::{Context, MAX_RECORD_BYTES, Rules},
};
use zeroize::Zeroizing;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-joint-history-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("owned test directory: {e}"),
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
    witness: lifecycle::circuit::Witness,
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let key = [0x71; 32];
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
            include_str!("../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
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
        let app = registry200_journal::Application::new([0x19; 32], 7, 8, &source).unwrap();
        let (bfv, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let anchor = bfv
            .key_anchor(
                &setup,
                KeyScope {
                    database: app.database,
                    bfv_key_domain: [0x88; 16],
                    epoch: 1,
                },
            )
            .unwrap();
        let key_evidence = anchor.prove().unwrap();
        let key_claim = setup
            .verify_key_transform(anchor.public_anchor(), key_evidence.as_bytes())
            .unwrap();
        let descriptor = Descriptor::checked(
            ApplicationDescriptor::from_application(&app).unwrap(),
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
            witness: lifecycle::circuit::Witness {
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
    let app = d.source_spec().unwrap();
    Genesis {
        network_id: app.network,
        database: app.database,
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
            max_headers: 16,
            max_shards: 2,
            max_updates: 1,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: registry200_joint::REQUEST_BYTES as u32,
            max_proof_bytes: registry200_joint::MANIFEST_BYTES as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: app.initial_shards(),
    }
}
fn keys() -> Vec<SigningKey> {
    let mut keys: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    keys
}
fn rules() -> Rules {
    Rules::multi_slot(
        profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap()
}
fn work(rules: &Rules) -> WorkGenesis {
    let seed = NetworkSeed::new(
        rules.seed_domain([0x19; 32]),
        [10; 32],
        [255; 32],
        Limits::new(16, 4).unwrap(),
    )
    .unwrap();
    let tickets = keys()
        .iter()
        .map(|key| WorkTicket::sign(&seed.bootstrap_election(), key, 0).unwrap())
        .collect();
    WorkGenesis::from_bootstrap(seed, tickets).unwrap()
}
fn binding(g: Genesis, claim: SetupClaim) -> JointBinding {
    let rules = rules();
    JointBinding::new(
        [0x19; 32],
        rules.clone(),
        work(&rules),
        g,
        fixture().descriptor.clone(),
        claim,
    )
    .unwrap()
}
fn certificate(context: &Context, d: &JointCandidate, round: u64, start: usize) -> Vec<u8> {
    // Test-only signed evidence uses the unchanged public SDK vote-domain rule.
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/consensus-vote-instance/v1");
    h.update(work_finality::profile_digest());
    h.update(context.id());
    let expected = VoteContext::new(
        context.set(),
        h.finalize().into(),
        context.slot(),
        round,
        Step::Precommit,
        Some(context.value_id(&d.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = keys()[start..start + 3]
        .iter()
        .map(|k| SignedVote::sign(expected, k).unwrap())
        .collect();
    QuorumCertificate::assemble(context.set(), &expected, &votes)
        .unwrap()
        .encode()
        .unwrap()
}
fn empty(journal: &Journal) -> CandidateBlock {
    let body = Body::Empty.encode(journal.profile()).unwrap();
    let mut header = journal
        .candidate(journal.best_validated().block, &Body::Empty, 1001)
        .unwrap();
    header.mine(1).unwrap();
    CandidateBlock::new(header, body).unwrap()
}

#[test]
fn new_binding_requires_joint_genesis_and_exact_closed_multislot_rules() {
    let f = fixture();
    let directory = Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.root(), f.descriptor.id(), 10_000_000_000).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let claim = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let g = genesis(&f.descriptor);
    let r = rules();
    let w = work(&r);
    let good = binding(g.clone(), claim.clone());
    assert_ne!(good.id(), f.descriptor.id());
    assert!(
        f.descriptor
            .source_spec()
            .unwrap()
            .require_genesis(&g)
            .is_err()
    );
    for case in 0..3 {
        let mut foreign = g.clone();
        match case {
            0 => foreign.application_commitment = f.descriptor.source_spec().unwrap().id(),
            1 => foreign.network_id[31] ^= 1,
            _ => foreign.initial_shards[0].heads.data[111] ^= 1,
        }
        assert!(
            JointBinding::new(
                [0x19; 32],
                r.clone(),
                w.clone(),
                foreign,
                f.descriptor.clone(),
                claim.clone()
            )
            .is_err()
        );
    }
    for foreign in [
        Rules::multi_slot(
            crate::profile_digest(),
            CANDIDATE_BYTES as u32,
            32,
            [100, 200, 300],
            10,
            MAX_RECORD_BYTES as u64,
        )
        .unwrap(),
        Rules::new(
            profile_digest(),
            CANDIDATE_BYTES as u32,
            32,
            [100, 200, 300],
            10,
            MAX_RECORD_BYTES as u64,
        )
        .unwrap(),
        Rules::multi_slot(
            profile_digest(),
            CANDIDATE_BYTES as u32 + 1,
            32,
            [100, 200, 300],
            10,
            MAX_RECORD_BYTES as u64,
        )
        .unwrap(),
    ] {
        assert!(
            JointBinding::new(
                [0x19; 32],
                foreign,
                w.clone(),
                g.clone(),
                f.descriptor.clone(),
                claim.clone()
            )
            .is_err()
        );
    }
    // The canonical setup claim is still metadata. Its full association must
    // fail in the concrete Kernel constructor, before any history escapes.
    let mut wrong = claim.encode();
    wrong[8] ^= 1;
    let wrong = SetupClaim::decode(&wrong).unwrap();
    let foreign = JointBinding::new([0x19; 32], r, w, g, f.descriptor.clone(), wrong).unwrap();
    assert_ne!(foreign.id(), good.id());
    assert!(JointHistory::new(foreign, depot).is_err());
    // Failed construction released the sole store gate; reopen the SAME quota.
    JointHistory::new(good, JointDepot::open(quota.depot_budget()).unwrap()).unwrap();
}

#[test]
fn checkpoint_is_strict_bounded_untrusted_metadata_with_distinct_joint_namespace() {
    let f = fixture();
    let directory = Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.root(), f.descriptor.id(), 10_000_000_000).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let setup = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let g = genesis(&f.descriptor);
    let b = binding(g.clone(), setup);
    let block = empty(&Journal::new(g).unwrap());
    let d = JointCandidate::for_context(&b, b.initial_context(), block.header().clone()).unwrap();
    assert_eq!(d.encode().len(), 272);
    assert_eq!(JointCandidate::decode(&d.encode()).unwrap(), d);
    for at in [0, 7] {
        let mut bad = d.encode();
        bad[at] ^= 1;
        assert!(JointCandidate::decode(&bad).is_err());
    }
    let mut zero = d.encode();
    zero[40..48].fill(0);
    assert!(JointCandidate::decode(&zero).is_err());
    let cert = certificate(b.initial_context(), &d, 0, 0);
    let checkpoint = JointCheckpoint::new(d.clone(), 0, cert).unwrap();
    let bytes = checkpoint.encode();
    assert_eq!(JointCheckpoint::decode(&bytes).unwrap().encode(), bytes);
    for n in [0, 8, CANDIDATE_BYTES, bytes.len() - 1] {
        assert!(JointCheckpoint::decode(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(JointCheckpoint::decode(&trailing).is_err());
    let mut bomb = bytes;
    bomb[8 + CANDIDATE_BYTES + 8..8 + CANDIDATE_BYTES + 12]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(JointCheckpoint::decode(&bomb).is_err());
    assert!(JointCheckpoint::new(d, 0, Vec::new()).is_err());
}

#[test]
fn actual_empty_quorum_duplicate_rounds_share_successor_and_invalid_inputs_do_not_advance() {
    let f = fixture();
    let directory = Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.root(), f.descriptor.id(), 10_000_000_000).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let setup = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let g = genesis(&f.descriptor);
    let b = binding(g.clone(), setup);
    let mut history = JointHistory::new(b.clone(), depot).unwrap();
    assert!(history.checked_parent().unwrap().is_none());
    let block = empty(&Journal::new(g).unwrap());
    let original = history.context().unwrap().clone();
    let d = JointCandidate::for_context(&b, &original, block.header().clone()).unwrap();
    let checkpoint = JointCheckpoint::new(d.clone(), 0, certificate(&original, &d, 0, 0)).unwrap();
    let mut damaged = checkpoint.certificate().to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let bad = JointCheckpoint::new(d.clone(), 0, damaged).unwrap();
    assert!(history.apply(&bad, &block).is_err());
    assert_eq!(history.context().unwrap(), &original);
    assert!(history.checked_parent().unwrap().is_none());
    let mut foreign = d.encode();
    foreign[8] ^= 1;
    let foreign = JointCandidate::decode(&foreign).unwrap();
    let foreign =
        JointCheckpoint::new(foreign.clone(), 0, certificate(&original, &foreign, 0, 0)).unwrap();
    assert!(history.apply(&foreign, &block).is_err());
    assert_eq!(history.context().unwrap(), &original);
    let checked = history.apply(&checkpoint, &block).unwrap();
    assert_eq!(checked.control(), Control::Pending);
    let successor = history.context().unwrap().clone();
    assert_eq!(successor.slot(), 2);
    let alternate = JointCheckpoint::new(d.clone(), 7, certificate(&original, &d, 7, 1)).unwrap();
    let again = history.apply(&alternate, &block).unwrap();
    assert_eq!(again.head(), checked.head());
    assert_eq!(again.decision_id(), checked.decision_id());
    assert_eq!(history.context().unwrap(), &successor);
    assert_ne!(checkpoint.certificate(), alternate.certificate());
    assert!(
        matches!(checked.control(), Control::Pending),
        "a QC does not create an Active Registry or SQL lock"
    );
}

fn proof_body(
    f: &Fixture,
    app: &Application,
    journal: &Journal,
    ingress: &JointEvidenceIngress,
    bootstrap: bool,
    enrollment: [u8; 32],
    old: [u8; 32],
) -> (Body, Option<protocol_storage::BlobId>) {
    use lifecycle::{
        circuit::{
            commitment,
            model::{Command, Operation as Op},
        },
        statement::{Expected, Phase, digest},
    };
    let head = journal.best_validated();
    let mut math = f.witness.clone();
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
    let mut claim = f.source.clone();
    claim.request = q;
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        math.salts[0],
        &math.plain,
    ));
    let source = admission::CanonicalSource::checked_claim(&claim).unwrap();
    let source_witness =
        source::circuit::Witness::new([0x71; 32], [Val::ONE; 4], math.salts[0], [255, 0, 255, 128]);
    let source_bytes = source::prove(&source, &source_witness)
        .unwrap()
        .into_bytes();
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
        math.salts[2] = f.witness.salts[4];
        math.salts[4] = [Val::from_u8(9); 4];
        math.command = Some(Command::control(Op::Begin, 1, 1, 0));
        let command = digest(&commitment::command_fields(
            &e,
            &math,
            math.command.as_ref().unwrap(),
        ));
        e.phase = Phase::Transition {
            old: source::statement::decode_digest(old).unwrap(),
            command,
        };
    }
    let prepared = lifecycle::PreparedWitness::new(
        &admission::Expected::checked_claim(&e).unwrap(),
        math.clone(),
    )
    .unwrap();
    let evidence = lifecycle::prove(
        &admission::Expected::checked_claim(&e).unwrap(),
        &prepared,
        &source_bytes,
    )
    .unwrap();
    let statement = evidence.statement();
    let next = source::statement::encode_digest(statement.next);
    let result = source::statement::encode_digest(statement.result);
    let pair = ingress.retain_public_blob(evidence.as_bytes()).unwrap();
    let (manifest, kind) = if bootstrap {
        (Manifest::bootstrap(next, pair).unwrap(), None)
    } else {
        let expected = control_kind::Expected::new(statement).unwrap();
        let fields = commitment::command_fields(&e, &math, math.command.as_ref().unwrap())
            .into_iter()
            .map(|v| v.as_canonical_u64())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let witness = control_kind::circuit::Witness::new(
            &expected,
            control_kind::circuit::Opening::new(fields).unwrap(),
        )
        .unwrap();
        let link = control_kind::prove(
            &expected,
            &witness,
            &control_kind::Prerequisites {
                lifecycle: evidence.as_bytes(),
            },
        )
        .unwrap();
        let kind = ingress.retain_public_blob(link.as_bytes()).unwrap();
        (
            Manifest::control(next, result, pair, kind).unwrap(),
            Some(kind),
        )
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
    let old = app
        .source_spec()
        .control(journal.validated_shards(head).unwrap())
        .unwrap();
    let mut body = AuthorizedTransition {
        parent: head.block,
        request: Request::new(
            app,
            if bootstrap {
                registry200_joint::Lane::Bootstrap
            } else {
                registry200_joint::Lane::Control
            },
            inner,
        )
        .unwrap()
        .encode()
        .unwrap(),
        updates: vec![ShardUpdate {
            id: app.source_spec().control_id,
            old,
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
    (Body::Transition(body), kind)
}
fn proposed(journal: &Journal, body: &Body) -> CandidateBlock {
    let head = journal.best_validated();
    let mut header = journal
        .candidate(head.block, body, 1001 + head.height)
        .unwrap();
    header.mine(1).unwrap();
    CandidateBlock::new(header, body.encode(journal.profile()).unwrap()).unwrap()
}

#[test]
fn genuine_signed_source_bootstrap_begin_and_kind_require_qc_and_replay_in_fresh_history() {
    let f = fixture();
    let directory = Directory::new();
    let capacity = 10_000_000_000;
    let namespace = f.descriptor.id();
    let quota = ParticipantQuota::create_new(directory.root(), namespace, capacity).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let claim = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    let g = genesis(&f.descriptor);
    let app = Application::new(f.descriptor.clone(), &g).unwrap();
    let b = binding(g.clone(), claim);
    let mut history = JointHistory::new(b.clone(), depot).unwrap();
    let builder = Journal::new(g.clone()).unwrap();
    let e = lifecycle::statement::Expected::bootstrap(
        &f.source,
        app.genesis(),
        builder.genesis_head().block,
        [0; 32],
    )
    .unwrap();
    let enrollment = source::statement::encode_digest(source::commitment::digest(
        &lifecycle::circuit::commitment::enrollment_fields(&e, &f.witness),
    ));
    let (boot, _) = proof_body(f, &app, &builder, &ingress, true, enrollment, [0; 32]);
    let boot_block = proposed(&builder, &boot);
    let d =
        JointCandidate::for_context(&b, history.context().unwrap(), boot_block.header().clone())
            .unwrap();
    let boot_qc = JointCheckpoint::new(
        d.clone(),
        0,
        certificate(history.context().unwrap(), &d, 0, 0),
    )
    .unwrap();
    let parent = history.apply(&boot_qc, &boot_block).unwrap();
    let Control::Active { registry, .. } = parent.control() else {
        panic!("real Bootstrap must activate")
    };
    // Building the next header needs only the exact already-checked body state.
    // Reuse history's private owned Journal in this owning test, never expose it.
    let (begin, kind) = proof_body(
        f,
        &app,
        &history.journal,
        &ingress,
        false,
        enrollment,
        registry,
    );
    let begin_block = proposed(&history.journal, &begin);
    let previous = history.context().unwrap().clone();
    let d = JointCandidate::for_context(&b, &previous, begin_block.header().clone()).unwrap();
    let begin_qc = JointCheckpoint::new(d.clone(), 0, certificate(&previous, &d, 0, 0)).unwrap();
    // Genuine owner signature + QC on a new q cannot relabel the old Source/Life/Kind proofs.
    let Body::Transition(ref honest) = begin else {
        unreachable!()
    };
    let mut changed = honest.clone();
    let outer = Request::decode(&changed.request).unwrap();
    let mut inner = outer.inner().clone();
    inner.nonce[31] ^= 1;
    inner.query = intent_query(
        app.source_spec(),
        app.genesis(),
        inner.parent,
        inner.nonce,
        inner.enrollment,
        inner.operation,
    );
    changed.request = Request::new(&app, registry200_joint::Lane::Control, inner)
        .unwrap()
        .encode()
        .unwrap();
    changed.sign(app.genesis(), &SigningKey::from_bytes(&[0x64; 32]));
    let changed = proposed(&history.journal, &Body::Transition(changed));
    let foreign = JointCandidate::for_context(&b, &previous, changed.header().clone()).unwrap();
    let foreign_qc =
        JointCheckpoint::new(foreign.clone(), 0, certificate(&previous, &foreign, 0, 0)).unwrap();
    previous
        .verify_commit(&foreign.encode(), 0, foreign_qc.certificate())
        .unwrap();
    assert!(history.apply(&foreign_qc, &changed).is_err());
    assert_eq!(history.context().unwrap(), &previous);
    assert_eq!(
        history.checked_parent().unwrap().unwrap().head(),
        parent.head()
    );
    let mut bad = honest.clone();
    bad.owner_signature[63] ^= 1;
    let bad = proposed(&history.journal, &Body::Transition(bad));
    let bd = JointCandidate::for_context(&b, &previous, bad.header().clone()).unwrap();
    let bq = JointCheckpoint::new(bd.clone(), 0, certificate(&previous, &bd, 0, 0)).unwrap();
    assert!(history.apply(&bq, &bad).is_err());
    assert_eq!(history.context().unwrap(), &previous);
    let final_parent = history.apply(&begin_qc, &begin_block).unwrap();
    let expected_context = history.context().unwrap().clone();
    assert_ne!(final_parent.control(), parent.control());
    assert_eq!(final_parent.slot(), 2);
    let alternate = JointCheckpoint::new(d.clone(), 7, certificate(&previous, &d, 7, 1)).unwrap();
    assert_eq!(
        history
            .apply(&alternate, &begin_block)
            .unwrap()
            .decision_id(),
        final_parent.decision_id()
    );
    assert_eq!(history.context().unwrap(), &expected_context);
    let used = quota.usage().unwrap().total_bytes();
    drop(history);
    drop(ingress);
    drop(quota);
    let quota = ParticipantQuota::open_existing(directory.root(), namespace, capacity).unwrap();
    let mut fresh = JointHistory::new(b, JointDepot::open(quota.depot_budget()).unwrap()).unwrap();
    fresh.apply(&boot_qc, &boot_block).unwrap();
    let replayed = fresh.apply(&begin_qc, &begin_block).unwrap();
    assert_eq!(replayed.head(), final_parent.head());
    assert_eq!(replayed.control(), final_parent.control());
    assert_eq!(fresh.context().unwrap(), &expected_context);
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
    let before = HistorySnapshot::read(&fresh);
    let kind = kind.expect("the genuine Begin retained its actual Kind proof");
    let digest = kind
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let path = quota
        .depot_directory()
        .join(format!("{digest}-{:016x}.blob", kind.bytes()));
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(path.canonicalize().unwrap(), path);
    assert_eq!(metadata.len(), kind.bytes());
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut original = [0];
    file.read_exact(&mut original).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[original[0] ^ 1]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    // A previously successful QC/parent cannot bypass freshly read proof bytes.
    assert!(matches!(
        fresh.apply(&begin_qc, &begin_block),
        Err(Error::Journal(
            version_journal::Error::RejectedComputationProof
        ))
    ));
    assert_eq!(HistorySnapshot::read(&fresh), before);
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&original).unwrap(); // Repair only this explicitly owned test fault.
    file.sync_all().unwrap();
    drop(file);
    fs::remove_file(&path).unwrap(); // Last fault: a missing tracked file poisons the shared ledger.
    assert!(matches!(
        fresh.apply(&begin_qc, &begin_block),
        Err(Error::Journal(
            version_journal::Error::RejectedComputationProof
        ))
    ));
    assert_eq!(HistorySnapshot::read(&fresh), before);
    assert!(matches!(
        quota.depot_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    // Keyless reconstruction only: no durable signer floor, freshness or SQL grant.
}

#[derive(Debug, PartialEq, Eq)]
struct HistorySnapshot {
    context: Context,
    head: version_journal::HeadRef,
    slot: u64,
    decision: Hash,
    control: Control,
    floor: version_journal::HeadRef,
    best: version_journal::HeadRef,
    bytes: u64,
}
impl HistorySnapshot {
    fn read(history: &JointHistory) -> Self {
        let parent = history.checked_parent().unwrap().unwrap();
        Self {
            context: history.context().unwrap().clone(),
            head: parent.head(),
            slot: parent.slot(),
            decision: parent.decision_id(),
            control: parent.control(),
            floor: history.journal.ancestry_floor(),
            best: history.journal.best_validated(),
            bytes: history.journal.accounted_bytes(),
        }
    }
}
