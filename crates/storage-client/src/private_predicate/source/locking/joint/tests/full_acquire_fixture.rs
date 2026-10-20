//! PUBLIC NONSECRET owning fixtures; no local QC assembler or selected FHE answer.
use super::*;
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_joint::{
    Application as JointApplication, Descriptor, JointDepot, JointEvidenceIngress, Manifest,
};
use registry200_journal::{
    ApplicationDescriptor, Operation as JournalOperation, Request as InnerRequest, intent_query,
};
use registry200_proof::{
    admission, control_kind,
    lifecycle::{
        self,
        circuit::{
            self as life, commitment as lc,
            model::{Command, Operation},
        },
    },
    source::{self, statement as ss},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Header, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits as WorkLimits, NetworkSeed, WorkTicket,
    consensus::{MAX_RECORD_BYTES, Rules},
};

pub(in crate::private_predicate::source::locking::joint) const CONTROLLERS: [[u8; 32]; 2] =
    [[0x84; 32], [0xa5; 32]];
pub(in crate::private_predicate::source::locking::joint) const ENROLL_SALT: [u64; 4] =
    [11, 12, 13, 14];
pub(in crate::private_predicate::source::locking::joint) const CAPACITY: u64 = 10_000_000_000;
pub(in crate::private_predicate::source::locking::joint) const TIMEOUTS: [u64; 3] = [180_000; 3];
pub(in crate::private_predicate::source::locking::joint) const DELTA: u64 = 1_000;

pub(in crate::private_predicate::source::locking::joint) struct Directory(PathBuf);
impl Directory {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-four-validator-owner-Acquire-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => panic!("Owned test directory: {e}"),
            }
        }
        panic!("Bounded owned directory allocation exhausted")
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // This exact independently created root is the only recursive target.
        // Children/quotas are dropped by the scenario before this owner.
        if self.0.canonicalize().ok().as_ref() == Some(&self.0) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
pub(in crate::private_predicate::source::locking::joint) fn identity() -> peer_runtime::Identity {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
    let mut p = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = p.self_signed(&key).unwrap();
    peer_runtime::Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
pub(in crate::private_predicate::source::locking::joint) fn signers() -> Vec<SigningKey> {
    let mut out: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    out.sort_by_key(|k| k.verifying_key().to_bytes());
    out
}
pub(in crate::private_predicate::source::locking::joint) fn binding(
    loaded: &crate::private_predicate::source::LoadedSource,
    setup: &bfv_query_core::PublicSetup,
    anchor: &bfv_query_core::BfvKeyAnchor,
    key: &bfv_key_transform::Statement,
    object: [u8; 32],
    quota: &protocol_storage::ParticipantQuota,
) -> JointBinding {
    let spec = Application::new([0x3a; 32], 7, 8, &loaded.draft).unwrap();
    let descriptor = Descriptor::checked(
        ApplicationDescriptor::from_application(&spec).unwrap(),
        object,
        setup,
        anchor,
        key,
    )
    .unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let claim = depot.retain_setup(&descriptor, setup).unwrap();
    drop(depot);
    let signer = SigningKey::from_bytes(&[0x5b; 32]);
    let g = Genesis {
        network_id: spec.network,
        database: spec.database,
        owner: signer.verifying_key().to_bytes(),
        application_commitment: descriptor.id(),
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
        initial_shards: spec.initial_shards(),
    };
    let rules = Rules::multi_slot(
        registry200_finality::joint::durable_profile_digest(),
        registry200_finality::joint::CANDIDATE_BYTES as u32,
        32,
        TIMEOUTS,
        DELTA,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    let seed = NetworkSeed::new(
        rules.seed_domain([0x3a; 32]),
        [10; 32],
        [255; 32],
        WorkLimits::new(16, 4).unwrap(),
    )
    .unwrap();
    // Bootstrap work is genuine. QC votes are exclusively produced later by
    // the four OS daemons; there is deliberately no fixture QC generator.
    let tickets = signers()
        .iter()
        .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
        .collect();
    let work = WorkGenesis::from_bootstrap(seed, tickets).unwrap();
    JointBinding::for_durable(spec.network, rules, work, g, descriptor, claim).unwrap()
}

pub(in crate::private_predicate::source::locking::joint) struct ControlState {
    pub registry: Registry,
    pub salt: [u64; 4],
    pub enrollment: [u8; 32],
}
impl ControlState {
    pub fn empty() -> Self {
        Self {
            registry: Registry::default(),
            salt: [21, 22, 23, 24],
            enrollment: [0; 32],
        }
    }
}

/// Actual owning Source/Life/Kind production for Bootstrap then Begin. The
/// returned model state is private prover input, never an accepted network state.
pub(in crate::private_predicate::source::locking::joint) fn control_block(
    owner: &SourceOwner,
    loaded: &crate::private_predicate::source::LoadedSource,
    binding: &JointBinding,
    parent: HeadRef,
    state: &mut ControlState,
    ingress: &JointEvidenceIngress,
    bootstrap: bool,
) -> registry200_finality::CandidateBlock {
    control_block_for(
        owner,
        loaded,
        binding,
        parent,
        state,
        ingress,
        (!bootstrap).then_some((1, 1)),
    )
}
pub(in crate::private_predicate::source::locking::joint) fn begin_block(
    owner: &SourceOwner,
    loaded: &crate::private_predicate::source::LoadedSource,
    binding: &JointBinding,
    parent: HeadRef,
    state: &mut ControlState,
    ingress: &JointEvidenceIngress,
    actor: (u64, u8),
) -> registry200_finality::CandidateBlock {
    control_block_for(owner, loaded, binding, parent, state, ingress, Some(actor))
}
fn control_block_for(
    owner: &SourceOwner,
    loaded: &crate::private_predicate::source::LoadedSource,
    binding: &JointBinding,
    parent: HeadRef,
    state: &mut ControlState,
    ingress: &JointEvidenceIngress,
    begin: Option<(u64, u8)>,
) -> registry200_finality::CandidateBlock {
    let bootstrap = begin.is_none();
    let app = JointApplication::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    let spec = app.source_spec();
    let n = begin.map_or(0, |(transaction, _)| transaction);
    let mut math = life::Witness {
        plain: loaded.plain.as_slice().try_into().unwrap(),
        controllers: CONTROLLERS,
        salts: [[Val::ZERO; 4]; 6],
        old: state.registry.clone(),
        command: begin.map(|(transaction, principal)| {
            Command::control(Operation::Begin, transaction, principal, 0)
        }),
    };
    math.salts[0] = [31 + n, 32, 33, 34].map(Val::from_u64);
    math.salts[1] = ENROLL_SALT.map(Val::from_u64);
    math.salts[2] = state.salt.map(Val::from_u64);
    math.salts[3] = [41 + n, 42, 43, 44].map(Val::from_u64);
    math.salts[4] = [51 + n, 52, 53, 54].map(Val::from_u64);
    math.salts[5] = [61 + n, 62, 63, 64].map(Val::from_u64);
    if bootstrap {
        let e = lifecycle::statement::Expected::bootstrap(
            &loaded.draft,
            app.genesis(),
            parent.block,
            [0; 32],
        )
        .unwrap();
        state.enrollment = ss::encode_digest(source::commitment::digest(&lc::enrollment_fields(
            &e, &math,
        )));
    }
    let e = lifecycle::statement::Expected::transition(
        &loaded.draft,
        app.genesis(),
        parent.block,
        state.enrollment,
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let old = if bootstrap {
        [0; 32]
    } else {
        ss::encode_digest(lifecycle::statement::digest(&lc::registry_fields(
            &e,
            &math,
            &state.registry,
            math.salts[2],
        )))
    };
    let operation = if bootstrap {
        JournalOperation::Bootstrap
    } else {
        JournalOperation::Transition
    };
    let nonce = [0xb1 + n as u8; 32];
    let q = intent_query(
        spec,
        app.genesis(),
        parent.block,
        nonce,
        state.enrollment,
        operation,
    );
    let mut source = loaded.draft.clone();
    source.request = q;
    source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &source,
        math.salts[0],
        &loaded.plain,
    ));
    let canonical = admission::CanonicalSource::checked_claim(&source).unwrap();
    let e = if bootstrap {
        lifecycle::statement::Expected::bootstrap(
            &source,
            app.genesis(),
            parent.block,
            state.enrollment,
        )
        .unwrap()
    } else {
        lifecycle::statement::Expected::transition(
            &source,
            app.genesis(),
            parent.block,
            state.enrollment,
            old,
            [0; 32],
        )
        .unwrap()
    };
    let e = if bootstrap {
        e
    } else {
        let command = lifecycle::statement::digest(&lc::command_fields(
            &e,
            &math,
            math.command.as_ref().unwrap(),
        ));
        lifecycle::statement::Expected::transition(
            &source,
            app.genesis(),
            parent.block,
            state.enrollment,
            old,
            ss::encode_digest(command),
        )
        .unwrap()
    };
    let source_proof = source::prove(
        &canonical,
        &owner.source_witness(math.salts[0], &loaded.originals),
    )
    .unwrap();
    let command_fields = math.command.as_ref().map(|command| {
        lc::command_fields(&e, &math, command)
            .into_iter()
            .map(|v| v.as_canonical_u64())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    });
    let next_registry = math
        .command
        .as_ref()
        .map(|command| {
            state
                .registry
                .step(command, e.parent, math.ages())
                .unwrap()
                .next
        })
        .unwrap_or_default();
    let next_salt = math.salts[4].map(|v| v.as_canonical_u64());
    let checked = admission::Expected::checked_claim(&e).unwrap();
    let witness = lifecycle::PreparedWitness::new(&checked, math).unwrap();
    let life = lifecycle::prove(&checked, &witness, source_proof.as_bytes()).unwrap();
    let statement = life.statement();
    let next = ss::encode_digest(statement.next);
    let result = ss::encode_digest(statement.result);
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    let manifest = if bootstrap {
        Manifest::bootstrap(next, pair).unwrap()
    } else {
        let expected = control_kind::Expected::new(statement).unwrap();
        let w = control_kind::circuit::Witness::new(
            &expected,
            control_kind::circuit::Opening::new(command_fields.unwrap()).unwrap(),
        )
        .unwrap();
        let kind = control_kind::prove(
            &expected,
            &w,
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
    state.registry = next_registry;
    state.salt = next_salt;
    let request = InnerRequest {
        operation,
        genesis: app.genesis(),
        parent: parent.block,
        application: spec.id(),
        nonce,
        query: q,
        enrollment: state.enrollment,
        opening: ss::encode_digest(source.open_commitment),
        command: match e.phase {
            lifecycle::statement::Phase::Bootstrap => [0; 32],
            lifecycle::statement::Phase::Transition { command, .. } => ss::encode_digest(command),
        },
        packets: source.packets,
    };
    transition(
        binding,
        parent,
        registry200_joint::Request::new(
            &app,
            if bootstrap {
                registry200_joint::Lane::Bootstrap
            } else {
                registry200_joint::Lane::Control
            },
            request,
        )
        .unwrap(),
        manifest,
        if bootstrap {
            Control::Pending
        } else {
            Control::Active {
                enrollment: state.enrollment,
                registry: old,
            }
        },
    )
}

pub(in crate::private_predicate::source::locking::joint) fn transition(
    binding: &JointBinding,
    parent: HeadRef,
    request: registry200_joint::Request,
    manifest: Manifest,
    old: Control,
) -> registry200_finality::CandidateBlock {
    let spec = binding.application_descriptor().source_spec().unwrap();
    let next = Control::Active {
        enrollment: request.inner().enrollment,
        registry: manifest.next_root(),
    };
    let mut body = AuthorizedTransition {
        parent: parent.block,
        request: request.encode().unwrap(),
        updates: vec![ShardUpdate {
            id: spec.control_id,
            old: old.heads(&spec),
            new: next.heads(&spec),
        }],
        proof: manifest.encode(),
        owner_signature: [0; 64],
    };
    body.sign(parent.genesis, &SigningKey::from_bytes(&[0x5b; 32]));
    let bytes = Body::Transition(body)
        .encode(&binding.journal_genesis().profile)
        .unwrap();
    let mut shards = spec.initial_shards();
    shards
        .iter_mut()
        .find(|s| s.id == spec.control_id)
        .unwrap()
        .heads = next.heads(&spec);
    let mut header = Header {
        genesis: parent.genesis,
        parent: parent.block,
        height: parent.height + 1,
        timestamp: 1001 + parent.height,
        target: Target([255; 32]),
        body_hash: version_journal::hash(&bytes),
        state_root: version_journal::state_root(&shards),
        nonce: 0,
    };
    header.mine(1).unwrap();
    registry200_finality::CandidateBlock::new(header, bytes).unwrap()
}
