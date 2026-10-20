//! PUBLIC NONSECRET owning inputs. Real application proofs and weighted QCs.
use super::*;
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_storage::ParticipantQuota;
use registry200_finality::joint::{CANDIDATE_BYTES, JointCandidate, JointCheckpoint, JointHistory};
use registry200_joint::{JointDepot, Manifest};
use registry200_journal::{Operation as JournalOperation, Request as InnerRequest, intent_query};
use registry200_proof::{
    admission, control_kind,
    source::{self, statement as ss},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Header, Journal, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits as WorkLimits, NetworkSeed, QuorumCertificate, SignedVote, Step,
    VoteContext, WorkTicket,
    consensus::{Context, MAX_RECORD_BYTES, Rules},
};

pub(in crate::private_predicate::source::locking::joint) const CONTROLLERS: [[u8; 32]; 2] =
    [[0x84; 32], [0xa5; 32]];
pub(in crate::private_predicate::source::locking::joint) const ENROLL_SALT: [u64; 4] =
    [11, 12, 13, 14];
pub(in crate::private_predicate::source::locking::joint) struct Built {
    pub binding: JointBinding,
    pub parent: VerifiedJointParent,
    pub registry: Registry,
    pub registry_salt: [u64; 4],
    pub context: work_finality::consensus::Context,
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let p = parent.join(format!(
                "dcs-joint-producer-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Self(p.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("owned directory: {e}"),
            }
        }
        panic!("bounded directory creation exhausted")
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
fn keys() -> Vec<SigningKey> {
    let mut keys: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    keys
}
fn work(rules: &Rules) -> WorkGenesis {
    let seed = NetworkSeed::new(
        rules.seed_domain([0x3a; 32]),
        [10; 32],
        [255; 32],
        WorkLimits::new(16, 4).unwrap(),
    )
    .unwrap();
    let tickets = keys()
        .iter()
        .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
        .collect();
    WorkGenesis::from_bootstrap(seed, tickets).unwrap()
}
fn qc(context: &Context, candidate: &JointCandidate) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/consensus-vote-instance/v1");
    h.update(work_finality::profile_digest());
    h.update(context.id());
    let vote = VoteContext::new(
        context.set(),
        h.finalize().into(),
        context.slot(),
        0,
        Step::Precommit,
        Some(context.value_id(&candidate.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = keys()[..3]
        .iter()
        .map(|k| SignedVote::sign(vote, k).unwrap())
        .collect();
    QuorumCertificate::assemble(context.set(), &vote, &votes)
        .unwrap()
        .encode()
        .unwrap()
}

/// The only sealed-parent constructor is actual JointHistory::apply. A temporary
/// empty Journal supplies the canonical genesis head, never authorizes a block.
pub(in crate::private_predicate::source::locking::joint) fn sealed_begin(
    owner: &SourceOwner,
    loaded: &crate::private_predicate::source::LoadedSource,
    descriptor: Descriptor,
    setup: &bfv_query_core::PublicSetup,
) -> Built {
    use lifecycle::{
        circuit::{
            self as life, commitment as lc,
            model::{Command, Operation},
        },
        statement::{Expected, Phase, digest},
    };
    let spec = descriptor.source_spec().unwrap();
    let signer = SigningKey::from_bytes(&[0x5b; 32]);
    let genesis = Genesis {
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
    let directory = Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.root(), descriptor.id(), 10_000_000_000).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let setup_claim = depot.retain_setup(&descriptor, setup).unwrap();
    let rules = Rules::multi_slot(
        registry200_finality::joint::profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    let binding = JointBinding::new(
        spec.network,
        rules.clone(),
        work(&rules),
        genesis.clone(),
        descriptor,
        setup_claim,
    )
    .unwrap();
    let app = JointApplication::new(binding.application_descriptor().clone(), &genesis).unwrap();
    let mut head = Journal::new(genesis.clone()).unwrap().genesis_head();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let mut registry = Registry::default();
    let mut registry_salt = [21, 22, 23, 24];
    let mut enrollment = [0; 32];
    let mut last = None;
    for ordinal in 0..2 {
        let mut math = life::Witness {
            plain: loaded.plain.as_slice().try_into().unwrap(),
            controllers: CONTROLLERS,
            salts: [[Val::ZERO; 4]; 6],
            old: registry.clone(),
            command: if ordinal == 0 {
                None
            } else {
                Some(Command::control(Operation::Begin, 1, 1, 0))
            },
        };
        math.salts[0] = [31 + ordinal, 32, 33, 34].map(Val::from_u64);
        math.salts[1] = ENROLL_SALT.map(Val::from_u64);
        math.salts[2] = registry_salt.map(Val::from_u64);
        math.salts[3] = [41 + ordinal, 42, 43, 44].map(Val::from_u64);
        math.salts[4] = [51 + ordinal, 52, 53, 54].map(Val::from_u64);
        math.salts[5] = [61 + ordinal, 62, 63, 64].map(Val::from_u64);
        if ordinal == 0 {
            let e = Expected::bootstrap(&loaded.draft, app.genesis(), head.block, [0; 32]).unwrap();
            enrollment = ss::encode_digest(source::commitment::digest(&lc::enrollment_fields(
                &e, &math,
            )));
        }
        let old = if ordinal == 0 {
            [0; 32]
        } else {
            ss::encode_digest(digest(&lc::registry_fields(
                &Expected::transition(
                    &loaded.draft,
                    app.genesis(),
                    head.block,
                    enrollment,
                    [0; 32],
                    [0; 32],
                )
                .unwrap(),
                &math,
                &registry,
                math.salts[2],
            )))
        };
        let operation = if ordinal == 0 {
            JournalOperation::Bootstrap
        } else {
            JournalOperation::Transition
        };
        let nonce = [0xb1 + ordinal as u8; 32];
        let q = intent_query(
            &spec,
            app.genesis(),
            head.block,
            nonce,
            enrollment,
            operation,
        );
        let mut claim = loaded.draft.clone();
        claim.request = q;
        claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &claim,
            math.salts[0],
            &math.plain,
        ));
        let canonical = admission::CanonicalSource::checked_claim(&claim).unwrap();
        let mut e = if ordinal == 0 {
            Expected::bootstrap(canonical.claim(), app.genesis(), head.block, enrollment).unwrap()
        } else {
            Expected::transition(
                canonical.claim(),
                app.genesis(),
                head.block,
                enrollment,
                old,
                [0; 32],
            )
            .unwrap()
        };
        if ordinal != 0 {
            e.phase = Phase::Transition {
                old: ss::decode_digest(old).unwrap(),
                command: digest(&lc::command_fields(
                    &e,
                    &math,
                    math.command.as_ref().unwrap(),
                )),
            };
        }
        let source_bytes = {
            let witness = owner.source_witness(math.salts[0], &loaded.originals);
            source::prove(&canonical, &witness).unwrap().into_bytes()
        };
        let expected = admission::Expected::checked_claim(&e).unwrap();
        let private = lifecycle::PreparedWitness::new(&expected, math.clone()).unwrap();
        let evidence = lifecycle::prove(&expected, &private, &source_bytes).unwrap();
        drop(private);
        drop(source_bytes);
        let statement = evidence.statement();
        let next = ss::encode_digest(statement.next);
        let result = ss::encode_digest(statement.result);
        let pair = ingress.retain_public_blob(evidence.as_bytes()).unwrap();
        let manifest = if ordinal == 0 {
            Manifest::bootstrap(next, pair).unwrap()
        } else {
            let expected = control_kind::Expected::new(statement).unwrap();
            let fields = lc::command_fields(&e, &math, math.command.as_ref().unwrap())
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
            let kind = control_kind::prove(
                &expected,
                &witness,
                &control_kind::Prerequisites {
                    lifecycle: evidence.as_bytes(),
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
            application: spec.id(),
            nonce,
            query: q,
            enrollment,
            opening: ss::encode_digest(canonical.claim().open_commitment),
            command: match e.phase {
                Phase::Bootstrap => [0; 32],
                Phase::Transition { command, .. } => ss::encode_digest(command),
            },
            packets: canonical.claim().packets.clone(),
        };
        let mut body = AuthorizedTransition {
            parent: head.block,
            request: JointRequest::new(
                &app,
                if ordinal == 0 {
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
                id: spec.control_id,
                old: if ordinal == 0 {
                    Control::Pending
                } else {
                    Control::Active {
                        enrollment,
                        registry: old,
                    }
                }
                .heads(&spec),
                new: Control::Active {
                    enrollment,
                    registry: next,
                }
                .heads(&spec),
            }],
            proof: manifest.encode(),
            owner_signature: [0; 64],
        };
        body.sign(app.genesis(), &signer);
        let body = Body::Transition(body).encode(&genesis.profile).unwrap();
        let mut shards = spec.initial_shards();
        shards
            .iter_mut()
            .find(|s| s.id == spec.control_id)
            .unwrap()
            .heads = Control::Active {
            enrollment,
            registry: next,
        }
        .heads(&spec);
        let mut header = Header {
            genesis: app.genesis(),
            parent: head.block,
            height: head.height + 1,
            timestamp: 1001 + head.height,
            target: Target([255; 32]),
            body_hash: version_journal::hash(&body),
            state_root: version_journal::state_root(&shards),
            nonce: 0,
        };
        header.mine(1).unwrap();
        let block = registry200_finality::CandidateBlock::new(header, body).unwrap();
        let candidate = JointCandidate::for_context(
            &binding,
            history.context().unwrap(),
            block.header().clone(),
        )
        .unwrap();
        let checkpoint = JointCheckpoint::new(
            candidate.clone(),
            0,
            qc(history.context().unwrap(), &candidate),
        )
        .unwrap();
        let checked = history.apply(&checkpoint, &block).unwrap();
        head = checked.head();
        last = Some(checked);
        if let Some(command) = &math.command {
            registry = registry.step(command, e.parent, math.ages()).unwrap().next;
        }
        registry_salt = math.salts[4].map(|v| v.as_canonical_u64());
        assert_eq!(
            Control::Active {
                enrollment,
                registry: next
            },
            history.checked_parent().unwrap().unwrap().control()
        );
    }
    let context = history.context().unwrap().clone();
    // No History, ingress, native proof buffers or CAS handle overlaps input16 production.
    drop(history);
    drop(ingress);
    drop(quota);
    drop(directory);
    Built {
        binding,
        parent: last.unwrap(),
        registry,
        registry_salt,
        context,
    }
}
