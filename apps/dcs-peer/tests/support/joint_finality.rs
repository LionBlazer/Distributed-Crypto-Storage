//! PUBLIC NONSECRET owning fixtures. Core Source/Lifecycle/Kind are genuinely
//! proved; mathematical model steps only build witnesses, never accept replies.
use bfv_query_core::{Geometry, KeyScope, Owner, PublicSetup};
use compact_store::Layout;
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use peer_runtime::{
    Endpoint, Identity,
    finality::{JointFinalityClient, ProofBlobSelector},
};
use protocol_storage::{BlobId, ParticipantQuota};
use registry200_finality::{
    CandidateBlock,
    joint::{
        CANDIDATE_BYTES, JointBinding, JointCandidate, JointCheckpoint, durable_profile_digest,
    },
};
use registry200_joint::{
    Application, Descriptor, JointDepot, JointEvidenceIngress, JointVerifier, Manifest, Request,
};
use registry200_journal::{ApplicationDescriptor, Control, Operation, intent_query};
use registry200_proof::{Val, admission, control_kind, lifecycle, source};
use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Journal, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits, NetworkSeed, WorkTicket,
    consensus::{Context, MAX_RECORD_BYTES, Rules},
};
use zeroize::Zeroizing;

pub(crate) fn identity() -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    Identity {
        certificate: p.self_signed(&key).unwrap().der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
pub(crate) fn directory() -> PathBuf {
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.local/network-tests");
    std::fs::create_dir_all(&parent).unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = parent.join(format!("joint-finality-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    path
}
pub(crate) fn until(mut f: impl FnMut() -> bool) {
    let end = Instant::now() + peer_runtime::finality::JOINT_OPERATION_BUDGET;
    loop {
        if f() {
            return;
        }
        assert!(
            Instant::now() < end,
            "Actual Joint OS/TLS condition timed out"
        );
        std::thread::park_timeout(Duration::from_millis(30));
    }
}
pub(crate) struct Prepared {
    pub block: CandidateBlock,
    next: lifecycle::circuit::Witness,
    pub kind: Option<BlobId>,
}
pub(crate) struct History {
    pub binding: JointBinding,
    pub signers: Vec<SigningKey>,
    pub setup: PublicSetup,
    pub ingress: JointEvidenceIngress,
    _quota: ParticipantQuota,
    app: Application,
    journal: Journal,
    verifier: JointVerifier,
    context: Context,
    claim: source::Statement,
    witness: lifecycle::circuit::Witness,
    enrollment: [u8; 32],
}
impl History {
    pub(crate) fn new(root: &Path) -> Self {
        let owner =
            compact_store::Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new([0x71; 32]));
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let limits = source::statement::limits();
        let stored = owner
            .seal(
                Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                limits,
            )
            .unwrap();
        let suffix: Vec<u8> = include_str!(
            "../../../../crates/compact-query/tests/fixtures/index-v3-four-row-suffix.hex"
        )
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
                Layout {
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
            [0x71; 32],
            [Val::ONE; 4],
        ));
        let claim = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&stored.encode(), &indexed.encode()],
            [stored.commitment(), indexed.commitment()],
            [0; 32],
            source::statement::encode_digest(ckey),
            [0; 32],
        )
        .unwrap();
        let spec = registry200_journal::Application::new([0x19; 32], 7, 8, &claim).unwrap();
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
        let evidence = anchor.prove().unwrap();
        let key = setup
            .verify_key_transform(anchor.public_anchor(), evidence.as_bytes())
            .unwrap();
        let descriptor = Descriptor::checked(
            ApplicationDescriptor::from_application(&spec).unwrap(),
            [0x51; 32],
            &setup,
            anchor.public_anchor(),
            key.statement(),
        )
        .unwrap();
        drop(evidence);
        drop(anchor);
        drop(bfv);
        let quota = ParticipantQuota::create_new(root, descriptor.id(), 10_000_000_000).unwrap();
        let depot = JointDepot::open(quota.depot_budget()).unwrap();
        let setup_claim = depot.retain_setup(&descriptor, &setup).unwrap();
        let ingress = depot.ingress();
        let rules = Rules::multi_slot(
            durable_profile_digest(),
            CANDIDATE_BYTES as u32,
            1000,
            [3000, 4000, 5000],
            1000,
            MAX_RECORD_BYTES as u64,
        )
        .unwrap();
        let mut signers: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
        signers.sort_by_key(|k| k.verifying_key().to_bytes());
        let seed = NetworkSeed::new(
            rules.seed_domain(spec.network),
            [10; 32],
            [255; 32],
            Limits::new(16, 4).unwrap(),
        )
        .unwrap();
        let tickets = signers
            .iter()
            .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
            .collect();
        let work = WorkGenesis::from_bootstrap(seed, tickets).unwrap();
        let genesis = Genesis {
            network_id: spec.network,
            database: spec.database,
            owner: SigningKey::from_bytes(&[0x64; 32])
                .verifying_key()
                .to_bytes(),
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
        let binding = JointBinding::for_durable(
            spec.network,
            rules,
            work,
            genesis.clone(),
            descriptor.clone(),
            setup_claim,
        )
        .unwrap();
        let app = Application::new(descriptor.clone(), &genesis).unwrap();
        let verifier =
            JointVerifier::new(descriptor, &genesis, binding.setup_claim(), depot).unwrap();
        let journal = Journal::new(genesis).unwrap();
        let context = binding.initial_context().clone();
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        let witness = lifecycle::circuit::Witness {
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
        };
        Self {
            binding,
            signers,
            setup,
            ingress,
            _quota: quota,
            app,
            journal,
            verifier,
            context,
            claim,
            witness,
            enrollment: [0; 32],
        }
    }
    pub(crate) fn prepare(&mut self, bootstrap: bool) -> Prepared {
        use lifecycle::{
            circuit::{
                commitment,
                model::{Command, Operation as Op},
            },
            statement::{Expected, Phase, digest},
        };
        let head = self.journal.best_validated();
        let mut witness = self.witness.clone();
        let operation = if bootstrap {
            Operation::Bootstrap
        } else {
            Operation::Transition
        };
        let nonce = if bootstrap { [0xa1; 32] } else { [0xa2; 32] };
        if bootstrap {
            let e = Expected::bootstrap(&self.claim, head.genesis, head.block, [0; 32]).unwrap();
            self.enrollment = source::statement::encode_digest(source::commitment::digest(
                &commitment::enrollment_fields(&e, &witness),
            ));
        }
        let query = intent_query(
            self.app.source_spec(),
            head.genesis,
            head.block,
            nonce,
            self.enrollment,
            operation,
        );
        let mut claim = self.claim.clone();
        claim.request = query;
        claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &claim,
            witness.salts[0],
            &witness.plain,
        ));
        let canonical = admission::CanonicalSource::checked_claim(&claim).unwrap();
        let private = source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            witness.salts[0],
            [255, 0, 255, 128],
        );
        let source = source::prove(&canonical, &private).unwrap();
        drop(private);
        let old_heads = self
            .app
            .source_spec()
            .control(self.journal.validated_shards(head).unwrap())
            .unwrap();
        let mut e = match Control::decode(self.app.source_spec(), old_heads).unwrap() {
            Control::Pending => {
                Expected::bootstrap(&claim, head.genesis, head.block, self.enrollment).unwrap()
            }
            Control::Active { registry, .. } => Expected::transition(
                &claim,
                head.genesis,
                head.block,
                self.enrollment,
                registry,
                [0; 32],
            )
            .unwrap(),
        };
        if !bootstrap {
            witness.salts[4] = [Val::from_u64(20 + head.height); 4];
            witness.command = Some(Command::control(Op::Begin, 1, 1, 0));
            let command = digest(&commitment::command_fields(
                &e,
                &witness,
                witness.command.as_ref().unwrap(),
            ));
            let Phase::Transition { old, .. } = e.phase else {
                panic!("Expected active Registry")
            };
            e.phase = Phase::Transition { old, command };
        }
        let checked = admission::Expected::checked_claim(&e).unwrap();
        let prepared = lifecycle::PreparedWitness::new(&checked, witness.clone()).unwrap();
        let evidence = lifecycle::prove(&checked, &prepared, source.as_bytes()).unwrap();
        drop(prepared);
        drop(source);
        let statement = evidence.statement();
        let next = source::statement::encode_digest(statement.next);
        let result = source::statement::encode_digest(statement.result);
        let pair = self
            .ingress
            .retain_public_blob(evidence.as_bytes())
            .unwrap();
        let (manifest, kind) = if bootstrap {
            (Manifest::bootstrap(next, pair).unwrap(), None)
        } else {
            let expected = control_kind::Expected::new(statement).unwrap();
            let fields =
                commitment::command_fields(&e, &witness, witness.command.as_ref().unwrap())
                    .into_iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
            let private = control_kind::circuit::Witness::new(
                &expected,
                control_kind::circuit::Opening::new(fields).unwrap(),
            )
            .unwrap();
            let link = control_kind::prove(
                &expected,
                &private,
                &control_kind::Prerequisites {
                    lifecycle: evidence.as_bytes(),
                },
            )
            .unwrap();
            let kind = self.ingress.retain_public_blob(link.as_bytes()).unwrap();
            (
                Manifest::control(next, result, pair, kind).unwrap(),
                Some(kind),
            )
        };
        let inner = registry200_journal::Request {
            operation,
            genesis: head.genesis,
            parent: head.block,
            application: self.app.source_spec().id(),
            nonce,
            query,
            enrollment: self.enrollment,
            opening: source::statement::encode_digest(claim.open_commitment),
            command: match e.phase {
                Phase::Bootstrap => [0; 32],
                Phase::Transition { command, .. } => source::statement::encode_digest(command),
            },
            packets: claim.packets,
        };
        let request = Request::new(
            &self.app,
            if bootstrap {
                registry200_joint::Lane::Bootstrap
            } else {
                registry200_joint::Lane::Control
            },
            inner,
        )
        .unwrap();
        let mut body = AuthorizedTransition {
            parent: head.block,
            request: request.encode().unwrap(),
            updates: vec![ShardUpdate {
                id: self.app.source_spec().control_id,
                old: old_heads,
                new: Control::Active {
                    enrollment: self.enrollment,
                    registry: next,
                }
                .heads(self.app.source_spec()),
            }],
            proof: manifest.encode(),
            owner_signature: [0; 64],
        };
        body.sign(head.genesis, &SigningKey::from_bytes(&[0x64; 32]));
        let body = Body::Transition(body);
        let mut header = self
            .journal
            .candidate(head.block, &body, 1001 + head.height)
            .unwrap();
        header.mine(1).unwrap();
        if let Some(command) = &witness.command {
            let step = witness
                .old
                .step(command, head.block, witness.ages())
                .unwrap();
            assert_eq!(step.outcome, 0);
            witness.old = step.next;
        }
        witness.salts[2] = witness.salts[4];
        witness.command = None;
        Prepared {
            block: CandidateBlock::new(header, body.encode(self.journal.profile()).unwrap())
                .unwrap(),
            next: witness,
            kind,
        }
    }
    pub(crate) fn upload(&self, client: &JointFinalityClient, prepared: &Prepared) {
        let Body::Transition(body) =
            Body::decode(prepared.block.body(), self.journal.profile()).unwrap()
        else {
            panic!("Expected transition")
        };
        for reference in Manifest::decode(&body.proof).unwrap().references() {
            let bytes = self
                .ingress
                .read_public_blob(reference.blob_id(), reference.byte_cap())
                .unwrap();
            until(|| {
                match client.put_proof_blob(
                    &prepared.block,
                    ProofBlobSelector::manifest(reference.ordinal() as u16).unwrap(),
                    reference.blob_id(),
                    &bytes,
                ) {
                    Ok(()) => true,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                    Err(e) => panic!("Actual authorized blob upload: {e}"),
                }
            });
        }
    }
    pub(crate) fn context(&self) -> &Context {
        &self.context
    }
    pub(crate) fn adopt(&mut self, prepared: Prepared, checkpoint: &JointCheckpoint) {
        let candidate = JointCandidate::for_context(
            &self.binding,
            &self.context,
            prepared.block.header().clone(),
        )
        .unwrap();
        assert_eq!(checkpoint.candidate(), &candidate);
        let decision = self
            .context
            .verify_commit(
                &candidate.encode(),
                checkpoint.round(),
                checkpoint.certificate(),
            )
            .unwrap();
        let context = self.context.after_decision(&decision).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.journal
            .import_block(
                prepared.block.header().clone(),
                prepared.block.body(),
                now,
                &self.verifier,
            )
            .unwrap();
        self.journal
            .restrict_ancestry_floor(self.journal.best_validated())
            .unwrap();
        self.context = context;
        self.witness = prepared.next;
    }
    pub(crate) fn tamper(
        &self,
        block: &CandidateBlock,
        change: impl FnOnce(&mut AuthorizedTransition),
    ) -> CandidateBlock {
        let Body::Transition(mut body) =
            Body::decode(block.body(), self.journal.profile()).unwrap()
        else {
            panic!("Expected transition")
        };
        change(&mut body);
        body.sign(block.header().genesis, &SigningKey::from_bytes(&[0x64; 32]));
        let bytes = Body::Transition(body)
            .encode(self.journal.profile())
            .unwrap();
        let mut header = block.header().clone();
        header.body_hash = version_journal::hash(&bytes);
        header.nonce = 0;
        header.mine(1).unwrap();
        CandidateBlock::new(header, bytes).unwrap()
    }
    pub(crate) fn empty(&self) -> CandidateBlock {
        let head = self.journal.best_validated();
        let mut header = self
            .journal
            .candidate(head.block, &Body::Empty, 1001 + head.height)
            .unwrap();
        header.mine(1).unwrap();
        CandidateBlock::new(header, Body::Empty.encode(self.journal.profile()).unwrap()).unwrap()
    }
}
pub(crate) struct Network<'a> {
    pub tls: &'a Identity,
    pub owner: [u8; 32],
    pub listen: Endpoint,
    pub neighbors: &'a [Endpoint],
    pub namespace: [u8; 32],
    pub index: usize,
}
pub(crate) fn bootstrap_frames(
    history: &History,
    network: Network<'_>,
    new: bool,
) -> Vec<Zeroizing<Vec<u8>>> {
    let Network {
        tls,
        owner,
        listen,
        neighbors,
        namespace,
        index,
    } = network;
    let binding = &history.binding;
    let config=serde_json::to_vec(&serde_json::json!({"version":1,"kind":"registry200-joint-participant-finality-v1","identity":tls,"authority":[],"owner":owner,
        "listen":listen.address,"neighbors":neighbors,"namespace":namespace,"capacity":10_000_000_000u64,"work_genesis":binding.work_genesis().id(),
        "journal_genesis":binding.journal_genesis().id().unwrap(),"binding":binding.id(),"rules":{"max_round":1000,"timeouts_ms":[3000,4000,5000],"timeout_delta_ms":1000,"wal_bytes":MAX_RECORD_BYTES},"signer":history.signers[index].to_bytes()})).unwrap();
    let mut frames = vec![
        Zeroizing::new(config),
        Zeroizing::new(binding.work_genesis().encode().unwrap()),
        Zeroizing::new(binding.journal_genesis().encode().unwrap()),
        Zeroizing::new(binding.application_descriptor().encode()),
        Zeroizing::new(binding.setup_claim().encode()),
    ];
    if new {
        let bytes = history.setup.to_bytes().unwrap();
        for part in bytes.chunks(protocol_storage::MAX_BLOB_BYTES as usize) {
            frames.push(Zeroizing::new(part.to_vec()));
        }
    }
    frames
}
