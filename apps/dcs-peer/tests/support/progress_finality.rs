//! PUBLIC NONSECRET fixtures for actual OS consensus. Model values build
//! genuine witnesses only; no local signature quorum or answer accepts a reply.
use bfv_query_core::{Geometry, KeyScope, Owner, PublicSetup};
use compact_store::Layout;
use ed25519_dalek::SigningKey;
use p3_field::PrimeCharacteristicRing;
use peer_runtime::{
    Endpoint, Identity,
    finality::{ProgressFinalityClient, ProgressProofBlobSelector},
};
use protocol_storage::{BlobId, ParticipantQuota};
use registry200_finality::{
    CandidateBlock,
    progress::{
        Binding, CANDIDATE_BYTES, Checkpoint, History as ClosedHistory, OperationExpectation,
        durable_profile_digest,
    },
};
use registry200_joint::progress::{
    Application, Descriptor, Lane, Manifest, ProgressDepot, ProgressEvidenceIngress, Request,
};
use registry200_journal::{ApplicationDescriptor, Control, Operation, intent_query};
use registry200_proof::{
    Val, admission::CanonicalSource, lifecycle, registry_progress as core, source,
};
use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use version_journal::{AuthorizedTransition, Body, Genesis, ProtocolProfile, ShardUpdate, Target};
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
    let path = parent.join(format!("progress-finality-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    path
}
pub(crate) fn until(mut f: impl FnMut() -> bool) {
    let end = Instant::now() + peer_runtime::finality::PROGRESS_OPERATION_BUDGET;
    loop {
        if f() {
            return;
        }
        assert!(
            Instant::now() < end,
            "Actual Progress OS/TLS condition timed out"
        );
        std::thread::park_timeout(Duration::from_millis(30));
    }
}
pub(crate) struct Prepared {
    pub block: CandidateBlock,
    expected: OperationExpectation,
    pub child: BlobId,
}
pub(crate) struct History {
    pub binding: Binding,
    pub signers: Vec<SigningKey>,
    pub setup: PublicSetup,
    pub ingress: ProgressEvidenceIngress,
    _quota: ParticipantQuota,
    app: Application,
    checked: ClosedHistory,
    claim: source::Statement,
    plain: [u8; 2348],
    controllers: [[u8; 32]; 2],
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
        let depot = ProgressDepot::open(quota.depot_budget(), &descriptor).unwrap();
        let setup_claim = depot.retain_setup(&setup).unwrap();
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
                max_request_bytes: registry200_joint::progress::REQUEST_BYTES as u32,
                max_proof_bytes: registry200_joint::progress::MANIFEST_BYTES as u32,
                max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
            },
            initial_shards: spec.initial_shards(),
        };
        let binding = Binding::for_durable(
            spec.network,
            rules,
            work,
            genesis.clone(),
            descriptor.clone(),
            setup_claim,
        )
        .unwrap();
        let app = Application::new(descriptor.clone(), &genesis).unwrap();
        let checked = ClosedHistory::new(binding.clone(), depot).unwrap();
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        Self {
            binding,
            signers,
            setup,
            ingress,
            _quota: quota,
            app,
            checked,
            claim,
            plain,
            controllers: [[0x41; 32], [0x42; 32]],
        }
    }
    pub(crate) fn prepare(&mut self, bootstrap: bool) -> Prepared {
        let head = if bootstrap {
            self.checked.bootstrap_parent().unwrap().head()
        } else {
            self.checked.checked_parent().unwrap().unwrap().head()
        };
        let old = if bootstrap {
            Control::Pending
        } else {
            self.checked.checked_parent().unwrap().unwrap().control()
        };
        let enrollment = match old {
            Control::Pending => {
                let e = lifecycle::statement::Expected::bootstrap(
                    &self.claim,
                    head.genesis,
                    head.block,
                    [0; 32],
                )
                .unwrap();
                source::statement::encode_digest(source::commitment::digest(
                    &lifecycle::circuit::commitment::enrollment_fields_opening(
                        &e,
                        &self.plain[124..156].try_into().unwrap(),
                        &self.controllers,
                        [Val::from_u8(3); 4],
                    ),
                ))
            }
            Control::Active { enrollment, .. } => enrollment,
        };
        let operation = if bootstrap {
            Operation::Bootstrap
        } else {
            Operation::Transition
        };
        let nonce = if bootstrap { [0xa1; 32] } else { [0xa2; 32] };
        let query = intent_query(
            self.app.source_spec(),
            head.genesis,
            head.block,
            nonce,
            enrollment,
            operation,
        );
        let mut claim = self.claim.clone();
        claim.request = query;
        claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &claim,
            [Val::TWO; 4],
            &self.plain,
        ));
        let canonical = CanonicalSource::checked_claim(&claim).unwrap();
        let raw = source::prove(
            &canonical,
            &source::circuit::Witness::new(
                [0x71; 32],
                [Val::ONE; 4],
                [Val::TWO; 4],
                [255, 0, 255, 128],
            ),
        )
        .unwrap();
        let source_id = self.ingress.retain_public_blob(raw.as_bytes()).unwrap();
        let (manifest, command, child) = if bootstrap {
            let e = core::BootstrapExpected::new(&canonical, head.genesis, head.block, enrollment)
                .unwrap();
            let w = core::BootstrapWitness::new(
                &e,
                Zeroizing::new(self.plain),
                Zeroizing::new(self.controllers),
                Zeroizing::new([[2; 4], [3; 4], [6; 4]]),
            )
            .unwrap();
            let proof = core::prove_bootstrap(&e, &w, raw.as_bytes()).unwrap();
            let child = self.ingress.retain_public_blob(proof.as_bytes()).unwrap();
            (
                Manifest::bootstrap(proof.statement().next(), source_id, child).unwrap(),
                [0; 32],
                child,
            )
        } else {
            let Control::Active { registry, .. } = old else {
                unreachable!()
            };
            let draft = core::transition::Expected::control(
                &canonical,
                head.genesis,
                head.block,
                enrollment,
                registry,
                [0; 32],
            )
            .unwrap();
            let command = lifecycle::circuit::model::Command::control(
                lifecycle::circuit::model::Operation::Begin,
                1,
                1,
                0,
            );
            let commitment = core::transition::command_commitment(
                &draft,
                &command,
                0,
                &self.controllers,
                [4; 4],
            )
            .unwrap();
            let e = core::transition::Expected::control(
                &canonical,
                head.genesis,
                head.block,
                enrollment,
                registry,
                commitment,
            )
            .unwrap();
            let witness = core::transition::Witness::control(
                &e,
                Zeroizing::new(self.plain),
                Zeroizing::new(self.controllers),
                Zeroizing::new(core::circuit::State::default()),
                Zeroizing::new(command),
                Zeroizing::new([[2; 4], [3; 4], [6; 4], [4; 4], [7; 4], [8; 4]]),
            )
            .unwrap();
            let proof = core::transition::prove(
                &e,
                &witness,
                &core::transition::Prerequisites {
                    source: raw.as_bytes(),
                    query: None,
                },
            )
            .unwrap();
            let child = self.ingress.retain_public_blob(proof.as_bytes()).unwrap();
            (
                Manifest::control(
                    proof.statement().next(),
                    proof.statement().result(),
                    source_id,
                    child,
                )
                .unwrap(),
                commitment,
                child,
            )
        };
        drop(raw);
        let request = Request::new(
            &self.app,
            if bootstrap {
                Lane::Bootstrap
            } else {
                Lane::Control
            },
            registry200_journal::Request {
                operation,
                genesis: head.genesis,
                parent: head.block,
                application: self.app.source_spec().id(),
                nonce,
                query,
                enrollment,
                opening: source::statement::encode_digest(claim.open_commitment),
                command,
                packets: claim.packets,
            },
        )
        .unwrap();
        let mut transition = AuthorizedTransition {
            parent: head.block,
            request: request.encode().unwrap(),
            updates: vec![ShardUpdate {
                id: self.app.source_spec().control_id,
                old: old.heads(self.app.source_spec()),
                new: Control::Active {
                    enrollment,
                    registry: manifest.next_root(),
                }
                .heads(self.app.source_spec()),
            }],
            proof: manifest.encode(),
            owner_signature: [0; 64],
        };
        transition.sign(head.genesis, &SigningKey::from_bytes(&[0x64; 32]));
        let body = Body::Transition(transition);
        let expected = if bootstrap {
            OperationExpectation::bootstrap(
                &self.binding,
                &self.checked.bootstrap_parent().unwrap(),
                &request,
                manifest,
                &body,
            )
        } else {
            OperationExpectation::transition(
                &self.binding,
                self.checked.checked_parent().unwrap().unwrap(),
                self.checked.context().unwrap(),
                &request,
                manifest,
                &body,
            )
        }
        .unwrap();
        Prepared {
            block: self.block(&body),
            expected,
            child,
        }
    }
    fn block(&self, body: &Body) -> CandidateBlock {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = self.checked.candidate_header(body, now, now).unwrap();
        header.mine(16).unwrap();
        CandidateBlock::new(
            header,
            body.encode(&self.binding.journal_genesis().profile)
                .unwrap(),
        )
        .unwrap()
    }
    pub(crate) fn upload(&self, client: &ProgressFinalityClient, prepared: &Prepared) {
        let Body::Transition(body) = Body::decode(
            prepared.block.body(),
            &self.binding.journal_genesis().profile,
        )
        .unwrap() else {
            panic!("Expected transition")
        };
        for r in Manifest::decode(&body.proof).unwrap().references() {
            let bytes = self
                .ingress
                .read_public_blob(r.blob_id(), r.byte_cap())
                .unwrap();
            until(|| {
                match client.put_proof_blob(
                    &prepared.block,
                    ProgressProofBlobSelector::manifest(r.ordinal() as u16).unwrap(),
                    r.blob_id(),
                    &bytes,
                ) {
                    Ok(()) => true,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                    Err(e) => panic!("Actual Progress proof upload: {e}"),
                }
            });
        }
    }
    pub(crate) fn context(&self) -> &Context {
        self.checked.context().unwrap()
    }
    pub(crate) fn adopt(&mut self, prepared: Prepared, checkpoint: &Checkpoint) {
        let receipt = self
            .checked
            .apply_operation(checkpoint, &prepared.block, &prepared.expected)
            .unwrap();
        assert_eq!(receipt.body_bytes(), prepared.block.body());
        assert_eq!(receipt.header(), prepared.block.header());
        assert_eq!(
            receipt.operation().request(),
            prepared.expected.request_bytes()
        );
        assert_eq!(
            receipt.operation().manifest().encode(),
            prepared.expected.manifest().encode()
        );
        assert_eq!(
            receipt.operation().next_root(),
            prepared.expected.manifest().next_root()
        );
        assert_eq!(
            receipt.next_context_id(),
            self.checked.context().unwrap().id()
        );
    }
    pub(crate) fn tamper(
        &self,
        block: &CandidateBlock,
        change: impl FnOnce(&mut AuthorizedTransition),
    ) -> CandidateBlock {
        let Body::Transition(mut body) =
            Body::decode(block.body(), &self.binding.journal_genesis().profile).unwrap()
        else {
            panic!("Expected transition")
        };
        change(&mut body);
        body.sign(block.header().genesis, &SigningKey::from_bytes(&[0x64; 32]));
        let bytes = Body::Transition(body)
            .encode(&self.binding.journal_genesis().profile)
            .unwrap();
        let mut header = block.header().clone();
        header.body_hash = version_journal::hash(&bytes);
        header.nonce = 0;
        header.mine(16).unwrap();
        CandidateBlock::new(header, bytes).unwrap()
    }
    pub(crate) fn empty(&self) -> CandidateBlock {
        self.block(&Body::Empty)
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
    let config=serde_json::to_vec(&serde_json::json!({"version":2,"kind":"registry208-progress-participant-finality-v2","identity":tls,"authority":[],"owner":owner,
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
