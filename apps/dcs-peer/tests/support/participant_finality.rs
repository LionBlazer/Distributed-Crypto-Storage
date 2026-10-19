//! PUBLIC NONSECRET owning fixtures. Actual Core proofs and actual OS peers;
//! native registry modeling only builds private witnesses, never accepts a reply.
use compact_store::{Layout, Owner};
use ed25519_dalek::SigningKey;
use p3_field::PrimeCharacteristicRing;
use registry200_finality::{Binding, CandidateBlock};
use registry200_journal::{Application, ApplicationDescriptor, Control, Request};
use registry200_proof::{
    Val, admission,
    lifecycle::{
        self,
        circuit::{
            Witness, commitment,
            model::{Command, Operation, Registry},
        },
        statement::{self, Expected, Phase},
    },
    source,
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Journal, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits, NetworkSeed, WorkTicket,
    consensus::{MAX_RECORD_BYTES, Rules},
};
use zeroize::Zeroizing;

pub struct Prepared {
    pub block: CandidateBlock,
    next: Witness,
    pub outcome: u8,
}
pub struct History {
    pub binding: Binding,
    pub keys: Vec<SigningKey>,
    pub journal: Journal,
    app: Application,
    claim: source::Statement,
    witness: Witness,
    enrollment: [u8; 32],
}
impl History {
    pub fn new() -> Self {
        let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new([0x71; 32]));
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let stored = owner
            .seal(
                Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                source::statement::limits(),
            )
            .unwrap();
        let suffix: Vec<_> = include_str!(
            "../../../../crates/compact-query/tests/fixtures/index-v3-four-row-suffix.hex"
        )
        .lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();
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
                source::statement::limits(),
            )
            .unwrap();
        let key = source::commitment::digest(&source::commitment::key_fields(
            &stored.commitment().encode(),
            [0x71; 32],
            [Val::ONE; 4],
        ));
        let claim = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&stored.encode(), &indexed.encode()],
            [stored.commitment(), indexed.commitment()],
            [0; 32],
            source::statement::encode_digest(key),
            [0; 32],
        )
        .unwrap();
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        let witness = Witness {
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
            old: Registry::default(),
            command: None,
        };
        let app = Application::new([9; 32], 7, 8, &claim).unwrap();
        let rules = Rules::multi_slot(
            registry200_finality::profile_digest(),
            registry200_finality::DESCRIPTOR_BYTES as u32,
            1000,
            [3000, 4000, 5000],
            1000,
            MAX_RECORD_BYTES as u64,
        )
        .unwrap();
        let mut keys: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
        keys.sort_by_key(|k| k.verifying_key().to_bytes());
        let seed = NetworkSeed::new(
            rules.seed_domain([9; 32]),
            [10; 32],
            [255; 32],
            Limits::new(16, 4).unwrap(),
        )
        .unwrap();
        let tickets = keys
            .iter()
            .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
            .collect();
        let work = WorkGenesis::from_bootstrap(seed, tickets).unwrap();
        let genesis = Genesis {
            network_id: [9; 32],
            database: app.database,
            owner: SigningKey::from_bytes(&[0x55; 32])
                .verifying_key()
                .to_bytes(),
            application_commitment: app.id(),
            timestamp: 1000,
            profile: ProtocolProfile {
                initial_target: Target([255; 32]),
                pow_limit: Target([255; 32]),
                block_spacing_secs: 10,
                retarget_interval: 100,
                max_future_secs: 60,
                confirmation_depth: 1,
                max_headers: 32,
                max_shards: 2,
                max_updates: 1,
                max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
                max_request_bytes: registry200_journal::REQUEST_BYTES as u32,
                max_proof_bytes: version_journal::MAX_BODY_BYTES as u32,
                max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
            },
            initial_shards: app.initial_shards(),
        };
        let binding = Binding::new(
            [9; 32],
            rules,
            work,
            genesis,
            ApplicationDescriptor::from_application(&app).unwrap(),
        )
        .unwrap();
        let journal = Journal::new(binding.journal_genesis().clone()).unwrap();
        Self {
            binding,
            keys,
            journal,
            app,
            claim,
            witness,
            enrollment: [0; 32],
        }
    }
    pub fn prepare(&mut self, operation: Option<Operation>, id: u64, wait: u8) -> Prepared {
        let parent = self.journal.best_validated();
        let old_heads = self
            .app
            .control(self.journal.validated_shards(parent).unwrap())
            .unwrap();
        if operation.is_none() {
            let provisional =
                Expected::bootstrap(&self.claim, parent.genesis, parent.block, [0; 32]).unwrap();
            self.enrollment = statement::encoded(source::commitment::digest(
                &commitment::enrollment_fields(&provisional, &self.witness),
            ));
        }
        let kind = if operation.is_none() {
            registry200_journal::Operation::Bootstrap
        } else {
            registry200_journal::Operation::Transition
        };
        let mut nonce = [0; 32];
        nonce[..8].copy_from_slice(&parent.height.to_le_bytes());
        nonce[8..16].copy_from_slice(&id.to_le_bytes());
        nonce[16] = wait;
        let mut source = self.claim.clone();
        source.request = registry200_journal::intent_query(
            &self.app,
            parent.genesis,
            parent.block,
            nonce,
            self.enrollment,
            kind,
        );
        source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &source,
            self.witness.salts[0],
            &self.witness.plain,
        ));
        let mut witness = self.witness.clone();
        witness.command = operation.map(|op| {
            let seq = witness
                .old
                .transactions
                .iter()
                .find(|t| t.id == id)
                .map_or(0, |t| t.sequence);
            let mut c = Command::control(op, id, id as u8, seq);
            if op == Operation::Acquire {
                c.mask = [255; 32];
                c.mode = 4;
                c.wait = wait;
                c.limit = 4;
                c.projection = 3;
            }
            c
        });
        let mut expected = match Control::decode(&self.app, old_heads).unwrap() {
            Control::Pending => {
                Expected::bootstrap(&source, parent.genesis, parent.block, self.enrollment).unwrap()
            }
            Control::Active { registry, .. } => Expected::transition(
                &source,
                parent.genesis,
                parent.block,
                self.enrollment,
                registry,
                [0; 32],
            )
            .unwrap(),
        };
        if let Phase::Transition { old, .. } = expected.phase {
            expected.phase = Phase::Transition {
                old,
                command: statement::digest(&commitment::command_fields(
                    &expected,
                    &witness,
                    witness.command.as_ref().unwrap(),
                )),
            };
        }
        let canonical = admission::CanonicalSource::checked_claim(&source).unwrap();
        let source_witness = source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        );
        let source_bytes = source::prove(&canonical, &source_witness)
            .unwrap()
            .into_bytes();
        drop(source_witness);
        let checked = admission::Expected::checked_claim(&expected).unwrap();
        let prepared = lifecycle::PreparedWitness::new(&checked, witness.clone()).unwrap();
        let evidence = lifecycle::prove(&checked, &prepared, &source_bytes).unwrap();
        drop(prepared);
        drop(source_bytes);
        let verified = registry200_proof::wire::verify(&checked, evidence.as_bytes()).unwrap();
        let next = statement::encoded(evidence.statement().next);
        assert_eq!(verified.next_root(), next);
        let outcome = if let Some(c) = &witness.command {
            let step = witness.old.step(c, parent.block, witness.ages()).unwrap();
            let outcome = step.outcome;
            witness.old = step.next;
            if outcome != 1 && outcome != 2 {
                witness.salts[2] = witness.salts[4];
            }
            outcome
        } else {
            witness.salts[2] = witness.salts[4];
            0
        };
        let command = match expected.phase {
            Phase::Bootstrap => [0; 32],
            Phase::Transition { command, .. } => statement::encoded(command),
        };
        let request = Request {
            operation: kind,
            genesis: parent.genesis,
            parent: parent.block,
            application: self.app.id(),
            nonce,
            query: source.request,
            enrollment: self.enrollment,
            opening: statement::encoded(source.open_commitment),
            command,
            packets: source.packets,
        };
        let mut tx = AuthorizedTransition {
            parent: parent.block,
            request: request.encode().unwrap(),
            updates: vec![ShardUpdate {
                id: self.app.control_id,
                old: old_heads,
                new: Control::Active {
                    enrollment: self.enrollment,
                    registry: next,
                }
                .heads(&self.app),
            }],
            proof: evidence.as_bytes().to_vec(),
            owner_signature: [0; 64],
        };
        tx.sign(parent.genesis, &SigningKey::from_bytes(&[0x55; 32]));
        drop(evidence);
        let body = Body::Transition(tx);
        let bytes = body
            .encode(&self.binding.journal_genesis().profile)
            .unwrap();
        let mut header = if outcome == 1 || outcome == 2 {
            // Genuine blocked proof, correctly mined unchanged-state header;
            // the real application MUST refuse it as a nonappendable transition.
            let mut h = self
                .journal
                .candidate(parent.block, &Body::Empty, 1001 + parent.height)
                .unwrap();
            h.body_hash = version_journal::hash(&bytes);
            h
        } else {
            self.journal
                .candidate(parent.block, &body, 1001 + parent.height)
                .unwrap()
        };
        header.mine(1000).unwrap();
        Prepared {
            block: CandidateBlock::new(header, bytes).unwrap(),
            next: witness,
            outcome,
        }
    }
    pub fn adopt(&mut self, prepared: Prepared) -> CandidateBlock {
        assert_eq!(prepared.outcome, 0);
        let verifier = registry200_journal::RegistryVerifier::new(
            self.app.clone(),
            self.binding.journal_genesis(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.journal
            .import_block(
                prepared.block.header().clone(),
                prepared.block.body(),
                now,
                &verifier,
            )
            .unwrap();
        self.witness = prepared.next;
        prepared.block
    }
}
