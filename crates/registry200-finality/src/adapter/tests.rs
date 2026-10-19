//! PUBLIC NONSECRET keys/openings. These are real local Journal/proof/filesystem
//! consumers, not a simulated network or a live SQL acceptance test.
use crate::adapter::RegistryFinality;
use crate::*;
use compact_store::{Layout, Owner};
use ed25519_dalek::SigningKey;
use p3_field::PrimeCharacteristicRing;
use protocol_storage::ByteBudget;
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
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Header, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits, NetworkSeed, QuorumCertificate, SignedVote, Step, VoteContext,
    WorkTicket,
    consensus::{Context, Input, MAX_RECORD_BYTES, Rules},
};
use zeroize::Zeroizing;

struct Files {
    parent: PathBuf,
    path: PathBuf,
    name: std::ffi::OsString,
}
impl Files {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..64 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = std::ffi::OsString::from(format!(
                "dcs-public-registry-finality-{}-{t}-{n}",
                std::process::id()
            ));
            let raw = parent.join(&name);
            match fs::create_dir(&raw) {
                Ok(()) => {
                    let path = raw.canonicalize().unwrap();
                    assert_eq!(path.parent(), Some(parent.as_path()));
                    assert_eq!(path.file_name(), Some(name.as_os_str()));
                    return Self { parent, path, name };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create public fixture directory: {e}"),
            }
        }
        panic!("bounded unique fixture directory");
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        if let Ok(actual) = self.path.canonicalize()
            && actual.parent() == Some(self.parent.as_path())
            && actual.file_name() == Some(self.name.as_os_str())
            && actual == self.path
        {
            let _ = fs::remove_dir_all(actual);
        }
    }
}
struct Fixture {
    binding: Binding,
    app: Application,
    claim: source::Statement,
    witness: Witness,
    keys: Vec<SigningKey>,
}
impl Fixture {
    fn new() -> Self {
        let key = [0x71; 32];
        let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(key));
        let limits = source::statement::limits();
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
                limits,
            )
            .unwrap();
        let suffix: Vec<u8> =
            include_str!("../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
                .lines()
                .filter(|line| !line.starts_with('#'))
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
        let root = source::commitment::digest(&source::commitment::key_fields(
            &stored.commitment().encode(),
            key,
            [Val::ONE; 4],
        ));
        let claim = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&stored.encode(), &indexed.encode()],
            [stored.commitment(), indexed.commitment()],
            [0; 32],
            source::statement::encode_digest(root),
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
            profile_digest(),
            DESCRIPTOR_BYTES as u32,
            32,
            [100, 200, 300],
            10,
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
        let journal = Genesis {
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
            journal,
            ApplicationDescriptor::from_application(&app).unwrap(),
        )
        .unwrap();
        drop(owner);
        drop(stored);
        drop(indexed);
        Self {
            binding,
            app,
            claim,
            witness,
            keys,
        }
    }
    fn key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.keys[0].to_bytes())
    }
    fn certificate(
        &self,
        context: &Context,
        descriptor: &Descriptor,
        round: u64,
        start: usize,
    ) -> QuorumCertificate {
        // Exact public vote domain of the independently pinned Context. This is
        // test-side construction; production exposes no stateless signer key.
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
            Some(context.value_id(&descriptor.encode()).unwrap()),
        )
        .unwrap();
        let votes: Vec<_> = self.keys[start..start + 3]
            .iter()
            .map(|key| SignedVote::sign(expected, key).unwrap())
            .collect();
        QuorumCertificate::assemble(context.set(), &expected, &votes).unwrap()
    }
    fn commit(&self, owned: &mut RegistryFinality, descriptor: &Descriptor) {
        let certificate = self.certificate(owned.context(), descriptor, 0, 0);
        let bytes = Input::Certificate {
            value: descriptor.encode().to_vec(),
            certificate,
        }
        .encode()
        .unwrap();
        owned.receive(&bytes).unwrap();
        assert_eq!(
            owned.finalized_head().unwrap().unwrap().head().block,
            descriptor.header().id()
        );
        assert_eq!(owned.context().slot(), descriptor.slot() + 1);
    }
    fn empty(&self, owned: &RegistryFinality, nonce: u64) -> (Header, Vec<u8>) {
        let state = owned.state.lock().unwrap();
        let parent = state.journal.journal().ancestry_floor();
        let mut h = state
            .journal
            .journal()
            .candidate(parent.block, &Body::Empty, 1000 + parent.height + 1)
            .unwrap();
        h.nonce = nonce;
        h.mine(1000).unwrap();
        (
            h,
            Body::Empty
                .encode(state.journal.journal().profile())
                .unwrap(),
        )
    }
}

#[test]
fn actual_empty_checkpoint_is_monotonic_durable_and_alternative_qc_does_not_fork_next_slot() {
    let f = Fixture::new();
    let files = Files::new();
    let budget = ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap();
    let mut owned =
        RegistryFinality::create_new(&files.path, f.binding.clone(), f.key(), &budget).unwrap();
    assert!(owned.finalized_head().unwrap().is_none());
    let (header, body) = f.empty(&owned, 0);
    let d = owned.import_candidate(header.clone(), &body).unwrap();
    // Duplicate import still runs actual Header/Body checks.
    assert_eq!(owned.import_candidate(header, &body).unwrap(), d);
    let (sibling, sibling_body) = f.empty(&owned, 1);
    assert_ne!(sibling.id(), d.header().id());
    assert_eq!(sibling.state_root, d.header().state_root);
    owned
        .import_candidate(sibling.clone(), &sibling_body)
        .unwrap();
    assert_eq!(Descriptor::decode(&d.encode()).unwrap(), d);
    for n in [0, 1, 79, DESCRIPTOR_BYTES - 1] {
        assert!(Descriptor::decode(&d.encode()[..n]).is_err());
    }
    let mut trailing = d.encode().to_vec();
    trailing.push(0);
    assert!(Descriptor::decode(&trailing).is_err());
    let original = owned.context().clone();
    let a = f.certificate(&original, &d, 0, 0);
    let b = f.certificate(&original, &d, 7, 1);
    let da = original
        .verify_commit(&d.encode(), 0, &a.encode().unwrap())
        .unwrap();
    let db = original
        .verify_commit(&d.encode(), 7, &b.encode().unwrap())
        .unwrap();
    assert_eq!(
        original.after_decision(&da).unwrap(),
        original.after_decision(&db).unwrap()
    );
    f.commit(&mut owned, &d);
    assert_eq!(
        owned.state.lock().unwrap().journal.journal().best_header(),
        d.header().id()
    );
    assert_eq!(
        owned
            .state
            .lock()
            .unwrap()
            .journal
            .journal()
            .best_validated()
            .block,
        d.header().id()
    );
    assert!(matches!(
        owned.import_candidate(sibling, &sibling_body),
        Err(Error::WrongContext)
    ));
    let floor = owned.finalized_head().unwrap().unwrap();
    let second_context = owned.context().clone();
    drop(owned);
    let reopened = RegistryFinality::open_existing(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.finalized_head().unwrap(), Some(floor));
    assert_eq!(reopened.context(), &second_context);
    assert!(reopened.outbound().unwrap().is_empty());
}

#[test]
fn missing_candidate_wrong_parent_and_signed_invalid_application_never_make_a_floor() {
    let f = Fixture::new();
    let files = Files::new();
    let mut owned = RegistryFinality::create_new(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    let (header, _) = f.empty(&owned, 0);
    let missing = Descriptor::for_context(&f.binding, owned.context(), header);
    assert!(owned.propose(&missing).is_err());
    assert!(owned.finalized_head().unwrap().is_none());
    let (stored, empty_body) = f.empty(&owned, 0);
    owned.import_candidate(stored.clone(), &empty_body).unwrap();
    let mut child = owned
        .state
        .lock()
        .unwrap()
        .journal
        .journal()
        .candidate(stored.id(), &Body::Empty, 1002)
        .unwrap();
    child.mine(1000).unwrap();
    assert!(matches!(
        owned.import_candidate(child, &empty_body),
        Err(Error::WrongContext)
    ));
    let mut tx = AuthorizedTransition {
        parent: f.binding.journal_genesis().id().unwrap(),
        request: vec![0],
        proof: vec![0],
        updates: vec![ShardUpdate {
            id: f.app.control_id,
            old: Control::Pending.heads(&f.app),
            new: Control::Active {
                enrollment: [0; 32],
                registry: [0; 32],
            }
            .heads(&f.app),
        }],
        owner_signature: [0; 64],
    };
    tx.sign(tx.parent, &SigningKey::from_bytes(&[0x55; 32]));
    let body = Body::Transition(tx);
    let mut h = owned
        .state
        .lock()
        .unwrap()
        .journal
        .journal()
        .candidate(f.binding.journal_genesis().id().unwrap(), &body, 1001)
        .unwrap();
    h.mine(1000).unwrap();
    let bytes = body.encode(&f.binding.journal_genesis().profile).unwrap();
    assert!(owned.import_candidate(h, &bytes).is_err());
    assert!(owned.finalized_head().unwrap().is_none());
    drop(owned);
    let reopened = RegistryFinality::open_existing(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    assert!(reopened.finalized_head().unwrap().is_none());
}

#[test]
fn actual_source_bootstrap_begin_acquire_end_decisions_reverify_after_private_inputs_drop() {
    let mut f = Fixture::new();
    let files = Files::new();
    let mut owned = RegistryFinality::create_new(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    let mut enrollment = [0; 32];
    for operation in [
        None,
        Some(Operation::Begin),
        Some(Operation::Acquire),
        Some(Operation::End),
    ] {
        let parent = owned
            .state
            .lock()
            .unwrap()
            .journal
            .journal()
            .ancestry_floor();
        let old_heads = {
            let state = owned.state.lock().unwrap();
            f.app
                .control(state.journal.journal().validated_shards(parent).unwrap())
                .unwrap()
        };
        let wire_operation = if operation.is_none() {
            registry200_journal::Operation::Bootstrap
        } else {
            registry200_journal::Operation::Transition
        };
        let provisional =
            Expected::bootstrap(&f.claim, parent.genesis, parent.block, enrollment).unwrap();
        if operation.is_none() {
            enrollment = statement::encoded(source::commitment::digest(
                &commitment::enrollment_fields(&provisional, &f.witness),
            ));
        }
        let nonce = [parent.height as u8 + 0x10; 32];
        f.claim.request = registry200_journal::intent_query(
            &f.app,
            parent.genesis,
            parent.block,
            nonce,
            enrollment,
            wire_operation,
        );
        f.claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &f.claim,
            f.witness.salts[0],
            &f.witness.plain,
        ));
        let mut expected = match Control::decode(&f.app, old_heads).unwrap() {
            Control::Pending => {
                Expected::bootstrap(&f.claim, parent.genesis, parent.block, enrollment).unwrap()
            }
            Control::Active { registry, .. } => Expected::transition(
                &f.claim,
                parent.genesis,
                parent.block,
                enrollment,
                registry,
                [0; 32],
            )
            .unwrap(),
        };
        f.witness.command = operation.map(|op| {
            let sequence = f
                .witness
                .old
                .transactions
                .first()
                .map_or(0, |tx| tx.sequence);
            let mut c = Command::control(op, 1, 1, sequence);
            if op == Operation::Acquire {
                c.mask = [255; 32];
                c.mode = 4;
                c.limit = 4;
                c.projection = 3;
            }
            c
        });
        if let Phase::Transition { old, .. } = expected.phase {
            let command = statement::digest(&commitment::command_fields(
                &expected,
                &f.witness,
                f.witness.command.as_ref().unwrap(),
            ));
            expected.phase = Phase::Transition { old, command };
        }
        let source = admission::CanonicalSource::checked_claim(&f.claim).unwrap();
        let source_witness = source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        );
        let source_bytes = source::prove(&source, &source_witness)
            .unwrap()
            .into_bytes();
        drop(source_witness);
        let checked = admission::Expected::checked_claim(&expected).unwrap();
        let prepared = lifecycle::PreparedWitness::new(&checked, f.witness.clone()).unwrap();
        let evidence = lifecycle::prove(&checked, &prepared, &source_bytes).unwrap();
        drop(prepared);
        drop(source_bytes);
        let next_root = statement::encoded(evidence.statement().next);
        let command = match expected.phase {
            Phase::Bootstrap => [0; 32],
            Phase::Transition { command, .. } => statement::encoded(command),
        };
        let request = Request {
            operation: wire_operation,
            genesis: parent.genesis,
            parent: parent.block,
            application: f.app.id(),
            nonce,
            query: f.claim.request,
            enrollment,
            opening: statement::encoded(f.claim.open_commitment),
            command,
            packets: f.claim.packets.clone(),
        };
        let mut tx = AuthorizedTransition {
            parent: parent.block,
            request: request.encode().unwrap(),
            updates: vec![ShardUpdate {
                id: f.app.control_id,
                old: old_heads,
                new: Control::Active {
                    enrollment,
                    registry: next_root,
                }
                .heads(&f.app),
            }],
            proof: evidence.as_bytes().to_vec(),
            owner_signature: [0; 64],
        };
        tx.sign(parent.genesis, &SigningKey::from_bytes(&[0x55; 32]));
        drop(evidence);
        let body = Body::Transition(tx);
        let mut header = owned
            .state
            .lock()
            .unwrap()
            .journal
            .journal()
            .candidate(parent.block, &body, 1001 + parent.height)
            .unwrap();
        header.mine(1000).unwrap();
        let bytes = body.encode(&f.binding.journal_genesis().profile).unwrap();
        drop(body);
        let descriptor = owned.import_candidate(header, &bytes).unwrap();
        drop(bytes);
        f.commit(&mut owned, &descriptor);
        if let Some(c) = f.witness.command.as_ref() {
            f.witness.old = f
                .witness
                .old
                .step(c, parent.block, f.witness.ages())
                .unwrap()
                .next;
        }
        f.witness.salts[2] = f.witness.salts[4];
    }
    assert!(f.witness.old.transactions.is_empty());
    let finalized = owned.finalized_head().unwrap();
    let next_context = owned.context().clone();
    let binding = f.binding.clone();
    let key = f.key();
    drop(f);
    drop(owned);
    let mut reopened = RegistryFinality::open_existing(
        &files.path,
        binding.clone(),
        key,
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.finalized_head().unwrap(), finalized);
    assert_eq!(reopened.context(), &next_context);
    // Private Source/registry openings, original owner and original signer were
    // dropped above. The keyless client checks actual persisted bytes/QCs from
    // independent public pins, one original proof-bearing block at a time.
    let mut follower = Follower::new(binding).unwrap();
    while let Some(checkpoint) = reopened
        .checkpoint_after(follower.context().slot() - 1)
        .unwrap()
    {
        let block = reopened
            .candidate_block(checkpoint.descriptor().header().id())
            .unwrap();
        let checked = follower.apply(&checkpoint, &block).unwrap();
        assert_eq!(checked.head().block, checkpoint.descriptor().header().id());
    }
    assert_eq!(follower.context(), &next_context);
    assert_eq!(
        follower.checked_head().unwrap().head(),
        finalized.unwrap().head()
    );
}

#[test]
fn untrusted_checkpoint_codec_and_duplicate_follower_reverify_cannot_skip_body_or_quorum() {
    let f = Fixture::new();
    let files = Files::new();
    let mut owned = RegistryFinality::create_new(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    let (header, body) = f.empty(&owned, 0);
    let d = owned.import_candidate(header, &body).unwrap();
    f.commit(&mut owned, &d);
    let checkpoint = owned.checkpoint_after(0).unwrap().unwrap();
    let block = owned.candidate_block(d.header().id()).unwrap();
    let checkpoint = Checkpoint::decode(&checkpoint.encode()).unwrap();
    let block = CandidateBlock::decode(&block.encode()).unwrap();
    let mut follower = Follower::new(f.binding.clone()).unwrap();
    let checked = follower.apply(&checkpoint, &block).unwrap();
    assert_eq!(
        checked.head(),
        owned.finalized_head().unwrap().unwrap().head()
    );
    let context = follower.context().clone();
    let mut bad_certificate = checkpoint.certificate().to_vec();
    *bad_certificate.last_mut().unwrap() ^= 1;
    let forged = Checkpoint::new(
        checkpoint.descriptor().clone(),
        checkpoint.round(),
        bad_certificate,
    )
    .unwrap();
    assert!(follower.apply(&forged, &block).is_err());
    let mut bad_body = block.body().to_vec();
    *bad_body.last_mut().unwrap() ^= 1;
    let forged = CandidateBlock::new(block.header().clone(), bad_body).unwrap();
    assert!(follower.apply(&checkpoint, &forged).is_err());
    assert_eq!(follower.context(), &context);
    assert_eq!(follower.apply(&checkpoint, &block).unwrap(), checked);
    assert_eq!(follower.context(), &context);
    assert!(owned.checkpoint_after(1).unwrap().is_none());
    for mut bytes in [checkpoint.encode(), block.encode()] {
        bytes.push(0);
        assert!(Checkpoint::decode(&bytes).is_err());
        assert!(CandidateBlock::decode(&bytes).is_err());
    }
    let mut oversized = block.encode();
    oversized[8 + version_journal::HEADER_BYTES..12 + version_journal::HEADER_BYTES]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CandidateBlock::decode(&oversized).is_err());
    drop(owned);
    let mut reopened = RegistryFinality::open_existing(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reopened.checkpoint_after(0).unwrap().unwrap().encode(),
        checkpoint.encode()
    );
    assert_eq!(
        reopened.candidate_block(d.header().id()).unwrap().encode(),
        block.encode()
    );
}

#[test]
fn durable_decision_before_floor_ack_recovers_but_a_torn_floor_tail_is_never_truncated() {
    let f = Fixture::new();
    for fault in [
        crate::store::Fault::AfterSync,
        crate::store::Fault::Partial(9),
    ] {
        let files = Files::new();
        let mut owned = RegistryFinality::create_new(
            &files.path,
            f.binding.clone(),
            f.key(),
            &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
        )
        .unwrap();
        let (header, body) = f.empty(&owned, 0);
        let descriptor = owned.import_candidate(header, &body).unwrap();
        let certificate = f.certificate(owned.context(), &descriptor, 0, 0);
        let input = Input::Certificate {
            value: descriptor.encode().to_vec(),
            certificate,
        }
        .encode()
        .unwrap();
        owned.floor.inject(fault);
        assert!(owned.receive(&input).is_err());
        assert!(owned.finalized_head().is_err());
        assert!(owned.outbound().is_err());
        drop(owned);
        let path = files.path.join("registry-finality-floor-v1");
        let exact = fs::read(&path).unwrap();
        let reopened = RegistryFinality::open_existing(
            &files.path,
            f.binding.clone(),
            f.key(),
            &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
        );
        match fault {
            crate::store::Fault::AfterSync => {
                let recovered = reopened.unwrap();
                assert_eq!(recovered.context().slot(), 2);
                assert_eq!(
                    recovered.finalized_head().unwrap().unwrap().head().block,
                    descriptor.header().id()
                );
                assert!(recovered.outbound().unwrap().is_empty());
                drop(recovered);
            }
            crate::store::Fault::Partial(_) => {
                assert!(matches!(reopened, Err(Error::CorruptFloor)))
            }
        }
        assert_eq!(fs::read(path).unwrap(), exact);
    }
}

#[test]
fn actual_retained_external_file_exhausts_the_same_signer_journal_floor_quota() {
    let f = Fixture::new();
    let files = Files::new();
    let budget = ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap();
    let mut owned =
        RegistryFinality::create_new(&files.path, f.binding.clone(), f.key(), &budget).unwrap();
    let before = owned.state.lock().unwrap().journal.disk_bytes();
    let path = files.path.join("public-external-retained-bytes");
    let external = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    external.try_lock().unwrap();
    external
        .set_len(version_journal::MAX_JOURNAL_BYTES - budget.used().unwrap())
        .unwrap();
    let charge = budget.register_file(&path).unwrap();
    assert_eq!(budget.used().unwrap(), version_journal::MAX_JOURNAL_BYTES);
    let (header, body) = f.empty(&owned, 0);
    assert!(owned.import_candidate(header, &body).is_err());
    assert_eq!(owned.state.lock().unwrap().journal.disk_bytes(), before);
    assert!(owned.finalized_head().unwrap().is_none());
    assert!(owned.outbound().unwrap().is_empty());
    drop(owned);
    drop(charge);
    drop(external);
    assert_eq!(budget.used().unwrap(), version_journal::MAX_JOURNAL_BYTES);
}

#[test]
fn final_admissible_header_keeps_its_floor_and_next_slot_is_terminal_after_reopen() {
    let mut f = Fixture::new();
    let mut genesis = f.binding.journal_genesis().clone();
    genesis.profile.max_headers = 2;
    f.binding = Binding::new(
        [9; 32],
        f.binding.rules().clone(),
        f.binding.work_genesis().clone(),
        genesis,
        f.binding.application_descriptor().clone(),
    )
    .unwrap();
    let files = Files::new();
    let mut owned = RegistryFinality::create_new(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    for _ in 0..2 {
        let (header, body) = f.empty(&owned, 0);
        let descriptor = owned.import_candidate(header, &body).unwrap();
        f.commit(&mut owned, &descriptor);
    }
    let final_floor = owned.finalized_head().unwrap().unwrap();
    let terminal_context = owned.context().clone();
    assert_eq!(final_floor.slot(), 2);
    assert_eq!(final_floor.head().height, 2);
    assert_eq!(terminal_context.slot(), 3);
    assert_eq!(owned.state.lock().unwrap().history.len(), 3);
    assert_eq!(
        owned.state.lock().unwrap().journal.journal().header_count(),
        2
    );
    let (extra, body) = f.empty(&owned, 0);
    assert!(matches!(
        owned.import_candidate(extra, &body),
        Err(Error::Journal(version_journal::Error::ResourceLimit))
    ));
    assert_eq!(owned.state.lock().unwrap().finalized, Some(final_floor));
    assert!(owned.outbound().is_err()); // failed precharged append closes this owner
    drop(owned);
    // Reconstruct actual extents in a fresh budget; the conservative failed
    // precharge in the old owner is never silently released or reused.
    let reopened = RegistryFinality::open_existing(
        &files.path,
        f.binding.clone(),
        f.key(),
        &ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.finalized_head().unwrap(), Some(final_floor));
    assert_eq!(reopened.context(), &terminal_context);
    assert_eq!(
        reopened
            .state
            .lock()
            .unwrap()
            .journal
            .journal()
            .header_count(),
        2
    );
    assert_eq!(reopened.state.lock().unwrap().history.len(), 3);
    assert!(reopened.outbound().unwrap().is_empty());
}
