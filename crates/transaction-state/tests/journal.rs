//! Genuine signed metadata transitions, real work, independent state witnesses
//! and durable journal I/O. No test adapter accepts an unproved SQL transition.
use ed25519_dalek::{Signer, SigningKey};
use transaction_state::*;
use version_journal::{
    AuthorizedTransition, Body, DurableJournal, Freshness, Genesis, HeadPair, Header, Journal,
    ProtocolProfile, ShardState, ShardUpdate, Target,
};

fn key() -> SigningKey {
    let mut seed = [0; 32];
    getrandom::getrandom(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}
struct OwnedFile(Option<std::path::PathBuf>);
impl Drop for OwnedFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}
fn profile() -> Profile {
    Profile {
        max_transactions: 8,
        max_locks: 32,
        max_lock_events: 128,
        max_candidates: 32,
        max_savepoints_per_transaction: 8,
        max_state_bytes: 64 * 1024,
        max_command_bytes: 4096,
    }
}
struct Fixture {
    context: Context,
    owner: SigningKey,
    controller: SigningKey,
    verifier: MetadataVerifier,
    genesis: Genesis,
}
impl Fixture {
    fn new() -> Self {
        let context = Context::new([1; 32], [2; 16], profile()).unwrap();
        let owner = key();
        let controller = key();
        let verifier = MetadataVerifier::new(context, 7);
        let state = State::new(context);
        let genesis = Genesis {
            network_id: context.network(),
            database: context.database(),
            owner: owner.verifying_key().to_bytes(),
            application_commitment: verifier.application_commitment(),
            timestamp: 1000,
            profile: ProtocolProfile {
                initial_target: Target([0x1f; 32]),
                pow_limit: Target([0x1f; 32]),
                block_spacing_secs: 1,
                retarget_interval: 1024,
                max_future_secs: 60,
                confirmation_depth: 1,
                max_headers: 128,
                max_shards: 4,
                max_updates: 4,
                max_body_bytes: 128 * 1024,
                max_request_bytes: 4096,
                max_proof_bytes: 64 * 1024,
                max_journal_bytes: 4 * 1024 * 1024,
            },
            initial_shards: vec![
                ShardState {
                    id: 7,
                    heads: verifier.heads(&state).unwrap(),
                },
                // Public opaque unchanged heads test that metadata evidence
                // cannot authorize an unrelated data-shard replacement.
                ShardState {
                    id: 9,
                    heads: HeadPair {
                        data: [4; 112],
                        index: [5; 112],
                    },
                },
            ],
        };
        Self {
            context,
            owner,
            controller,
            verifier,
            genesis,
        }
    }
    fn signed(
        &self,
        journal: &Journal,
        parent: [u8; 32],
        state: &State,
        id: TransactionId,
        controller: &SigningKey,
        action: Action,
    ) -> SignedIntent {
        let intent = Intent {
            genesis: journal.genesis_id(),
            parent,
            controller: ControllerId(controller.verifying_key().to_bytes()),
            statement: [6; 32],
            command: Command {
                expected_revision: state.revision(),
                transaction: id,
                sequence: state.transaction(id).map_or(0, |tx| tx.next_sequence),
                action,
            },
        };
        let signature = controller
            .sign(&intent.signing_message(self.context).unwrap())
            .to_bytes();
        SignedIntent { intent, signature }
    }
    fn body(&self, parent: [u8; 32], prepared: &PreparedTransition) -> Body {
        let mut transition = AuthorizedTransition {
            parent,
            request: prepared.request.clone(),
            proof: prepared.witness.clone(),
            updates: vec![prepared.update.clone()],
            owner_signature: [0; 64],
        };
        transition.sign(self.genesis.id().unwrap(), &self.owner);
        Body::Transition(transition)
    }
}
fn mined(
    journal: &Journal,
    parent: [u8; 32],
    body: &Body,
    verifier: &MetadataVerifier,
) -> (Header, Vec<u8>) {
    journal.verify_candidate(parent, body, verifier).unwrap();
    let height = journal.header(parent).map_or(0, |header| header.height);
    let mut header = journal.candidate(parent, body, 1001 + height).unwrap();
    header.mine(100_000).unwrap();
    (header, body.encode(journal.profile()).unwrap())
}
fn append(
    journal: &mut Journal,
    parent: [u8; 32],
    body: &Body,
    verifier: &MetadataVerifier,
) -> [u8; 32] {
    let (header, bytes) = mined(journal, parent, body, verifier);
    journal
        .import_block(header, &bytes, 2000, verifier)
        .unwrap()
        .block
}
fn row() -> RowKey {
    RowKey {
        table: [7; 32],
        row: [8; 32],
    }
}

#[test]
fn signed_metadata_state_is_confirmed_without_granting_permission_to_update_data() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.genesis.clone()).unwrap();
    let initial = State::new(fixture.context);
    let parent = journal.genesis_id();
    let id = initial.next_transaction_id().unwrap();
    let signed = fixture.signed(
        &journal,
        parent,
        &initial,
        id,
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let begun = fixture.verifier.prepare(&initial, &signed).unwrap();
    let body = fixture.body(parent, &begun);
    let (header, bytes) = mined(&journal, parent, &body, &fixture.verifier);
    let block = header.id();

    journal
        .import_block(header.clone(), &bytes, 2000, &fixture.verifier)
        .unwrap();

    assert_eq!(journal.best_validated().block, block);
    assert_eq!(
        journal.resolve(Freshness::LatestConfirmed).unwrap().height,
        0
    );
    assert_eq!(
        journal.validated_shards(journal.best_validated()).unwrap()[0].heads,
        begun.update.new
    );
    // The same durable publication identity is idempotent, not another BEGIN.
    journal
        .import_block(header, &bytes, 2000, &fixture.verifier)
        .unwrap();
    assert_eq!(journal.best_validated().height, 1);
    append(&mut journal, block, &Body::Empty, &fixture.verifier);
    let confirmed = journal.resolve(Freshness::LatestConfirmed).unwrap();
    assert_eq!(confirmed.block, block);
    assert!(journal.resolve(Freshness::Exact(confirmed)).is_ok());

    let signed = fixture.signed(
        &journal,
        journal.best_validated().block,
        &begun.state,
        id,
        &fixture.controller,
        Action::Acquire {
            candidates: vec![row()],
            mode: LockMode::Update,
            wait: WaitPolicy::NoWait,
            offset: 0,
            limit: Some(1),
        },
    );
    let locked = fixture.verifier.prepare(&begun.state, &signed).unwrap();
    let parent = journal.best_validated().block;
    let locked_block = append(
        &mut journal,
        parent,
        &fixture.body(parent, &locked),
        &fixture.verifier,
    );
    append(&mut journal, locked_block, &Body::Empty, &fixture.verifier);
    assert_eq!(locked.state.held_mode(id, row()), Some(LockMode::Update));
    assert_eq!(
        journal.resolve(Freshness::LatestConfirmed).unwrap().block,
        locked_block
    );
    assert_eq!(
        journal
            .shards(
                journal.resolve(Freshness::LatestConfirmed).unwrap(),
                Freshness::AtLeast(confirmed)
            )
            .unwrap()[1],
        fixture.genesis.initial_shards[1]
    );
}

#[test]
fn tampered_witness_and_an_extra_data_update_never_publish_a_head() {
    let fixture = Fixture::new();
    let journal = Journal::new(fixture.genesis.clone()).unwrap();
    let state = State::new(fixture.context);
    let parent = journal.genesis_id();
    let signed = fixture.signed(
        &journal,
        parent,
        &state,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let prepared = fixture.verifier.prepare(&state, &signed).unwrap();
    let Body::Transition(valid) = fixture.body(parent, &prepared) else {
        unreachable!()
    };
    let before = journal.best_validated();
    for kind in 0..5 {
        let mut altered = valid.clone();
        match kind {
            0 => altered.proof.push(0),
            1 => altered.proof[96] ^= 1,
            2 => altered.request[120] ^= 1,
            3 => altered.updates[0].new.index[40] ^= 1,
            4 => altered.updates.push(ShardUpdate {
                id: 9,
                old: fixture.genesis.initial_shards[1].heads,
                new: HeadPair {
                    data: [10; 112],
                    index: [11; 112],
                },
            }),
            _ => unreachable!(),
        }
        altered.sign(parent, &fixture.owner);

        let result =
            journal.verify_candidate(parent, &Body::Transition(altered), &fixture.verifier);

        assert!(result.is_err(), "tamper case {kind}");
        assert_eq!(journal.best_validated(), before);
    }
}

#[test]
fn controller_cannot_release_another_transaction_even_with_outer_owner_permission() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.genesis.clone()).unwrap();
    let initial = State::new(fixture.context);
    let root = journal.genesis_id();
    let signed = fixture.signed(
        &journal,
        root,
        &initial,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let begun = fixture.verifier.prepare(&initial, &signed).unwrap();
    let parent = append(
        &mut journal,
        root,
        &fixture.body(root, &begun),
        &fixture.verifier,
    );
    let outsider = key();
    let signed = fixture.signed(
        &journal,
        parent,
        &begun.state,
        TransactionId(1),
        &outsider,
        Action::End {
            completion: Completion::Abort,
        },
    );
    assert!(matches!(
        fixture.verifier.prepare(&begun.state, &signed),
        Err(Error::WrongController)
    ));
    let forged_state = begun
        .state
        .transition(
            ControllerId(fixture.controller.verifying_key().to_bytes()),
            &signed.intent.command,
        )
        .unwrap()
        .state;
    let mut forged = AuthorizedTransition {
        parent,
        request: signed.encode(fixture.context).unwrap(),
        proof: begun.state.encode().unwrap(),
        updates: vec![ShardUpdate {
            id: 7,
            old: begun.update.new,
            new: fixture.verifier.heads(&forged_state).unwrap(),
        }],
        owner_signature: [0; 64],
    };
    forged.sign(root, &fixture.owner);
    let before = journal.best_validated();

    let result = journal.verify_candidate(parent, &Body::Transition(forged), &fixture.verifier);

    assert_eq!(
        result,
        Err(version_journal::Error::RejectedComputationProof)
    );
    assert_eq!(journal.best_validated(), before);
}

#[test]
fn a_signed_command_cannot_be_rebased_or_replayed_with_a_new_state_revision() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.genesis.clone()).unwrap();
    let initial = State::new(fixture.context);
    let root = journal.genesis_id();
    let signed = fixture.signed(
        &journal,
        root,
        &initial,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let begun = fixture.verifier.prepare(&initial, &signed).unwrap();
    let parent = append(
        &mut journal,
        root,
        &fixture.body(root, &begun),
        &fixture.verifier,
    );
    let fresh = fixture.signed(
        &journal,
        parent,
        &begun.state,
        TransactionId(1),
        &fixture.controller,
        Action::Savepoint { name: [12; 32] },
    );
    let prepared = fixture.verifier.prepare(&begun.state, &fresh).unwrap();
    let new_parent = append(&mut journal, parent, &Body::Empty, &fixture.verifier);
    let Body::Transition(mut rebased) = fixture.body(new_parent, &prepared) else {
        unreachable!()
    };
    rebased.sign(root, &fixture.owner);

    let result =
        journal.verify_candidate(new_parent, &Body::Transition(rebased), &fixture.verifier);

    assert_eq!(
        result,
        Err(version_journal::Error::RejectedComputationProof)
    );
    // Original exact parent remains a valid branch-specific command.
    assert!(
        journal
            .verify_candidate(parent, &fixture.body(parent, &prepared), &fixture.verifier)
            .is_ok()
    );
    let mut replay = fresh;
    replay.intent.command.expected_revision += 1;
    assert!(matches!(
        replay.verify(fixture.context),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn confirmed_control_receipts_can_be_reorganized_and_do_not_establish_finality() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.genesis.clone()).unwrap();
    let initial = State::new(fixture.context);
    let root = journal.genesis_id();
    let signed_a = fixture.signed(
        &journal,
        root,
        &initial,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let a = fixture.verifier.prepare(&initial, &signed_a).unwrap();
    let a_block = append(
        &mut journal,
        root,
        &fixture.body(root, &a),
        &fixture.verifier,
    );
    append(&mut journal, a_block, &Body::Empty, &fixture.verifier);
    let old = journal.resolve(Freshness::LatestConfirmed).unwrap();
    assert_eq!(old.block, a_block);
    let other = key();
    let signed_b = fixture.signed(
        &journal,
        root,
        &initial,
        TransactionId(1),
        &other,
        Action::Begin { snapshot: [9; 32] },
    );
    let b = fixture.verifier.prepare(&initial, &signed_b).unwrap();
    let mut tip = append(
        &mut journal,
        root,
        &fixture.body(root, &b),
        &fixture.verifier,
    );

    for _ in 0..3 {
        tip = append(&mut journal, tip, &Body::Empty, &fixture.verifier);
    }

    assert_eq!(
        journal.resolve(Freshness::AtLeast(old)),
        Err(version_journal::Error::Reorganized)
    );
    assert_eq!(
        journal.validated_shards(journal.best_validated()).unwrap()[0].heads,
        b.update.new
    );
    assert_ne!(a.update.new, b.update.new);
}

#[test]
fn controller_signatures_and_bounded_command_codec_bind_every_context_and_policy_byte() {
    let fixture = Fixture::new();
    let journal = Journal::new(fixture.genesis.clone()).unwrap();
    let state = State::new(fixture.context);
    let signed = fixture.signed(
        &journal,
        journal.genesis_id(),
        &state,
        TransactionId(1),
        &fixture.controller,
        Action::Acquire {
            candidates: vec![row()],
            mode: LockMode::Update,
            wait: WaitPolicy::SkipLocked,
            offset: 0,
            limit: None,
        },
    );
    let bytes = signed.encode(fixture.context).unwrap();
    let decoded = SignedIntent::decode(&bytes, fixture.context).unwrap();
    assert_eq!(decoded, signed);
    decoded.verify(fixture.context).unwrap();
    for offset in [88, 120, 184, 216, 232, 241, 242, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            SignedIntent::decode(&changed, fixture.context)
                .and_then(|intent| intent.verify(fixture.context))
                .is_err(),
            "offset {offset}"
        );
    }
    let mut oversized_count = bytes.clone();
    oversized_count[248..252].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        SignedIntent::decode(&oversized_count, fixture.context),
        Err(Error::ResourceLimit)
    ));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        SignedIntent::decode(&trailing, fixture.context),
        Err(Error::InvalidEncoding)
    ));
    let wrong = Context::new([20; 32], fixture.context.database(), profile()).unwrap();
    assert!(signed.verify(wrong).is_err());
}

#[test]
fn public_control_verification_rejects_an_inconsistent_parent_database() {
    let fixture = Fixture::new();
    let journal = Journal::new(fixture.genesis.clone()).unwrap();
    let state = State::new(fixture.context);
    let parent = journal.genesis_head();
    let signed = fixture.signed(
        &journal,
        parent.block,
        &state,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let prepared = fixture.verifier.prepare(&state, &signed).unwrap();
    let mut next = fixture.genesis.initial_shards.clone();
    next[0].heads = prepared.update.new;
    let updates = [prepared.update];
    let statement = version_journal::TransitionStatement {
        genesis: parent.genesis,
        database: parent.database,
        application_commitment: fixture.verifier.application_commitment(),
        parent,
        previous_shards: &fixture.genesis.initial_shards,
        next_shards: &next,
        request: &prepared.request,
        updates: &updates,
        proof: &prepared.witness,
        next_state_root: version_journal::state_root(&next),
    };
    let verified = fixture.verifier.verify_control(&statement).unwrap();
    assert_eq!(verified.parent(), parent.block);
    assert_eq!(verified.genesis(), parent.genesis);
    assert_eq!(verified.state().revision(), 1);
    assert_eq!(verified.outcome(), &Outcome::Began(TransactionId(1)));
    let mut inconsistent = statement;
    inconsistent.parent.database = [99; 16];

    let result = fixture.verifier.verify_control(&inconsistent);

    assert!(matches!(result, Err(Error::WrongDomain)));
}

#[test]
fn equal_control_outcomes_do_not_alias_different_signed_statement_requests() {
    let fixture = Fixture::new();
    let journal = Journal::new(fixture.genesis.clone()).unwrap();
    let state = State::new(fixture.context);
    let parent = journal.genesis_head();
    let mut signed = fixture.signed(
        &journal,
        parent.block,
        &state,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let first = fixture.verifier.prepare(&state, &signed).unwrap();
    signed.intent.statement[0] ^= 1;
    signed.signature = fixture
        .controller
        .sign(&signed.intent.signing_message(fixture.context).unwrap())
        .to_bytes();
    let second = fixture.verifier.prepare(&state, &signed).unwrap();
    assert_eq!(first.update, second.update);
    assert_eq!(first.outcome, second.outcome);
    let mut next = fixture.genesis.initial_shards.clone();
    next[0].heads = first.update.new;
    let updates = [first.update];
    let mut statement = version_journal::TransitionStatement {
        genesis: parent.genesis,
        database: parent.database,
        application_commitment: fixture.verifier.application_commitment(),
        parent,
        previous_shards: &fixture.genesis.initial_shards,
        next_shards: &next,
        request: &first.request,
        updates: &updates,
        proof: &first.witness,
        next_state_root: version_journal::state_root(&next),
    };

    let receipt = fixture.verifier.verify_control(&statement).unwrap();
    statement.request = &second.request;
    let other = fixture.verifier.verify_control(&statement).unwrap();

    assert!(receipt.matches_request(&first.request));
    assert!(other.matches_request(&second.request));
    assert!(!receipt.matches_request(&second.request));
    assert!(!other.matches_request(&first.request));
    assert_ne!(receipt.request_digest(), other.request_digest());
    assert_eq!(receipt.state().encode(), other.state().encode());
    let mut corrupt = first.request;
    corrupt.push(0);
    assert!(!receipt.matches_request(&corrupt));
}

#[test]
fn durable_metadata_reopens_and_rejected_witness_cannot_change_file_or_head() {
    let fixture = Fixture::new();
    let state = State::new(fixture.context);
    let path = std::env::temp_dir().join(format!(
        "dcs-transaction-journal-{}-{}.bin",
        std::process::id(),
        u128::from_le_bytes({
            let mut bytes = [0; 16];
            getrandom::getrandom(&mut bytes).unwrap();
            bytes
        })
    ));
    let mut cleanup = OwnedFile(None);
    let mut durable = DurableJournal::create(&path, fixture.genesis.clone(), [71; 32]).unwrap();
    cleanup.0 = Some(path.clone());
    let root = durable.journal().genesis_id();
    let signed = fixture.signed(
        durable.journal(),
        root,
        &state,
        TransactionId(1),
        &fixture.controller,
        Action::Begin { snapshot: [9; 32] },
    );
    let begun = fixture.verifier.prepare(&state, &signed).unwrap();
    let body = fixture.body(root, &begun);
    let (header, bytes) = mined(durable.journal(), root, &body, &fixture.verifier);
    let block = header.id();
    durable
        .append_block(header, &bytes, 2000, &fixture.verifier)
        .unwrap();
    let (header, bytes) = mined(durable.journal(), block, &Body::Empty, &fixture.verifier);
    durable
        .append_block(header, &bytes, 2000, &fixture.verifier)
        .unwrap();
    let before = durable
        .journal()
        .resolve(Freshness::LatestConfirmed)
        .unwrap();
    let parent = durable.journal().best_validated().block;
    let signed = fixture.signed(
        durable.journal(),
        parent,
        &begun.state,
        TransactionId(1),
        &fixture.controller,
        Action::Savepoint { name: [12; 32] },
    );
    let prepared = fixture.verifier.prepare(&begun.state, &signed).unwrap();
    let Body::Transition(mut bad) = fixture.body(parent, &prepared) else {
        unreachable!()
    };
    bad.proof.push(0);
    bad.sign(root, &fixture.owner);
    let body = Body::Transition(bad);
    let mut header = durable.journal().candidate(parent, &body, 1003).unwrap();
    header.mine(100_000).unwrap();
    let bytes = body.encode(durable.journal().profile()).unwrap();
    // Windows' exclusive lifecycle lock forbids a second handle reading bytes.
    // Close our writer before snapshotting, then reopen against the pinned genesis.
    drop(durable);
    let file_before = std::fs::read(&path).unwrap();
    let mut durable = DurableJournal::open(
        &path,
        fixture.genesis.clone(),
        [71; 32],
        2000,
        &fixture.verifier,
    )
    .unwrap();

    let result = durable.append_block(header, &bytes, 2000, &fixture.verifier);

    assert!(result.is_err());
    assert_eq!(durable.disk_bytes(), file_before.len() as u64);
    assert_eq!(
        durable
            .journal()
            .resolve(Freshness::LatestConfirmed)
            .unwrap(),
        before
    );
    drop(durable);
    assert_eq!(std::fs::read(&path).unwrap(), file_before);
    let reopened = DurableJournal::open(
        &path,
        fixture.genesis.clone(),
        [71; 32],
        2000,
        &fixture.verifier,
    )
    .unwrap();
    assert_eq!(
        reopened
            .journal()
            .resolve(Freshness::LatestConfirmed)
            .unwrap(),
        before
    );
    assert_eq!(
        reopened
            .journal()
            .shards(before, Freshness::Exact(before))
            .unwrap()[0]
            .heads,
        begun.update.new
    );
    drop(reopened);
}
