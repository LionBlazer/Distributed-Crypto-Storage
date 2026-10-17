//! Streamed real proofs and durable lifecycle behavior, with bounded short histories.
use super::*;

#[test]
fn seven_operations_failed_end_abort_and_durable_reopen_use_eight_real_proof_pairs() {
    let f = Fixture::new().unwrap();
    let verifier = f.verifier().unwrap();
    let counted = CountVerifier {
        inner: &verifier,
        calls: Cell::new(0),
    };
    let directory = OwnedDirectory::new().unwrap();
    let path = directory.journal();
    let namespace = [0xD5; 32];
    let mut durable = DurableJournal::create(&path, f.genesis.clone(), namespace).unwrap();
    for b in &prefix().blocks {
        durable
            .append_block(b.header.clone(), &b.body, 10000, &counted)
            .unwrap();
    }
    let mut state = after_begin(&f);
    let mut last = None;
    for index in 1..7 {
        let parent = durable.journal().best_validated();
        let cmd = fixture::main_command(index, &state);
        let produced = f
            .transition(
                durable.journal(),
                parent,
                &state,
                cmd,
                [0xC2 + index as u8; 32],
            )
            .unwrap();
        if index == 2 {
            assert_eq!(produced.returned, [true, true, false, false]);
            assert_eq!(produced.private.registry.transactions[0].held, [4, 4, 0, 0]);
        }
        if index == 3 {
            assert_eq!(produced.private.registry.transactions[0].held, [0; 4]);
            assert_eq!(
                produced.private.registry.transactions[0].savepoints.len(),
                1
            );
        }
        if index == 4 {
            assert!(
                produced.private.registry.transactions[0]
                    .savepoints
                    .is_empty()
            );
        }
        if index == 5 {
            assert!(produced.private.registry.transactions[0].failed);
        }
        assert_eq!(produced.outcome, if index == 6 { 3 } else { 0 });
        let bytes = produced.body.encode(durable.journal().profile()).unwrap();
        assert!(bytes.len() <= version_journal::MAX_BODY_BYTES);
        let header = fixture::candidate(
            durable.journal(),
            parent.block,
            &produced.body,
            1002 + index as u64,
        )
        .unwrap();
        durable
            .append_block(header.clone(), &bytes, 10000, &counted)
            .unwrap();
        state = produced.private;
        if index == 6 {
            last = Some((header, bytes));
        }
    }
    assert_eq!(counted.calls.get(), 8);
    assert_eq!(state.registry.revision, 7);
    assert_eq!(state.registry.allocator, 1);
    assert!(state.registry.transactions.is_empty());
    let tip = durable.journal().best_validated();
    let last = last.unwrap();
    let before = (durable.disk_bytes(), durable.journal().accounted_bytes());
    durable
        .append_block(last.0.clone(), &last.1, 10000, &counted)
        .unwrap();
    assert_eq!(counted.calls.get(), 8); // Exact stored retry is idempotent, not a new proof shortcut.
    assert_eq!(
        (durable.disk_bytes(), durable.journal().accounted_bytes()),
        before
    );
    assert_eq!(durable.journal().best_validated(), tip);
    drop(last);
    let empty = Body::Empty;
    let h = fixture::candidate(durable.journal(), tip.block, &empty, 1010).unwrap();
    durable
        .append_block(
            h,
            &empty.encode(durable.journal().profile()).unwrap(),
            10000,
            &counted,
        )
        .unwrap();
    assert_eq!(
        durable
            .journal()
            .resolve(Freshness::LatestConfirmed)
            .unwrap(),
        tip
    );
    let final_tip = durable.journal().best_validated();
    let disk = durable.disk_bytes();
    drop(durable); // Never retain both full in-memory journals during reopen.
    counted.calls.set(0);
    let reopened =
        DurableJournal::open(&path, f.genesis.clone(), namespace, 10000, &counted).unwrap();
    assert_eq!(counted.calls.get(), 8);
    assert_eq!(reopened.journal().best_validated(), final_tip);
    assert_eq!(reopened.disk_bytes(), disk);
    let parent = reopened.journal().best_validated();
    // Private owner state is externally retained. Reopen restores public heads/proofs only.
    let cmd = command(&state, CommandOperation::Begin, 2, 1);
    assert!(
        f.prepare(reopened.journal(), parent, &state, cmd.clone(), [0xE1; 32])
            .is_ok()
    );
    let mut wrong = state;
    wrong.salt[0] += Val::ONE;
    assert!(matches!(
        f.prepare(reopened.journal(), parent, &wrong, cmd, [0xE1; 32]),
        Err(Error::InvalidTransition)
    ));
}

#[test]
fn upgrade_then_rollback_restores_preexisting_mode_and_release_preserves_it() {
    let f = Fixture::new().unwrap();
    let mut j = journal(2);
    let mut state = after_begin(&f);
    let mut acquire = command(&state, CommandOperation::Acquire, 1, 1);
    acquire.mask = [255; 32];
    acquire.mode = 1;
    acquire.limit = 1;
    drop(apply(&f, &mut j, &mut state, acquire, 0xC1));
    assert_eq!(state.registry.transactions[0].held, [1, 0, 0, 0]);
    let mut save = command(&state, CommandOperation::Savepoint, 1, 1);
    save.name = [0x55; 32];
    drop(apply(&f, &mut j, &mut state, save, 0xC2));
    let mut upgrade = command(&state, CommandOperation::Acquire, 1, 1);
    upgrade.mask = [255; 32];
    upgrade.mode = 4;
    upgrade.limit = 1;
    drop(apply(&f, &mut j, &mut state, upgrade, 0xC3));
    assert_eq!(state.registry.transactions[0].held, [4, 0, 0, 0]);
    let mut rollback = command(&state, CommandOperation::RollbackTo, 1, 1);
    rollback.name = [0x55; 32];
    drop(apply(&f, &mut j, &mut state, rollback, 0xC4));
    assert_eq!(state.registry.transactions[0].held, [1, 0, 0, 0]);
    assert_eq!(state.registry.transactions[0].savepoints.len(), 1);
    let mut release = command(&state, CommandOperation::Release, 1, 1);
    release.name = [0x55; 32];
    drop(apply(&f, &mut j, &mut state, release, 0xC5));
    assert_eq!(state.registry.transactions[0].held, [1, 0, 0, 0]);
    assert!(state.registry.transactions[0].savepoints.is_empty());
    let end = command(&state, CommandOperation::End, 1, 1);
    let result = apply(&f, &mut j, &mut state, end, 0xC6);
    assert_eq!(result.outcome, 0);
    assert!(state.registry.transactions.is_empty());
}

#[test]
fn genuine_wait_nowait_and_skip_use_other_owner_locks_without_fake_cas() {
    let f = Fixture::new().unwrap();
    let directory = OwnedDirectory::new().unwrap();
    let namespace = [0xD6; 32];
    let mut durable =
        DurableJournal::create(directory.journal(), f.genesis.clone(), namespace).unwrap();
    let verifier = f.verifier().unwrap();
    for b in &prefix().blocks {
        durable
            .append_block(b.header.clone(), &b.body, 10000, &verifier)
            .unwrap();
    }
    let mut state = after_begin(&f);
    let begin = command(&state, CommandOperation::Begin, 2, 2);
    durable_apply(&f, &mut durable, &mut state, begin, 0xD1);
    let mut acquire = command(&state, CommandOperation::Acquire, 1, 1);
    acquire.mask = [255; 32];
    acquire.mode = 4;
    acquire.limit = 1;
    durable_apply(&f, &mut durable, &mut state, acquire, 0xD2);
    assert_eq!(state.registry.transactions[0].held, [4, 0, 0, 0]);
    for wait in [0, 1] {
        let parent = durable.journal().best_validated();
        let mut acquire = command(&state, CommandOperation::Acquire, 2, 2);
        acquire.mask = [255; 32];
        acquire.mode = 4;
        acquire.wait = wait;
        acquire.limit = 1;
        let produced = f
            .transition(
                durable.journal(),
                parent,
                &state,
                acquire,
                [0xE2 + wait; 32],
            )
            .unwrap();
        assert_eq!(produced.outcome, wait + 1);
        assert_eq!(produced.private, state);
        let Body::Transition(t) = &produced.body else {
            unreachable!()
        };
        let verified = wire::verify(&produced.expected, &t.proof).unwrap(); // Genuine no-transition evidence first.
        let lifecycle::Phase::Transition { old, .. } = produced.expected.phase else {
            unreachable!()
        };
        assert_eq!(verified.next, old);
        assert_eq!(t.updates[0].old, t.updates[0].new);
        let before = (
            durable.journal().best_validated(),
            durable.disk_bytes(),
            durable.journal().accounted_bytes(),
        );
        assert_eq!(
            fixture::candidate(
                durable.journal(),
                parent.block,
                &produced.body,
                2000 + parent.height + u64::from(wait)
            ),
            Err(Error::InvalidTransition)
        );
        // Reach the actual durable import boundary with the genuine unchanged-root pair.
        // Empty has precisely the same state root; only the full signed Body hash changes.
        let bytes = produced.body.encode(durable.journal().profile()).unwrap();
        let mut header = durable
            .journal()
            .candidate(
                parent.block,
                &Body::Empty,
                2000 + parent.height + u64::from(wait),
            )
            .unwrap();
        header.body_hash = version_journal::hash(&bytes);
        header.mine(1024).unwrap();
        assert_eq!(
            durable.append_block(header, &bytes, 10000, &verifier),
            Err(Error::InvalidTransition)
        );
        assert_eq!(
            (
                durable.journal().best_validated(),
                durable.disk_bytes(),
                durable.journal().accounted_bytes()
            ),
            before
        );
    }
    let mut skip = command(&state, CommandOperation::Acquire, 2, 2);
    skip.mask[255 / 8] |= 1 << (255 % 8);
    skip.mask[128 / 8] |= 1 << (128 % 8); // Candidates at original positions 0,2,3.
    skip.mode = 4;
    skip.wait = 2;
    skip.offset = 1;
    skip.limit = 1;
    skip.projection = 3;
    let produced = f
        .transition(
            durable.journal(),
            durable.journal().best_validated(),
            &state,
            skip,
            [0xD3; 32],
        )
        .unwrap();
    assert_eq!(produced.outcome, 0);
    assert_eq!(produced.skipped, [true, false, false, false]);
    assert_eq!(produced.returned, [false, false, false, true]);
    let bytes = produced.body.encode(durable.journal().profile()).unwrap();
    let parent = durable.journal().best_validated();
    let h = fixture::candidate(
        durable.journal(),
        parent.block,
        &produced.body,
        2000 + parent.height,
    )
    .unwrap();
    durable.append_block(h, &bytes, 10000, &verifier).unwrap();
    state = produced.private;
    drop(bytes);
    drop(produced.body);
    assert_eq!(state.registry.transactions[1].held, [0, 0, 4, 4]);
    let save = command(&state, CommandOperation::Savepoint, 2, 2); // Zero savepoint name is valid.
    durable_apply(&f, &mut durable, &mut state, save, 0xD4);
    let survivor = state.registry.transactions[1].clone();
    let end = command(&state, CommandOperation::End, 1, 1);
    durable_apply(&f, &mut durable, &mut state, end, 0xD5);
    assert_eq!(state.registry.transactions, [survivor]);
    let begin = command(&state, CommandOperation::Begin, 3, 2); // Same principal may control two IDs; no ABA.
    durable_apply(&f, &mut durable, &mut state, begin, 0xD6);
    assert_eq!(state.registry.allocator, 3);
    assert_eq!(
        state
            .registry
            .transactions
            .iter()
            .map(|t| t.id)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(
        state.registry.transactions[0].principal,
        state.registry.transactions[1].principal
    );
    let stale = Command::control(CommandOperation::End, 1, 1, 1);
    assert!(
        f.prepare(
            durable.journal(),
            durable.journal().best_validated(),
            &state,
            stale,
            [0xE9; 32]
        )
        .is_err()
    );
}
fn durable_apply(
    f: &Fixture,
    d: &mut DurableJournal,
    state: &mut PrivateState,
    c: Command,
    ordinal: u8,
) {
    let parent = d.journal().best_validated();
    let produced = f
        .transition(d.journal(), parent, state, c, [ordinal; 32])
        .unwrap();
    let h = fixture::candidate(
        d.journal(),
        parent.block,
        &produced.body,
        2000 + parent.height,
    )
    .unwrap();
    d.append_block(
        h,
        &produced.body.encode(d.journal().profile()).unwrap(),
        10000,
        &f.verifier().unwrap(),
    )
    .unwrap();
    assert!(produced.outcome == 0 || produced.outcome == 3);
    *state = produced.private;
}

#[test]
fn failed_savepoint_recovery_releases_child_locks_and_retains_the_target() {
    let f = Fixture::new().unwrap();
    let mut j = journal(2);
    let mut state = after_begin(&f);
    let save = command(&state, CommandOperation::Savepoint, 1, 1);
    drop(apply(&f, &mut j, &mut state, save, 0xF1));
    let mut acquire = command(&state, CommandOperation::Acquire, 1, 1);
    acquire.mask = [255; 32];
    acquire.mode = 4;
    acquire.limit = 1;
    drop(apply(&f, &mut j, &mut state, acquire, 0xF2));
    let fail = command(&state, CommandOperation::FailCurrent, 1, 1);
    drop(apply(&f, &mut j, &mut state, fail, 0xF3));
    assert!(state.registry.transactions[0].failed);
    assert_eq!(state.registry.transactions[0].held, [0; 4]);
    let save = command(&state, CommandOperation::Savepoint, 1, 1);
    assert!(
        f.prepare(&j, j.best_validated(), &state, save, [0xFA; 32])
            .is_err()
    );
    let rollback = command(&state, CommandOperation::RollbackTo, 1, 1);
    drop(apply(&f, &mut j, &mut state, rollback, 0xF4));
    assert!(!state.registry.transactions[0].failed);
    assert_eq!(state.registry.transactions[0].savepoints.len(), 1);
    let release = command(&state, CommandOperation::Release, 1, 1);
    drop(apply(&f, &mut j, &mut state, release, 0xF5));
    assert!(state.registry.transactions[0].savepoints.is_empty());
}

#[test]
fn valid_sibling_proofs_exhaust_same_genesis_quota_without_publication_or_disk_write() {
    let f = Fixture::new().unwrap();
    let directory = OwnedDirectory::new().unwrap();
    let verifier = f.verifier().unwrap();
    let counted = CountVerifier {
        inner: &verifier,
        calls: Cell::new(0),
    };
    let mut durable =
        DurableJournal::create(directory.journal(), f.genesis.clone(), [0xD7; 32]).unwrap();
    let boot = &prefix().blocks[0];
    durable
        .append_block(boot.header.clone(), &boot.body, 10000, &counted)
        .unwrap();
    let body = Body::decode(&prefix().blocks[1].body, &f.genesis.profile).unwrap();
    let encoded = &prefix().blocks[1].body;
    let parent = boot.header.id();
    let mut rejected = false;
    for attempt in 0..9 {
        let header = fixture::candidate(durable.journal(), parent, &body, 2000 + attempt).unwrap();
        let id = header.id();
        assert!(durable.journal().header(id).is_none());
        let before = (
            durable.journal().best_validated(),
            durable.journal().accounted_bytes(),
            durable.journal().header_count(),
            durable.disk_bytes(),
            std::fs::metadata(directory.journal()).unwrap().len(),
        );
        let calls = counted.calls.get();
        match durable.append_block(header, encoded, 10000, &counted) {
            Ok(_) => assert_eq!(counted.calls.get(), calls + 1),
            Err(error) => {
                assert_eq!(error, Error::ResourceLimit);
                assert_eq!(counted.calls.get(), calls + 1); // Proof valid for THIS same genesis/parent first.
                assert_eq!(
                    (
                        durable.journal().best_validated(),
                        durable.journal().accounted_bytes(),
                        durable.journal().header_count(),
                        durable.disk_bytes(),
                        std::fs::metadata(directory.journal()).unwrap().len()
                    ),
                    before
                );
                assert!(durable.journal().header(id).is_none());
                rejected = true;
                break;
            }
        }
    }
    assert!(
        rejected,
        "fixed full main openings force quota failure within nine sibling attempts"
    );
    assert!(durable.journal().accounted_bytes() <= version_journal::MAX_JOURNAL_BYTES);
    assert!(durable.disk_bytes() <= version_journal::MAX_JOURNAL_BYTES);
}

#[test]
fn detached_valid_branch_is_not_fresh_and_its_proof_cannot_move_to_same_root_parent() {
    let f = Fixture::new().unwrap();
    let verifier = f.verifier().unwrap();
    let mut j = journal(2);
    let detached = j.best_validated();
    fixture::append(&mut j, &verifier, detached.block, &Body::Empty, 1500).unwrap();
    assert_eq!(j.resolve(Freshness::AtLeast(detached)).unwrap(), detached);
    // Same genuinely proved request remains valid on another header under its ORIGINAL parent.
    let body = Body::Transition(transition(1));
    let same_parent = prefix().blocks[0].header.id();
    let sibling = fixture::append(&mut j, &verifier, same_parent, &body, 1600).unwrap();
    assert!(j.body(sibling.id()).is_some());
    // This stronger fork intentionally keeps the bootstrap Cold unchanged via Empty blocks.
    let mut parent = same_parent;
    for stamp in 1700..1703 {
        parent = fixture::append(&mut j, &verifier, parent, &Body::Empty, stamp)
            .unwrap()
            .id();
    }
    assert_eq!(j.best_validated().block, parent);
    assert_eq!(
        j.resolve(Freshness::AtLeast(detached)),
        Err(Error::Reorganized)
    );
    let mut t = transition(1);
    assert_eq!(
        t.updates[0].old,
        f.application
            .control(j.validated_shards(j.best_validated()).unwrap())
            .unwrap()
    );
    t.parent = parent;
    let mut r = Request::decode(&t.request).unwrap();
    r.parent = parent;
    r.query = request::intent_query(
        &f.application,
        r.genesis,
        parent,
        r.nonce,
        r.enrollment,
        r.operation,
    );
    t.request = r.encode().unwrap();
    let counted = CountVerifier {
        inner: &verifier,
        calls: Cell::new(0),
    };
    let before = j.best_validated();
    assert_eq!(
        import(&mut j, &counted, &sign(&f, t), 1800),
        Err(Error::RejectedComputationProof)
    );
    assert_eq!(counted.calls.get(), 1);
    assert_eq!(j.best_validated(), before);
}
