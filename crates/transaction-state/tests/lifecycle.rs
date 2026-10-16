//! Public nonsecret control fixtures. These tests do not execute encrypted SQL.
use transaction_state::*;

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
fn context() -> Context {
    Context::new([1; 32], [2; 16], profile()).unwrap()
}
fn actor(id: u8) -> ControllerId {
    ControllerId([id; 32])
}
fn row(id: u8) -> RowKey {
    RowKey {
        table: [3; 32],
        row: [id; 32],
    }
}
fn command(state: &State, id: TransactionId, action: Action) -> Command {
    Command {
        expected_revision: state.revision(),
        transaction: id,
        sequence: state.transaction(id).map_or(0, |tx| tx.next_sequence),
        action,
    }
}
fn begin(state: &mut State, who: ControllerId) -> TransactionId {
    let id = state.next_transaction_id().unwrap();
    apply(state, who, id, Action::Begin { snapshot: [4; 32] });
    id
}
fn apply(state: &mut State, who: ControllerId, id: TransactionId, action: Action) -> Outcome {
    let transition = state.transition(who, &command(state, id, action)).unwrap();
    *state = transition.state;
    transition.outcome
}
fn lock(rows: Vec<RowKey>, mode: LockMode) -> Action {
    Action::Acquire {
        candidates: rows,
        mode,
        wait: WaitPolicy::NoWait,
        offset: 0,
        limit: None,
    }
}
// Public v2 wire contract: state header108, then id8/controller32/sequence8/snapshot32.
const FIRST_STATUS: usize = 108 + 8 + 32 + 8 + 32;

#[test]
fn base_failure_releases_own_locks_immediately_but_keeps_failed_record_and_other_owners() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::Share),
    );
    apply(
        &mut state,
        actor(11),
        b,
        lock(vec![row(1)], LockMode::KeyShare),
    );
    let before = state.transaction(a).unwrap();
    let revision = state.revision();

    let outcome = apply(&mut state, actor(10), a, Action::FailCurrent);

    assert_eq!(outcome, Outcome::Failed);
    assert_eq!(state.held_mode(a, row(1)), None);
    assert_eq!(state.held_mode(b, row(1)), Some(LockMode::KeyShare));
    let failed = state.transaction(a).unwrap();
    assert_eq!(failed.status, TransactionStatus::Failed);
    assert_eq!(failed.snapshot, before.snapshot);
    assert_eq!(failed.next_sequence, before.next_sequence + 1);
    assert_eq!(state.revision(), revision + 1);
    assert_eq!(state.active_transactions(), 2);
    assert_eq!(
        State::decode(&state.encode().unwrap(), context()).unwrap(),
        state
    );
}

#[test]
fn frame_failure_restores_prior_strength_then_rollback_to_recovers_and_can_repeat() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::KeyShare),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1), row(2)], LockMode::NoKeyUpdate),
    );
    apply(
        &mut state,
        actor(11),
        b,
        lock(vec![row(1)], LockMode::KeyShare),
    );

    apply(&mut state, actor(10), a, Action::FailCurrent);

    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::KeyShare));
    assert_eq!(state.held_mode(a, row(2)), None);
    assert_eq!(state.held_mode(b, row(1)), Some(LockMode::KeyShare));
    assert_eq!(
        state.transaction(a).unwrap().status,
        TransactionStatus::Failed
    );
    assert_eq!(
        apply(
            &mut state,
            actor(10),
            a,
            Action::RollbackTo { name: [1; 32] }
        ),
        Outcome::RolledBackTo
    );
    assert_eq!(
        state.transaction(a).unwrap().status,
        TransactionStatus::Active
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(2)], LockMode::Update),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::RollbackTo { name: [1; 32] },
    );
    assert_eq!(state.held_mode(a, row(2)), None);
    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::KeyShare));
}

#[test]
fn released_child_locks_belong_to_parent_failure_frame() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::KeyShare),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::Share),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [2; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1), row(2)], LockMode::NoKeyUpdate),
    );
    apply(&mut state, actor(10), a, Action::Release { name: [2; 32] });
    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::NoKeyUpdate));

    apply(&mut state, actor(10), a, Action::FailCurrent);

    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::KeyShare));
    assert_eq!(state.held_mode(a, row(2)), None);
    apply(
        &mut state,
        actor(10),
        a,
        Action::RollbackTo { name: [1; 32] },
    );
    assert!(matches!(
        state.transition(
            actor(10),
            &command(&state, a, Action::RollbackTo { name: [2; 32] })
        ),
        Err(Error::UnknownSavepoint)
    ));
}

#[test]
fn failed_frame_rejects_new_work_release_and_repeated_failure_without_consuming_sequence() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(&mut state, actor(10), a, Action::FailCurrent);
    let before = state.encode().unwrap();
    for action in [
        lock(vec![row(1)], LockMode::Update),
        Action::Savepoint { name: [2; 32] },
        Action::Release { name: [1; 32] },
        Action::FailCurrent,
    ] {
        assert!(matches!(
            state.transition(actor(10), &command(&state, a, action)),
            Err(Error::TransactionFailed)
        ));
        assert_eq!(state.encode().unwrap(), before);
    }
    assert!(matches!(
        state.transition(
            actor(10),
            &command(&state, a, Action::RollbackTo { name: [9; 32] })
        ),
        Err(Error::UnknownSavepoint)
    ));
    assert_eq!(state.encode().unwrap(), before);
}

#[test]
fn committing_a_failed_frame_ends_as_abort_and_never_reuses_transaction_id() {
    for with_savepoint in [false, true] {
        let mut state = State::new(context());
        let a = begin(&mut state, actor(10));
        apply(
            &mut state,
            actor(10),
            a,
            lock(vec![row(1)], LockMode::Update),
        );
        if with_savepoint {
            apply(
                &mut state,
                actor(10),
                a,
                Action::Savepoint { name: [1; 32] },
            );
        }
        apply(&mut state, actor(10), a, Action::FailCurrent);

        let outcome = apply(
            &mut state,
            actor(10),
            a,
            Action::End {
                completion: Completion::Commit,
            },
        );

        assert_eq!(outcome, Outcome::Ended(Completion::Abort));
        assert_eq!(state.transaction(a), None);
        assert_eq!(state.held_mode(a, row(1)), None);
        assert_eq!(begin(&mut state, actor(10)), TransactionId(a.0 + 1));
    }
}

#[test]
fn duplicate_names_recover_newest_failed_frame_then_reveal_the_older_cut() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::Update),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(2)], LockMode::Update),
    );
    apply(&mut state, actor(10), a, Action::FailCurrent);
    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::Update));
    assert_eq!(state.held_mode(a, row(2)), None);

    apply(
        &mut state,
        actor(10),
        a,
        Action::RollbackTo { name: [1; 32] },
    );

    assert_eq!(
        state.transaction(a).unwrap().status,
        TransactionStatus::Active
    );
    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::Update));
    apply(&mut state, actor(10), a, Action::Release { name: [1; 32] });
    apply(
        &mut state,
        actor(10),
        a,
        Action::RollbackTo { name: [1; 32] },
    );
    assert_eq!(state.held_mode(a, row(1)), None);
}

#[test]
fn rollback_to_an_older_point_recovers_and_removes_younger_failed_frame() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::Update),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [2; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(2)], LockMode::Update),
    );
    apply(&mut state, actor(10), a, Action::FailCurrent);

    apply(
        &mut state,
        actor(10),
        a,
        Action::RollbackTo { name: [1; 32] },
    );

    assert_eq!(
        state.transaction(a).unwrap().status,
        TransactionStatus::Active
    );
    assert_eq!(state.held_mode(a, row(1)), None);
    assert_eq!(state.held_mode(a, row(2)), None);
    assert!(matches!(
        state.transition(
            actor(10),
            &command(&state, a, Action::RollbackTo { name: [2; 32] })
        ),
        Err(Error::UnknownSavepoint)
    ));
}

#[test]
fn protocol_rejection_and_wait_or_nowait_conflict_do_not_implicitly_fail_a_frame() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::Update),
    );
    apply(
        &mut state,
        actor(11),
        b,
        lock(vec![row(2)], LockMode::KeyShare),
    );
    let fail = command(&state, b, Action::FailCurrent);
    let before = state.encode().unwrap();
    assert!(matches!(
        state.transition(actor(10), &fail),
        Err(Error::WrongController)
    ));
    let mut bad_sequence = fail.clone();
    bad_sequence.sequence += 1;
    assert!(matches!(
        state.transition(actor(11), &bad_sequence),
        Err(Error::WrongSequence)
    ));
    let mut stale = fail.clone();
    stale.expected_revision -= 1;
    assert!(matches!(
        state.transition(actor(11), &stale),
        Err(Error::StaleRevision)
    ));
    for wait in [WaitPolicy::Wait, WaitPolicy::NoWait] {
        let action = Action::Acquire {
            candidates: vec![row(3), row(1)],
            mode: LockMode::Update,
            wait,
            offset: 0,
            limit: None,
        };
        let result = state.transition(actor(11), &command(&state, b, action));
        assert!(match wait {
            WaitPolicy::Wait => matches!(result, Err(Error::Blocked(_))),
            WaitPolicy::NoWait => matches!(result, Err(Error::LockUnavailable(_))),
            WaitPolicy::SkipLocked => unreachable!(),
        });
        assert_eq!(state.encode().unwrap(), before);
    }
    assert_eq!(
        state.transaction(b).unwrap().status,
        TransactionStatus::Active
    );
    assert_eq!(state.held_mode(b, row(2)), Some(LockMode::KeyShare));
    let failed = state.transition(actor(11), &fail).unwrap().state;
    assert!(matches!(
        failed.transition(actor(11), &fail),
        Err(Error::StaleRevision)
    ));
}

#[test]
fn failure_and_recovery_work_at_full_transaction_lock_event_savepoint_and_byte_caps() {
    let mut limits = profile();
    limits.max_transactions = 1;
    limits.max_locks = 4;
    limits.max_lock_events = 4;
    limits.max_savepoints_per_transaction = 2;
    // v2 header108 + transaction89 + two savepoints72 + four lock events260.
    limits.max_state_bytes = 529;
    let mut state = State::new(Context::new([1; 32], [2; 16], limits).unwrap());
    let a = begin(&mut state, actor(10));
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1), row(2)], LockMode::Update),
    );
    apply(
        &mut state,
        actor(10),
        a,
        Action::Savepoint { name: [2; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(3), row(4)], LockMode::Update),
    );
    assert_eq!(state.encode().unwrap().len(), 529);
    assert!(matches!(
        state.transition(
            actor(10),
            &command(&state, a, Action::Savepoint { name: [3; 32] })
        ),
        Err(Error::ResourceLimit)
    ));

    apply(&mut state, actor(10), a, Action::FailCurrent);

    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::Update));
    assert_eq!(state.held_mode(a, row(3)), None);
    apply(
        &mut state,
        actor(10),
        a,
        Action::RollbackTo { name: [1; 32] },
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(4)], LockMode::Update),
    );
    assert_eq!(
        state.transaction(a).unwrap().status,
        TransactionStatus::Active
    );
}

#[test]
fn v2_status_is_canonical_and_failed_state_cannot_retain_events_beyond_current_cut() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let mut malformed = state.encode().unwrap();
    assert_eq!(malformed[FIRST_STATUS], 0);
    malformed[FIRST_STATUS] = 2;
    assert_eq!(
        State::decode(&malformed, context()),
        Err(Error::InvalidEncoding)
    );
    apply(
        &mut state,
        actor(10),
        a,
        lock(vec![row(1)], LockMode::Update),
    );
    let mut impossible = state.encode().unwrap();
    impossible[FIRST_STATUS] = 1;
    assert_eq!(
        State::decode(&impossible, context()),
        Err(Error::InvalidState)
    );
    apply(&mut state, actor(10), a, Action::FailCurrent);
    let image = state.encode().unwrap();
    assert_eq!(image[FIRST_STATUS], 1);
    assert_eq!(State::decode(&image, context()).unwrap(), state);
}

#[test]
fn v1_state_intent_and_head_namespaces_are_not_accepted_as_v2() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let image = state.encode().unwrap();
    assert_eq!(&image[..8], b"DCSTXS02");
    let mut legacy = image.clone();
    legacy[..8].copy_from_slice(b"DCSTXS01");
    legacy.remove(FIRST_STATUS);
    assert_eq!(
        State::decode(&legacy, context()),
        Err(Error::InvalidEncoding)
    );
    let signed = SignedIntent {
        intent: Intent {
            genesis: [5; 32],
            parent: [6; 32],
            controller: actor(10),
            statement: [7; 32],
            command: command(&state, a, Action::FailCurrent),
        },
        signature: [0; 64],
    };
    let mut intent = signed.encode(context()).unwrap();
    assert_eq!(&intent[..8], b"DCSTXI02");
    assert_eq!(SignedIntent::decode(&intent, context()).unwrap(), signed);
    intent[..8].copy_from_slice(b"DCSTXI01");
    assert_eq!(
        SignedIntent::decode(&intent, context()),
        Err(Error::InvalidEncoding)
    );
    let heads = MetadataVerifier::new(context(), 7).heads(&state).unwrap();
    assert_eq!(&heads.data[..8], b"DCSTXH02");
    assert_eq!(&heads.index[..8], b"DCSTXH02");
}
