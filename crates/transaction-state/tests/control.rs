//! Public non-secret identities exercise the pure control protocol, not SQL or
//! authenticated caller transport. Journal tests separately use fresh real keys.
use transaction_state::*;

fn profile() -> Profile {
    Profile {
        max_transactions: 8,
        max_locks: 32,
        max_lock_events: 128,
        max_candidates: 2048,
        max_savepoints_per_transaction: 8,
        max_state_bytes: 64 * 1024,
        max_command_bytes: 256 * 1024,
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
fn command(state: &State, transaction: TransactionId, action: Action) -> Command {
    Command {
        expected_revision: state.revision(),
        transaction,
        sequence: state
            .transaction(transaction)
            .map_or(0, |tx| tx.next_sequence),
        action,
    }
}
fn begin(state: &mut State, actor: ControllerId) -> TransactionId {
    let id = state.next_transaction_id().unwrap();
    *state = state
        .transition(
            actor,
            &command(state, id, Action::Begin { snapshot: [4; 32] }),
        )
        .unwrap()
        .state;
    id
}
fn acquire(rows: Vec<RowKey>, mode: LockMode, wait: WaitPolicy, limit: Option<u32>) -> Action {
    Action::Acquire {
        candidates: rows,
        mode,
        wait,
        offset: 0,
        limit,
    }
}
fn arrange_lock(
    state: &mut State,
    id: TransactionId,
    who: ControllerId,
    rows: Vec<RowKey>,
    mode: LockMode,
) {
    *state = state
        .transition(
            who,
            &command(state, id, acquire(rows, mode, WaitPolicy::NoWait, None)),
        )
        .unwrap()
        .state;
}

#[test]
fn every_postgresql_row_mode_observes_the_documented_other_owner_conflicts() {
    use LockMode::*;
    let modes = [KeyShare, Share, NoKeyUpdate, Update];
    let conflicts = [
        [false, false, false, true],
        [false, false, true, true],
        [false, true, true, true],
        [true, true, true, true],
    ];
    for (request_index, requested) in modes.into_iter().enumerate() {
        for (held_index, held) in modes.into_iter().enumerate() {
            let mut state = State::new(context());
            let a = begin(&mut state, actor(10));
            let b = begin(&mut state, actor(11));
            arrange_lock(&mut state, a, actor(10), vec![row(1)], held);
            let before = state.encode().unwrap();

            let result = state.transition(
                actor(11),
                &command(
                    &state,
                    b,
                    acquire(vec![row(1)], requested, WaitPolicy::NoWait, None),
                ),
            );

            if conflicts[request_index][held_index] {
                assert!(
                    matches!(result, Err(Error::LockUnavailable(ref conflict))
                    if conflict.row == row(1) && conflict.holders == vec![a]),
                    "{requested:?} vs {held:?}"
                );
                assert_eq!(state.encode().unwrap(), before);
            } else {
                let next = result.unwrap().state;
                assert_eq!(next.held_mode(a, row(1)), Some(held));
                assert_eq!(next.held_mode(b, row(1)), Some(requested));
            }
        }
    }
}

#[test]
fn a_late_nowait_conflict_preserves_all_original_locks_and_sequence() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    arrange_lock(&mut state, a, actor(10), vec![row(2)], LockMode::Share);
    arrange_lock(&mut state, b, actor(11), vec![row(2)], LockMode::KeyShare);
    let before = state.encode().unwrap();

    let result = state.transition(
        actor(11),
        &command(
            &state,
            b,
            acquire(
                vec![row(1), row(2)],
                LockMode::NoKeyUpdate,
                WaitPolicy::NoWait,
                None,
            ),
        ),
    );

    assert!(matches!(result, Err(Error::LockUnavailable(ref conflict)) if conflict.candidate == 1));
    assert_eq!(state.encode().unwrap(), before);
    assert_eq!(state.held_mode(b, row(1)), None);
    assert_eq!(state.held_mode(b, row(2)), Some(LockMode::KeyShare));
}

#[test]
fn wait_reports_exact_blockers_without_a_grant_or_partial_state_change() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    arrange_lock(&mut state, a, actor(10), vec![row(2)], LockMode::Update);
    let before = state.commitment().unwrap();

    let result = state.transition(
        actor(11),
        &command(
            &state,
            b,
            acquire(
                vec![row(1), row(2)],
                LockMode::Update,
                WaitPolicy::Wait,
                None,
            ),
        ),
    );

    assert!(matches!(result, Err(Error::Blocked(ref conflict))
        if conflict.candidate == 1 && conflict.holders == vec![a]));
    assert_eq!(state.commitment().unwrap(), before);
    assert_eq!(state.held_mode(b, row(1)), None);
}

#[test]
fn skip_locked_preserves_candidate_order_and_applies_limit_after_skips() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    arrange_lock(&mut state, a, actor(10), vec![row(3)], LockMode::Update);

    let result = state
        .transition(
            actor(11),
            &command(
                &state,
                b,
                acquire(
                    vec![row(3), row(2), row(1)],
                    LockMode::Update,
                    WaitPolicy::SkipLocked,
                    Some(1),
                ),
            ),
        )
        .unwrap();

    assert_eq!(
        result.outcome,
        Outcome::Acquired(Selection {
            selected: vec![1],
            skipped: vec![0]
        })
    );
    assert_eq!(result.state.held_mode(b, row(2)), Some(LockMode::Update));
    assert_eq!(result.state.held_mode(b, row(1)), None);
    assert_eq!(result.state.held_mode(a, row(3)), Some(LockMode::Update));
}

#[test]
fn offset_rows_are_locked_but_rows_after_limit_are_untouched() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let request = command(
        &state,
        a,
        Action::Acquire {
            candidates: vec![row(3), row(2), row(1)],
            mode: LockMode::Update,
            wait: WaitPolicy::NoWait,
            offset: 1,
            limit: Some(1),
        },
    );

    let result = state.transition(actor(10), &request).unwrap();

    assert_eq!(
        result.outcome,
        Outcome::Acquired(Selection {
            selected: vec![1],
            skipped: vec![]
        })
    );
    assert_eq!(result.state.held_mode(a, row(3)), Some(LockMode::Update));
    assert_eq!(result.state.held_mode(a, row(2)), Some(LockMode::Update));
    assert_eq!(result.state.held_mode(a, row(1)), None);
}

#[test]
fn repeated_own_references_do_not_duplicate_holders_or_downgrade_protection() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::Update);
    let sequence = state.transaction(a).unwrap().next_sequence;

    let result = state
        .transition(
            actor(10),
            &command(
                &state,
                a,
                acquire(
                    vec![row(1), row(1)],
                    LockMode::KeyShare,
                    WaitPolicy::SkipLocked,
                    None,
                ),
            ),
        )
        .unwrap();

    assert_eq!(
        result.outcome,
        Outcome::Acquired(Selection {
            selected: vec![0, 1],
            skipped: vec![]
        })
    );
    assert_eq!(result.state.holders(row(1)), vec![(a, LockMode::Update)]);
    assert_eq!(result.state.commitment().unwrap().holder_count, 1);
    assert_eq!(
        result.state.transaction(a).unwrap().next_sequence,
        sequence + 1
    );
}

#[test]
fn many_repeated_skips_use_positions_instead_of_repeating_holder_lists() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    let c = begin(&mut state, actor(12));
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::KeyShare);
    arrange_lock(&mut state, b, actor(11), vec![row(1)], LockMode::KeyShare);

    let result = state
        .transition(
            actor(12),
            &command(
                &state,
                c,
                acquire(
                    vec![row(1); 1024],
                    LockMode::Update,
                    WaitPolicy::SkipLocked,
                    Some(1),
                ),
            ),
        )
        .unwrap();

    assert_eq!(
        result.outcome,
        Outcome::Acquired(Selection {
            selected: vec![],
            skipped: (0..1024).collect()
        })
    );
    assert_eq!(result.state.commitment().unwrap().holder_count, 2);
    assert_eq!(result.state.held_mode(c, row(1)), None);
}

#[test]
fn rollback_to_restores_upgrade_and_preserves_other_owners_acquired_after_savepoint() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let b = begin(&mut state, actor(11));
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::KeyShare);
    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::Savepoint { name: [1; 32] }),
        )
        .unwrap()
        .state;
    arrange_lock(
        &mut state,
        a,
        actor(10),
        vec![row(1)],
        LockMode::NoKeyUpdate,
    );
    arrange_lock(&mut state, a, actor(10), vec![row(2)], LockMode::Update);
    arrange_lock(&mut state, b, actor(11), vec![row(1)], LockMode::KeyShare);
    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::Savepoint { name: [2; 32] }),
        )
        .unwrap()
        .state;
    arrange_lock(&mut state, a, actor(10), vec![row(3)], LockMode::Update);
    let sequence = state.transaction(a).unwrap().next_sequence;

    let result = state
        .transition(
            actor(10),
            &command(&state, a, Action::RollbackTo { name: [1; 32] }),
        )
        .unwrap();

    let state = result.state;
    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::KeyShare));
    assert_eq!(state.held_mode(b, row(1)), Some(LockMode::KeyShare));
    assert_eq!(state.held_mode(a, row(2)), None);
    assert_eq!(state.held_mode(a, row(3)), None);
    assert_eq!(state.transaction(a).unwrap().next_sequence, sequence + 1);
    assert!(
        state
            .transition(
                actor(10),
                &command(&state, a, Action::RollbackTo { name: [1; 32] })
            )
            .is_ok()
    );
    assert!(matches!(
        state.transition(
            actor(10),
            &command(&state, a, Action::Release { name: [2; 32] })
        ),
        Err(Error::UnknownSavepoint)
    ));
}

#[test]
fn releasing_a_savepoint_keeps_locks_for_the_older_rollback_frame() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::KeyShare);
    for name in [[1; 32], [2; 32]] {
        state = state
            .transition(actor(10), &command(&state, a, Action::Savepoint { name }))
            .unwrap()
            .state;
    }
    arrange_lock(
        &mut state,
        a,
        actor(10),
        vec![row(1), row(2)],
        LockMode::Update,
    );

    let released = state
        .transition(
            actor(10),
            &command(&state, a, Action::Release { name: [2; 32] }),
        )
        .unwrap()
        .state;

    assert_eq!(released.held_mode(a, row(1)), Some(LockMode::Update));
    assert_eq!(released.held_mode(a, row(2)), Some(LockMode::Update));
    let restored = released
        .transition(
            actor(10),
            &command(&released, a, Action::RollbackTo { name: [1; 32] }),
        )
        .unwrap()
        .state;
    assert_eq!(restored.held_mode(a, row(1)), Some(LockMode::KeyShare));
    assert_eq!(restored.held_mode(a, row(2)), None);
}

#[test]
fn repeated_savepoint_names_shadow_then_reveal_the_older_point() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::Savepoint { name: [1; 32] }),
        )
        .unwrap()
        .state;
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::Update);
    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::Savepoint { name: [1; 32] }),
        )
        .unwrap()
        .state;
    arrange_lock(&mut state, a, actor(10), vec![row(2)], LockMode::Update);

    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::RollbackTo { name: [1; 32] }),
        )
        .unwrap()
        .state;

    assert_eq!(state.held_mode(a, row(1)), Some(LockMode::Update));
    assert_eq!(state.held_mode(a, row(2)), None);
    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::Release { name: [1; 32] }),
        )
        .unwrap()
        .state;
    state = state
        .transition(
            actor(10),
            &command(&state, a, Action::RollbackTo { name: [1; 32] }),
        )
        .unwrap()
        .state;
    assert_eq!(state.held_mode(a, row(1)), None);
}

#[test]
fn limits_reject_atomically_but_end_releases_at_capacity_without_reusing_ids() {
    let mut limits = profile();
    limits.max_transactions = 1;
    limits.max_locks = 1;
    limits.max_lock_events = 1;
    let context = Context::new([1; 32], [2; 16], limits).unwrap();
    let mut state = State::new(context);
    let a = begin(&mut state, actor(10));
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::Update);
    let before = state.encode().unwrap();
    assert!(matches!(
        state.transition(
            actor(11),
            &command(
                &state,
                TransactionId(2),
                Action::Begin { snapshot: [4; 32] }
            )
        ),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        state.transition(
            actor(10),
            &command(
                &state,
                a,
                acquire(vec![row(2)], LockMode::Update, WaitPolicy::NoWait, None)
            )
        ),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(state.encode().unwrap(), before);

    state = state
        .transition(
            actor(10),
            &command(
                &state,
                a,
                Action::End {
                    completion: Completion::Commit,
                },
            ),
        )
        .unwrap()
        .state;

    assert_eq!(state.active_transactions(), 0);
    assert!(state.holders(row(1)).is_empty());
    assert_eq!(state.next_transaction_id(), Ok(TransactionId(2)));
    assert!(matches!(
        state.transition(
            actor(10),
            &command(&state, a, Action::Begin { snapshot: [4; 32] })
        ),
        Err(Error::WrongSequence)
    ));
    let next = begin(&mut state, actor(11));
    assert_eq!(next, TransactionId(2));
}

#[test]
fn wrong_controller_stale_revision_and_replayed_sequence_do_not_change_state() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    let old = command(&state, a, Action::Savepoint { name: [1; 32] });
    state = state.transition(actor(10), &old).unwrap().state;
    let before = state.encode().unwrap();

    assert!(matches!(
        state.transition(actor(10), &old),
        Err(Error::StaleRevision)
    ));
    let mut replay = old;
    replay.expected_revision = state.revision();
    assert!(matches!(
        state.transition(actor(10), &replay),
        Err(Error::WrongSequence)
    ));
    assert!(matches!(
        state.transition(
            actor(11),
            &command(
                &state,
                a,
                Action::End {
                    completion: Completion::Abort
                }
            )
        ),
        Err(Error::WrongController)
    ));
    assert_eq!(state.encode().unwrap(), before);
}

#[test]
fn canonical_state_rejects_wrong_context_trailing_data_and_hostile_counts() {
    let mut state = State::new(context());
    let a = begin(&mut state, actor(10));
    arrange_lock(&mut state, a, actor(10), vec![row(1)], LockMode::Share);
    let image = state.encode().unwrap();
    assert_eq!(
        State::decode(&image, context()).unwrap().encode().unwrap(),
        image
    );
    assert!(matches!(
        State::decode(&image, Context::new([9; 32], [2; 16], profile()).unwrap()),
        Err(Error::WrongDomain)
    ));
    let mut trailing = image.clone();
    trailing.push(0);
    assert!(matches!(
        State::decode(&trailing, context()),
        Err(Error::InvalidEncoding)
    ));
    let mut hostile = image.clone();
    hostile[104..108].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        State::decode(&hostile, context()),
        Err(Error::ResourceLimit)
    ));
    for length in [0, 8, 107, image.len() - 1] {
        assert!(State::decode(&image[..length], context()).is_err());
    }
    let mut changed_limits = profile();
    changed_limits.max_locks += 1;
    assert!(matches!(
        State::decode(
            &image,
            Context::new([1; 32], [2; 16], changed_limits).unwrap()
        ),
        Err(Error::WrongDomain)
    ));
}

#[test]
fn direct_commands_cannot_bypass_the_signed_command_byte_budget() {
    let mut limits = profile();
    limits.max_command_bytes = 512;
    let mut state = State::new(Context::new([1; 32], [2; 16], limits).unwrap());
    let a = begin(&mut state, actor(10));
    let before = state.encode().unwrap();

    let result = state.transition(
        actor(10),
        &command(
            &state,
            a,
            acquire(vec![row(1); 4], LockMode::Update, WaitPolicy::NoWait, None),
        ),
    );

    assert!(matches!(result, Err(Error::ResourceLimit)));
    assert_eq!(state.encode().unwrap(), before);
}
