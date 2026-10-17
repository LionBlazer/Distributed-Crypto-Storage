//! Independent public native State oracle; never used by proof acceptance.
use super::*;
use transaction_state as tx;
fn mode(m: u8) -> tx::LockMode {
    match m {
        1 => tx::LockMode::KeyShare,
        2 => tx::LockMode::Share,
        3 => tx::LockMode::NoKeyUpdate,
        4 => tx::LockMode::Update,
        _ => unreachable!(),
    }
}
fn row(w: &Witness, i: usize) -> tx::RowKey {
    tx::RowKey {
        table: w.table(),
        row: w.plain[2220 + 32 * i..2220 + 32 * (i + 1)]
            .try_into()
            .unwrap(),
    }
}
fn action(c: &Command, w: &Witness, parent: [u8; 32]) -> tx::Action {
    match c.operation {
        Operation::Begin => tx::Action::Begin { snapshot: parent },
        Operation::Acquire => tx::Action::Acquire {
            candidates: w
                .ages()
                .into_iter()
                .enumerate()
                .filter(|(_, age)| c.mask[usize::from(*age) / 8] & (1 << (*age % 8)) != 0)
                .map(|(i, _)| row(w, i))
                .collect(),
            mode: mode(c.mode),
            wait: match c.wait {
                0 => tx::WaitPolicy::Wait,
                1 => tx::WaitPolicy::NoWait,
                2 => tx::WaitPolicy::SkipLocked,
                _ => unreachable!(),
            },
            offset: u32::from(c.offset),
            limit: Some(u32::from(c.limit)),
        },
        Operation::FailCurrent => tx::Action::FailCurrent,
        Operation::Savepoint => tx::Action::Savepoint { name: c.name },
        Operation::RollbackTo => tx::Action::RollbackTo { name: c.name },
        Operation::Release => tx::Action::Release { name: c.name },
        Operation::End => tx::Action::End {
            completion: if c.abort {
                tx::Completion::Abort
            } else {
                tx::Completion::Commit
            },
        },
    }
}
pub(super) fn all_operations() {
    let fixture = Fixture::new().unwrap();
    let context = tx::Context::new(
        [0xC1; 32],
        fixture.source.heads[0][8..24].try_into().unwrap(),
        tx::Profile {
            max_transactions: 2,
            max_locks: 8,
            max_lock_events: 64,
            max_candidates: 4,
            max_savepoints_per_transaction: 2,
            max_state_bytes: 8192,
            max_command_bytes: 4096,
        },
    )
    .unwrap();
    let mut native = tx::State::new(context);
    let mut image = Registry::default();
    let mut script = vec![
        command(Operation::Begin, 1, 1, 0),
        command(Operation::Begin, 2, 1, 0),
        acquire(1, 1, 1, 1, 0, 0, 1),
        command(Operation::Savepoint, 1, 1, 2),
        acquire(1, 1, 3, 4, 0, 0, 1),
        command(Operation::Savepoint, 1, 1, 4),
        acquire(1, 1, 5, 4, 0, 0, 4),
        command(Operation::FailCurrent, 1, 1, 6),
        command(Operation::RollbackTo, 1, 1, 7),
        command(Operation::Release, 1, 1, 8),
        command(Operation::FailCurrent, 1, 1, 9),
        command(Operation::End, 1, 1, 10),
        command(Operation::Begin, 3, 2, 0),
        command(Operation::End, 2, 1, 1),
    ];
    script.push(command(Operation::Begin, 4, 1, 0));
    let mut holder = acquire(4, 1, 1, 4, 0, 0, 1);
    holder.mask = [0; 32];
    holder.mask[31] = 128;
    script.push(holder);
    let mut skip = acquire(3, 2, 1, 4, 2, 1, 1);
    skip.mask = [0; 32];
    skip.mask[16] = 1;
    skip.mask[31] = 128;
    script.push(skip);
    script.push(acquire(3, 2, 2, 1, 0, 0, 4));
    script.push(acquire(3, 2, 2, 1, 1, 0, 4));
    for (i, c) in script.into_iter().enumerate() {
        let parent = [i as u8 + 1; 32];
        let (e, w) = fixture
            .transition(image.clone(), c.clone(), [0xB0 + i as u8; 32], parent)
            .unwrap();
        valid(&e, &w);
        let result = image.step(&c, parent, w.ages()).unwrap();
        let native_command = tx::Command {
            expected_revision: native.revision(),
            transaction: tx::TransactionId(c.transaction),
            sequence: c.sequence,
            action: action(&c, &w, parent),
        };
        let actual = native.transition(
            tx::ControllerId(w.controllers[usize::from(c.principal - 1)]),
            &native_command,
        );
        if result.outcome == 1 || result.outcome == 2 {
            if result.outcome == 1 {
                assert!(matches!(actual, Err(tx::Error::Blocked(_))));
            } else {
                assert!(matches!(actual, Err(tx::Error::LockUnavailable(_))));
            }
            assert_eq!(result.next, image);
            assert_eq!(native.revision(), image.revision);
            continue;
        }
        let transition = actual.unwrap();
        if let tx::Outcome::Acquired(selection) = &transition.outcome {
            let candidates: Vec<_> = w
                .ages()
                .into_iter()
                .enumerate()
                .filter(|(_, age)| c.mask[usize::from(*age) / 8] & (1 << (*age % 8)) != 0)
                .map(|(i, _)| i)
                .collect();
            let mut returned = [false; 4];
            let mut skipped = [false; 4];
            for index in &selection.selected {
                returned[candidates[*index as usize]] = true;
            }
            for index in &selection.skipped {
                skipped[candidates[*index as usize]] = true;
            }
            assert_eq!(returned, result.returned);
            assert_eq!(skipped, result.skipped);
        }
        if c.operation == Operation::End && result.outcome == 3 {
            assert_eq!(
                transition.outcome,
                tx::Outcome::Ended(tx::Completion::Abort)
            );
        }
        native = transition.state;
        image = result.next;
        assert_eq!(native.revision(), image.revision);
        assert_eq!(native.active_transactions(), image.transactions.len());
        assert_eq!(native.next_transaction_id().unwrap().0, image.allocator + 1);
        for t in &image.transactions {
            let info = native.transaction(tx::TransactionId(t.id)).unwrap();
            assert_eq!(
                info.controller.0,
                w.controllers[usize::from(t.principal - 1)]
            );
            assert_eq!(info.next_sequence, t.sequence);
            assert_eq!(info.snapshot, t.snapshot);
            assert_eq!(
                info.status,
                if t.failed {
                    tx::TransactionStatus::Failed
                } else {
                    tx::TransactionStatus::Active
                }
            );
            for r in 0..4 {
                assert_eq!(
                    native.held_mode(tx::TransactionId(t.id), row(&w, r)),
                    if t.held[r] == 0 {
                        None
                    } else {
                        Some(mode(t.held[r]))
                    }
                );
            }
        }
    }
}
