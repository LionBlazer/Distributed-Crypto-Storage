//! PUBLIC NONSECRET owning examples. Native State is a development oracle only.
use super::{
    fixture::{Fixture, PARENT},
    layout::*,
    model::{Command, Operation, Registry, Savepoint, Transaction},
    statement::{self, Phase},
    trace::Witness,
    *,
};
use crate::backend::{Backend, TRACE_HEIGHT, Val};
use crate::primitive::{Kind, PublicStatement};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::cell::Cell;
mod native;

fn command(operation: Operation, id: u64, principal: u8, sequence: u64) -> Command {
    Command::control(operation, id, principal, sequence)
}
fn begun() -> Registry {
    Registry {
        revision: 2,
        allocator: 2,
        transactions: vec![
            Transaction {
                id: 1,
                principal: 1,
                sequence: 1,
                failed: false,
                snapshot: [0x11; 32],
                held: [0; 4],
                savepoints: Vec::new(),
            },
            Transaction {
                id: 2,
                principal: 2,
                sequence: 1,
                failed: false,
                snapshot: [0x22; 32],
                held: [0; 4],
                savepoints: Vec::new(),
            },
        ],
    }
}
fn acquire(
    id: u64,
    principal: u8,
    sequence: u64,
    mode: u8,
    wait: u8,
    offset: u8,
    limit: u8,
) -> Command {
    let mut c = command(Operation::Acquire, id, principal, sequence);
    c.mask = [255; 32];
    c.mode = mode;
    c.wait = wait;
    c.offset = offset;
    c.limit = limit;
    c.projection = 3;
    c
}
fn valid(e: &Expected, w: &Witness) -> (Statement, RowMajorMatrix<Val>) {
    let s = w.statement(e).unwrap();
    let trace = w.trace(&s).unwrap();
    check_constraints(&s.air(), &trace, &s.public_values());
    (s, trace)
}
fn binding(e: &mut Expected, w: &Witness) {
    let old = statement::digest(&statement::registry_fields(e, w, &w.old, w.salts[2]));
    e.phase = Phase::Transition {
        old,
        command: [Val::ZERO; 4],
    };
    let cmd = statement::digest(&statement::command_fields(
        e,
        w,
        w.command.as_ref().unwrap(),
    ));
    e.phase = Phase::Transition { old, command: cmd };
}
fn forged(e: &Expected, w: &Witness, step: &model::Step) -> (Statement, RowMajorMatrix<Val>) {
    let mut s = Statement {
        expected: e.clone(),
        next: [Val::ZERO; 4],
        result: [Val::ZERO; 4],
    };
    let salt = if step.outcome == 1 || step.outcome == 2 {
        w.salts[2]
    } else {
        w.salts[4]
    };
    s.next = statement::digest(&statement::registry_fields(e, w, &step.next, salt));
    s.result = statement::digest(&statement::result_fields(&s, w, step));
    let trace = w.trace_step(&s, step).unwrap();
    (s, trace)
}
fn rejects(s: &Statement, trace: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &trace, &s.public_values(), Some(1)).is_ok());
    let backend = Backend::new(s).unwrap();
    // The owning negative reaches the actual raw SDK; host step() is not the rejection gate.
    if let Ok(proof) = p3_uni_stark::prove(&backend.config, &s.air(), trace, &s.public_values()) {
        assert!(backend.verify(s, &proof).is_err());
    }
}

/// Rebuild every actual permutation after a malicious public claim or immutable-bank edit.
/// It does not call the model and does not bypass any honest AIR assertion.
fn rehash(
    s: &mut Statement,
    trace: &mut RowMajorMatrix<Val>,
    mut altered: impl FnMut(air::Stream, usize, Val) -> Val,
) {
    let mut checkpoint = [Val::ZERO; 12];
    for (r, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[CP..WORDS].copy_from_slice(&checkpoint);
        let mut input = [Val::ZERO; 12];
        if let Some((stream, block)) = air::absorb(r) {
            let a = air::LifecycleAir::new(s);
            for (word, value) in input[..8].iter_mut().enumerate() {
                let field = 8 * block + word;
                *value = altered(stream, field, a.field(row, stream, field, word));
            }
            if !air::reset(r) {
                input[8..].copy_from_slice(&checkpoint[8..]);
            }
        }
        let output = crate::opening::poseidon::write(&mut row[..CP], input);
        if air::absorb(r).is_some() {
            checkpoint = output;
        }
        let root = output[..4].try_into().unwrap();
        match r {
            84 => s.expected.source.open_commitment = root,
            92 => s.expected.enrollment = root,
            117 => {
                let Phase::Transition { command, .. } = s.expected.phase else {
                    unreachable!()
                };
                s.expected.phase = Phase::Transition { old: root, command };
            }
            137 => {
                let Phase::Transition { old, .. } = s.expected.phase else {
                    unreachable!()
                };
                s.expected.phase = Phase::Transition { old, command: root };
            }
            162 => s.next = root,
            180 => s.result = root,
            _ => {}
        }
    }
}

#[test]
fn new_empty_bootstrap_opens_exact_source_principals_and_registry200() {
    let fixture = Fixture::new().unwrap();
    let (e, w) = fixture.bootstrap().unwrap();
    let (s, trace) = valid(&e, &w);
    assert_eq!(s.kind(), Kind::RegistryLifecycleBootstrap);
    assert_eq!(s.public_values().len(), 104);
    assert_eq!(BaseAir::<Val>::width(&s.air()), 1082);
    let fields = statement::registry_fields(&e, &w, &Registry::default(), w.salts[4]);
    assert_eq!(fields.len(), 200);
    assert_eq!(fields[80..190], [Val::ZERO; 110]);
    assert_eq!(fields[194..], [Val::ZERO; 6]);
    assert_eq!(statement::digest(&fields), s.next);
    assert_eq!(trace.values.len() / 1082, 512);
    assert_ne!(
        statement::registry_profile(),
        crate::opening::locking::statement::registry_profile()
    );
}
#[test]
fn all_seven_commands_have_complete_streams_and_native_semantics() {
    native::all_operations();
}
#[test]
fn newest_duplicate_zero_name_is_retained_then_release_reveals_older_frame() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[0].held = [2, 0, 0, 0];
    old.transactions[0].savepoints = vec![
        Savepoint {
            name: [0; 32],
            held: [1, 0, 0, 0],
        },
        Savepoint {
            name: [0; 32],
            held: [2, 0, 0, 0],
        },
    ];
    let c = command(Operation::RollbackTo, 1, 1, 1);
    let (e, w) = fixture.transition(old, c, [0x91; 32], PARENT).unwrap();
    valid(&e, &w);
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(step.next.transactions[0].held, [2, 0, 0, 0]);
    assert_eq!(step.next.transactions[0].savepoints.len(), 2);
    let c = command(Operation::Release, 1, 1, 2);
    let (e, w) = fixture
        .transition(step.next, c, [0x92; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(step.next.transactions[0].savepoints.len(), 1);
    assert_eq!(step.next.transactions[0].held, [2, 0, 0, 0]);
}
#[test]
fn rollback_restores_upgrade_and_preserves_other_transaction() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[0].held = [4, 0, 0, 0];
    old.transactions[0].savepoints = vec![Savepoint {
        name: [7; 32],
        held: [1, 0, 0, 0],
    }];
    old.transactions[1].held = [0, 3, 0, 0];
    let mut c = command(Operation::RollbackTo, 1, 1, 1);
    c.name = [7; 32];
    let (e, w) = fixture
        .transition(old.clone(), c, [0x93; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(step.next.transactions[0].held, [1, 0, 0, 0]);
    assert_eq!(step.next.transactions[1], old.transactions[1]);
    let mut bad = step.clone();
    bad.next.transactions[0].held[0] = 4;
    let (s, t) = forged(&e, &w, &bad);
    rejects(&s, t);
}
#[test]
fn release_retains_locks_and_fail_current_uses_parent_frame() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[0].held = [4, 0, 0, 0];
    old.transactions[0].savepoints = vec![
        Savepoint {
            name: [1; 32],
            held: [1, 0, 0, 0],
        },
        Savepoint {
            name: [2; 32],
            held: [2, 0, 0, 0],
        },
    ];
    let mut c = command(Operation::Release, 1, 1, 1);
    c.name = [2; 32];
    let (e, w) = fixture.transition(old, c, [0x94; 32], PARENT).unwrap();
    valid(&e, &w);
    let released = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(released.next.transactions[0].held, [4, 0, 0, 0]);
    let c = command(Operation::FailCurrent, 1, 1, 2);
    let (e, w) = fixture
        .transition(released.next, c, [0x95; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    let failed = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(failed.next.transactions[0].held, [1, 0, 0, 0]);
    assert!(failed.next.transactions[0].failed);
}
#[test]
fn end_compacts_entire_survivor_and_next_begin_never_reuses_id() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[1].snapshot = [0xFE; 32];
    old.transactions[1].held = [0, 2, 0, 0];
    old.transactions[1].savepoints = vec![
        Savepoint {
            name: [0x81; 32],
            held: [0, 1, 0, 0],
        },
        Savepoint {
            name: [0; 32],
            held: [0, 2, 0, 0],
        },
    ];
    let c = command(Operation::End, 1, 1, 1);
    let (e, w) = fixture
        .transition(old.clone(), c, [0x96; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    let ended = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(ended.next.transactions, vec![old.transactions[1].clone()]);
    assert_eq!(ended.next.allocator, 2);
    let c = command(Operation::Begin, 3, 2, 0);
    let (e, w) = fixture
        .transition(ended.next, c, [0x97; 32], [0xCE; 32])
        .unwrap();
    valid(&e, &w);
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), [0xCE; 32], w.ages())
        .unwrap();
    assert_eq!(step.next.transactions[1].id, 3);
    assert_eq!(step.next.transactions[1].snapshot, [0xCE; 32]);
    assert_eq!(step.next.transactions[0].principal, 2);
    assert_eq!(step.next.transactions[1].principal, 2);
    let mut old = begun();
    old.transactions[0].snapshot = [0xE3; 32];
    old.transactions[0].held = [2, 0, 0, 0];
    old.transactions[0].failed = true;
    old.transactions[0].savepoints = vec![
        Savepoint {
            name: [0x23; 32],
            held: [1, 0, 0, 0],
        },
        Savepoint {
            name: [0x24; 32],
            held: [2, 0, 0, 0],
        },
    ];
    let c = command(Operation::End, 2, 2, 1);
    let (e, w) = fixture
        .transition(old.clone(), c, [0xDB; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(step.next.transactions, vec![old.transactions[0].clone()]);
}
#[test]
fn acquire_skip_offset_and_atomic_failure_preserve_counter_and_result_contract() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[1].held = [4, 0, 4, 0];
    for wait in 0..3 {
        let c = acquire(1, 1, 1, 4, wait, 1, 1);
        let (e, w) = fixture
            .transition(old.clone(), c, [0x98 + wait; 32], PARENT)
            .unwrap();
        let (s, _) = valid(&e, &w);
        let step = w
            .old
            .step(w.command.as_ref().unwrap(), PARENT, w.ages())
            .unwrap();
        let result = statement::result_fields(&s, &w, &step);
        if wait < 2 {
            assert_eq!(step.next, old);
            let Phase::Transition { old, .. } = e.phase else {
                unreachable!()
            };
            assert_eq!(s.next, old);
            assert_eq!(result[121..133], [Val::ZERO; 12]);
        } else {
            assert_eq!(step.skipped, [true, false, true, false]);
            assert_eq!(step.returned, [false, false, false, true]);
            assert_eq!(step.next.transactions[0].held, [0, 4, 0, 4]);
        }
    }
}
#[test]
fn limit_zero_is_success_while_invalid_and_failed_commands_do_not_auto_fail() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[1].held = [4; 4];
    let c = acquire(1, 1, 1, 4, 0, 0, 0);
    let (e, w) = fixture
        .transition(old.clone(), c, [0xA0; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    let next = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    assert_eq!(next.next.revision, 3);
    assert_eq!(next.next.transactions[0].held, [0; 4]);
    old.transactions[0].failed = true;
    for operation in [
        Operation::Acquire,
        Operation::Savepoint,
        Operation::Release,
        Operation::FailCurrent,
    ] {
        let c = if operation == Operation::Acquire {
            acquire(1, 1, 1, 1, 0, 0, 4)
        } else {
            command(operation, 1, 1, 1)
        };
        assert!(old.step(&c, PARENT, w.ages()).is_err());
    }
    assert!(old.transactions[0].failed);
    let mut failed = begun();
    failed.revision = 3;
    failed.transactions[0].sequence = 2;
    failed.transactions[0].failed = true;
    let c = command(Operation::Savepoint, 1, 1, 2);
    let mut active = failed.clone();
    active.transactions[0].failed = false;
    let mut bad = active.step(&c, PARENT, w.ages()).unwrap();
    bad.next.transactions[0].failed = true;
    let (failed_e, failed_w) = fixture.transition(failed, c, [0xDA; 32], PARENT).unwrap();
    let (s, t) = forged(&failed_e, &failed_w, &bad);
    rejects(&s, t);
}
#[test]
fn limb_carry_gold_alias_and_end_at_max_sequence_are_distinct() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.revision = u64::from(u32::MAX);
    old.transactions[0].sequence = u64::from(u32::MAX);
    let c = command(Operation::Savepoint, 1, 1, u64::from(u32::MAX));
    let (e, w) = fixture.transition(old, c, [0xA1; 32], PARENT).unwrap();
    valid(&e, &w);
    let mut old = begun();
    old.transactions[0].sequence = u64::MAX;
    let c = command(Operation::End, 1, 1, u64::MAX);
    let (e, w) = fixture.transition(old, c, [0xA2; 32], PARENT).unwrap();
    valid(&e, &w);
    let (e, w) = fixture.begin().unwrap();
    let mut step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    step.next.revision = 0xFFFF_FFFF_0000_0002;
    let (s, t) = forged(&e, &w, &step);
    rejects(&s, t);
}
#[test]
fn gold_modulus_id_is_positive_and_all_three_u64_overflows_reject() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    let p = 0xFFFF_FFFF_0000_0001;
    old.transactions.truncate(1);
    old.transactions[0].id = p;
    old.allocator = p;
    old.revision = p;
    let c = command(Operation::End, p, 1, 1);
    let (e, w) = fixture
        .transition(old.clone(), c, [0xA3; 32], PARENT)
        .unwrap();
    valid(&e, &w);
    old.revision = u64::MAX;
    assert!(
        old.step(&command(Operation::End, p, 1, 1), PARENT, w.ages())
            .is_err()
    );
    old.allocator = u64::MAX;
    assert!(
        old.step(&command(Operation::Begin, u64::MAX, 1, 0), PARENT, w.ages())
            .is_err()
    );
    let mut old = begun();
    old.transactions[0].sequence = u64::MAX;
    assert!(
        old.step(
            &command(Operation::Savepoint, 1, 1, u64::MAX),
            PARENT,
            w.ages()
        )
        .is_err()
    );
}
#[test]
fn coherent_wrong_target_and_other_owner_erasure_reach_sdk_rejection() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    old.transactions[0].held = [3, 0, 0, 0];
    old.transactions[0].savepoints = vec![
        Savepoint {
            name: [0; 32],
            held: [1, 0, 0, 0],
        },
        Savepoint {
            name: [0; 32],
            held: [2, 0, 0, 0],
        },
    ];
    old.transactions[1].held = [0, 3, 0, 0];
    let c = command(Operation::RollbackTo, 1, 1, 1);
    let (e, w) = fixture.transition(old, c, [0xA4; 32], PARENT).unwrap();
    let honest = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    valid(&e, &w);
    for attack in 0..2 {
        let mut bad = honest.clone();
        if attack == 0 {
            bad.next.transactions[0].held[0] = 1;
            bad.next.transactions[0].savepoints.truncate(1);
        } else {
            bad.next.transactions[1].held = [0; 4];
            bad.next.transactions[1].savepoints.clear();
        }
        let (s, mut t) = forged(&e, &w, &bad);
        if attack == 0 {
            for row in t.values.as_chunks_mut::<WIDTH>().0 {
                row[TARGET] = Val::ONE;
                row[TARGET + 1] = Val::ZERO;
            }
        }
        rejects(&s, t);
    }
}
#[test]
fn all_eight_name_words_and_compacted_snapshot_are_constrained() {
    let fixture = Fixture::new().unwrap();
    let mut old = begun();
    let mut name = [0; 32];
    name[31] = 1;
    old.transactions[0].savepoints = vec![Savepoint { name, held: [0; 4] }];
    let mut c = command(Operation::RollbackTo, 1, 1, 1);
    assert!(old.step(&c, PARENT, [0; 4]).is_err());
    c.name = name;
    let (e, w) = fixture.transition(old, c, [0xA5; 32], PARENT).unwrap();
    valid(&e, &w);
    let old = begun();
    let c = command(Operation::End, 1, 1, 1);
    let (e, w) = fixture.transition(old, c, [0xA6; 32], PARENT).unwrap();
    let mut bad = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    bad.next.transactions[0].snapshot[31] ^= 1;
    let (s, t) = forged(&e, &w, &bad);
    rejects(&s, t);
}
#[test]
fn padding_last_row_and_canonical_absence_cannot_hide_state() {
    let fixture = Fixture::new().unwrap();
    let (e, w) = fixture.begin().unwrap();
    let (s, mut t) = valid(&e, &w);
    let at = (TRACE_HEIGHT - 1) * WIDTH + slot(NEW, 1) + SNAPSHOT + 255;
    t.values[at] = Val::ONE;
    rejects(&s, t);
}
#[test]
fn full_expected_context_and_fresh_salts_change_only_their_intended_roots() {
    let fixture = Fixture::new().unwrap();
    let (e, w) = fixture.begin().unwrap();
    let (s, _) = valid(&e, &w);
    for field in 0..9 {
        let mut foreign = e.clone();
        match field {
            0 => foreign.parent[31] ^= 1,
            1 => foreign.genesis[31] ^= 1,
            2 => foreign.source.request[31] ^= 1,
            3 => foreign.source.heads[1][111] ^= 1,
            4 => foreign.source.key_commitment[3] += Val::ONE,
            5 => foreign.enrollment[3] += Val::ONE,
            6 => foreign.source.open_commitment[3] += Val::ONE,
            7 => {
                let Phase::Transition { old, command } = foreign.phase else {
                    unreachable!()
                };
                let mut old = old;
                old[3] += Val::ONE;
                foreign.phase = Phase::Transition { old, command };
            }
            _ => {
                let Phase::Transition { old, command } = foreign.phase else {
                    unreachable!()
                };
                let mut command = command;
                command[3] += Val::ONE;
                foreign.phase = Phase::Transition { old, command };
            }
        };
        assert!(s.require_expected(&foreign).is_err());
    }
    let mut changed = w.clone();
    changed.salts[4][3] += Val::ONE;
    let changed = changed.statement(&e).unwrap();
    assert_ne!(s.next, changed.next);
    assert_ne!(s.result, changed.result);
    assert_eq!(s.expected.context(), changed.expected.context());
}
#[test]
fn bootstrap_and_transition_security_paths_are_analytical() {
    // These normal entry points must stay independent of every trace/proof/Journal factory.
    gate("security", true).unwrap();
    gate("security", false).unwrap();
    assert!(gate("unknown", false).is_err());
}
#[test]
fn genuine_source_first_bootstrap_and_all_lifecycle_operations_verify_without_receipts() {
    let fixture = Fixture::new().unwrap();
    let (e, w) = fixture.bootstrap().unwrap();
    let (boot, mut proof) = prove(&e, &fixture.source_witness, &w).unwrap();
    verify(&e, &boot, &proof).unwrap();
    let source = proof.source.take().unwrap();
    assert!(verify(&e, &boot, &proof).is_err());
    proof.source = Some(source);
    let calls = Cell::new(0);
    let mut foreign = e.clone();
    foreign.source = fixture.source([0xAA; 32]);
    assert!(
        prove_child_with_trace(&foreign, &boot, proof.source.as_ref().unwrap(), || {
            calls.set(calls.get() + 1);
            Err(Error::Proving)
        })
        .is_err()
    );
    assert_eq!(calls.get(), 0);
    let data: [u8; 12] = w.plain[..12].try_into().unwrap();
    let (bytes, bytes_witness) = crate::opening::fixture::from_suffix(
        crate::opening::Relation::Bytes,
        [0x71; 32],
        ([Val::ONE; 4], [Val::TWO; 4]),
        fixture.source.request,
        data,
        &w.plain[124..],
    )
    .unwrap();
    let bytes_backend = Backend::new(&bytes).unwrap();
    let bytes_proof = bytes_backend
        .prove_with_trace(&bytes, || bytes_witness.trace(&bytes))
        .unwrap();
    bytes_backend.verify(&bytes, &bytes_proof).unwrap();
    let mut wrong_kind = e.clone();
    wrong_kind.source = bytes;
    assert!(
        prove_child_with_trace(&wrong_kind, &boot, &bytes_proof, || {
            calls.set(calls.get() + 1);
            Err(Error::Proving)
        })
        .is_err()
    );
    assert_eq!(calls.get(), 0);
    let mut foreign_witness = w.clone();
    foreign_witness.controllers[1][31] ^= 1;
    let mut foreign_expected = e.clone();
    foreign_expected.enrollment = crate::opening::commitment::digest(
        &statement::enrollment_fields(&foreign_expected, &foreign_witness),
    );
    let foreign_statement = foreign_witness.statement(&foreign_expected).unwrap();
    let foreign_child = prove_child_with_trace(
        &foreign_expected,
        &foreign_statement,
        proof.source.as_ref().unwrap(),
        || foreign_witness.trace(&foreign_statement),
    )
    .unwrap();
    let mut foreign_pair = CompositeProof {
        source: proof.source.take(),
        child: foreign_child,
    };
    verify(&foreign_expected, &foreign_statement, &foreign_pair).unwrap();
    assert!(verify(&e, &foreign_statement, &foreign_pair).is_err());
    proof.source = foreign_pair.source.take();
    let mut old = Registry::default();
    let mut old_salt = w.salts[4];
    let mut old_root = boot.next;
    let mut script = vec![
        command(Operation::Begin, 1, 1, 0),
        command(Operation::Savepoint, 1, 1, 1),
        acquire(1, 1, 2, 1, 0, 0, 4),
        command(Operation::Savepoint, 1, 1, 3),
        acquire(1, 1, 4, 4, 0, 0, 4),
        command(Operation::FailCurrent, 1, 1, 5),
        command(Operation::RollbackTo, 1, 1, 6),
        command(Operation::Release, 1, 1, 7),
        command(Operation::FailCurrent, 1, 1, 8),
        command(Operation::End, 1, 1, 9),
    ];
    for (i, c) in script.drain(..).enumerate() {
        let (mut expected, mut witness) = fixture
            .transition(old, c, fixture.source.request, [i as u8 + 1; 32])
            .unwrap();
        witness.salts[2] = old_salt;
        binding(&mut expected, &witness);
        let Phase::Transition { old: claimed, .. } = expected.phase else {
            unreachable!()
        };
        assert_eq!(claimed, old_root);
        if i == 0 {
            let mut foreign = expected.clone();
            let Phase::Transition { old, mut command } = foreign.phase else {
                unreachable!()
            };
            command[3] += Val::ONE;
            foreign.phase = Phase::Transition { old, command };
            let s = witness.statement(&expected).unwrap();
            assert!(
                prove_child_with_trace(&foreign, &s, proof.source.as_ref().unwrap(), || {
                    calls.set(calls.get() + 1);
                    Err(Error::Proving)
                })
                .is_err()
            );
            assert_eq!(calls.get(), 0);
        }
        let s = witness.statement(&expected).unwrap();
        let child = prove_child_with_trace(&expected, &s, proof.source.as_ref().unwrap(), || {
            witness.trace(&s)
        })
        .unwrap();
        let mut pair = CompositeProof {
            source: proof.source.take(),
            child,
        };
        verify(&expected, &s, &pair).unwrap();
        proof.source = pair.source.take();
        let next = witness
            .old
            .step(
                witness.command.as_ref().unwrap(),
                expected.parent,
                witness.ages(),
            )
            .unwrap();
        if i == 9 {
            assert_eq!(next.outcome, 3);
            assert!(next.next.transactions.is_empty());
        }
        old = next.next;
        old_salt = witness.salts[4];
        old_root = s.next;
    }
}

#[test]
fn coherent_stale_command_counters_and_controller_words_reject_after_full_rehash() {
    let fixture = Fixture::new().unwrap();
    let old = begun();
    let c = command(Operation::Savepoint, 1, 1, 1);
    let (e, w) = fixture.transition(old, c, [0xC1; 32], PARENT).unwrap();
    for field in [113, 120, 121, 123] {
        let (mut s, mut trace) = valid(&e, &w);
        rehash(&mut s, &mut trace, |stream, f, value| {
            if matches!(stream, air::Stream::Command) && f == field {
                if field == 121 || field == 123 {
                    value - Val::ONE
                } else {
                    value + Val::ONE
                }
            } else {
                value
            }
        });
        assert!(!check_all_constraints(&s.air(), &trace, &s.public_values(), Some(1)).is_ok());
        // Repair only the malicious emitted field and all dependent commitments as a positive control.
        let mut repaired = trace.clone();
        let mut repaired_statement = s.clone();
        rehash(&mut repaired_statement, &mut repaired, |_, _, v| v);
        check_constraints(
            &repaired_statement.air(),
            &repaired,
            &repaired_statement.public_values(),
        );
        rejects(&s, trace);
    }
}
#[test]
fn wrong_principal_and_unknown_eighth_name_word_reject_inside_air() {
    let fixture = Fixture::new().unwrap();
    let old = begun();
    let original = command(Operation::Savepoint, 1, 1, 1);
    let (e, w) = fixture
        .transition(old, original, [0xC2; 32], PARENT)
        .unwrap();
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    let mut wrong = w.clone();
    wrong.command.as_mut().unwrap().principal = 2;
    let mut e = e.clone();
    binding(&mut e, &wrong);
    let (s, t) = forged(&e, &wrong, &step);
    rejects(&s, t);
    let mut old = begun();
    old.transactions[0].savepoints = vec![Savepoint {
        name: [0; 32],
        held: [0; 4],
    }];
    let c = command(Operation::RollbackTo, 1, 1, 1);
    let (mut e, mut w) = fixture.transition(old, c, [0xC3; 32], PARENT).unwrap();
    let step = w
        .old
        .step(w.command.as_ref().unwrap(), PARENT, w.ages())
        .unwrap();
    w.command.as_mut().unwrap().name[31] = 1;
    binding(&mut e, &w);
    let (s, mut t) = forged(&e, &w, &step);
    // Coherently pretend the final word matched; all other target/update equations agree.
    for row in t.values.as_chunks_mut::<WIDTH>().0 {
        row[EQ_NAME + 14] = Val::ONE;
        row[EQ_NAME + 15] = Val::ZERO;
        row[EQ_NAME + 24] = Val::ONE;
        row[TARGET] = Val::ONE;
        row[TARGET + 1] = Val::ZERO;
    }
    rejects(&s, t);
}
#[test]
fn canonical_absent_garbage_rejects_with_repaired_hashes_and_positive_clear_control() {
    let fixture = Fixture::new().unwrap();
    let (e, w) = fixture.begin().unwrap();
    let (mut s, mut t) = valid(&e, &w);
    let at = slot(NEW, 1) + SNAPSHOT + 255;
    for row in t.values.as_chunks_mut::<WIDTH>().0 {
        row[at] = Val::ONE;
    }
    rehash(&mut s, &mut t, |_, _, v| v);
    let mut repaired = t.clone();
    let mut repaired_s = s.clone();
    for row in repaired.values.as_chunks_mut::<WIDTH>().0 {
        row[at] = Val::ZERO;
    }
    rehash(&mut repaired_s, &mut repaired, |_, _, v| v);
    check_constraints(&repaired_s.air(), &repaired, &repaired_s.public_values());
    rejects(&s, t);
}
#[test]
fn final_source_row_id_word_is_linked_even_when_every_commitment_is_rebuilt() {
    let fixture = Fixture::new().unwrap();
    let (e, w) = fixture.begin().unwrap();
    let (mut s, mut t) = valid(&e, &w);
    let at = 84 * WIDTH + WORDS + 32;
    let original = t.values[at];
    t.values[at] = Val::ONE - original;
    rehash(&mut s, &mut t, |_, _, v| v);
    let mut repaired = t.clone();
    let mut repaired_s = s.clone();
    let delta = if original == Val::ZERO {
        Val::ONE
    } else {
        -Val::ONE
    };
    for row in repaired.values.as_chunks_mut::<WIDTH>().0 {
        row[IDS + 31] += delta;
    }
    rehash(&mut repaired_s, &mut repaired, |_, _, v| v);
    check_constraints(&repaired_s.air(), &repaired, &repaired_s.public_values());
    rejects(&s, t);
}

#[test]
fn forged_skip_cannot_omit_unlocked_first_match_in_the_new_registry200_air() {
    let fixture = Fixture::new().unwrap();
    let real = begun();
    let c = acquire(1, 1, 1, 4, 2, 0, 1);
    let (e, w) = fixture
        .transition(real.clone(), c.clone(), [0xC4; 32], PARENT)
        .unwrap();
    let honest = w.old.step(&c, PARENT, w.ages()).unwrap();
    assert_eq!(honest.returned, [true, false, false, false]);
    valid(&e, &w);
    let mut holder = real.clone();
    holder.transactions[1].held[0] = 4;
    let mut alternate = holder.step(&c, PARENT, w.ages()).unwrap();
    assert_eq!(alternate.returned, [false, true, false, false]);
    assert_eq!(alternate.skipped, [true, false, false, false]);
    // A real holder is the positive control for this exact alternate walk.
    let (control_e, control_w) = fixture.transition(holder, c, [0xC4; 32], PARENT).unwrap();
    valid(&control_e, &control_w);
    // Restore the true complete other-owner state, retaining only the false walk.
    alternate.next.transactions[1] = real.transactions[1].clone();
    let (s, t) = forged(&e, &w, &alternate);
    rejects(&s, t);
}
