//! Pure owner mathematics, explicitly NOT a predicate/control proof or SQL gate.
use super::circuit::*;
use crate::{
    BackendError,
    lifecycle::circuit::model::{Command, Operation, Registry, Savepoint, Transaction},
};
use zeroize::Zeroizing;
fn tx(id: u64, held: [u8; 4]) -> Transaction {
    Transaction {
        id,
        principal: id as u8,
        sequence: 1,
        failed: false,
        snapshot: [id as u8; 32],
        held,
        savepoints: vec![],
    }
}
fn statement() -> StatementOpening {
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 0x80;
    StatementOpening {
        scope: [1; 64],
        enrollment: [1; 4],
        client: [2; 32],
        call: 1,
        transaction: 2,
        principal: 2,
        controller: [3; 32],
        invocation: [4; 32],
        sql_identity: [5; 32],
        snapshot: [2; 32],
        mask,
        mode: 4,
        wait: 0,
        offset: 1,
        limit: 1,
        projection: 1,
        salt: [7; 4],
    }
}
fn state() -> State {
    State {
        registry: Registry {
            revision: 2,
            allocator: 2,
            transactions: vec![tx(1, [0, 0, 0, 4]), tx(2, [0; 4])],
        },
        progress: [None, None],
    }
}

#[test]
fn native_math_retains_prefix_and_carries_waiter_by_stable_id_then_resumes_original_window() {
    let old = Zeroizing::new(state());
    let s = Zeroizing::new(statement());
    let parked = Zeroizing::new(old.predicate(&s, [0, 1, 128, 255], [8; 4]).unwrap());
    assert!(parked.status == Status::Parked);
    assert_eq!(parked.next.registry.transactions[1].held, [4, 0, 0, 0]);
    assert_eq!(parked.visited, [true, false, false, false]);
    assert_eq!(parked.selected, [false; 4]);
    assert_eq!(parked.cursor, 3);
    assert_eq!(parked.holder, 1);
    let progress_root = parked.next.progress[1].as_ref().unwrap().root().unwrap();
    let end = Command::control(Operation::End, 1, 1, 1);
    let carried = Zeroizing::new(parked.next.control(&end, [0x11; 32]).unwrap());
    assert_eq!(carried.registry.transactions[0].id, 2);
    assert_eq!(
        carried.progress[0].as_ref().unwrap().root().unwrap(),
        progress_root
    );
    assert!(carried.progress[1].is_none());
    let done = Zeroizing::new(carried.predicate(&s, [0, 1, 128, 255], [9; 4]).unwrap());
    assert!(done.status == Status::Done);
    assert!(done.resumed);
    assert_eq!(done.microstep, 2);
    assert_eq!(done.selected, [false, false, false, true]);
    assert_eq!(done.next.registry.transactions[0].held, [4, 0, 0, 4]);
    assert!(done.next.progress[0].is_none());
    for n in 0..8 {
        let mut changed = (*s).clone();
        match n {
            0 => changed.mask[31] = 0,
            1 => changed.offset = 0,
            2 => changed.limit = 2,
            3 => changed.projection = 2,
            4 => changed.controller[31] ^= 1,
            5 => changed.call += 1,
            6 => changed.sql_identity[31] ^= 1,
            _ => changed.salt[3] += 1,
        }
        assert!(
            carried
                .predicate(&changed, [0, 1, 128, 255], [9; 4])
                .is_err()
        );
    }
    let mut lost_prefix = (*carried).clone();
    lost_prefix.registry.transactions[0].held[0] = 0;
    assert_eq!(lost_prefix.require_canonical(), Err(BackendError::Shape));
    let mut reset = (*carried).clone();
    reset.progress[0].as_mut().unwrap().cursor = 0;
    assert!(reset.require_canonical().is_err());
}

#[test]
fn native_nowait_requires_real_conflict_and_fails_only_current_savepoint_scope() {
    let mut old = state();
    old.registry.transactions[1].held = [4, 3, 0, 0];
    old.registry.transactions[1].savepoints.push(Savepoint {
        name: [0x22; 32],
        held: [4, 0, 0, 0],
    });
    let old = Zeroizing::new(old);
    let mut s = statement();
    s.wait = 1;
    let failed = Zeroizing::new(old.predicate(&s, [0, 1, 128, 255], [9; 4]).unwrap());
    assert!(failed.status == Status::Error);
    assert!(failed.next.registry.transactions[1].failed);
    assert_eq!(failed.next.registry.transactions[1].held, [4, 0, 0, 0]);
    assert_eq!(failed.block, [false, false, false, true]);
    assert_eq!(
        failed.next.registry.transactions[0],
        old.registry.transactions[0]
    );
    assert!(failed.next.progress[1].is_none());
    let mut no_conflict = (*old).clone();
    no_conflict.registry.transactions[0].held[3] = 0;
    let done = no_conflict.predicate(&s, [0, 1, 128, 255], [9; 4]).unwrap();
    assert!(done.status == Status::Done);
    assert!(!done.next.registry.transactions[1].failed);
    let arbitrary_failure = Command::control(Operation::FailCurrent, 2, 2, 1);
    assert!(old.control(&arbitrary_failure, [0; 32]).is_err());
}

#[test]
fn blocked_cursor_zero_is_still_resume_and_limit_zero_acquires_nothing() {
    let mut old = state();
    old.registry.transactions[0].held = [4, 0, 0, 0];
    let s = statement();
    let first = old.predicate(&s, [0, 1, 128, 255], [8; 4]).unwrap();
    assert!(first.status == Status::Parked);
    assert_eq!(first.cursor, 0);
    assert!(!first.resumed);
    let second = first.next.predicate(&s, [0, 1, 128, 255], [9; 4]).unwrap();
    assert!(second.status == Status::Parked);
    assert!(second.resumed);
    assert_eq!(second.cursor, 0);
    let mut zero = s;
    zero.limit = 0;
    let step = old.predicate(&zero, [0, 1, 128, 255], [10; 4]).unwrap();
    assert!(step.status == Status::Done);
    assert_eq!(step.next.registry.transactions[1].held, [0; 4]);
    assert_eq!(step.visited, [false; 4]);
    assert_eq!(step.selected, [false; 4]);
}

#[test]
fn private_preimages_keep_exact_fullmask_and_cursor_zero_resume_action() {
    use crate::Val;
    use p3_field::PrimeCharacteristicRing;
    let mut old = state();
    old.registry.transactions[0].held = [4, 0, 0, 0];
    let s = statement();
    let first = old.predicate(&s, [0, 1, 128, 255], [8; 4]).unwrap();
    let second = first.next.predicate(&s, [0, 1, 128, 255], [9; 4]).unwrap();
    let statement_fields = super::fields::statement(&s);
    assert_eq!(statement_fields.len(), 96);
    assert_eq!(statement_fields[78], Val::ONE); // mask bit0
    assert_eq!(statement_fields[85], Val::from_u32(0x8000_0000)); // bit255
    assert_eq!(statement_fields[95], Val::ZERO);
    let p = first.next.progress[1].as_ref().unwrap();
    let progress = super::fields::progress(p).unwrap();
    assert_eq!(progress.len(), 48);
    assert_eq!(progress[24], Val::ZERO);
    assert_eq!(progress[33], Val::ONE);
    assert_eq!(progress[34], Val::ZERO);
    assert_eq!(&progress[44..], &[Val::ZERO; 4]);
    let context = [Val::from_u8(0x53); 100];
    let roots = [[Val::from_u8(0x61); 4]; 3];
    let first_fields = first
        .result_fields(&context, roots, &s, [[Val::ZERO; 4]; 2], [10; 4])
        .unwrap();
    let second_fields = second
        .result_fields(&context, roots, &s, [[Val::ZERO; 4]; 2], [11; 4])
        .unwrap();
    assert_eq!(first_fields.len(), 160);
    assert_eq!(second_fields.len(), 160);
    assert_eq!(first_fields[117], Val::ZERO);
    assert_eq!(second_fields[117], Val::ONE);
    assert_eq!(second_fields[121], Val::ZERO); // prior cursor is still zero
    assert_eq!(&second_fields[154..], &[Val::ZERO; 6]);
}

#[test]
fn skip_conflict_precedes_offset_and_limit_stops_before_any_extra_lock() {
    let mut old = state();
    old.registry.transactions[0].held = [4, 0, 0, 0];
    let mut s = statement();
    s.wait = 2;
    s.mask[0] = 3;
    s.mask[16] = 1;

    let next = old.predicate(&s, [0, 1, 128, 255], [9; 4]).unwrap();

    assert!(next.status == Status::Done);
    assert_eq!(next.skipped, [true, false, false, false]);
    assert_eq!(next.visited, [false, true, true, false]);
    assert_eq!(next.selected, [false, false, true, false]);
    assert_eq!(next.next.registry.transactions[1].held, [0, 4, 4, 0]);
    assert_eq!(next.cursor, 3);
    assert!(next.next.progress.iter().all(Option::is_none));

    s.limit = 0;
    let zero = old.predicate(&s, [0, 1, 128, 255], [10; 4]).unwrap();
    assert!(zero.status == Status::Done);
    assert_eq!(zero.cursor, 0);
    assert_eq!(zero.skipped, [false; 4]);
    assert_eq!(zero.visited, [false; 4]);
    assert_eq!(zero.selected, [false; 4]);
    assert_eq!(zero.next.registry.transactions[1].held, [0; 4]);
}
