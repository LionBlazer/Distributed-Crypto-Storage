//! PUBLIC NONSECRET fixtures. Native reference tests and rebuilt real proofs
//! exercise separate owning boundaries; no fixture answer is a SQL acceptance.
use super::{
    air::*,
    trace::{Registry, Transaction, bits},
    *,
};
use crate::backend::{self, Backend};
use crate::opening::poseidon;
use crate::primitive::{Kind, PublicStatement};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use transaction_state as tx;

fn pinned(e: &mut Expected, w: &Witness) {
    e.old = commitment::digest(&statement::registry_fields(e, w, &w.old, w.salts[1]));
    e.plan = commitment::digest(&statement::plan_fields(e, w));
}
fn valid(e: &Expected, w: &Witness) -> (Statement, RowMajorMatrix<Val>) {
    let s = statement::proposed(e, w).unwrap();
    let trace = w.trace(&s).unwrap();
    check_constraints(&s.air(), &trace, &s.public_values());
    (s, trace)
}
fn rows(trace: &mut RowMajorMatrix<Val>, mut f: impl FnMut(&mut [Val])) {
    for r in trace.values.as_chunks_mut::<WIDTH>().0 {
        f(r);
    }
}
/// Rebuild genuine P2 cells and resulting outputs, preserving independently
/// fixed C_open/C_old/C_plan. This is stronger than replaying an existing proof.
fn rehash(s: &mut Statement, trace: &mut RowMajorMatrix<Val>, rebind_plan: bool, rebind_old: bool) {
    for _ in 0..3 {
        let air = LockingAir::new(s);
        let mut checkpoint = [Val::ZERO; 12];
        for (physical, row) in trace
            .values
            .as_chunks_mut::<WIDTH>()
            .0
            .iter_mut()
            .enumerate()
        {
            row[CHECKPOINT..WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = absorb(physical) {
                for (slot, v) in input[..8].iter_mut().enumerate() {
                    *v = air.field(row, stream, block * 8 + slot, slot);
                }
                if !reset(physical) {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let out = poseidon::write(&mut row[..CHECKPOINT], input);
            if absorb(physical).is_some() {
                checkpoint = out;
            }
            let d: [Val; 4] = out[..4].try_into().unwrap();
            match physical {
                98 if rebind_old => s.expected.old = d,
                116 if rebind_plan => s.expected.plan = d,
                130 => s.next = d,
                277 => s.owned = d,
                298 => s.returned = d,
                _ => {}
            }
        }
    }
}
fn rebuilt_rejects(s: &Statement, trace: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &trace, &s.public_values(), Some(1)).is_ok());
    let b = Backend::new(s).unwrap();
    if let Ok(proof) = p3_uni_stark::prove(&b.config, &s.air(), trace, &s.public_values()) {
        assert!(b.verify(s, &proof).is_err());
    }
}
fn mode(code: u8) -> tx::LockMode {
    match code {
        1 => tx::LockMode::KeyShare,
        2 => tx::LockMode::Share,
        3 => tx::LockMode::NoKeyUpdate,
        4 => tx::LockMode::Update,
        _ => panic!("nonempty fixture mode"),
    }
}
fn mode_code(mode: tx::LockMode) -> u8 {
    match mode {
        tx::LockMode::KeyShare => 1,
        tx::LockMode::Share => 2,
        tx::LockMode::NoKeyUpdate => 3,
        tx::LockMode::Update => 4,
    }
}
fn row(w: &Witness, i: usize) -> tx::RowKey {
    tx::RowKey {
        table: w.plan.table,
        row: w.plain[2220 + 32 * i..2252 + 32 * i].try_into().unwrap(),
    }
}
fn command(s: &tx::State, id: tx::TransactionId, action: tx::Action) -> tx::Command {
    tx::Command {
        expected_revision: s.revision(),
        transaction: id,
        sequence: s.transaction(id).map_or(0, |t| t.next_sequence),
        action,
    }
}
fn apply(s: &mut tx::State, id: tx::TransactionId, action: tx::Action) {
    let actor = s
        .transaction(id)
        .map_or(tx::ControllerId([0x40 + id.0 as u8; 32]), |t| t.controller);
    *s = s.transition(actor, &command(s, id, action)).unwrap().state;
}
fn native_state(w: &mut Witness, holdings: [[u8; 4]; 2], failed: [bool; 2]) -> tx::State {
    let context = tx::Context::new(
        [0xA1; 32],
        [0xC1; 16],
        tx::Profile {
            max_transactions: 2,
            max_locks: 8,
            max_lock_events: 32,
            max_candidates: 4,
            max_savepoints_per_transaction: 2,
            max_state_bytes: 4096,
            max_command_bytes: 4096,
        },
    )
    .unwrap();
    let mut s = tx::State::new(context);
    for t in 0..2 {
        let id = s.next_transaction_id().unwrap();
        let actor = tx::ControllerId([0x41 + t as u8; 32]);
        s = s
            .transition(
                actor,
                &command(
                    &s,
                    id,
                    tx::Action::Begin {
                        snapshot: [0xB1; 32],
                    },
                ),
            )
            .unwrap()
            .state;
        for (i, m) in holdings[t].iter().enumerate() {
            if *m != 0 {
                apply(
                    &mut s,
                    id,
                    tx::Action::Acquire {
                        candidates: vec![row(w, i)],
                        mode: mode(*m),
                        wait: tx::WaitPolicy::Wait,
                        offset: 0,
                        limit: None,
                    },
                );
            }
        }
        if failed[t] {
            apply(&mut s, id, tx::Action::Savepoint { name: [0xDD; 32] });
            apply(&mut s, id, tx::Action::FailCurrent);
        }
    }
    w.old = Registry {
        revision: s.revision().try_into().unwrap(),
        tx: core::array::from_fn(|t| {
            let id = tx::TransactionId(t as u64 + 1);
            let info = s.transaction(id).unwrap();
            Transaction {
                id: id.0 as u32,
                controller: info.controller.0,
                sequence: info.next_sequence.try_into().unwrap(),
                failed: info.status == tx::TransactionStatus::Failed,
                held: core::array::from_fn(|i| s.held_mode(id, row(w, i)).map_or(0, mode_code)),
            }
        }),
    };
    s
}
/// The reference performs the actual metadata transition, not our prefix loop.
fn oracle(w: &Witness, s: &tx::State) {
    let ordinals: Vec<_> = (0..4)
        .filter(|i| {
            let age = w.plain[3 * i];
            w.plan.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0
        })
        .collect();
    let a = usize::from(w.plan.actor);
    let id = tx::TransactionId(u64::from(w.old.tx[a].id));
    let action = tx::Action::Acquire {
        candidates: ordinals.iter().map(|i| row(w, *i)).collect(),
        mode: mode(w.plan.mode),
        wait: match w.plan.wait {
            0 => tx::WaitPolicy::Wait,
            1 => tx::WaitPolicy::NoWait,
            _ => tx::WaitPolicy::SkipLocked,
        },
        offset: u32::from(w.plan.offset),
        limit: Some(u32::from(w.plan.limit)),
    };
    let actual = s.transition(
        tx::ControllerId(w.old.tx[a].controller),
        &command(s, id, action),
    );
    let got = w.walk().unwrap();
    let expected = match actual {
        Ok(done) => {
            assert_eq!(got.outcome, 0);
            let tx::Outcome::Acquired(receipt) = done.outcome else {
                panic!("acquire outcome")
            };
            let returned: Vec<_> = receipt
                .selected
                .iter()
                .map(|p| ordinals[*p as usize])
                .collect();
            let skipped: Vec<_> = receipt
                .skipped
                .iter()
                .map(|p| ordinals[*p as usize])
                .collect();
            assert_eq!(
                returned,
                (0..4).filter(|i| got.returned[*i]).collect::<Vec<_>>()
            );
            assert_eq!(skipped, (0..4).filter(|i| got.skip[*i]).collect::<Vec<_>>());
            done.state
        }
        Err(tx::Error::Blocked(conflict)) => {
            assert_eq!(got.outcome, 1);
            assert!(got.block[ordinals[conflict.candidate as usize]]);
            s.clone()
        }
        Err(tx::Error::LockUnavailable(conflict)) => {
            assert_eq!(got.outcome, 2);
            assert!(got.block[ordinals[conflict.candidate as usize]]);
            s.clone()
        }
        Err(error) => panic!("unexpected native fixture error {error:?}"),
    };
    assert_eq!(u64::from(got.next.revision), expected.revision());
    for t in 0..2 {
        let id = tx::TransactionId(u64::from(got.next.tx[t].id));
        let info = expected.transaction(id).unwrap();
        assert_eq!(u64::from(got.next.tx[t].sequence), info.next_sequence);
        assert_eq!(
            got.next.tx[t].failed,
            info.status == tx::TransactionStatus::Failed
        );
        for i in 0..4 {
            assert_eq!(
                got.next.tx[t].held[i],
                expected.held_mode(id, row(w, i)).map_or(0, mode_code)
            );
        }
    }
}

#[test]
fn stable_registry_encoding_is_query_independent_but_query_plan_is_not() {
    let (e, _, w) = fixture().unwrap();
    assert_eq!(
        statement::registry_fields(&e, &w, &w.old, w.salts[1]).len(),
        112
    );
    assert_eq!(statement::plan_fields(&e, &w).len(), 144);
    let s = statement::proposed(&e, &w).unwrap();
    assert_eq!(s.public_values().len(), 116);
    assert_eq!(statement::output_fields(&s, &w, true).unwrap().len(), 168);
    assert_eq!(statement::output_fields(&s, &w, false).unwrap().len(), 168);
    let mut other = e.clone();
    other.parent = [9; 32];
    other.source.request = [8; 32];
    assert_eq!(
        statement::registry_fields(&e, &w, &w.old, w.salts[1]),
        statement::registry_fields(&other, &w, &w.old, w.salts[1])
    );
    assert_ne!(
        statement::plan_fields(&e, &w),
        statement::plan_fields(&other, &w)
    );
}
#[test]
fn all_mode_pairs_match_the_independent_native_conflict_table() {
    for requested in 1..=4 {
        for held in 1..=4 {
            assert_eq!(
                trace::conflicts(requested, held),
                mode(requested).conflicts(mode(held))
            );
            let (mut e, _, mut w) = fixture().unwrap();
            w.plan.mode = requested;
            let state = native_state(&mut w, [[0; 4], [held, 0, 0, 0]], [false; 2]);
            pinned(&mut e, &w);
            oracle(&w, &state);
            valid(&e, &w);
        }
    }
}
#[test]
fn skip_passes_locked_first_match_and_returns_the_later_limit_prefix() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.limit = 1;
    let state = native_state(&mut w, [[0; 4], [4, 0, 0, 0]], [false; 2]);
    pinned(&mut e, &w);
    oracle(&w, &state);
    let (s, _) = valid(&e, &w);
    let out = statement::output_fields(&s, &w, false).unwrap();
    assert_eq!(out[119], Val::ONE);
    assert_eq!(out[120], Val::ONE);
    assert_eq!(out[121], Val::ZERO);
}
#[test]
fn offset_rows_acquire_ownership_without_becoming_returned_rows() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.offset = 1;
    w.plan.limit = 1;
    let state = native_state(&mut w, [[0; 4]; 2], [false; 2]);
    pinned(&mut e, &w);
    oracle(&w, &state);
    let (s, _) = valid(&e, &w);
    let got = w.walk().unwrap();
    assert_eq!(got.next.tx[0].held, [4, 4, 0, 0]);
    assert_ne!(s.owned, s.returned);
    assert_eq!(got.returned, [false, true, false, false]);
}
#[test]
fn late_wait_and_nowait_conflict_undo_earlier_upgrade_and_all_counters() {
    for wait in [0, 1] {
        let (mut e, _, mut w) = fixture().unwrap();
        w.plan.wait = wait;
        let state = native_state(&mut w, [[1, 0, 0, 0], [0, 4, 0, 0]], [false; 2]);
        pinned(&mut e, &w);
        oracle(&w, &state);
        let (s, _) = valid(&e, &w);
        let got = w.walk().unwrap();
        assert_eq!(got.next.tx[0].held, w.old.tx[0].held);
        assert_eq!(s.next, e.old);
        for owned in [false, true] {
            assert!(
                statement::output_fields(&s, &w, owned).unwrap()[119..167]
                    .iter()
                    .all(|v| *v == Val::ZERO)
            );
        }
    }
}
#[test]
fn own_upgrade_never_skips_and_failed_other_owner_keeps_pre_savepoint_locks() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.limit = 4;
    let state = native_state(&mut w, [[1, 0, 0, 0], [0, 4, 0, 0]], [false, true]);
    pinned(&mut e, &w);
    oracle(&w, &state);
    valid(&e, &w);
    let got = w.walk().unwrap();
    assert!(got.visit[0]);
    assert!(got.skip[1]);
    assert_eq!(got.next.tx[0].held[0], 4);
}
#[test]
fn limit_zero_changes_only_success_counters_and_does_not_acquire_offset() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.limit = 0;
    w.plan.offset = 4;
    let state = native_state(&mut w, [[0; 4], [4; 4]], [false; 2]);
    pinned(&mut e, &w);
    oracle(&w, &state);
    valid(&e, &w);
    let got = w.walk().unwrap();
    assert_eq!(got.next.tx[0].held, [0; 4]);
    assert_eq!(got.next.revision, w.old.revision + 1);
    assert_eq!(got.next.tx[0].sequence, w.old.tx[0].sequence + 1);
}
#[test]
fn bounded_counter_admission_rejects_even_before_a_wait_conflict() {
    let (_, _, mut w) = fixture().unwrap();
    w.plan.wait = 0;
    w.old.tx[1].held[0] = 4;
    w.old.revision = u32::MAX;
    assert!(w.walk().is_err());
    w.old.revision = 3;
    w.old.tx[0].sequence = u32::MAX;
    assert!(w.walk().is_err());
    w.old.tx[0].sequence = 1;
    w.old.tx[1].sequence = u32::MAX;
    assert!(w.walk().is_ok());
}
#[test]
fn genuine_composite_requires_source_and_independent_old_root_plan_parent() {
    let (e, sw, w) = fixture().unwrap();
    let (s, mut proof) = prove_composite(&e, &sw, &w).unwrap();
    verify_composite(&e, &s, &proof).unwrap();
    for changed in 0..3 {
        let mut expected = e.clone();
        match changed {
            0 => expected.old[0] += Val::ONE,
            1 => expected.plan[0] += Val::ONE,
            _ => expected.parent[0] ^= 1,
        }
        assert!(verify_composite(&expected, &s, &proof).is_err());
        let mut changed_statement = s.clone();
        changed_statement.expected = expected;
        assert!(
            Backend::new(&changed_statement)
                .unwrap()
                .verify(&changed_statement, &proof.locking)
                .is_err()
        );
    }
    proof.source = None;
    assert!(verify_composite(&e, &s, &proof).is_err());
}
#[test]
fn failed_actor_cannot_acquire_even_with_recomputed_plan_commitment() {
    let (mut e, _, mut w) = fixture().unwrap();
    native_state(&mut w, [[0; 4]; 2], [true, false]);
    pinned(&mut e, &w);
    let mut s = statement::proposed(&e, &w).unwrap();
    let mut trace = w.trace(&s).unwrap();
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn omitted_other_holder_cannot_open_the_independently_fixed_registry() {
    let (mut e, _, mut w) = fixture().unwrap();
    native_state(&mut w, [[0; 4], [4, 0, 0, 0]], [false; 2]);
    pinned(&mut e, &w);
    let mut s = statement::proposed(&e, &w).unwrap();
    w.old.tx[1].held[0] = 0;
    let mut trace = w.trace(&s).unwrap();
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn forged_conflict_cannot_create_a_skip_without_an_actual_other_holder() {
    let (e, _, mut w) = fixture().unwrap();
    let (mut s, _) = valid(&e, &w);
    let expected_old = e.old;
    let expected_plan = e.plan;

    // Build a complete alternate walk: pretend the first row is held by owner1.
    // All downstream ranks, targets, holdings, compaction and outputs then agree
    // with skipping it and returning rows1/2 instead of the genuine rows0/1.
    w.old.tx[1].held[0] = 4;
    let mut trace = w.trace(&s).unwrap();
    // Retain the REAL complete old registry and REAL unchanged nonactor. The
    // claimed conflict must therefore be false; the downstream walk stays forged.
    rows(&mut trace, |r| {
        for start in [HELD + 20, NEXT_HELD + 20] {
            r[start..start + 5].fill(Val::ZERO);
            r[start] = Val::ONE;
        }
    });
    rehash(&mut s, &mut trace, false, false);
    assert_eq!(s.expected.old, expected_old);
    assert_eq!(s.expected.plan, expected_plan);
    let first = &trace.values[..WIDTH];
    assert_eq!(first[CONFLICT], Val::ONE);
    assert_eq!(first[SKIP], Val::ONE);
    assert_eq!(first[VISIT], Val::ZERO);
    assert_eq!(first[RETURN], Val::ZERO);
    assert_eq!(first[COMPACT_RETURN + 1], Val::ONE);
    assert_eq!(first[COMPACT_RETURN + 4 + 2], Val::ONE);

    // Exactly ONE equation per row may reject: the omitted-holder -> conflict
    // binding. Other walk/commitment/ownership equations must all remain valid.
    let report = check_all_constraints(
        &s.air(),
        &trace,
        &s.public_values(),
        Some(backend::TRACE_HEIGHT + 1),
    );
    assert_eq!(report.failures.len(), backend::TRACE_HEIGHT);
    let conflict_constraint = report.failures[0].constraint;
    for (row, failure) in report.failures.iter().enumerate() {
        assert_eq!(failure.row, row);
        assert_eq!(failure.constraint, conflict_constraint);
    }
    rebuilt_rejects(&s, trace);
}
#[test]
fn changed_source_rowid_cannot_be_hidden_by_recomputed_control_outputs() {
    let (e, _, w) = fixture().unwrap();
    let (mut s, mut trace) = valid(&e, &w);
    rows(&mut trace, |r| r[IDS] += Val::ONE);
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn blocked_reblinding_cannot_change_the_old_root_or_confer_a_grant() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.wait = 0;
    native_state(&mut w, [[0; 4], [0, 4, 0, 0]], [false; 2]);
    pinned(&mut e, &w);
    let (mut s, mut trace) = valid(&e, &w);
    rows(&mut trace, |r| r[SALTS + 12] += Val::ONE);
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn offset_and_limit_values_five_to_seven_reject_inside_the_air() {
    for (start, value) in [(OFFSET, 5), (LIMIT, 7)] {
        let (e, _, w) = fixture().unwrap();
        let (mut s, mut trace) = valid(&e, &w);
        rows(&mut trace, |r| bits(&mut r[start..start + 3], value));
        rehash(&mut s, &mut trace, true, false);
        rebuilt_rejects(&s, trace);
    }
}
#[test]
fn forged_unsigned_counter_wrap_is_not_a_field_valid_success() {
    for blocked in [false, true] {
        let (mut e, _, mut w) = fixture().unwrap();
        if blocked {
            w.plan.wait = 0;
            w.old.tx[1].held[1] = 4;
            pinned(&mut e, &w);
        }
        let (mut s, mut trace) = valid(&e, &w);
        rows(&mut trace, |r| {
            bits(&mut r[REVISION..CANDIDATE_REVISION], u64::from(u32::MAX));
            bits(&mut r[CANDIDATE_REVISION..HELD], 0);
        });
        // Rebind the valid MAX old registry and plan, plus every downstream
        // commitment. Rejection must not come from a stale root or public input.
        rehash(&mut s, &mut trace, true, true);
        if blocked {
            assert_eq!(s.next, s.expected.old);
            let first = &trace.values[..WIDTH];
            assert_eq!(first[OUTCOME], Val::ZERO);
            assert_eq!(first[OUTCOME + 1], Val::ONE);
            assert_eq!(&first[SALTS + 12..SALTS + 16], &first[SALTS + 4..SALTS + 8]);
            assert!(first[COMPACT_RETURN..SALTS].iter().all(|v| *v == Val::ZERO));
        }
        // The sole broken equation is unconditional candidate-revision admission,
        // including when success=0. A success-gated guard would wrongly accept.
        let report = check_all_constraints(
            &s.air(),
            &trace,
            &s.public_values(),
            Some(backend::TRACE_HEIGHT + 1),
        );
        assert_eq!(report.failures.len(), backend::TRACE_HEIGHT);
        let admission_constraint = report.failures[0].constraint;
        for (row, failure) in report.failures.iter().enumerate() {
            assert_eq!(failure.row, row);
            assert_eq!(failure.constraint, admission_constraint);
        }
        rebuilt_rejects(&s, trace);
    }
}
#[test]
fn row300_ordering_and_controller_bits_are_constrained_not_host_labels() {
    for bad_controller in [false, true] {
        let (e, _, w) = fixture().unwrap();
        let (mut s, mut trace) = valid(&e, &w);
        if bad_controller {
            rows(&mut trace, |r| r[CONTROLLERS] = Val::from_u8(2));
        } else {
            trace.values[300 * WIDTH + WORDS] = Val::ONE;
        }
        rehash(&mut s, &mut trace, false, false);
        rebuilt_rejects(&s, trace);
    }
}
#[test]
fn exact_shape_and_new_profile_leave_old_selection_guards_distinct() {
    let (e, _, w) = fixture().unwrap();
    let s = statement::proposed(&e, &w).unwrap();
    let a = s.air();
    assert_eq!(
        (
            a.width(),
            a.num_public_values(),
            a.num_periodic_columns(),
            a.main_next_row_columns().len()
        ),
        (1948, 116, 512, 1948)
    );
    assert_ne!(
        backend::profile_digest(Kind::LockingSelection),
        backend::profile_digest(Kind::SelectionOpening)
    );
    assert_eq!(
        backend::AllocationEstimate::for_width(WIDTH).main_lde_bytes,
        127991808
    );
}

#[test]
fn complete_filtered_exhaustion_returns_fewer_than_limit_without_truncation() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.mask = [0; 32];
    w.plan.mask[16] = 1;
    w.plan.limit = 4;
    let native = native_state(&mut w, [[0; 4]; 2], [false; 2]);
    pinned(&mut e, &w);
    oracle(&w, &native);
    valid(&e, &w);
    assert_eq!(w.walk().unwrap().returned, [false, false, false, true]);
}
#[test]
fn late_blocked_command_cannot_keep_its_tentative_earlier_return() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.wait = 0;
    native_state(&mut w, [[0; 4], [0, 4, 0, 0]], [false; 2]);
    pinned(&mut e, &w);
    let (mut s, mut trace) = valid(&e, &w);
    rows(&mut trace, |r| {
        r[COMPACT_RETURN] = Val::ONE;
        r[PRESENT_RETURN] = Val::ONE;
        r[COMPACT_OWNED] = Val::ONE;
        r[PRESENT_OWNED] = Val::ONE;
    });
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn another_owners_compatible_mode_cannot_be_changed_by_this_command() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.mode = 2;
    pinned(&mut e, &w);
    let (mut s, mut trace) = valid(&e, &w);
    rows(&mut trace, |r| {
        r[NEXT_HELD + 20] = Val::ZERO;
        r[NEXT_HELD + 21] = Val::ONE;
    });
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn incompatible_old_registry_rejects_even_when_its_hash_and_plan_are_rebuilt() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.old.tx[0].held[0] = 4;
    w.old.tx[1].held[0] = 4;
    pinned(&mut e, &w);
    let mut s = statement::proposed(&e, &w).unwrap();
    let mut trace = w.trace(&s).unwrap();
    rehash(&mut s, &mut trace, false, false);
    rebuilt_rejects(&s, trace);
}
#[test]
fn genuine_byte_opening_proof_cannot_substitute_for_canonical_source() {
    let (e, sw, w) = fixture().unwrap();
    let (s, mut proof) = prove_composite(&e, &sw, &w).unwrap();
    let mut bytes = e.source.clone();
    bytes.relation = Relation::Bytes;
    // Opening commitments include the relation's profile. First prove valid
    // byte evidence, then test its rejection as foreign canonical evidence.
    bytes.open_commitment =
        commitment::digest(&commitment::opening_fields(&bytes, w.salts[0], &w.plain));
    let b = Backend::new(&bytes).unwrap();
    let foreign = b.prove_with_trace(&bytes, || sw.trace(&bytes)).unwrap();
    b.verify(&bytes, &foreign).unwrap();
    proof.source = Some(foreign);
    assert!(verify_composite(&e, &s, &proof).is_err());
}

#[test]
fn second_actor_upgrades_own_lock_and_preserves_the_failed_first_owner() {
    let (mut e, _, mut w) = fixture().unwrap();
    w.plan.actor = 1;
    w.plan.limit = 4;
    let state = native_state(&mut w, [[0, 4, 0, 0], [1, 0, 0, 0]], [true, false]);
    pinned(&mut e, &w);
    oracle(&w, &state);
    valid(&e, &w);

    let got = w.walk().unwrap();
    assert_eq!(got.outcome, 0);
    assert!(got.visit[0]);
    assert!(!got.skip[0]);
    assert!(got.skip[1]);
    assert_eq!(got.returned, [true, false, true, true]);
    assert_eq!(got.next.tx[1].held, [4, 0, 4, 4]);
    assert_eq!(got.next.tx[1].sequence, w.old.tx[1].sequence + 1);
    let before = &w.old.tx[0];
    let after = &got.next.tx[0];
    assert_eq!(after.id, before.id);
    assert_eq!(after.controller, before.controller);
    assert_eq!(after.sequence, before.sequence);
    assert_eq!(after.failed, before.failed);
    assert_eq!(after.held, before.held);
    assert!(after.failed);
}
