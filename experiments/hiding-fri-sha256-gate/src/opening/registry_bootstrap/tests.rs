//! PUBLIC NONSECRET examples; native State is an oracle, never proof acceptance.
use super::{air::*, *};
use crate::backend::{Backend, TRACE_HEIGHT};
use crate::opening::{locking, poseidon};
use crate::primitive::{Kind, PublicStatement};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{Field, PrimeCharacteristicRing};
use std::cell::Cell;
use transaction_state as tx;

fn valid(e: &Expected, w: &Witness) -> (Statement, RowMajorMatrix<Val>) {
    let s = w.statement(e).unwrap();
    let trace = w.trace(&s).unwrap();
    check_constraints(&s.air(), &trace, &s.public_values());
    (s, trace)
}
fn rows(trace: &mut RowMajorMatrix<Val>, mut f: impl FnMut(&mut [Val])) {
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        f(row);
    }
}
/// Rebuild every actual permutation and checkpoint, including zero-input padding.
/// The returned roots let each test explicitly choose which independent claim to
/// preserve. This is not an acceptance path or an alternate relation evaluator.
fn rehash(
    s: &mut Statement,
    trace: &mut RowMajorMatrix<Val>,
    mut altered: impl FnMut(Stream, usize, Val) -> Val,
    rebind_enrollment: bool,
) -> [[Val; 4]; 3] {
    let air = BootstrapAir::new(s);
    let mut checkpoint = [Val::ZERO; 12];
    let mut roots = [[Val::ZERO; 4]; 3];
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
            for (slot, value) in input[..8].iter_mut().enumerate() {
                let field = block * 8 + slot;
                *value = altered(stream, field, air.field(row, stream, field, slot));
            }
            if !reset(physical) {
                input[8..].copy_from_slice(&checkpoint[8..]);
            }
        }
        let output = poseidon::write(&mut row[..CHECKPOINT], input);
        if absorb(physical).is_some() {
            checkpoint = output;
        }
        let digest: [Val; 4] = output[..4].try_into().unwrap();
        match physical {
            84 => roots[0] = digest,
            92 => roots[1] = digest,
            106 => roots[2] = digest,
            _ => {}
        }
    }
    if rebind_enrollment {
        s.expected.enrollment = roots[1];
    }
    s.registry = roots[2];
    roots
}
fn rebuilt_rejects(s: &Statement, trace: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &trace, &s.public_values(), Some(1)).is_ok());
    let backend = Backend::new(s).unwrap();
    // Use the raw SDK so the honest witness constructor cannot reject the attack
    // for us. A generated hostile proof must fail the real verifier.
    if let Ok(p) = p3_uni_stark::prove(&backend.config, &s.air(), trace, &s.public_values()) {
        assert!(backend.verify(s, &p).is_err());
    }
}
fn exactly_one_row(s: &Statement, trace: &RowMajorMatrix<Val>, row: usize) {
    let report = check_all_constraints(&s.air(), trace, &s.public_values(), Some(2));
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].row, row);
}

#[test]
fn complete_bootstrap_streams_match_registry112_and_two_native_begin_steps() {
    let (e, _, w) = fixture().unwrap();
    let (s, trace) = valid(&e, &w);
    assert_eq!(s.kind(), Kind::RegistryBootstrap);
    assert_eq!(s.public_values().len(), 104);
    assert_eq!(BaseAir::<Val>::width(&s.air()), 1082);
    assert_eq!(BaseAir::<Val>::num_periodic_columns(&s.air()), 512);
    let enrollment = statement::enrollment_fields(&e, &w);
    let registry = statement::registry_fields(&e, &w);
    assert_eq!(enrollment.len(), 64);
    assert_eq!(registry.len(), 112);
    assert_eq!(registry[75], Val::from_u8(2));
    for (t, controller) in w.controllers.iter().enumerate() {
        let at = 76 + t * 15;
        assert_eq!(registry[at], Val::from_usize(t + 1));
        assert_eq!(
            registry[at + 1..at + 9],
            crate::opening::statement::words(controller).collect::<Vec<_>>()
        );
        assert_eq!(registry[at + 9], Val::ONE);
        assert_eq!(registry[at + 10..at + 15], [Val::ZERO; 5]);
    }
    // The old public API encoding is exactly the same root, not a relabeled kind.
    let (old_e, _, mut old_w) = locking::fixture().unwrap();
    old_w.plain = w.plain;
    old_w.plan.table = w.table();
    old_w.old = w.registry();
    let old_e = locking::statement::Expected::checked(
        &e.source,
        e.genesis,
        e.parent,
        locking::statement::encoded(old_e.old),
        locking::statement::encoded(old_e.plan),
    )
    .unwrap();
    assert_eq!(
        registry,
        locking::statement::registry_fields(&old_e, &old_w, &old_w.old, w.salts[2])
    );
    let context = tx::Context::new(
        e.genesis,
        e.source.heads[0][8..24].try_into().unwrap(),
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
    let mut native = tx::State::new(context);
    for (t, controller) in w.controllers.iter().enumerate() {
        let id = native.next_transaction_id().unwrap();
        let transition = native
            .transition(
                tx::ControllerId(*controller),
                &tx::Command {
                    expected_revision: native.revision(),
                    transaction: id,
                    sequence: 0,
                    action: tx::Action::Begin { snapshot: e.parent },
                },
            )
            .unwrap();
        native = transition.state;
        assert_eq!(id, tx::TransactionId(t as u64 + 1));
    }
    assert_eq!(native.revision(), 2);
    for (t, controller) in w.controllers.iter().enumerate() {
        let id = tx::TransactionId(t as u64 + 1);
        let info = native.transaction(id).unwrap();
        assert_eq!(info.controller, tx::ControllerId(*controller));
        assert_eq!(info.next_sequence, 1);
        assert_eq!(info.status, tx::TransactionStatus::Active);
        for bytes in w.plain[2220..2348].as_chunks::<32>().0 {
            assert_eq!(
                native.held_mode(
                    id,
                    tx::RowKey {
                        table: w.table(),
                        row: *bytes
                    }
                ),
                None
            );
        }
    }
    let final_row = &trace.values[511 * WIDTH..512 * WIDTH];
    assert_eq!(&final_row[CHECKPOINT..CHECKPOINT + 4], &s.registry);
}

#[test]
fn genuine_source_and_bootstrap_verify_and_foreign_enrollment_is_not_the_expected_one() {
    let (e, sw, w) = fixture().unwrap();
    let (s, mut p) = prove(&e, &sw, &w).unwrap();
    verify(&e, &s, &p).unwrap();
    // Fresh backend checks replay cryptographically, rather than relying only on
    // exact Expected comparison in the composite wrapper.
    for part in 0..5 {
        let mut changed = s.clone();
        match part {
            0 => changed.expected.parent[0] ^= 1,
            1 => changed.expected.genesis[0] ^= 1,
            2 => changed.expected.source.request[0] ^= 1,
            3 => changed.expected.enrollment[0] += Val::ONE,
            _ => changed.registry[0] += Val::ONE,
        }
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &p.bootstrap)
                .is_err()
        );
        assert!(verify(&e, &changed, &p).is_err());
    }
    let mut foreign_w = w.clone();
    foreign_w.controllers[1][31] ^= 1;
    let mut foreign_e = e.clone();
    foreign_e.enrollment =
        commitment::digest(&statement::enrollment_fields(&foreign_e, &foreign_w));
    let foreign_s = foreign_w.statement(&foreign_e).unwrap();
    assert_ne!(foreign_s.registry, s.registry);
    assert_ne!(foreign_e.enrollment, e.enrollment);
    let child = prove_child_with_trace(&foreign_e, &foreign_s, p.source.as_ref().unwrap(), || {
        foreign_w.trace(&foreign_s)
    })
    .unwrap();
    let foreign_p = CompositeProof {
        source: p.source.take(),
        bootstrap: child,
    };
    verify(&foreign_e, &foreign_s, &foreign_p).unwrap();
    assert!(verify(&e, &foreign_s, &foreign_p).is_err());
}

#[test]
fn actual_source_verification_and_exact_expected_precede_child_factory() {
    let (e, sw, w) = fixture().unwrap();
    let source_backend = Backend::new(&e.source).unwrap();
    let source = source_backend
        .prove_with_trace(&e.source, || sw.trace(&e.source))
        .unwrap();
    source_backend.verify(&e.source, &source).unwrap();
    let s = w.statement(&e).unwrap();
    for part in 0..9 {
        let mut bad = s.clone();
        match part {
            0 => bad.expected.parent[0] ^= 1,
            1 => bad.expected.genesis[0] ^= 1,
            2 => bad.expected.enrollment[0] += Val::ONE,
            3 => bad.expected.source.request[0] ^= 1,
            4 => bad.expected.source.heads[1][111] ^= 1,
            5 => bad.expected.source.key_commitment[0] += Val::ONE,
            6 => bad.expected.source.open_commitment[0] += Val::ONE,
            7 => bad.expected.source.packets[1].truncate(1),
            _ => bad.expected.source.relation = Relation::Bytes,
        }
        let called = Cell::new(false);
        assert!(
            prove_child_with_trace(&e, &bad, &source, || {
                called.set(true);
                w.trace(&bad)
            })
            .is_err()
        );
        assert!(!called.get());
    }
    // Malformed independent Expected and malformed submitted statement are total
    // errors, even before a source public-values word conversion is possible.
    let mut malformed_e = e.clone();
    malformed_e.source.packets[1].truncate(1);
    for malformed_statement in [false, true] {
        let mut submitted = s.clone();
        if malformed_statement {
            submitted.expected.source.packets[1].truncate(1);
        }
        let called = Cell::new(false);
        assert!(
            prove_child_with_trace(&malformed_e, &submitted, &source, || {
                called.set(true);
                w.trace(&submitted)
            })
            .is_err()
        );
        assert!(!called.get());
    }
    let mut wrong_source_e = e.clone();
    wrong_source_e.source.request[31] ^= 1;
    let wrong_s = w.statement(&wrong_source_e).unwrap();
    let called = Cell::new(false);
    assert!(
        prove_child_with_trace(&wrong_source_e, &wrong_s, &source, || {
            called.set(true);
            w.trace(&wrong_s)
        })
        .is_err()
    );
    assert!(!called.get());
}

#[test]
fn missing_or_genuine_byte_source_cannot_substitute_for_canonical_prerequisite() {
    let (e, sw, w) = fixture().unwrap();
    let s = w.statement(&e).unwrap();
    let child = Backend::new(&s)
        .unwrap()
        .prove_with_trace(&s, || w.trace(&s))
        .unwrap();
    let mut p = CompositeProof {
        source: None,
        bootstrap: child,
    };
    assert!(verify(&e, &s, &p).is_err());
    let mut bytes = e.source.clone();
    bytes.relation = Relation::Bytes;
    bytes.open_commitment =
        commitment::digest(&commitment::opening_fields(&bytes, w.salts[0], &w.plain));
    let b = Backend::new(&bytes).unwrap();
    let byte_proof = b.prove_with_trace(&bytes, || sw.trace(&bytes)).unwrap();
    b.verify(&bytes, &byte_proof).unwrap();
    let called = Cell::new(false);
    assert!(
        prove_child_with_trace(&e, &s, &byte_proof, || {
            called.set(true);
            w.trace(&s)
        })
        .is_err()
    );
    assert!(!called.get());
    p.source = Some(byte_proof);
    assert!(verify(&e, &s, &p).is_err());
    assert!(
        Expected::checked(&bytes, e.genesis, e.parent, registry::encoded(e.enrollment)).is_err()
    );
}

#[test]
fn coherent_nonempty_or_uninitialized_registry_fields_are_rejected() {
    let (e, _, w) = fixture().unwrap();
    let (original, original_trace) = valid(&e, &w);
    for (field, bad) in [
        (75, 0),
        (76, 2),
        (85, 0),
        (86, 1),
        (87, 4),
        (91, 1),
        (100, 2),
        (101, 1),
        (105, 1),
    ] {
        let mut s = original.clone();
        let mut trace = original_trace.clone();
        let _ = rehash(
            &mut s,
            &mut trace,
            |stream, f, value| {
                if matches!(stream, Stream::Registry) && f == field {
                    Val::from_u8(bad)
                } else {
                    value
                }
            },
            false,
        );
        assert_ne!(s.registry, original.registry);
        exactly_one_row(&s, &trace, 93 + field / 8);
        rebuilt_rejects(&s, trace);
    }
}

#[test]
fn enrollment_and_registry_cannot_open_different_controllers() {
    let (e, _, w) = fixture().unwrap();
    let (original, original_trace) = valid(&e, &w);
    let mut s = original.clone();
    let mut trace = original_trace.clone();
    let _ = rehash(
        &mut s,
        &mut trace,
        |stream, field, value| {
            if matches!(stream, Stream::Registry) && field == 99 {
                value + Val::ONE
            } else {
                value
            }
        },
        false,
    );
    exactly_one_row(&s, &trace, 93 + 99 / 8);
    assert_eq!(s.expected.enrollment, e.enrollment);
    rebuilt_rejects(&s, trace.clone());
    let _ = rehash(&mut s, &mut trace, |_, _, value| value, false);
    check_constraints(&s.air(), &trace, &s.public_values());
    assert_eq!(s.registry, original.registry);
}

#[test]
fn zero_controller_and_nonboolean_controller_bits_fail_with_rebuilt_real_roots() {
    let (e, _, mut w) = fixture().unwrap();
    w.controllers[1] = [0; 32];
    let mut e = e;
    e.enrollment = commitment::digest(&statement::enrollment_fields(&e, &w));
    let s = w.statement(&e).unwrap();
    let trace = w.trace(&s).unwrap();
    let report =
        check_all_constraints(&s.air(), &trace, &s.public_values(), Some(TRACE_HEIGHT + 1));
    assert_eq!(report.failures.len(), TRACE_HEIGHT);
    rebuilt_rejects(&s, trace);
    let (e, _, w) = fixture().unwrap();
    let (mut s, mut trace) = valid(&e, &w);
    rows(&mut trace, |row| {
        row[CONTROLLERS] = Val::from_u8(2);
        let sum: Val = row[CONTROLLERS..CONTROLLERS + 256].iter().copied().sum();
        row[INVERSES] = sum.inverse();
    });
    let _ = rehash(&mut s, &mut trace, |_, _, value| value, true);
    let report =
        check_all_constraints(&s.air(), &trace, &s.public_values(), Some(TRACE_HEIGHT + 1));
    assert_eq!(report.failures.len(), TRACE_HEIGHT);
    rebuilt_rejects(&s, trace);
}

#[test]
fn complete_table_and_final_ordinal_rowid_must_be_captured_from_the_same_source() {
    let (e, _, w) = fixture().unwrap();
    let (original, original_trace) = valid(&e, &w);
    for (column, source_field) in [(TABLE + 7, 87 + 31 + 7), (IDS + 31, 673)] {
        let mut s = original.clone();
        let mut trace = original_trace.clone();
        rows(&mut trace, |row| row[column] += Val::ONE);
        let _ = rehash(&mut s, &mut trace, |_, _, value| value, true);
        exactly_one_row(&s, &trace, source_field / 8);
        rebuilt_rejects(&s, trace.clone());
        rows(&mut trace, |row| row[column] -= Val::ONE);
        let _ = rehash(&mut s, &mut trace, |_, _, value| value, true);
        check_constraints(&s.air(), &trace, &s.public_values());
        assert_eq!(s.registry, original.registry);
        assert_eq!(s.expected.enrollment, original.expected.enrollment);
    }
}

#[test]
fn final_source_word_is_not_omitted_when_registry_and_all_hashes_are_rebuilt() {
    let (e, _, w) = fixture().unwrap();
    let (mut s, mut trace) = valid(&e, &w);
    let slot = 673 % 8;
    let bit = trace.values[84 * WIDTH + WORDS + slot * 32];
    let delta = Val::ONE - bit - bit;
    trace.values[84 * WIDTH + WORDS + slot * 32] = Val::ONE - bit;
    rows(&mut trace, |row| row[IDS + 31] += delta);
    let roots = rehash(&mut s, &mut trace, |_, _, value| value, false);
    assert_ne!(roots[0], e.source.open_commitment);
    // C_open has four field limbs: several constraints can fail on this one
    // row. Scan the complete trace to exclude failures at any other row.
    let report = check_all_constraints(&s.air(), &trace, &s.public_values(), None);
    assert!(!report.is_ok());
    assert!(report.failures.iter().all(|failure| failure.row == 84));
    rebuilt_rejects(&s, trace.clone());
    // Child-only repair isolates C_open; this does not supply the now-missing
    // canonical source proof for that different source opening.
    s.expected.source.open_commitment = roots[0];
    check_constraints(&s.air(), &trace, &s.public_values());
}

#[test]
fn domain_version_genesis_and_key_scope_cannot_be_relabelled_by_rehashing() {
    let (e, _, w) = fixture().unwrap();
    let (original, original_trace) = valid(&e, &w);
    for (enrollment, field) in [
        (true, 0),
        (true, 4),
        (true, 13),
        (true, 21),
        (true, 29),
        (false, 0),
        (false, 5),
        (false, 20),
        (false, 28),
        (false, 32),
    ] {
        let mut s = original.clone();
        let mut trace = original_trace.clone();
        let _ = rehash(
            &mut s,
            &mut trace,
            |stream, f, value| {
                let selected = if enrollment {
                    matches!(stream, Stream::Enrollment)
                } else {
                    matches!(stream, Stream::Registry)
                };
                if selected && f == field {
                    value + Val::ONE
                } else {
                    value
                }
            },
            enrollment,
        );
        exactly_one_row(&s, &trace, if enrollment { 85 } else { 93 } + field / 8);
        rebuilt_rejects(&s, trace);
    }
}

#[test]
fn salts_checkpoint_and_padding_cannot_change_after_the_last_active_hash() {
    let (e, _, w) = fixture().unwrap();
    let (original, original_trace) = valid(&e, &w);
    for column in [
        TABLE,
        IDS + 31,
        CONTROLLERS + 511,
        SALTS,
        SALTS + 11,
        INVERSES + 1,
        CHECKPOINT,
    ] {
        let mut trace = original_trace.clone();
        trace.values[511 * WIDTH + column] += Val::ONE;
        assert!(
            !check_all_constraints(&original.air(), &trace, &original.public_values(), Some(1))
                .is_ok()
        );
        rebuilt_rejects(&original, trace);
    }
    let mut trace = original_trace;
    let at = 107 * WIDTH;
    let mut input = [Val::ZERO; 12];
    input[0] = Val::ONE;
    let _ = poseidon::write(&mut trace.values[at..at + CHECKPOINT], input);
    rebuilt_rejects(&original, trace);
}

#[test]
fn enrollment_scope_is_query_independent_but_bootstrap_statement_binds_exact_context() {
    let (e, _, w) = fixture().unwrap();
    let s = w.statement(&e).unwrap();
    let mut changed = e.clone();
    changed.parent[0] ^= 1;
    changed.source.request[0] ^= 1;
    changed.source.heads[0][111] ^= 1;
    changed.source.open_commitment[0] += Val::ONE;
    assert_eq!(
        statement::enrollment_fields(&e, &w),
        statement::enrollment_fields(&changed, &w)
    );
    assert_eq!(
        statement::registry_fields(&e, &w),
        statement::registry_fields(&changed, &w)
    );
    assert_ne!(
        s.public_values(),
        w.statement(&changed).unwrap().public_values()
    );
    assert!(s.require_expected(&changed).is_err());
    changed = e.clone();
    changed.source.key_commitment[0] += Val::ONE;
    assert_ne!(
        statement::enrollment_fields(&e, &w),
        statement::enrollment_fields(&changed, &w)
    );
    assert_ne!(
        statement::registry_fields(&e, &w),
        statement::registry_fields(&changed, &w)
    );
}
