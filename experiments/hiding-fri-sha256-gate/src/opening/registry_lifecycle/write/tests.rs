//! PUBLIC NONSECRET owning relations. Conditional cases are not accepted Journal histories.
use super::super::{
    journal::write_input,
    model::{Savepoint, Transaction},
    statement as lifecycle,
};
use super::{
    compiler::{ActorOpening, CompiledWrite},
    statement::{Expected, Statement},
    trace::{Witness, refresh},
    *,
};
use crate::{
    backend::{Backend, Val},
    opening::{commitment, statement as source},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use registry200_proof::{
    admission::CanonicalSource,
    write::{
        air::{self, WriteAir},
        layout::*,
        statement as fixed,
    },
};
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};
const SQL: &str = "UPDATE records SET amount = amount + 1 WHERE age >= 128";
fn conditional(sql: &str, mode: u8) -> (crate::opening::trace::Witness, Expected, Witness) {
    write_input::conditional(sql, mode).unwrap()
}
fn source_proof(e: &Expected, w: &crate::opening::trace::Witness) -> Proof<Config> {
    let b = Backend::new(e.source()).unwrap();
    let p = b
        .prove_with_trace(e.source(), || w.trace(e.source()))
        .unwrap();
    b.verify(e.source(), &p).unwrap();
    p
}
fn pin(e: &Expected, w: &Witness) -> Expected {
    let mut parent = e.parent().clone();
    let anchor = e.lifecycle_anchor().unwrap();
    parent.enrollment = source::encode_digest(commitment::digest(&lifecycle::enrollment_fields(
        &anchor, &w.opening,
    )));
    let mut anchor = anchor;
    anchor.enrollment = source::decode_digest(parent.enrollment).unwrap();
    parent.registry = source::encode_digest(lifecycle::digest(&lifecycle::registry_fields(
        &anchor,
        &w.opening,
        &w.opening.old,
        w.opening.salts[2],
    )));
    let canonical = CanonicalSource::checked_claim(e.source()).unwrap();
    let draft = Expected::checked(&canonical, parent.clone(), e.sql_identity(), [0; 32]).unwrap();
    let command = fixed::command_digest(&compiler::command_fields(&draft, &w.command));
    Expected::checked(
        &canonical,
        parent,
        e.sql_identity(),
        source::encode_digest(command),
    )
    .unwrap()
}
fn own_child(e: &Expected, w: &Witness, source: &Proof<Config>) -> Statement {
    let s = w.statement(e).unwrap();
    let p = prove_child_with_factory(e, &s, Some(source), || w.trace(&s)).unwrap();
    Backend::new(&s).unwrap().verify(&s, &p).unwrap();
    s
}
fn amounts(w: &Witness) -> [u16; 4] {
    core::array::from_fn(|i| {
        u16::from_le_bytes(w.opening.plain[3 * i + 1..3 * i + 3].try_into().unwrap())
    })
}
fn raw_claim(
    e: &Expected,
    w: &Witness,
    new: [u16; 4],
    matches: [bool; 4],
) -> (Statement, RowMajorMatrix<Val>) {
    let s = Statement {
        expected: e.clone(),
        image: fixed::image_digest(&w.image_fields(e, new)),
    };
    let trace = w.trace_with_outputs(&s, new, matches).unwrap();
    (s, trace)
}
fn rejects_actual_sdk(s: &Statement, trace: RowMajorMatrix<Val>) {
    let b = Backend::new(s).unwrap();
    let attempt = catch_unwind(AssertUnwindSafe(|| b.prove_with_trace(s, || Ok(trace))));
    if let Ok(Ok(proof)) = attempt {
        assert!(
            b.verify(s, &proof).is_err(),
            "rebuilt invalid AIR trace was accepted"
        );
    }
}
fn set_bits(trace: &mut RowMajorMatrix<Val>, at: usize, bits: usize, value: u64) {
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        super::super::trace::bits(&mut row[at..at + bits], value);
    }
}
fn set_field(trace: &mut RowMajorMatrix<Val>, at: usize, value: Val) {
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        row[at] = value;
    }
}
fn repair_image(
    mut s: Statement,
    mut trace: RowMajorMatrix<Val>,
) -> (Statement, RowMajorMatrix<Val>) {
    s.image = refresh(&s, &mut trace);
    (s, trace)
}
fn native(fields: &[Val]) -> [Val; 4] {
    let p = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        p.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}

#[test]
fn genuine_signed_history_fresh_write_bytes_preserve_registry_and_reject_same_root_stale_ancestry()
{
    let mut p = write_input::produce(SQL, [0xA1; 32]).unwrap();
    assert!(
        p.body_bytes
            .iter()
            .all(|n| *n <= version_journal::MAX_BODY_BYTES)
    );
    assert!(p.frame.len() <= frame::MAX_FRAME);
    let before = p.journal.best_validated();
    let control = p
        .application
        .control(p.journal.validated_shards(before).unwrap())
        .unwrap();
    let fresh = frame::decode_and_verify(&p.expected, &p.frame).unwrap();
    assert_eq!(fresh.values(), p.statement.values());
    assert_eq!(
        p.expected.parent().registry,
        registry200_journal::Control::decode(&p.application, control)
            .map(|c| match c {
                registry200_journal::Control::Active { registry, .. } => registry,
                _ => panic!(),
            })
            .unwrap()
    );
    // An independent native sponge covers all original identities, ages and four expected amounts.
    let suffix = crate::opening::fixture::canonical_suffix();
    let table = &suffix[..32];
    let ids = &suffix[2096..2224];
    let mut image = source::words(&fixed::IMAGE_DOMAIN)
        .chain([Val::ONE])
        .chain(p.expected.context())
        .chain(p.expected.registry())
        .chain(p.expected.command())
        .chain([Val::from_u8(4)])
        .chain(source::words(table))
        .collect::<Vec<_>>();
    for (i, (age, value)) in [(255u8, 1u16), (0, 65535), (255, 257), (128, 256)]
        .into_iter()
        .enumerate()
    {
        image.push(Val::from_usize(i));
        image.extend(source::words(&ids[32 * i..32 * (i + 1)]));
        image.extend([Val::from_u8(age), Val::from_u16(value)]);
    }
    image.extend([Val::from_u8(23); 4]);
    image.extend([Val::ZERO; 6]);
    assert_eq!(image.len(), 192);
    assert_eq!(native(&image), fresh.image);
    // Same genuine Acquire body, original parent and roots, but a different valid sibling header.
    let verifier =
        registry200_journal::RegistryVerifier::new(p.application.clone(), p.journal.genesis())
            .unwrap();
    let mut sibling = p.journal.header(before.block).unwrap().clone();
    let bytes = p.journal.body(before.block).unwrap().to_vec();
    sibling.nonce = sibling.nonce.checked_add(1).unwrap();
    sibling.mine(1024).unwrap();
    assert_ne!(sibling.id(), before.block);
    p.journal
        .import_block(sibling.clone(), &bytes, 10000, &verifier)
        .unwrap();
    let mut parent = sibling.id();
    for timestamp in [3000, 3001] {
        let mut header = p
            .journal
            .candidate(parent, &version_journal::Body::Empty, timestamp)
            .unwrap();
        header.mine(1024).unwrap();
        let bytes = version_journal::Body::Empty
            .encode(p.journal.profile())
            .unwrap();
        parent = header.id();
        p.journal
            .import_block(header, &bytes, 10000, &verifier)
            .unwrap();
    }
    assert_eq!(
        p.journal
            .resolve(version_journal::Freshness::AtLeast(before)),
        Err(version_journal::Error::Reorganized)
    );
    assert_eq!(
        p.application
            .control(
                p.journal
                    .validated_shards(p.journal.best_validated())
                    .unwrap()
            )
            .unwrap(),
        control
    );
    // Historical mathematical proof remains valid; there is no supplied freshness Boolean.
    assert!(frame::decode_and_verify(&p.expected, &p.frame).is_ok());
}
#[test]
fn exact_sql_nonce_compiler_derives_mask_delta_and_rejects_foreign_command_openings() {
    let (_, e, w) = conditional(SQL, 4);
    assert_eq!(w.command.mask[0] & 1, 0);
    assert_eq!(w.command.mask[31] & 128, 128);
    assert_eq!(w.command.delta, 1);
    for text in [
        "SELECT amount FROM records",
        "UPDATE records SET amount = amount + 65536",
        "UPDATE records SET amount = amount + 1 RETURNING amount",
    ] {
        assert!(CompiledWrite::compile(text, [0; 32]).is_err());
    }
    let canonical = CanonicalSource::checked_claim(e.source()).unwrap();
    let opening = || ActorOpening {
        transaction: w.command.transaction,
        principal: w.command.principal,
        controller: w.command.controller,
        revision: w.command.revision,
        sequence: w.command.sequence,
        salt: w.command.salt,
    };
    let original = CompiledWrite::compile(SQL, [0xE3; 32]).unwrap();
    assert_eq!(original.query(e.parent()), e.source().request);
    let (bound, _) = original
        .bind(&canonical, e.parent().clone(), opening())
        .unwrap();
    e.require_same(&bound).unwrap();
    for (sql, nonce) in [
        (SQL, [0xA2; 32]),
        (
            "UPDATE records SET amount = amount + 2 WHERE age >= 128",
            [0xE3; 32],
        ),
        (
            "UPDATE records SET amount = amount + 1 WHERE age < 128",
            [0xE3; 32],
        ),
    ] {
        let compiled = CompiledWrite::compile(sql, nonce).unwrap();
        assert_ne!(compiled.query(e.parent()), e.source().request);
        assert!(
            compiled
                .bind(&canonical, e.parent().clone(), opening())
                .is_err()
        );
    }
    let mut foreign_parent = e.parent().clone();
    foreign_parent.block[31] ^= 1;
    assert!(
        original
            .bind(&canonical, foreign_parent, opening())
            .is_err()
    );
}
#[test]
fn mode_three_and_four_write_every_selected_original_with_compatible_other_keyshare() {
    let (source, e, w) = conditional(SQL, 4);
    let proof = source_proof(&e, &source);
    let s = own_child(&e, &w, &proof);
    assert_eq!(
        w.outputs().unwrap(),
        ([1, 65535, 257, 256], [true, false, true, true])
    );
    // Byte carries and final-row boundary use a separately encrypted genuine Source.
    let data = [255, 255, 0, 0, 255, 255, 255, 255, 15, 128, 254, 255];
    let (other_source, other_e, other_w) =
        write_input::conditional_data(SQL, 4, Some(data)).unwrap();
    let other_proof = source_proof(&other_e, &other_source);
    assert_eq!(other_w.outputs().unwrap().0, [256, 65535, 4096, 65535]);
    let _ = own_child(&other_e, &other_w, &other_proof);
    drop(other_proof);
    let mut w = w.clone();
    w.opening.old.revision = 5;
    w.opening.old.allocator = 2;
    w.command.revision = 5;
    w.opening.old.transactions[0].held = [3; 4];
    w.opening.old.transactions.push(Transaction {
        id: 2,
        principal: 2,
        sequence: 1,
        failed: false,
        snapshot: [9; 32],
        held: [1; 4],
        savepoints: vec![],
    });
    let e = pin(&e, &w);
    let other = own_child(&e, &w, &proof);
    assert_ne!(s.image, other.image);
}
#[test]
fn weak_other_actor_or_last_row_missing_lock_rejects_even_when_delta_is_zero() {
    let (source, e, w) = conditional(SQL, 4);
    let proof = source_proof(&e, &source);
    let _ = own_child(&e, &w, &proof);
    for case in 0..5 {
        let mut bad = w.clone();
        match case {
            0 => bad.opening.old.transactions[0].held = [1; 4],
            1 => bad.opening.old.transactions[0].held = [2; 4],
            2 => bad.opening.old.transactions[0].held[3] = 0,
            3 => {
                bad.command.delta = 0;
                bad.opening.old.transactions[0].held[3] = 0;
            }
            _ => {
                bad.opening.old.revision = 5;
                bad.command.revision = 5;
                bad.opening.old.allocator = 2;
                bad.opening.old.transactions[0].held = [0; 4];
                bad.opening.old.transactions.push(Transaction {
                    id: 2,
                    principal: 2,
                    sequence: 1,
                    failed: false,
                    snapshot: [9; 32],
                    held: [4; 4],
                    savepoints: vec![],
                });
            }
        }
        let expected = pin(&e, &bad);
        assert!(bad.statement(&expected).is_err());
        let mut new = amounts(&bad);
        for i in [0, 2, 3] {
            new[i] = new[i].wrapping_add(bad.command.delta);
        }
        let (s, trace) = raw_claim(&expected, &bad, new, [true, false, true, true]);
        rejects_actual_sdk(&s, trace);
    }
}
#[test]
fn empty_and_zero_delta_are_positive_but_one_selected_overflow_rejects_globally() {
    let (source, e, w) = conditional(SQL, 4);
    let proof = source_proof(&e, &source);
    let mut empty = w.clone();
    empty.command.mask = [0; 32];
    empty.opening.old.transactions[0].held = [0; 4];
    let empty_e = pin(&e, &empty);
    assert_eq!(empty.outputs().unwrap(), ([0, 65535, 256, 255], [false; 4]));
    let _ = own_child(&empty_e, &empty, &proof);
    let mut zero = w.clone();
    zero.command.delta = 0;
    let zero_e = pin(&e, &zero);
    assert_eq!(zero.outputs().unwrap().0, [0, 65535, 256, 255]);
    let _ = own_child(&zero_e, &zero, &proof);
    let mut all = w.clone();
    all.command.mask = [255; 32];
    all.command.delta = 0;
    let all_e = pin(&e, &all);
    let _ = own_child(&all_e, &all, &proof);
    all.command.delta = 1;
    let all_e = pin(&e, &all);
    assert!(all.statement(&all_e).is_err());
    let (s, trace) = raw_claim(&all_e, &all, [1, 0, 257, 256], [true; 4]);
    rejects_actual_sdk(&s, trace);
}
#[test]
fn full_u64_actor_and_counter_successors_bind_high_limbs_failed_state_and_controller() {
    let (source, e, w) = conditional(SQL, 4);
    let proof = source_proof(&e, &source);
    let mut high = w.clone();
    let id = (1u64 << 32) + 17;
    high.opening.old.transactions[0].id = id;
    high.command.transaction = id;
    high.opening.old.allocator = id;
    high.opening.old.revision = id + 3;
    high.command.revision = id + 3;
    high.opening.old.transactions[0].sequence = (1u64 << 32) + 29;
    high.command.sequence = (1u64 << 32) + 29;
    let expected = pin(&e, &high);
    let _ = own_child(&expected, &high, &proof);
    for case in 0..6 {
        let mut bad = high.clone();
        match case {
            0 => bad.command.transaction ^= 1u64 << 32,
            1 => bad.command.revision ^= 1u64 << 32,
            2 => bad.command.sequence ^= 1u64 << 32,
            3 => {
                bad.command.principal = 2;
                bad.command.controller = bad.opening.controllers[1];
            }
            4 => bad.command.controller[31] ^= 1,
            _ => {
                bad.opening.old.transactions[0].failed = true;
                bad.opening.old.transactions[0].savepoints.push(Savepoint {
                    name: [7; 32],
                    held: [4; 4],
                });
            }
        }
        let expected = pin(&e, &bad);
        assert!(bad.statement(&expected).is_err());
        let (s, trace) = raw_claim(
            &expected,
            &bad,
            [1, 65535, 257, 256],
            [true, false, true, true],
        );
        rejects_actual_sdk(&s, trace);
    }
    for counter in 0..2 {
        let mut bad = high.clone();
        if counter == 0 {
            bad.opening.old.revision = u64::MAX;
            bad.command.revision = u64::MAX;
        } else {
            bad.opening.old.transactions[0].sequence = u64::MAX;
            bad.command.sequence = u64::MAX;
        }
        let expected = pin(&e, &bad);
        let (s, trace) = raw_claim(
            &expected,
            &bad,
            [1, 65535, 257, 256],
            [true, false, true, true],
        );
        rejects_actual_sdk(&s, trace);
    }
}
#[test]
fn coherently_rehashed_raw_traces_cannot_omit_rows_or_change_unselected_identity_or_carries() {
    let (source, e, w) = conditional(SQL, 4);
    let proof = source_proof(&e, &source);
    let s = own_child(&e, &w, &proof);
    for case in 0..9 {
        let mut trace = w.trace(&s).unwrap();
        match case {
            0 => {
                set_field(&mut trace, MATCHES + 3, Val::ZERO);
                set_bits(&mut trace, NEW_AMOUNTS + 48, 16, 255);
            }
            1 => set_bits(&mut trace, NEW_AMOUNTS + 16, 16, 65534),
            2 => set_bits(&mut trace, DATA, 8, 254),
            3 => {
                let value = trace.values[TABLE + 7] + Val::ONE;
                set_field(&mut trace, TABLE + 7, value);
            }
            4 => {
                let value = trace.values[IDS + 31] + Val::ONE;
                set_field(&mut trace, IDS + 31, value);
            }
            5 => set_bits(&mut trace, NEW_AMOUNTS + 48, 16, 257),
            6 => set_field(&mut trace, NEXT_REV + 63, Val::TWO),
            7 => set_field(&mut trace, CARRY, Val::ONE),
            _ => {
                trace.values[84 * WIDTH + WORDS + 7 * 32] = Val::ONE;
            }
        }
        let (s, trace) = repair_image(s.clone(), trace);
        rejects_actual_sdk(&s, trace);
    }
    // A coherently rehashed nonzero final Image192 padding field still contradicts the fixed AIR.
    let mut trace = w.trace(&s).unwrap();
    let air = WriteAir::new(&s);
    let mut checkpoint = [Val::ZERO; 12];
    let mut image = [Val::ZERO; 4];
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
            for (i, v) in input[..8].iter_mut().enumerate() {
                *v = air.field(row, stream, 8 * block + i, i);
            }
            if !air::reset(r) {
                input[8..].copy_from_slice(&checkpoint[8..]);
            }
            if r == 161 {
                input[7] = Val::ONE;
            }
        }
        let output = crate::opening::poseidon::write(&mut row[..CP], input);
        if air::absorb(r).is_some() {
            checkpoint = output;
        }
        if r == 161 {
            image = output[..4].try_into().unwrap();
        }
    }
    let forged = Statement { expected: e, image };
    rejects_actual_sdk(&forged, trace);
}
#[test]
fn fresh_image_salt_is_valid_but_source_enrollment_registry_and_command_salt_substitution_is_not() {
    let (source, e, w) = conditional(SQL, 4);
    let proof = source_proof(&e, &source);
    let s = own_child(&e, &w, &proof);
    let mut fresh = w.clone();
    fresh.image_salt[3] += Val::ONE;
    let other = own_child(&e, &fresh, &proof);
    assert_ne!(s.image, other.image);
    for at in [SALTS + 3, SALTS + 7, SALTS + 11, SALTS + 15] {
        let mut trace = w.trace(&s).unwrap();
        let value = trace.values[at] + Val::ONE;
        set_field(&mut trace, at, value);
        let (s, trace) = repair_image(s.clone(), trace);
        rejects_actual_sdk(&s, trace);
    }
}
#[test]
fn full_independent_context_and_genuine_foreign_source_reject_before_the_child_factory() {
    let (source, e, w) = conditional(SQL, 4);
    let (s, p) = prove(&e, &source, &w).unwrap();
    let bytes = frame::encode(&e, &s, &p).unwrap();
    let called = Cell::new(0);
    assert!(
        prove_child_with_factory(&e, &s, None, || {
            called.set(called.get() + 1);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert_eq!(called.get(), 0);
    for case in 0..9 {
        let mut parent = e.parent().clone();
        let mut sql = e.sql_identity();
        let mut command = source::encode_digest(e.command());
        let mut source = e.source().clone();
        match case {
            0 => parent.genesis[31] ^= 1,
            1 => parent.application[31] ^= 1,
            2 => parent.block[31] ^= 1,
            3 => parent.enrollment[0] ^= 1,
            4 => parent.registry[0] ^= 1,
            5 => sql[31] ^= 1,
            6 => command[0] ^= 1,
            7 => source.request[31] ^= 1,
            _ => source.packets[1][2383] ^= 1,
        }
        match CanonicalSource::checked_claim(&source) {
            Ok(canonical) => {
                let foreign = Expected::checked(&canonical, parent, sql, command).unwrap();
                assert!(frame::decode_and_verify(&foreign, &bytes).is_err());
                assert!(
                    prove_child_with_factory(&foreign, &s, Some(&p.source), || {
                        called.set(called.get() + 1);
                        Err(Error::Shape)
                    })
                    .is_err()
                );
            }
            Err(_) => assert_eq!(case, 8),
        }
        assert_eq!(called.get(), 0);
    }
    let (foreign_source, foreign, fw) =
        conditional("UPDATE records SET amount = amount + 2 WHERE age >= 128", 4);
    let (fs, fp) = prove(&foreign, &foreign_source, &fw).unwrap();
    let fbytes = frame::encode(&foreign, &fs, &fp).unwrap();
    assert!(frame::decode_and_verify(&foreign, &fbytes).is_ok());
    assert!(frame::decode_and_verify(&e, &fbytes).is_err());
    assert!(
        prove_child_with_factory(&e, &s, Some(&fp.source), || {
            called.set(called.get() + 1);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert_eq!(called.get(), 0);
}
#[test]
fn distinct_pair_frame_caps_canonical_roots_and_real_nested_damage_fail_closed() {
    let (source, e, w) = conditional(SQL, 4);
    let (s, mut p) = prove(&e, &source, &w).unwrap();
    let bytes = frame::encode(&e, &s, &p).unwrap();
    assert!(frame::decode_and_verify(&e, &bytes).is_ok());
    for at in [0, 8, 15, 47, 79, 80, 84, 119] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(frame::decode_and_verify(&e, &bad).is_err());
    }
    let mut alias = bytes.clone();
    alias[88..96].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
    assert!(frame::Frame::parse(&alias).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(frame::Frame::parse(&trailing).is_err());
    assert!(frame::Frame::parse(&bytes[..119]).is_err());
    assert!(matches!(
        frame::Frame::parse(&vec![0; frame::MAX_FRAME + 1]),
        Err(frame::Error::ResourceLimit)
    ));
    for at in [80, 84] {
        let mut bomb = bytes.clone();
        bomb[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            frame::Frame::parse(&bomb),
            Err(frame::Error::ResourceLimit)
        ));
    }
    p.child.ood_pow_witness += Val::ONE;
    assert!(frame::encode(&e, &s, &p).is_err());
    let parsed = frame::Frame::parse(&bytes).unwrap();
    let mut child = parsed.child.to_vec();
    child[0] ^= 1;
    let rebuilt = frame::join(parsed.image, parsed.source, &child).unwrap();
    assert!(frame::decode_and_verify(&e, &rebuilt).is_err());
    let raw = postcard::to_allocvec(&p.child).unwrap();
    let prefix = postcard::to_allocvec(&p.child.commitments).unwrap().len();
    let mut bomb = raw[..prefix].to_vec();
    bomb.extend([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
    let rebuilt = frame::join(parsed.image, parsed.source, &bomb).unwrap();
    assert!(matches!(
        frame::decode_and_verify(&e, &rebuilt),
        Err(frame::Error::ResourceLimit)
    ));
    let mut bad = p.child;
    bad.ood_pow_witness = Val::ZERO;
    bad.opened_values.trace_next = None;
    let hostile = postcard::to_allocvec(&bad).unwrap();
    let rebuilt = frame::join(parsed.image, parsed.source, &hostile).unwrap();
    assert!(frame::decode_and_verify(&e, &rebuilt).is_err());
    assert_eq!(registry200_proof::write::layout::WIDTH, 4216);
    assert_eq!(fixed::PUBLIC_VALUES, 128);
    assert!(
        s.image
            .iter()
            .all(|v| v.as_canonical_u64() < 0xffff_ffff_0000_0001)
    );
}
