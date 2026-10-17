//! PUBLIC NONSECRET full-source examples, real parent proofs and rebuilt attacks.
use super::{
    statement::{Expected, Producer, Statement},
    trace::{self, Witness},
    *,
};
use crate::backend;
use crate::opening::{
    commitment,
    locking::{self, statement as locked},
    selection::encoding::{air::*, trace::bits},
};
use crate::primitive::PublicStatement;
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use std::cell::Cell;

fn case(wait: u8, limit: u8, held: bool) -> Fixture {
    let Fixture {
        expected: mut le,
        source,
        lock: mut lw,
        ..
    } = fixture().unwrap();
    lw.plan.wait = wait;
    lw.plan.limit = limit;
    let holdings = [[0; 4], [if held { 4 } else { 0 }, 0, 0, 0]];
    let native = locking::tests::native_state(&mut lw, holdings, [false; 2]);
    locking::tests::oracle(&lw, &native);
    le.old = commitment::digest(&locked::registry_fields(&le, &lw, &lw.old, lw.salts[1]));
    le.plan = commitment::digest(&locked::plan_fields(&le, &lw));
    let parent = locked::proposed(&le, &lw).unwrap();
    let e = Expected::canonical(&le, &parent).unwrap();
    let shape = Statement::new(e.clone(), [Val::ZERO; 4]);
    let ew = Witness::from_lock(&shape, &lw, [Val::from_u8(0x61); 4]).unwrap();
    let s = ew.returned_statement(e.clone());
    Fixture {
        expected: le,
        source,
        lock: lw,
        encoding_expected: e,
        statement: s,
        witness: ew,
    }
}
fn valid(s: &Statement, w: &Witness) -> RowMajorMatrix<Val> {
    Backend::new(s).unwrap(); // Actual symbolic gates precede this test's allocation.
    let t = w.trace_returned(s).unwrap();
    check_constraints(&s.air(), &t, &s.public_values());
    t
}
fn raw_rejects(s: &Statement, t: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &t, &s.public_values(), Some(1)).is_ok());
    let b = Backend::new(s).unwrap();
    if let Ok(p) = p3_uni_stark::prove(&b.config, &s.air(), t, &s.public_values()) {
        assert!(Backend::new(s).unwrap().verify(s, &p).is_err());
    }
}
fn no_factory(e: &Expected, s: &Statement, p: Option<Evidence<'_, '_>>) {
    let called = Cell::new(false);
    assert!(
        prove_with_trace(e, s, p, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
}
fn upstream(w: &Witness) -> Vec<u64> {
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext};
    use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
    use fhe_traits::FheEncoder;
    let mut slots = vec![0; 8192];
    for (i, value) in w.original().into_iter().enumerate() {
        slots[[0, 1, 2, 3, 4096, 4097, 4098, 4099, 512, 513, 514, 515][i]] = value;
    }
    let parameters = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(114689)
        .set_moduli(&[
            8796092858369,
            8796092792833,
            17592186028033,
            17592185438209,
            17592184717313,
        ])
        .set_variance(10)
        .build_arc()
        .unwrap();
    let plain = Plaintext::try_encode(&slots, Encoding::simd(), &parameters).unwrap();
    Poly::try_convert_from(
        &plain,
        parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap()
    .coefficients()
    .row(0)
    .to_vec()
}

#[test]
fn exact_return168_context_and_all8192_coefficients_preserve_originals_after_skip_and_offset() {
    let Fixture {
        lock: lw,
        encoding_expected: e,
        statement: s,
        witness: w,
        ..
    } = case(2, 1, true);
    assert_eq!(lw.walk().unwrap().returned, [false, false, false, true]);
    assert_eq!(lw.walk().unwrap().visit, [false, false, true, true]);
    assert_eq!(w.tuples[0][..4], [1, 3, 128, 255]);
    assert!(w.tuples[1..].iter().flatten().all(|v| *v == 0));
    assert_eq!(w.original(), [128, 0, 0, 0, 255, 0, 0, 0, 1, 0, 0, 0]);
    let fields = locked::output_fields(e.lock(), &lw, false).unwrap();
    assert_eq!(fields.len(), 168);
    assert_eq!(fields[114], Val::ZERO);
    assert_eq!(commitment::digest(&fields), e.lock().returned);
    assert_ne!(e.lock().returned, e.lock().owned);
    let a = s.air();
    assert_eq!(
        (a.width(), a.num_public_values(), a.num_periodic_columns()),
        (3580, 128, 215)
    );
    assert_eq!(s.public_values()[8..124], e.lock().public_values());
    assert_eq!(
        backend::AllocationEstimate::for_width(WIDTH).main_lde_bytes,
        234946560
    );
    let actual = w.coefficients();
    for ((m, scaled), expected) in actual.into_iter().zip(upstream(&w)) {
        assert_eq!(m, expected);
        assert_eq!(scaled, expected * 78307 % 114689);
    }
    let _ = valid(&s, &w);
}
#[test]
fn genuine_complete_parent_and_child_proofs_verify_nonempty_and_successful_limit_zero() {
    for limit in [0, 1] {
        let Fixture {
            expected: le,
            source,
            lock: lw,
            encoding_expected: e,
            statement: s,
            witness: w,
        } = case(2, limit, true);
        let (_, mut parent) = locking::prove_composite(&le, &source, &lw).unwrap();
        let proof = prove_with_trace(&e, &s, Some(Evidence::Canonical(&parent)), || {
            w.trace_returned(&s)
        })
        .unwrap();
        verify(&e, &s, Some(Evidence::Canonical(&parent)), &proof).unwrap();
        let source = parent.source.take();
        no_factory(&e, &s, Some(Evidence::Canonical(&parent)));
        assert!(verify(&e, &s, Some(Evidence::Canonical(&parent)), &proof).is_err());
        parent.source = source;
        verify(&e, &s, Some(Evidence::Canonical(&parent)), &proof).unwrap();
        if limit == 0 {
            assert!(w.original().iter().all(|v| *v == 0));
        }
    }
}
#[test]
fn genuine_blocked_and_nowait_parent_proofs_cannot_be_relabelled_as_empty_success() {
    for wait in [0, 1] {
        let Fixture {
            expected: le,
            source,
            lock: lw,
            encoding_expected: e,
            statement: s,
            witness: w,
        } = case(wait, 1, true);
        assert_eq!(lw.walk().unwrap().outcome, wait + 1);
        assert_eq!(e.lock().next, e.lock().expected.old);
        assert!(w.original().iter().all(|v| *v == 0));
        let (_, parent) = locking::prove_composite(&le, &source, &lw).unwrap();
        locking::verify_composite(&le, e.lock(), &parent).unwrap();
        let t = w.trace_returned(&s).unwrap();
        // A genuine blocked root has outcome1/2 at114; child fixes precisely0.
        let report = check_all_constraints(&s.air(), &t, &s.public_values(), None);
        assert!(!report.is_ok());
        assert!(report.failures.iter().all(|f| f.row == 21));
        raw_rejects(&s, t);
    }
}
#[test]
fn independently_expected_source_parent_request_and_plan_reject_before_child_factory() {
    let Fixture {
        encoding_expected: e,
        statement: s,
        ..
    } = case(2, 1, true);
    no_factory(&e, &s, None);
    for field in 0..6 {
        let mut changed = e.clone();
        let Producer::Canonical {
            expected,
            statement,
        } = &mut changed.producer
        else {
            unreachable!()
        };
        match field {
            0 => expected.parent[0] ^= 1,
            1 => expected.plan[0] += Val::ONE,
            2 => expected.old[0] += Val::ONE,
            3 => expected.source.request[0] ^= 1,
            4 => expected.source.packets[1].truncate(1),
            _ => statement.returned[0] += Val::ONE,
        }
        no_factory(&changed, &s, None);
    }
}
#[test]
fn coherent_owned_set_including_offset_rows_cannot_open_the_returned_root() {
    let Fixture {
        lock: lw,
        encoding_expected: e,
        witness: mut w,
        ..
    } = case(2, 1, true);
    let selected: Vec<_> = lw
        .walk()
        .unwrap()
        .visit
        .into_iter()
        .enumerate()
        .filter_map(|(i, v)| v.then_some(i))
        .collect();
    assert_eq!(selected, [2, 3]);
    w.tuples = [[0; 12]; 4];
    for (slot, i) in selected.into_iter().enumerate() {
        w.tuples[slot][..4].copy_from_slice(&[
            1,
            i as u32,
            u32::from(lw.plain[3 * i]),
            u32::from(u16::from_le_bytes([
                lw.plain[3 * i + 1],
                lw.plain[3 * i + 2],
            ])),
        ]);
        for (word, bytes) in lw.plain[2220 + 32 * i..2252 + 32 * i]
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
        {
            w.tuples[slot][4 + word] = u32::from_le_bytes(*bytes);
        }
    }
    let s = w.returned_statement(e.clone());
    let t = w.trace_returned(&s).unwrap();
    let report = check_all_constraints(&s.air(), &t, &s.public_values(), None);
    assert!(!report.is_ok());
    assert!(report.failures.iter().all(|f| f.row == 21));
    // Repair ONLY claimed RETURN168 contents/context: all native constraints pass.
    // This is not a genuine lock proof or an independently authorized root.
    let mut fields = locked::output_fields(e.lock(), &lw, false).unwrap();
    for (dst, tuple) in fields[119..167]
        .as_chunks_mut::<12>()
        .0
        .iter_mut()
        .zip(w.tuples)
    {
        for (dst, value) in dst.iter_mut().zip(tuple) {
            *dst = Val::from_u32(value);
        }
    }
    let mut repaired = e.clone();
    let Producer::Canonical { statement, .. } = &mut repaired.producer else {
        unreachable!()
    };
    statement.returned = commitment::digest(&fields);
    assert_ne!(statement.returned, e.lock().returned);
    let repaired_s = w.returned_statement(repaired);
    let _ = valid(&repaired_s, &w);
    raw_rejects(&s, t);
}
#[test]
fn rebuilt_wrong_original_rowid_duplicate_order_and_inactive_tail_cannot_open_return168() {
    let Fixture {
        encoding_expected: e,
        witness: honest,
        ..
    } = case(2, 2, false);
    assert_eq!(honest.tuples[0][1], 2);
    assert_eq!(honest.tuples[1][1], 3);
    for attack in 0..6 {
        let mut w = Witness {
            tuples: honest.tuples,
            selected_salt: honest.selected_salt,
            encoding_salt: honest.encoding_salt,
        };
        match attack {
            0 => w.tuples[0][2] ^= 1,
            1 => w.tuples[0][3] ^= 1,
            2 => w.tuples[0][11] ^= 1,
            3 => w.tuples[1] = w.tuples[0],
            4 => w.tuples.swap(0, 1),
            _ => w.tuples[3][3] = 1,
        }
        let s = w.returned_statement(e.clone());
        raw_rejects(&s, w.trace_returned(&s).unwrap());
    }
    let Fixture {
        lock,
        encoding_expected: e,
        witness: mut w,
        ..
    } = case(2, 1, true);
    assert!(lock.walk().unwrap().skip[0]);
    // Replace the actual returned row3 by the genuine original row0 that was
    // locked and skipped. All child coefficient/hash cells are rebuilt.
    w.tuples = [[0; 12]; 4];
    w.tuples[0][..4].copy_from_slice(&[1, 0, 255, 0]);
    for (word, bytes) in lock.plain[2220..2252].as_chunks::<4>().0.iter().enumerate() {
        w.tuples[0][4 + word] = u32::from_le_bytes(*bytes);
    }
    let s = w.returned_statement(e);
    raw_rejects(&s, w.trace_returned(&s).unwrap());
}
#[test]
fn rebuilt_last_coefficient_and_current_next_carry_cannot_replace_the_full_encoding() {
    let Fixture {
        statement: s,
        witness: w,
        ..
    } = case(2, 1, true);
    for attack in 0..2 {
        let mut t = valid(&s, &w);
        let mut changed = s.clone();
        if attack == 0 {
            let row = &mut t.values[511 * WIDTH..512 * WIDTH];
            let old = lane::<Val, _>(row, 15, 1).as_canonical_u64();
            let value = (old + 1) % 114689;
            let at = COEFF + 15 * LANE_BITS;
            bits(&mut row[at + 17..at + 34], value);
            bits(&mut row[at + 87..at + 104], 114688 - value);
        } else {
            t.values[250 * WIDTH + CARRY + 7] += Val::ONE;
        }
        changed.encoded = trace::refresh_returned(&changed, &mut t);
        // refresh recomputes all hash/carry cells; retain a genuine broken edge.
        if attack == 1 {
            t.values[250 * WIDTH + CARRY + 7] += Val::ONE;
        }
        raw_rejects(&changed, t);
    }
}
#[test]
fn fresh_sdk_verifier_rejects_foreign_return_context_and_encoding_salt() {
    let Fixture {
        encoding_expected: e,
        statement: s,
        witness: mut w,
        ..
    } = case(2, 1, true);
    let proof = Backend::new(&s)
        .unwrap()
        .prove_with_trace(&s, || w.trace_returned(&s))
        .unwrap();
    Backend::new(&s).unwrap().verify(&s, &proof).unwrap();
    w.encoding_salt[0] += Val::ONE;
    let fresh = w.returned_statement(e.clone());
    assert_ne!(fresh.encoded, s.encoded);
    assert!(
        Backend::new(&fresh)
            .unwrap()
            .verify(&fresh, &proof)
            .is_err()
    );
    for field in 0..3 {
        let mut e = e.clone();
        let Producer::Canonical {
            expected,
            statement,
        } = &mut e.producer
        else {
            unreachable!()
        };
        match field {
            0 => expected.parent[0] ^= 1,
            1 => expected.source.request[0] ^= 1,
            _ => expected.plan[0] += Val::ONE,
        };
        statement.expected = expected.clone();
        let replay = w.returned_statement(e);
        assert!(
            Backend::new(&replay)
                .unwrap()
                .verify(&replay, &proof)
                .is_err()
        );
    }
}
