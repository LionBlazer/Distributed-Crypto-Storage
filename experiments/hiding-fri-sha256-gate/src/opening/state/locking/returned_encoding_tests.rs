//! Actual cache admission and query-specific lock/encoding proofs. Public fixtures.
use super::*;
use crate::opening::locking::encoding::{self as encoded, statement as es, trace::Witness as EW};
use crate::primitive::PublicStatement;
use std::cell::Cell;

#[test]
fn actual_cold_certificate_supports_nonempty_and_limit_zero_typed_return_encodings() {
    let (state, cold_witness, plain, salt) = super::super::fixture().unwrap();
    let source_proof = {
        let witness = cold_witness;
        let backend = Backend::new(&state).unwrap();
        backend
            .prove_with_trace(&state, || witness.trace(state.source()))
            .unwrap()
    };
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    cache
        .admit(
            &state,
            Candidate::new(state.clone(), Some(source_proof)).unwrap(),
        )
        .unwrap();
    let charged = cache.owned_bytes();
    let first_sql = crate::opening::locking::sql::CompiledLockPlan::compile(
        "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
        [1; 32],
    )
    .unwrap();
    let (mut first_e, mut first_w) =
        sql_fixture(&state, plain, salt, &first_sql, [0xB1; 32]).unwrap();
    first_w.old.tx[1].held[0] = 4;
    pin(&mut first_e, &first_w);
    let first = Statement::proposed(&first_e, &first_w).unwrap();
    let second_sql = crate::opening::locking::sql::CompiledLockPlan::compile(
        "SELECT age FROM records WHERE FALSE LIMIT 0 FOR SHARE NOWAIT",
        [2; 32],
    )
    .unwrap();
    let (mut second_e, mut second_w) =
        sql_fixture(&state, plain, salt, &second_sql, [0xB2; 32]).unwrap();
    second_w.old = first_w.walk().unwrap().next;
    second_w.salts[1] = first_w.salts[3];
    pin(&mut second_e, &second_w);
    let second = Statement::proposed(&second_e, &second_w).unwrap();
    assert_eq!(second_e.inner.old, first.inner.next);
    assert_ne!(first_e.inner.request(), second_e.inner.request());
    let lease = cache.lease(&state).unwrap();
    for (expected, lock, witness) in [(first_e, first, first_w), (second_e, second, second_w)] {
        let lp = lease.prove_lock(&expected, &lock, &witness).unwrap();
        let ee = es::Expected::certified(&expected, &lock).unwrap();
        let shape = es::Statement::new(ee.clone(), [Val::ZERO; 4]);
        let ew = EW::from_lock(&shape, &witness, [Val::from_u8(0x61); 4]).unwrap();
        let s = ew.returned_statement(ee.clone());
        let p = encoded::prove_with_trace(
            &ee,
            &s,
            Some(encoded::Evidence::Certified {
                lease: &lease,
                proof: &lp,
            }),
            || ew.trace_returned(&s),
        )
        .unwrap();
        encoded::verify(
            &ee,
            &s,
            Some(encoded::Evidence::Certified {
                lease: &lease,
                proof: &lp,
            }),
            &p,
        )
        .unwrap();
        assert_eq!(s.public_values()[8..124], lock.public_values());
        // A new control parent cannot replay either the warm lock or its child.
        let mut changed = expected.clone();
        changed.inner.parent[0] ^= 1;
        let new_lock = Statement::proposed(&changed, &witness).unwrap();
        let new_e = es::Expected::certified(&changed, &new_lock).unwrap();
        let new_s = ew.returned_statement(new_e.clone());
        assert!(Backend::new(&new_s).unwrap().verify(&new_s, &p).is_err());
        let calls = Cell::new(0);
        assert!(
            encoded::prove_with_trace(
                &new_e,
                &new_s,
                Some(encoded::Evidence::Certified {
                    lease: &lease,
                    proof: &lp
                }),
                || {
                    calls.set(calls.get() + 1);
                    Err(Error::Shape)
                }
            )
            .is_err()
        );
        assert_eq!(calls.get(), 0);
    }
    assert_eq!(cache.owned_bytes(), charged);
    cache.clear();
    assert!(cache.lease(&state).is_err());
}
#[test]
fn producer_contract_and_full_independent_expected_reject_before_any_encoding_factory() {
    let (state, cold_witness, plain, salt) = super::super::fixture().unwrap();
    let source_proof = Backend::new(&state)
        .unwrap()
        .prove_with_trace(&state, || cold_witness.trace(state.source()))
        .unwrap();
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    cache
        .admit(
            &state,
            Candidate::new(state.clone(), Some(source_proof)).unwrap(),
        )
        .unwrap();
    let (expected, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let lock = Statement::proposed(&expected, &witness).unwrap();
    let lease = cache.lease(&state).unwrap();
    let lp = lease.prove_lock(&expected, &lock, &witness).unwrap();
    let ee = es::Expected::certified(&expected, &lock).unwrap();
    let ew = EW::from_lock(
        &es::Statement::new(ee.clone(), [Val::ZERO; 4]),
        &witness,
        [Val::from_u8(0x61); 4],
    )
    .unwrap();
    let s = ew.returned_statement(ee.clone());
    for field in 0..6 {
        let mut changed = expected.clone();
        match field {
            0 => changed.inner.parent[0] ^= 1,
            1 => changed.inner.old[0] += Val::ONE,
            2 => changed.inner.plan[0] += Val::ONE,
            3 => {
                changed.inner.source.heads[0][8] ^= 1;
                changed.inner.source.request = super::super::version_tag(&changed.inner.source);
            }
            4 => {
                changed.inner.source.key_commitment[0] += Val::ONE;
                changed.inner.source.request = super::super::version_tag(&changed.inner.source);
            }
            _ => changed.inner.source.open_commitment[0] += Val::ONE,
        }
        // A well-shaped independently different typed parent is still foreign.
        let changed_lock = Statement::proposed(&changed, &witness).unwrap();
        let changed_e = es::Expected::certified(&changed, &changed_lock).unwrap();
        let changed_s = ew.returned_statement(changed_e.clone());
        let called = Cell::new(false);
        assert!(
            encoded::prove_with_trace(
                &changed_e,
                &changed_s,
                Some(encoded::Evidence::Certified {
                    lease: &lease,
                    proof: &lp
                }),
                || {
                    called.set(true);
                    Err(Error::Shape)
                }
            )
            .is_err()
        );
        assert!(!called.get());
    }
    let called = Cell::new(false);
    assert!(
        encoded::prove_with_trace(&ee, &s, None, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
    // A REAL canonical source+lock proof is not a StateLease witness substitute.
    let encoded::Fixture {
        expected: ce,
        source,
        lock: cw,
        encoding_expected: canonical_e,
        statement: canonical_s,
        ..
    } = encoded::fixture().unwrap();
    let (_, cp) = crate::opening::locking::prove_composite(&ce, &source, &cw).unwrap();
    let called = Cell::new(false);
    assert!(
        encoded::prove_with_trace(&ee, &s, Some(encoded::Evidence::Canonical(&cp)), || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
    let called = Cell::new(false);
    assert!(
        encoded::prove_with_trace(
            &canonical_e,
            &canonical_s,
            Some(encoded::Evidence::Certified {
                lease: &lease,
                proof: &lp
            }),
            || {
                called.set(true);
                Err(Error::Shape)
            }
        )
        .is_err()
    );
    assert!(!called.get());
}
