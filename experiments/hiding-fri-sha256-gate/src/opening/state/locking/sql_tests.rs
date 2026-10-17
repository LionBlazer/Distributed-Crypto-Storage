//! Actual compiled requests reuse an admitted source; no fresh source authority is invented.
use super::*;
use crate::opening::locking::sql::CompiledLockPlan;
use crate::primitive::PublicStatement;
use std::cell::Cell;

#[test]
fn one_actual_certificate_supports_two_compiled_sql_requests_with_distinct_control_parents() {
    let (state, source_witness, plain, state_salt) = super::super::fixture().unwrap();
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    let source_proof = {
        let backend = Backend::new(&state).unwrap();
        let proof = backend
            .prove_with_trace(&state, || source_witness.trace(state.source()))
            .unwrap();
        backend.verify(&state, &proof).unwrap();
        proof
    };
    cache
        .admit(
            &state,
            Candidate::new(state.clone(), Some(source_proof)).unwrap(),
        )
        .unwrap();
    let first_sql = CompiledLockPlan::compile(
        "SELECT amount FROM records FOR UPDATE SKIP LOCKED LIMIT 1",
        [1; 32],
    )
    .unwrap();
    let (first_expected, first_witness) =
        sql_fixture(&state, plain, state_salt, &first_sql, [0xB1; 32]).unwrap();
    let first = Statement::proposed(&first_expected, &first_witness).unwrap();
    let second_sql = CompiledLockPlan::compile(
        "SELECT amount FROM records WHERE FALSE LIMIT 0 FOR SHARE NOWAIT",
        [2; 32],
    )
    .unwrap();
    let (mut second_expected, mut second_witness) =
        sql_fixture(&state, plain, state_salt, &second_sql, [0xB2; 32]).unwrap();
    second_witness.old = first_witness.walk().unwrap().next;
    second_witness.salts[1] = first_witness.salts[3];
    pin(&mut second_expected, &second_witness);
    let second = Statement::proposed(&second_expected, &second_witness).unwrap();
    assert_eq!(second_expected.inner.old, first.inner.next);
    assert_eq!(
        first_expected.inner.source.public_values(),
        second_expected.inner.source.public_values()
    );
    assert_ne!(
        *first_expected.inner.request(),
        *second_expected.inner.request()
    );
    assert_eq!(
        first_expected.inner.source.request,
        super::super::version_tag(state.source())
    );
    let lease = cache.lease(&state).unwrap();
    let first_proof = lease
        .prove_lock(&first_expected, &first, &first_witness)
        .unwrap();
    lease
        .verify_lock(&first_expected, &first, &first_proof)
        .unwrap();
    let second_proof = lease
        .prove_lock(&second_expected, &second, &second_witness)
        .unwrap();
    lease
        .verify_lock(&second_expected, &second, &second_proof)
        .unwrap();
    assert!(second_witness.walk().unwrap().returned.iter().all(|v| !v));
    assert!(
        Backend::new(&second)
            .unwrap()
            .verify(&second, &first_proof)
            .is_err()
    );
    let calls = Cell::new(0);
    assert!(
        lease
            .prove_lock_with_trace(&second_expected, &first, || {
                calls.set(calls.get() + 1);
                Err(Error::Shape)
            })
            .is_err()
    );
    assert_eq!(calls.get(), 0);
}
