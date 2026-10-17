//! Genuine old Local proof is never evidence for a typed successful-return formation.
use super::*;
use crate::opening::locking::formation;
use crate::primitive::PublicStatement;
#[test]
fn genuine_old_selection_local_kind_cannot_substitute_for_lock_return_formation() {
    let old = public_fixture().unwrap();
    let proof = {
        let b = Backend::new(&old.statement).unwrap();
        let p = b
            .prove_with_trace(&old.statement, || old.local.trace(&old.statement))
            .unwrap();
        b.verify(&old.statement, &p).unwrap();
        p
    };
    let new = formation::canonical_fixture(false).unwrap();
    assert_ne!(old.statement.kind(), new.f.statement.kind());
    assert!(
        Backend::new(&new.f.statement)
            .unwrap()
            .verify(&new.f.statement, &proof)
            .is_err()
    );
    let p = {
        let b = Backend::new(&new.f.statement).unwrap();
        let p = b
            .prove_with_trace(&new.f.statement, || {
                new.f.local.trace_returned(&new.f.statement)
            })
            .unwrap();
        b.verify(&new.f.statement, &p).unwrap();
        p
    };
    assert!(
        Backend::new(&old.statement)
            .unwrap()
            .verify(&old.statement, &p)
            .is_err()
    );
}
