//! Public nonsecret SQL plans feed genuine old source/lock proofs, never peer answers.
use super::{
    sql::CompiledLockPlan,
    tests::{native_state, oracle, rebuilt_rejects},
    *,
};
use crate::primitive::PublicStatement;
use p3_air::check_constraints;

fn pin(e: &mut Expected, w: &Witness) {
    e.old = commitment::digest(&statement::registry_fields(e, w, &w.old, w.salts[1]));
    e.plan = commitment::digest(&statement::plan_fields(e, w));
}
#[test]
fn query_identity_binds_exact_sql_and_independent_nonce_without_choosing_authority() {
    let sql = "SELECT amount FROM records WHERE age>=128 FOR UPDATE SKIP LOCKED LIMIT 1 OFFSET 1";
    let first = CompiledLockPlan::compile(sql, [1; 32]).unwrap();
    assert_eq!(
        first.request(),
        CompiledLockPlan::compile(sql, [1; 32]).unwrap().request()
    );
    assert_ne!(
        first.request(),
        CompiledLockPlan::compile(sql, [2; 32]).unwrap().request()
    );
    assert_ne!(
        first.request(),
        CompiledLockPlan::compile(&format!("{sql} "), [1; 32])
            .unwrap()
            .request()
    );
    let p = first.plan([0x31; 32], 1).unwrap();
    assert_eq!(
        (p.actor, p.mode, p.wait, p.offset, p.limit, p.projection),
        (1, 4, 2, 1, 1, 2)
    );
    assert_eq!(p.table, [0x31; 32]);
    assert_eq!(p.mask[0], 0);
    assert_eq!(&p.mask[16..], &[255; 16]);
    let (mut expected, _, _) = sql_fixture(&first).unwrap();
    expected.source.request[0] ^= 1;
    assert!(
        first
            .expected(&expected.source, [1; 32], [2; 32], [0; 32], [0; 32])
            .is_err()
    );
}
#[test]
fn bounded_adapter_rejects_oversized_windows_and_reverse_projection_instead_of_clamping() {
    for sql in [
        "SELECT * FROM records OFFSET 5 FOR UPDATE",
        "SELECT age FROM records LIMIT 5 FOR SHARE",
        "SELECT amount,age FROM records FOR UPDATE",
        "SELECT * FROM records",
        "SELECT COUNT(*) FROM records",
    ] {
        assert!(CompiledLockPlan::compile(sql, [1; 32]).is_err(), "{sql}");
    }
    let p = CompiledLockPlan::compile(
        "SELECT * FROM records OFFSET 4 LIMIT NULL FOR KEY SHARE",
        [1; 32],
    )
    .unwrap()
    .plan([3; 32], 0)
    .unwrap();
    assert_eq!((p.offset, p.limit, p.mode), (4, 4, 1));
    assert!(
        CompiledLockPlan::compile("SELECT * FROM records FOR UPDATE", [1; 32])
            .unwrap()
            .plan([3; 32], 2)
            .is_err()
    );
}
#[test]
fn actual_parsed_lock_modes_and_policies_match_the_real_transaction_state_oracle() {
    for strength in ["KEY SHARE", "SHARE", "NO KEY UPDATE", "UPDATE"] {
        for wait in ["", "NOWAIT", "SKIP LOCKED"] {
            let sql = format!(
                "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR {strength} {wait}"
            );
            let plan = CompiledLockPlan::compile(&sql, [4; 32]).unwrap();
            let (mut expected, _, mut witness) = sql_fixture(&plan).unwrap();
            let native = native_state(&mut witness, [[0; 4], [4, 0, 0, 0]], [false; 2]);
            pin(&mut expected, &witness);
            oracle(&witness, &native);
            let s = statement::proposed(&expected, &witness).unwrap();
            check_constraints(&s.air(), &witness.trace(&s).unwrap(), &s.public_values());
            let walk = witness.walk().unwrap();
            if wait == "SKIP LOCKED" {
                assert_eq!(walk.visit, [false, false, true, true]);
                assert_eq!(walk.returned, [false, false, false, true]);
                assert_eq!(
                    walk.next.tx[0].held,
                    [0, 0, witness.plan.mode, witness.plan.mode]
                );
            } else {
                assert!(walk.returned.iter().all(|v| !v));
                assert_eq!(walk.next.tx[0].held, [0; 4]);
            }
        }
    }
}
#[test]
fn genuine_parsed_skip_locked_proof_uses_complete_source_beyond_the_return_prefix() {
    let sql = CompiledLockPlan::compile(
        "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
        [5; 32],
    )
    .unwrap();
    let (mut expected, source_witness, mut witness) = sql_fixture(&sql).unwrap();
    let native = native_state(&mut witness, [[0; 4], [4, 0, 0, 0]], [false; 2]);
    pin(&mut expected, &witness);
    oracle(&witness, &native);
    let (s, proof) = prove_composite(&expected, &source_witness, &witness).unwrap();
    verify_composite(&expected, &s, &proof).unwrap();
    assert_eq!(
        witness.walk().unwrap().returned,
        [false, false, false, true]
    );
    // A coherent different request still needs its own genuine cryptographic proof.
    let mut changed = expected.clone();
    changed.parent[0] ^= 1;
    let replay = statement::proposed(&changed, &witness).unwrap();
    assert!(
        Backend::new(&replay)
            .unwrap()
            .verify(&replay, &proof.locking)
            .is_err()
    );
}
#[test]
fn a_rebuilt_prover_selected_lock_policy_cannot_replace_the_compiled_plan() {
    let sql = CompiledLockPlan::compile(
        "SELECT age FROM records LIMIT 1 FOR UPDATE SKIP LOCKED",
        [6; 32],
    )
    .unwrap();
    let (mut expected, _, mut witness) = sql_fixture(&sql).unwrap();
    let _ = native_state(&mut witness, [[0; 4], [4, 0, 0, 0]], [false; 2]);
    pin(&mut expected, &witness);
    witness.plan.wait = 1; // All walk/P2 cells are rebuilt for NOWAIT, but C_plan stays independently fixed.
    let s = statement::proposed(&expected, &witness).unwrap();
    rebuilt_rejects(&s, witness.trace(&s).unwrap());
}
