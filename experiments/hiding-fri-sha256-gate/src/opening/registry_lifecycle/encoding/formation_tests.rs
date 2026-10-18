//! Genuine non-answer lifecycle proofs cannot become successful Acquire encoding inputs.
use super::super::model::{Command, Operation};
use super::*;
use p3_field::PrimeCharacteristicRing;
#[test]
fn genuine_wait_nowait_and_failed_commit_end_abort_do_not_supply_formation_encoding() {
    let f = fixture::Fixture::new(1).unwrap();
    for case in 0..3 {
        let mut old = f.parent_witness.old.clone();
        let command = if case < 2 {
            let mut c = f.parent_witness.command.clone().unwrap();
            c.offset = 0;
            c.wait = case;
            c
        } else {
            old.revision = 3;
            old.transactions[0].sequence = 2;
            old.transactions[0].failed = true;
            Command::control(Operation::End, 1, 1, 2)
        };
        let (e, w) = f
            .source
            .transition(
                old,
                command,
                f.parent.source.request,
                super::super::fixture::PARENT,
            )
            .unwrap();
        let (s, pair) = super::super::prove(&e, &f.source.source_witness, &w).unwrap();
        super::super::verify(&e, &s, &pair).unwrap();
        let compiled = CompiledQuery::compile(
            if case == 0 {
                "SELECT amount FROM records WHERE age>=128 LIMIT 1 FOR UPDATE"
            } else if case == 1 {
                "SELECT amount FROM records WHERE age>=128 LIMIT 1 FOR UPDATE NOWAIT"
            } else {
                "SELECT amount FROM records WHERE age>=128 LIMIT 1 FOR UPDATE"
            },
            [0xF6; 32],
            e.source.request,
        )
        .unwrap();
        let c = w.command.as_ref().unwrap();
        let bound = compiled.bind(
            &e,
            &s,
            CommandOpening {
                transaction: c.transaction,
                principal: c.principal,
                controller: w.controllers[0],
                revision: w.old.revision,
                sequence: c.sequence,
                salt: w.salts[3],
            },
        );
        if case == 2 {
            assert!(bound.is_err());
        } else {
            let bound = bound.unwrap();
            assert!(
                prove_with_formation_opening(&bound, &w, &pair, [Val::from_u8(36); 4]).is_err()
            );
        }
    }
}
