//! PUBLIC NONSECRET preimage examples only, not valid Source/proof fixtures.
use super::*;
use crate::{
    lifecycle::circuit::model::{Command, Operation, Step},
    source::Relation,
};
use p3_field::PrimeField64;

// Exact pre-extraction fixed144 builder, retained as the parity oracle for this
// boundary move. Neither helper computes a query or verifies any proof.
fn original(s: &Statement, w: &Witness, step: &Step) -> Vec<Val> {
    let e = &s.expected;
    let Phase::Transition { old, command } = e.phase else {
        unreachable!()
    };
    let c = w.command.as_ref().unwrap();
    let mut out = source::words(&RESULT_DOMAIN)
        .chain([Val::from_u8(2)])
        .chain(e.context())
        .chain(old)
        .chain(command)
        .chain(s.next)
        .collect::<Vec<_>>();
    out.push(Val::from_u8(c.operation as u8));
    out.push(Val::from_u8(step.outcome));
    out.extend(limbs(c.transaction));
    for flags in [step.returned, step.skipped, step.visit] {
        out.extend(flags.map(|b| Val::from_bool(b && step.outcome == 0)));
    }
    out.extend(w.salts[5]);
    out.extend([Val::ZERO; 7]);
    assert_eq!(out.len(), 144);
    out
}

#[test]
fn result_opening_preserves_original144_for_all_opcodes_outcomes_and_u64_limbs() {
    let source = source::Statement {
        relation: Relation::CanonicalIndex,
        request: [0x32; 32],
        heads: [[0x43; 112]; 2],
        packets: [vec![0x54; 60], vec![0x65; 2384]],
        key_commitment: [Val::from_u8(7); 4],
        open_commitment: [Val::from_u8(8); 4],
    };
    let expected =
        Expected::transition(&source, [0x76; 32], [0x87; 32], [0; 32], [0; 32], [0; 32]).unwrap();
    let statement = Statement {
        expected,
        next: [Val::from_u8(9); 4],
        result: [Val::ZERO; 4],
    };
    let flags = [
        [true, false, true, false],
        [false, true, false, true],
        [true; 4],
    ];
    for operation in Operation::ALL {
        for outcome in 0..=3 {
            for transaction in [1, u32::MAX as u64, 1u64 << 32, u64::MAX] {
                let mut witness = Witness {
                    plain: [0; 2348],
                    controllers: [[1; 32]; 2],
                    salts: [[Val::ZERO; 4]; 6],
                    old: Registry::default(),
                    command: Some(Command::control(operation, transaction, 1, 1)),
                };
                witness.salts[5] = [10, 11, 12, 13].map(Val::from_u8);
                let step = Step {
                    next: Registry::default(),
                    outcome,
                    search: [false; 4],
                    attempt: [false; 4],
                    conflict: [false; 4],
                    block: [false; 4],
                    returned: flags[0],
                    skipped: flags[1],
                    visit: flags[2],
                };
                let opening = ResultFieldsOpening {
                    operation,
                    outcome,
                    transaction,
                    flags,
                    salt: witness.salts[5],
                };
                let fields = result_fields_opening(&statement, &opening);
                assert_eq!(fields, original(&statement, &witness, &step));
                assert_eq!(result_fields(&statement, &witness, &step), fields);
                assert_eq!(fields[117].as_canonical_u64(), operation as u64);
                assert_eq!(fields[118].as_canonical_u64(), outcome as u64);
                assert_eq!(
                    fields[119].as_canonical_u64(),
                    transaction & u32::MAX as u64
                );
                assert_eq!(fields[120].as_canonical_u64(), transaction >> 32);
                if outcome != 0 {
                    assert_eq!(fields[121..133], [Val::ZERO; 12]);
                }
                assert_eq!(fields[137..144], [Val::ZERO; 7]);
            }
        }
    }
}
