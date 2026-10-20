//! Fixed private opening field builders. Model execution is prover-only.
use super::{
    Witness,
    model::{Command, Registry},
};
use crate::{
    BackendError as Error, Val,
    lifecycle::statement::{
        COMMAND_DOMAIN, Expected, Phase, RESULT_DOMAIN, Statement, digest, stable_prefix,
    },
    source::{commitment, statement as source},
};
use p3_field::PrimeCharacteristicRing;
use zeroize::Zeroizing;
pub fn enrollment_fields(e: &Expected, w: &Witness) -> Vec<Val> {
    enrollment_fields_opening(e, &w.table(), &w.controllers, w.salts[1])
}
/// Explicit private enrollment preimage, independent of unrelated Source DATA.
/// Reopening these fields is mathematical association, not proof verification.
pub fn enrollment_fields_opening(
    e: &Expected,
    table: &[u8; 32],
    controllers: &[[u8; 32]; 2],
    salt: [Val; 4],
) -> Vec<Val> {
    let mut out = stable_prefix(e, true);
    out.extend(source::words(table));
    out.push(Val::from_u8(2));
    for (i, c) in controllers.iter().enumerate() {
        out.push(Val::from_usize(i + 1));
        out.extend(source::words(c));
    }
    out.extend(salt);
    assert_eq!(out.len(), 64);
    out
}
fn limbs(value: u64) -> [Val; 2] {
    [
        Val::from_u32(value as u32),
        Val::from_u32((value >> 32) as u32),
    ]
}
pub fn registry_fields(e: &Expected, w: &Witness, state: &Registry, salt: [Val; 4]) -> Vec<Val> {
    let row_ids: Zeroizing<[[u8; 32]; 4]> = Zeroizing::new(core::array::from_fn(|i| {
        w.plain[2220 + 32 * i..2252 + 32 * i].try_into().unwrap()
    }));
    registry_fields_opening(e, &w.table(), &row_ids, &w.controllers, state, salt)
}
/// Complete Registry200 opening. All original IDs remain in ordinal order.
/// The existing witness writer delegates here without changing field order.
/// The caller supplies a canonical Registry, as required by the legacy writer.
pub fn registry_fields_opening(
    e: &Expected,
    table: &[u8; 32],
    row_ids: &[[u8; 32]; 4],
    controllers: &[[u8; 32]; 2],
    state: &Registry,
    salt: [Val; 4],
) -> Vec<Val> {
    let mut out = stable_prefix(e, false);
    out.extend(e.enrollment);
    out.extend(source::words(table));
    out.extend(row_ids.iter().flat_map(|id| source::words(id)));
    out.extend([Val::from_u8(2), Val::from_u8(4), Val::from_u8(2)]);
    out.extend(limbs(state.revision));
    out.extend(limbs(state.allocator));
    for t in 0..2 {
        if let Some(tx) = state.transactions.get(t) {
            out.push(Val::ONE);
            out.extend(limbs(tx.id));
            out.push(Val::from_u8(tx.principal));
            out.extend(source::words(&controllers[usize::from(tx.principal - 1)]));
            out.extend(limbs(tx.sequence));
            out.push(Val::from_bool(tx.failed));
            out.extend(source::words(&tx.snapshot));
            out.extend(tx.held.map(Val::from_u8));
            for f in 0..2 {
                if let Some(s) = tx.savepoints.get(f) {
                    out.push(Val::ONE);
                    out.extend(source::words(&s.name));
                    out.extend(s.held.map(Val::from_u8));
                } else {
                    out.extend([Val::ZERO; 13]);
                }
            }
        } else {
            out.extend([Val::ZERO; 53]);
        }
    }
    out.extend(salt);
    out.extend([Val::ZERO; 6]);
    assert_eq!(out.len(), 200);
    out
}
pub struct CommandFieldsOpening {
    pub controller: [u8; 32],
    pub revision: u64,
    pub salt: [Val; 4],
}
pub fn command_fields(e: &Expected, w: &Witness, c: &Command) -> Vec<Val> {
    command_fields_opening(
        e,
        c,
        &CommandFieldsOpening {
            controller: w.controllers[usize::from(c.principal - 1)],
            revision: w.old.revision,
            salt: w.salts[3],
        },
    )
}
pub fn command_fields_opening(
    e: &Expected,
    c: &Command,
    opening: &CommandFieldsOpening,
) -> Vec<Val> {
    let Phase::Transition { old, .. } = e.phase else {
        unreachable!()
    };
    let mut out = source::words(&COMMAND_DOMAIN)
        .chain([Val::from_u8(2)])
        .chain(e.context())
        .chain(old)
        .collect::<Vec<_>>();
    out.push(Val::from_u8(c.operation as u8));
    out.extend(limbs(c.transaction));
    out.push(Val::from_u8(c.principal));
    out.extend(source::words(&opening.controller));
    out.extend(limbs(opening.revision));
    out.extend(limbs(c.sequence));
    out.extend(source::words(&c.mask));
    out.extend([c.mode, c.wait, c.offset, c.limit, c.projection].map(Val::from_u8));
    out.extend(source::words(&c.name));
    if c.operation == super::model::Operation::Begin {
        out.extend(source::words(&e.parent));
    } else {
        out.extend([Val::ZERO; 8]);
    }
    out.push(Val::from_bool(c.abort));
    out.extend(opening.salt);
    out.push(Val::ZERO);
    assert_eq!(out.len(), 160);
    out
}
pub fn result_fields(s: &Statement, w: &Witness, step: &super::model::Step) -> Vec<Val> {
    let c = w.command.as_ref().unwrap();
    result_fields_opening(
        s,
        &ResultFieldsOpening {
            operation: c.operation,
            outcome: step.outcome,
            transaction: c.transaction,
            flags: [step.returned, step.skipped, step.visit],
            salt: w.salts[5],
        },
    )
}
/// Private preimage metadata only. Rehashing it verifies no query, proof, quorum
/// or current head. The original trace writer and owner completion share this
/// exact fixed144 encoding, with no plaintext Source/model execution required.
pub struct ResultFieldsOpening {
    pub operation: super::model::Operation,
    pub outcome: u8,
    pub transaction: u64,
    pub flags: [[bool; 4]; 3],
    pub salt: [Val; 4],
}
/// Requires a Transition statement, as does the existing result writer.
pub fn result_fields_opening(s: &Statement, opening: &ResultFieldsOpening) -> Vec<Val> {
    let e = &s.expected;
    let Phase::Transition { old, command } = e.phase else {
        unreachable!()
    };
    let mut out = source::words(&RESULT_DOMAIN)
        .chain([Val::from_u8(2)])
        .chain(e.context())
        .chain(old)
        .chain(command)
        .chain(s.next)
        .collect::<Vec<_>>();
    out.push(Val::from_u8(opening.operation as u8));
    out.push(Val::from_u8(opening.outcome));
    out.extend(limbs(opening.transaction));
    for flags in opening.flags {
        out.extend(flags.map(|b| Val::from_bool(b && opening.outcome == 0)));
    }
    out.extend(opening.salt);
    out.extend([Val::ZERO; 7]);
    assert_eq!(out.len(), 144);
    out
}
pub fn proposed(e: &Expected, w: &Witness) -> Result<Statement, Error> {
    e.require_contract()?;
    if commitment::digest(&enrollment_fields(e, w)) != e.enrollment {
        return Err(Error::Shape);
    }
    let (next, salt, step) = match e.phase {
        Phase::Bootstrap => {
            if w.command.is_some() || w.old != Registry::default() {
                return Err(Error::Shape);
            }
            (Registry::default(), w.salts[4], None)
        }
        Phase::Transition { old, command } => {
            let c = w.command.as_ref().ok_or(Error::Shape)?;
            let step = w.old.step(c, e.parent, w.ages())?;
            if digest(&registry_fields(e, w, &w.old, w.salts[2])) != old
                || digest(&command_fields(e, w, c)) != command
            {
                return Err(Error::Shape);
            }
            let salt = if step.outcome == 1 || step.outcome == 2 {
                w.salts[2]
            } else {
                w.salts[4]
            };
            (step.next.clone(), salt, Some(step))
        }
    };
    let mut s = Statement {
        expected: e.clone(),
        next: digest(&registry_fields(e, w, &next, salt)),
        result: [Val::ZERO; 4],
    };
    if let Some(step) = step {
        s.result = digest(&result_fields(&s, w, &step));
    }
    Ok(s)
}

#[cfg(test)]
#[path = "result_fields_tests.rs"]
mod result_fields_tests;

#[cfg(test)]
mod opening_fields_tests {
    use super::*;
    use crate::lifecycle::{
        circuit::model::{Savepoint, Transaction},
        statement::{ENROLL_DOMAIN, REGISTRY_DOMAIN, enrollment_profile, registry_profile},
    };

    // Literal published pre-extraction field order. Mathematical fixture only;
    // these dummy Source headers are never presented as a genuine Source proof.
    fn prefix(e: &Expected, enroll: bool) -> Vec<Val> {
        source::words(if enroll {
            &ENROLL_DOMAIN
        } else {
            &REGISTRY_DOMAIN
        })
        .chain([Val::from_u8(2)])
        .chain(source::words(&if enroll {
            enrollment_profile()
        } else {
            registry_profile()
        }))
        .chain(source::words(&e.genesis))
        .chain(source::words(&e.source.heads[0][8..40]))
        .chain(e.source.key_commitment)
        .collect()
    }
    fn old_registry(e: &Expected, w: &Witness, state: &Registry, salt: [Val; 4]) -> Vec<Val> {
        let mut v = prefix(e, false);
        v.extend(e.enrollment);
        v.extend(source::words(&w.table()));
        v.extend(source::words(&w.plain[2220..2348]));
        v.extend([2, 4, 2].map(Val::from_u8));
        let two = |n: u64| [Val::from_u32(n as u32), Val::from_u32((n >> 32) as u32)];
        v.extend(two(state.revision));
        v.extend(two(state.allocator));
        for i in 0..2 {
            if let Some(t) = state.transactions.get(i) {
                v.push(Val::ONE);
                v.extend(two(t.id));
                v.push(Val::from_u8(t.principal));
                v.extend(source::words(&w.controllers[usize::from(t.principal - 1)]));
                v.extend(two(t.sequence));
                v.push(Val::from_bool(t.failed));
                v.extend(source::words(&t.snapshot));
                v.extend(t.held.map(Val::from_u8));
                for j in 0..2 {
                    if let Some(s) = t.savepoints.get(j) {
                        v.push(Val::ONE);
                        v.extend(source::words(&s.name));
                        v.extend(s.held.map(Val::from_u8));
                    } else {
                        v.extend([Val::ZERO; 13]);
                    }
                }
            } else {
                v.extend([Val::ZERO; 53]);
            }
        }
        v.extend(salt);
        v.extend([Val::ZERO; 6]);
        v
    }
    #[test]
    fn explicit_openings_preserve_literal_enrollment_and_registry_field_order() {
        let s = crate::source::Statement {
            relation: crate::source::Relation::CanonicalIndex,
            request: [3; 32],
            heads: [[4; 112]; 2],
            packets: [vec![0; 60], vec![0; 2384]],
            key_commitment: [Val::from_u8(5); 4],
            open_commitment: [Val::ZERO; 4],
        };
        let e = Expected::transition(&s, [6; 32], [7; 32], [0; 32], [0; 32], [0; 32]).unwrap();
        let mut w = Witness {
            plain: core::array::from_fn(|i| i as u8),
            controllers: [[11; 32], [12; 32]],
            salts: [[Val::from_u8(13); 4]; 6],
            old: Registry::default(),
            command: None,
        };
        let table = w.table();
        let ids =
            core::array::from_fn(|i| w.plain[2220 + 32 * i..2252 + 32 * i].try_into().unwrap());
        let mut literal = prefix(&e, true);
        literal.extend(source::words(&table));
        literal.push(Val::from_u8(2));
        for (i, c) in w.controllers.iter().enumerate() {
            literal.push(Val::from_usize(i + 1));
            literal.extend(source::words(c));
        }
        literal.extend(w.salts[1]);
        assert_eq!(literal.len(), 64);
        assert_eq!(enrollment_fields(&e, &w), literal);
        assert_eq!(
            enrollment_fields_opening(&e, &table, &w.controllers, w.salts[1]),
            literal
        );
        let mut state = Registry {
            revision: u64::MAX - 2,
            allocator: (1u64 << 32) + 1,
            transactions: Vec::new(),
        };
        for count in 0..=2 {
            if count > 0 {
                state.transactions.push(Transaction {
                    id: (1u64 << 32) + count - 1,
                    principal: count as u8,
                    sequence: (1u64 << 40) + count,
                    failed: false,
                    snapshot: [20 + count as u8; 32],
                    held: [1; 4],
                    savepoints: vec![
                        Savepoint {
                            name: [31; 32],
                            held: [0; 4],
                        },
                        Savepoint {
                            name: [32; 32],
                            held: [1; 4],
                        },
                    ],
                });
            }
            state.require_canonical().unwrap();
            let literal = old_registry(&e, &w, &state, w.salts[4]);
            assert_eq!(literal.len(), 200);
            assert_eq!(registry_fields(&e, &w, &state, w.salts[4]), literal);
            assert_eq!(
                registry_fields_opening(&e, &table, &ids, &w.controllers, &state, w.salts[4]),
                literal
            );
            assert_eq!(
                digest(&literal),
                digest(&registry_fields(&e, &w, &state, w.salts[4]))
            );
        }
        // Final original RowID limb and controller words cannot disappear.
        let root = digest(&registry_fields(&e, &w, &state, w.salts[4]));
        w.plain[2347] ^= 1;
        assert_ne!(digest(&registry_fields(&e, &w, &state, w.salts[4])), root);
        w.plain[2347] ^= 1;
        w.controllers[1][31] ^= 1;
        assert_ne!(digest(&registry_fields(&e, &w, &state, w.salts[4])), root);
    }
}
