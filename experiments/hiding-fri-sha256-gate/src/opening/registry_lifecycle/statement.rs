//! Private witness/command field builders remain with the experiment producer.
use super::{
    model::{Command, Registry},
    trace::Witness,
};
use crate::backend::{Error, Val};
use crate::opening::{commitment, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;
#[cfg(test)]
pub(super) use registry200_proof::lifecycle::statement::registry_profile;
pub(super) use registry200_proof::lifecycle::statement::{
    COMMAND_DOMAIN, Expected, Phase, RESULT_DOMAIN, Statement, digest, encoded, stable_prefix,
};
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        if self.expected.is_bootstrap() {
            Kind::RegistryLifecycleBootstrap
        } else {
            Kind::RegistryLifecycle
        }
    }
    fn public_values(&self) -> Vec<Val> {
        Statement::values(self)
    }
    fn air(&self) -> PrimitiveAir {
        if self.expected.is_bootstrap() {
            PrimitiveAir::LifecycleBootstrap(Box::new(super::bootstrap::BootstrapAir::new(self)))
        } else {
            PrimitiveAir::Lifecycle(Box::new(super::air::LifecycleAir::new(self)))
        }
    }
}
pub(super) fn enrollment_fields(e: &Expected, w: &Witness) -> Vec<Val> {
    let mut out = stable_prefix(e, true);
    out.extend(source::words(&w.table()));
    out.push(Val::from_u8(2));
    for (i, c) in w.controllers.iter().enumerate() {
        out.push(Val::from_usize(i + 1));
        out.extend(source::words(c));
    }
    out.extend(w.salts[1]);
    assert_eq!(out.len(), 64);
    out
}
fn limbs(value: u64) -> [Val; 2] {
    [
        Val::from_u32(value as u32),
        Val::from_u32((value >> 32) as u32),
    ]
}
pub(super) fn registry_fields(
    e: &Expected,
    w: &Witness,
    state: &Registry,
    salt: [Val; 4],
) -> Vec<Val> {
    let mut out = stable_prefix(e, false);
    out.extend(e.enrollment);
    out.extend(source::words(&w.table()));
    out.extend(source::words(&w.plain[2220..2348]));
    out.extend([Val::from_u8(2), Val::from_u8(4), Val::from_u8(2)]);
    out.extend(limbs(state.revision));
    out.extend(limbs(state.allocator));
    for t in 0..2 {
        if let Some(tx) = state.transactions.get(t) {
            out.push(Val::ONE);
            out.extend(limbs(tx.id));
            out.push(Val::from_u8(tx.principal));
            out.extend(source::words(&w.controllers[usize::from(tx.principal - 1)]));
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
pub(super) struct CommandFieldsOpening {
    pub controller: [u8; 32],
    pub revision: u64,
    pub salt: [Val; 4],
}
pub(super) fn command_fields(e: &Expected, w: &Witness, c: &Command) -> Vec<Val> {
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
pub(super) fn command_fields_opening(
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
pub(super) fn result_fields(s: &Statement, w: &Witness, step: &super::model::Step) -> Vec<Val> {
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
pub(super) fn proposed(e: &Expected, w: &Witness) -> Result<Statement, Error> {
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
