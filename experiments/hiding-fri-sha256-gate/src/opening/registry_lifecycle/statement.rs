//! Typed independent expectations. Roots and commitments are outputs, never authority.
use super::{
    air, bootstrap,
    model::{Command, Registry},
    trace::Witness,
};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{Relation, commitment, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use sha2::{Digest, Sha256};

pub(super) const CONTEXT: usize = 100;
pub(super) const BOOTSTRAP_VALUES: usize = 104;
pub(super) const STEP_VALUES: usize = 116;
pub(super) const ENROLL_DOMAIN: [u8; 16] = *b"DCS/LFENR/N4/v2!";
pub(super) const REGISTRY_DOMAIN: [u8; 16] = *b"DCS/LFREG/N4/v2!";
pub(super) const COMMAND_DOMAIN: [u8; 16] = *b"DCS/LFCMD/N4/v2!";
pub(super) const RESULT_DOMAIN: [u8; 16] = *b"DCS/LFRES/N4/v2!";

pub(super) fn enrollment_profile() -> [u8; 32] {
    Sha256::digest(b"DCS/principal-enrollment64/v2/N4-T2/labels1-2/controller256/nonzero/owner-authorized-externally").into()
}
pub(super) fn registry_profile() -> [u8; 32] {
    Sha256::digest(b"DCS/private-lifecycle-registry200/v2/N4-T2-D2/u64-limbs/sorted-compact/present/snapshot/monotone-held/latest-name/absent-zero/allocator-no-reuse").into()
}
#[derive(Clone)]
pub(super) enum Phase {
    Bootstrap,
    Transition { old: [Val; 4], command: [Val; 4] },
}
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) source: source::Statement,
    pub(super) genesis: [u8; 32],
    pub(super) parent: [u8; 32],
    pub(super) enrollment: [Val; 4],
    pub(super) phase: Phase,
}
impl Expected {
    pub(in crate::opening) fn bootstrap(
        source: &source::Statement,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
    ) -> Result<Self, Error> {
        let out = Self {
            source: source.clone(),
            genesis,
            parent,
            enrollment: source::decode_digest(enrollment)?,
            phase: Phase::Bootstrap,
        };
        out.require_contract()?;
        Ok(out)
    }
    pub(in crate::opening) fn transition(
        source: &source::Statement,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
        old: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, Error> {
        let mut out = Self::bootstrap(source, genesis, parent, enrollment)?;
        out.phase = Phase::Transition {
            old: source::decode_digest(old)?,
            command: source::decode_digest(command)?,
        };
        Ok(out)
    }
    pub(super) fn require_contract(&self) -> Result<(), Error> {
        if self.source.relation != Relation::CanonicalIndex
            || self.source.packets[0].len() != 60
            || self.source.packets[1].len() != 2384
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn kind(&self) -> Kind {
        match self.phase {
            Phase::Bootstrap => Kind::RegistryLifecycleBootstrap,
            Phase::Transition { .. } => Kind::RegistryLifecycle,
        }
    }
    pub(super) fn context(&self) -> Vec<Val> {
        let out = source::words(&profile_digest(self.kind()))
            .chain(source::words(&self.source.request))
            .chain(self.source.heads.iter().flat_map(|h| source::words(h)))
            .chain(self.source.key_commitment)
            .chain(self.source.open_commitment)
            .chain(source::words(&self.genesis))
            .chain(source::words(&self.parent))
            .chain(self.enrollment)
            .collect::<Vec<_>>();
        assert_eq!(out.len(), CONTEXT);
        out
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(super) expected: Expected,
    pub(super) next: [Val; 4],
    pub(super) result: [Val; 4],
}
impl Statement {
    pub(in crate::opening) fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_contract()?;
        e.require_contract()?;
        let a = &self.expected.source;
        let b = &e.source;
        let phase = match (&self.expected.phase, &e.phase) {
            (Phase::Bootstrap, Phase::Bootstrap) => true,
            (
                Phase::Transition { old: a, command: b },
                Phase::Transition { old: c, command: d },
            ) => a == c && b == d,
            _ => false,
        };
        if !phase
            || a.relation != b.relation
            || a.request != b.request
            || a.heads != b.heads
            || a.packets != b.packets
            || a.key_commitment != b.key_commitment
            || a.open_commitment != b.open_commitment
            || self.expected.genesis != e.genesis
            || self.expected.parent != e.parent
            || self.expected.enrollment != e.enrollment
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        self.expected.kind()
    }
    fn public_values(&self) -> Vec<Val> {
        let mut out = self.expected.context();
        if let Phase::Transition { old, command } = self.expected.phase {
            out.extend(old);
            out.extend(command);
        }
        out.extend(self.next);
        if matches!(self.expected.phase, Phase::Transition { .. }) {
            out.extend(self.result);
        }
        out
    }
    fn air(&self) -> PrimitiveAir {
        match self.expected.phase {
            Phase::Bootstrap => {
                PrimitiveAir::LifecycleBootstrap(Box::new(bootstrap::BootstrapAir::new(self)))
            }
            Phase::Transition { .. } => {
                PrimitiveAir::Lifecycle(Box::new(air::LifecycleAir::new(self)))
            }
        }
    }
}
pub(super) fn encoded(root: [Val; 4]) -> [u8; 32] {
    crate::opening::locking::statement::encoded(root)
}
/// Only the three new fixed stream lengths. Source/enrollment keep their own fixed codec.
pub(super) fn digest(fields: &[Val]) -> [Val; 4] {
    assert!(matches!(fields.len(), 144 | 160 | 200));
    let mut state = [Val::ZERO; 12];
    let permutation = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        permutation.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
pub(super) fn stable_prefix(e: &Expected, enrollment: bool) -> Vec<Val> {
    let domain = if enrollment {
        ENROLL_DOMAIN
    } else {
        REGISTRY_DOMAIN
    };
    let profile = if enrollment {
        enrollment_profile()
    } else {
        registry_profile()
    };
    source::words(&domain)
        .chain([Val::from_u8(2)])
        .chain(source::words(&profile))
        .chain(source::words(&e.genesis))
        .chain(source::words(&e.source.heads[0][8..40]))
        .chain(e.source.key_commitment)
        .collect()
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
