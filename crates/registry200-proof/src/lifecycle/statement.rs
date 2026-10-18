//! Typed independent expectations. Roots and commitments are outputs, never authority.

use super::profile_digest;
use crate::source::{Relation, statement as source};
use bfv_hiding_stark::{Error, Val};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use sha2::{Digest, Sha256};

pub const CONTEXT: usize = 100;
pub const BOOTSTRAP_VALUES: usize = 104;
pub const STEP_VALUES: usize = 116;
pub const ENROLL_DOMAIN: [u8; 16] = *b"DCS/LFENR/N4/v2!";
pub const REGISTRY_DOMAIN: [u8; 16] = *b"DCS/LFREG/N4/v2!";
pub const COMMAND_DOMAIN: [u8; 16] = *b"DCS/LFCMD/N4/v2!";
pub const RESULT_DOMAIN: [u8; 16] = *b"DCS/LFRES/N4/v2!";

pub fn enrollment_profile() -> [u8; 32] {
    Sha256::digest(b"DCS/principal-enrollment64/v2/N4-T2/labels1-2/controller256/nonzero/owner-authorized-externally").into()
}
pub fn registry_profile() -> [u8; 32] {
    Sha256::digest(b"DCS/private-lifecycle-registry200/v2/N4-T2-D2/u64-limbs/sorted-compact/present/snapshot/monotone-held/latest-name/absent-zero/allocator-no-reuse").into()
}
#[derive(Clone)]
pub enum Phase {
    Bootstrap,
    Transition { old: [Val; 4], command: [Val; 4] },
}
#[derive(Clone)]
pub struct Expected {
    pub source: source::Statement,
    pub genesis: [u8; 32],
    pub parent: [u8; 32],
    pub enrollment: [Val; 4],
    pub phase: Phase,
}
impl Expected {
    pub fn bootstrap(
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
    pub fn transition(
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
    pub fn require_contract(&self) -> Result<(), Error> {
        if self.source.relation != Relation::CanonicalIndex
            || self.source.packets[0].len() != 60
            || self.source.packets[1].len() != 2384
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn is_bootstrap(&self) -> bool {
        matches!(self.phase, Phase::Bootstrap)
    }
    pub fn context(&self) -> Vec<Val> {
        let out = source::words(&profile_digest(self.is_bootstrap()))
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
pub struct Statement {
    pub expected: Expected,
    pub next: [Val; 4],
    pub result: [Val; 4],
}
impl Statement {
    pub fn require_expected(&self, e: &Expected) -> Result<(), Error> {
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
impl Statement {
    pub fn values(&self) -> Vec<Val> {
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
}
pub fn encoded(root: [Val; 4]) -> [u8; 32] {
    source::encode_digest(root)
}
/// Only the three new fixed stream lengths. Source/enrollment keep their own fixed codec.
pub fn digest(fields: &[Val]) -> [Val; 4] {
    assert!(matches!(fields.len(), 144 | 160 | 200));
    let mut state = [Val::ZERO; 12];
    let permutation = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        permutation.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
pub fn stable_prefix(e: &Expected, enrollment: bool) -> Vec<Val> {
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
