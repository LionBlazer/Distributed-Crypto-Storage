//! Independently supplied canonical source and enrollment anchor.
use super::{air, trace::Witness};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{Relation, commitment, locking::statement as registry, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;

pub(super) const PUBLIC_VALUES: usize = 104;
pub(super) const ENROLLMENT: usize = 96;
pub(super) const REGISTRY: usize = 100;
pub(super) const ENROLLMENT_DOMAIN: [u8; 16] = *b"DCS/LKENR/N4/v1!";

/// The caller must obtain this exact enrollment root from its owner-authorized
/// post-genesis request. This experiment does not implement that authorization.
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) source: source::Statement,
    pub(super) genesis: [u8; 32],
    pub(super) parent: [u8; 32],
    pub(super) enrollment: [Val; 4],
}
impl Expected {
    pub(in crate::opening) fn checked(
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
        };
        out.require_contract()?;
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
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(super) expected: Expected,
    pub(super) registry: [Val; 4],
}
impl Statement {
    /// Public output only; this accessor confers no owner authority or freshness.
    pub(in crate::opening) fn registry_root(&self) -> [u8; 32] {
        registry::encoded(self.registry)
    }
    pub(in crate::opening) fn checked(
        expected: &Expected,
        registry: [u8; 32],
    ) -> Result<Self, Error> {
        expected.require_contract()?;
        Ok(Self {
            expected: expected.clone(),
            registry: source::decode_digest(registry)?,
        })
    }
    pub(in crate::opening) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        self.expected.require_contract()?;
        expected.require_contract()?;
        let a = &self.expected.source;
        let b = &expected.source;
        if a.relation != b.relation
            || a.request != b.request
            || a.heads != b.heads
            || a.packets != b.packets
            || a.key_commitment != b.key_commitment
            || a.open_commitment != b.open_commitment
            || self.expected.genesis != expected.genesis
            || self.expected.parent != expected.parent
            || self.expected.enrollment != expected.enrollment
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::RegistryBootstrap
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::RegistryBootstrap(Box::new(air::BootstrapAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        source::words(&profile_digest(self.kind()))
            .chain(source::words(&self.expected.source.request))
            .chain(
                self.expected
                    .source
                    .heads
                    .iter()
                    .flat_map(|h| source::words(h)),
            )
            .chain(self.expected.source.key_commitment)
            .chain(self.expected.source.open_commitment)
            .chain(source::words(&self.expected.genesis))
            .chain(source::words(&self.expected.parent))
            .chain(self.expected.enrollment)
            .chain(self.registry)
            .collect()
    }
}
pub(super) fn stable_prefix(expected: &Expected, enrollment: bool) -> Vec<Val> {
    let (domain, profile) = if enrollment {
        (ENROLLMENT_DOMAIN, profile_digest(Kind::RegistryBootstrap))
    } else {
        (registry::REGISTRY_DOMAIN, registry::registry_profile())
    };
    source::words(&domain)
        .chain([Val::ONE])
        .chain(source::words(&profile))
        .chain(source::words(&expected.genesis))
        .chain(source::words(&expected.source.heads[0][8..40]))
        .chain(expected.source.key_commitment)
        .collect()
}
pub(super) fn enrollment_fields(expected: &Expected, witness: &Witness) -> Vec<Val> {
    let mut out = stable_prefix(expected, true);
    out.extend(source::words(&witness.table()));
    out.push(Val::from_u8(2));
    for (t, controller) in witness.controllers.iter().enumerate() {
        out.push(Val::from_usize(t + 1));
        out.extend(source::words(controller));
    }
    out.extend(witness.salts[1]);
    assert_eq!(out.len(), 64);
    out
}
pub(super) fn registry_fields(expected: &Expected, witness: &Witness) -> Vec<Val> {
    registry::registry_fields_opening(
        &registry::RegistryScope {
            genesis: &expected.genesis,
            source: &expected.source,
            table: &witness.table(),
            row_ids: witness.plain[2220..2348].try_into().unwrap(),
        },
        &witness.registry(),
        witness.salts[2],
    )
}
pub(super) fn proposed(expected: &Expected, witness: &Witness) -> Result<Statement, Error> {
    expected.require_contract()?;
    Statement::checked(
        expected,
        registry::encoded(commitment::digest(&registry_fields(expected, witness))),
    )
}
