//! Full independent parent, separate SQL identity, and the new encoding commitment.
use super::super::statement as lifecycle;
use super::{air::EncodingAir, compiler};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::statement as source;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};
pub(super) const PUBLIC_VALUES: usize = 136;
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) parent: lifecycle::Expected,
    pub(super) producer: lifecycle::Statement,
    pub(super) sql_identity: [u8; 32],
    pub(super) projection: u8,
}
impl Expected {
    pub(super) fn require_contract(&self) -> Result<(), Error> {
        self.parent.require_contract()?;
        self.producer.require_expected(&self.parent)?;
        if !matches!(self.parent.phase, lifecycle::Phase::Transition { .. })
            || !(1..=3).contains(&self.projection)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn require_same(&self, other: &Self) -> Result<(), Error> {
        compiler::require_same(self, other)
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(super) expected: Expected,
    pub(super) encoded: [Val; 4],
}
impl Statement {
    pub(super) fn new(expected: Expected, encoded: [Val; 4]) -> Self {
        Self { expected, encoded }
    }
    pub(super) fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
    pub(super) fn context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/Result144-originals-full8192W/context/v1");
        h.update(profile_digest(Kind::RegistryLifecycleEncoding));
        h.update(self.expected.sql_identity);
        for x in self.expected.producer.public_values() {
            h.update(x.as_canonical_u64().to_le_bytes());
        }
        source::words(&<[u8; 32]>::from(h.finalize()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::RegistryLifecycleEncoding
    }
    fn public_values(&self) -> Vec<Val> {
        source::words(&profile_digest(self.kind()))
            .chain(self.expected.producer.public_values())
            .chain(source::words(&self.expected.sql_identity))
            .chain(self.encoded)
            .collect()
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::LifecycleEncoding(Box::new(EncodingAir::new(self)))
    }
}
