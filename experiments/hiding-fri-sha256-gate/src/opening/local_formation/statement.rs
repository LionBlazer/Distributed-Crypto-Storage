//! Exact producer identities; no root label or ciphertext digest is an authority.
use super::{NOISE_DOMAIN, air, basis, encoding};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{Relation, selection, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

#[cfg(test)]
pub(super) use bfv_ciphertext_formation::PUBLIC_VALUES;
#[derive(Clone)]
pub(super) struct Expected {
    pub(super) source: source::Statement,
    pub(super) selection: selection::statement::Statement,
    pub(super) encoding: encoding::statement::Statement,
    pub(super) bases: [basis::statement::Statement; 5],
}
fn shaped(s: &source::Statement) -> bool {
    s.relation == Relation::CanonicalIndex && s.packets[0].len() == 60 && s.packets[1].len() == 2384
}
impl Expected {
    pub(super) fn new(
        source: source::Statement,
        selection: selection::statement::Statement,
        encoding: encoding::statement::Statement,
        bases: [basis::statement::Statement; 5],
    ) -> Result<Self, Error> {
        let value = Self {
            source,
            selection,
            encoding,
            bases,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        if !shaped(&self.source)
            || !shaped(&self.selection.source)
            || !shaped(&self.encoding.selection.source)
        {
            return Err(Error::Shape);
        }
        self.selection.require_source(&self.source)?;
        self.encoding.selection.require_source(&self.source)?;
        self.encoding.require_selection(&self.selection)?;
        let first = &self.bases[0].expected;
        if first.key().expected.descriptor.database.as_slice() != &self.source.heads[0][8..24] {
            return Err(Error::Shape);
        }
        for (i, s) in self.bases.iter().enumerate() {
            let e = &s.expected;
            if e.ciphertext().basis() != i
                || e.request() != self.selection.request()
                || e.key().public_values() != first.key().public_values()
                || e.ciphertext().bytes() != first.ciphertext().bytes()
                || e.ciphertext().parameter_bytes() != first.ciphertext().parameter_bytes()
                || e.ciphertext().b_coefficients().len() != super::N
            {
                return Err(Error::Shape);
            }
        }
        Ok(())
    }
    fn same(&self, other: &Self) -> Result<(), Error> {
        self.validate()?;
        other.validate()?;
        if self.source.public_values() != other.source.public_values()
            || self.selection.public_values() != other.selection.public_values()
            || self.encoding.public_values() != other.encoding.public_values()
        {
            return Err(Error::Shape);
        }
        for (a, b) in self.bases.iter().zip(&other.bases) {
            a.require_expected(&b.expected)?;
            if a.result != b.result {
                return Err(Error::Shape);
            }
        }
        Ok(())
    }
    pub(super) fn context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/BFV-LOCAL-FORMATION-CONTEXT/v1");
        h.update(profile_digest(Kind::BfvLocalFormation));
        for values in [
            self.source.public_values(),
            self.selection.public_values(),
            self.encoding.public_values(),
        ] {
            h.update((values.len() as u64).to_le_bytes());
            for v in values {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        for s in &self.bases {
            for v in s.public_values() {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        for bytes in [
            self.bases[0].expected.ciphertext().parameter_bytes(),
            self.bases[0].expected.ciphertext().bytes(),
        ] {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.update(b"old-Selection88/age0..4/amount4096..4100/presence512..516/raw-W8192");
        basis::statement::words(&h.finalize().into())
    }
}
#[derive(Clone)]
pub(super) struct Statement {
    pub(super) expected: Expected,
    pub(super) noise: [Val; 4],
}
impl Statement {
    pub(super) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        self.expected.same(expected)
    }
    pub(super) fn noise_context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(NOISE_DOMAIN);
        for v in self.expected.context() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        basis::statement::words(&h.finalize().into())
    }
    pub(super) fn contexts(&self) -> [[Val; 8]; 7] {
        core::array::from_fn(|s| match s {
            0..=4 => self.expected.bases[s].contexts()[1],
            5 => self.expected.encoding.context(),
            _ => self.noise_context(),
        })
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::BfvLocalFormation
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::LocalFormation(Box::new(air::LocalAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        basis::statement::words(&profile_digest(self.kind()))
            .into_iter()
            .chain(self.expected.context())
            .chain(self.expected.encoding.encoded)
            .chain(self.expected.bases.iter().flat_map(|s| s.result))
            .chain(self.noise)
            .collect()
    }
}
