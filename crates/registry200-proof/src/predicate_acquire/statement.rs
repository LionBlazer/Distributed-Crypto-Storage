//! Sealed complete mathematical expectations. Checked metadata is not a proof receipt.
use super::{PUBLIC_VALUES, profile_digest};
use crate::{
    BackendError as Error, Val,
    admission::CanonicalSource,
    coefficient_encoding::{Role, statement::Statement as Query},
    lifecycle::statement::{Phase, Statement as Lifecycle},
    source,
};
use p3_field::PrimeField64;
use sha2::{Digest, Sha512};

#[derive(Clone)]
pub struct Expected {
    query: Query,
    lifecycle: Lifecycle,
}
impl Expected {
    pub fn new(query: &Query, lifecycle: &Lifecycle) -> Result<Self, Error> {
        if query.expected.role() != Role::PrivateMask || lifecycle.expected.is_bootstrap() {
            return Err(Error::Shape);
        }
        let checked = CanonicalSource::checked_claim(query.expected.source_claim())?;
        let old = &lifecycle.expected.source;
        let actual = CanonicalSource::checked_claim(old)?;
        if checked.claim().values() != actual.claim().values()
            || checked.claim().heads != old.heads
            || checked.claim().packets != old.packets
        {
            return Err(Error::Shape);
        }
        lifecycle.expected.require_contract()?;
        Ok(Self {
            query: query.clone(),
            lifecycle: lifecycle.clone(),
        })
    }
    pub fn query(&self) -> &Query {
        &self.query
    }
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }
    pub fn values(&self) -> Vec<Val> {
        let values: Vec<_> = source::statement::words(&profile_digest())
            .chain(self.query.values())
            .chain(self.lifecycle.values())
            .collect();
        assert_eq!(values.len(), PUBLIC_VALUES);
        values
    }
    pub fn require_same(&self, other: &Self) -> Result<(), Error> {
        self.query.require_expected(&other.query.expected)?;
        self.lifecycle.require_expected(&other.lifecycle.expected)?;
        if self.values() != other.values() {
            return Err(Error::Shape);
        }
        Ok(())
    }
    /// Complete public association only; never a substitute for proof verification.
    pub fn identity(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(b"DCS/predicate-acquire-link/full-public-identity/v1");
        for v in self.values() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        let s = self.query.expected.source_claim();
        for bytes in s
            .heads
            .iter()
            .map(|v| v.as_slice())
            .chain(s.packets.iter().map(Vec::as_slice))
        {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.finalize().into()
    }
    pub(crate) fn roots(&self) -> [Val; 12] {
        let Phase::Transition { old, command } = self.lifecycle.expected.phase else {
            unreachable!()
        };
        old.into_iter()
            .chain(command)
            .chain(self.lifecycle.next)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
