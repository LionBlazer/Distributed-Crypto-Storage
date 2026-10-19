//! Sealed complete public expectations. Construction verifies metadata, not proofs.
use super::{PUBLIC_VALUES, profile_digest};
use crate::{
    BackendError as Error, Val,
    admission::{CanonicalSource, Expected as LifecycleExpected},
    lifecycle::statement::{Phase, Statement as Lifecycle},
    source,
};
use p3_field::PrimeField64;
use sha2::{Digest, Sha512};

#[derive(Clone)]
pub struct Expected {
    source: CanonicalSource,
    lifecycle: Lifecycle,
}
impl Expected {
    pub fn new(lifecycle: &Lifecycle) -> Result<Self, Error> {
        if lifecycle.expected.is_bootstrap() {
            return Err(Error::Shape);
        }
        let source = CanonicalSource::checked_claim(&lifecycle.expected.source)?;
        LifecycleExpected::checked_claim(&lifecycle.expected)?;
        Ok(Self {
            source,
            lifecycle: lifecycle.clone(),
        })
    }
    pub fn source(&self) -> &CanonicalSource {
        &self.source
    }
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }
    pub fn values(&self) -> Vec<Val> {
        let values: Vec<_> = source::statement::words(&profile_digest())
            .chain(self.source.claim().values())
            .chain(self.lifecycle.values())
            .collect();
        assert_eq!(values.len(), PUBLIC_VALUES);
        values
    }
    pub fn require_same(&self, other: &Self) -> Result<(), Error> {
        self.lifecycle.require_expected(&other.lifecycle.expected)?;
        if self.values() != other.values()
            || self.source.claim().heads != other.source.claim().heads
            || self.source.claim().packets != other.source.claim().packets
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn identity(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(b"DCS/control-kind-link/full-public-identity/v1");
        for v in self.values() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        for bytes in self
            .source
            .claim()
            .heads
            .iter()
            .map(|v| v.as_slice())
            .chain(self.source.claim().packets.iter().map(Vec::as_slice))
        {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.finalize().into()
    }
    pub(crate) fn roots(&self) -> ([Val; 4], [Val; 4]) {
        let Phase::Transition { old, command } = self.lifecycle.expected.phase else {
            unreachable!()
        };
        (old, command)
    }
}
