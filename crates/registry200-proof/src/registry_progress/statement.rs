//! Independent public bootstrap inputs. A constructor is not verification.
use crate::{
    BackendError as Error, Val, admission::CanonicalSource, lifecycle::statement as life, source,
};
use p3_field::PrimeField64;
use sha2::{Digest, Sha512};

#[derive(Clone)]
pub struct BootstrapExpected {
    pub(crate) source: CanonicalSource,
    pub(crate) genesis: [u8; 32],
    pub(crate) parent: [u8; 32],
    pub(crate) enrollment: [Val; 4],
}
impl BootstrapExpected {
    pub fn new(
        source: &CanonicalSource,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            source: CanonicalSource::checked_claim(source.claim())?,
            genesis,
            parent,
            enrollment: source::statement::decode_digest(enrollment)?,
        })
    }
    pub fn source(&self) -> &source::Statement {
        self.source.claim()
    }
    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }
    pub fn parent(&self) -> [u8; 32] {
        self.parent
    }
    pub fn enrollment(&self) -> [Val; 4] {
        self.enrollment
    }
    pub(crate) fn legacy(&self) -> life::Expected {
        life::Expected::bootstrap(
            self.source(),
            self.genesis,
            self.parent,
            source::statement::encode_digest(self.enrollment),
        )
        .unwrap()
    }
    pub(crate) fn context(&self) -> Vec<Val> {
        let mut values = self.legacy().context();
        for (a, b) in values[..8]
            .iter_mut()
            .zip(source::statement::words(&super::bootstrap_profile_digest()))
        {
            *a = b;
        }
        values
    }
    pub(crate) fn require_same(&self, other: &Self) -> Result<(), Error> {
        CanonicalSource::checked_claim(self.source())?;
        CanonicalSource::checked_claim(other.source())?;
        if self.context() != other.context()
            || self.source().values() != other.source().values()
            || self.source().heads != other.source().heads
            || self.source().packets != other.source().packets
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct BootstrapStatement {
    pub(crate) expected: BootstrapExpected,
    pub(crate) next: [Val; 4],
}
impl BootstrapStatement {
    pub fn from_claim(expected: &BootstrapExpected, next: [u8; 32]) -> Result<Self, Error> {
        expected.require_same(expected)?;
        Ok(Self {
            expected: expected.clone(),
            next: source::statement::decode_digest(next)?,
        })
    }
    pub fn expected(&self) -> &BootstrapExpected {
        &self.expected
    }
    pub fn next(&self) -> [u8; 32] {
        source::statement::encode_digest(self.next)
    }
    pub fn values(&self) -> Vec<Val> {
        let out: Vec<_> = source::statement::words(&super::bootstrap_profile_digest())
            .chain(self.expected.source().values())
            .chain(self.expected.context())
            .chain(self.next)
            .collect();
        assert_eq!(out.len(), super::BOOTSTRAP_VALUES);
        out
    }
    pub fn require_expected(&self, expected: &BootstrapExpected) -> Result<(), Error> {
        self.expected.require_same(expected)
    }
    pub fn identity(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(b"DCS/registry-statement-progress/bootstrap/public-claim/v1");
        for v in self.values() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        for b in self
            .expected
            .source()
            .heads
            .iter()
            .map(|b| b.as_slice())
            .chain(self.expected.source().packets.iter().map(Vec::as_slice))
        {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
        h.finalize().into()
    }
}
