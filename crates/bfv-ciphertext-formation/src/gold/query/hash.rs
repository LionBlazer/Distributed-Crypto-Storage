//! Closed SHA-suite proof of the same full fused Stmt96/mask/QueryCt relation.
//! Unit success creates no old VerifiedFormation, Word, current-head or SQL grant.
//! See `query/README.md` for ownership and independent receiving requirements.
use super::{Expected, Prepared};
use crate::gold::{Result, program::query_formation::hash_backend as backend};

pub const MAX_EVIDENCE_BYTES: usize = backend::MAX_FRAME_BYTES;

/// Distinct SHA protocol/frame identity; the original fused profile is unchanged.
pub fn profile_digest() -> [u8; 32] {
    backend::profile_digest()
}

/// Consume the original guarded QueryCt and complete statement preparation.
/// The produced bytes remain unverified until a receiving native verification.
pub fn prove(expected: &Expected, prepared: Prepared) -> Result<Vec<u8>> {
    backend::produce(expected, prepared)
}

/// Independently verify the actual SHA native argument against the full Expected.
pub fn verify(expected: &Expected, bytes: &[u8]) -> Result<()> {
    backend::receive(expected, bytes)
}

/// Reusable PUBLIC PP for one exact independently retained original query.
/// Each prove consumes new protected inputs and generates fresh private masks/salts.
pub struct Prover {
    inner: backend::ProverSetup,
}
impl Prover {
    pub fn new(expected: &Expected) -> Result<Self> {
        Ok(Self {
            inner: backend::ProverSetup::new(expected)?,
        })
    }
    pub fn expected(&self) -> &Expected {
        self.inner.expected()
    }
    pub fn prove(&self, prepared: Prepared) -> Result<Vec<u8>> {
        self.inner.produce(prepared)
    }
}

/// One locally reconstructed public receiving setup, scoped to its full query.
/// A prior proof success or failure never bypasses subsequent native verification.
pub struct Verifier {
    inner: backend::ReceivingSetup,
}
impl Verifier {
    pub fn new(expected: &Expected) -> Result<Self> {
        Ok(Self {
            inner: backend::ReceivingSetup::new(expected)?,
        })
    }
    pub fn expected(&self) -> &Expected {
        self.inner.expected()
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        self.inner.receive(bytes)
    }
}
