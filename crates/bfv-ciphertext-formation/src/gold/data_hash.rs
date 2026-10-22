//! Closed SHA-suite proof of the same dense DATA relation and protected inputs.
//! Native verification returns mathematical unit success, never an old Formation,
//! DATA installation, Source/current-head or SQL capability. See `DATA-HASH.md`.
use super::{Expected, Prepared};
use crate::gold::{Result, program::dense_data_inventory::hash_backend as backend};

pub const MAX_EVIDENCE_BYTES: usize = backend::MAX_FRAME_BYTES;

/// Distinct SHA protocol/frame identity; existing DATA identities are unchanged.
pub fn profile_digest() -> [u8; 32] {
    backend::profile_digest()
}

/// Consume the original guarded W/key inputs. Returned bytes are unverified.
pub fn prove(expected: &Expected, prepared: Prepared) -> Result<Vec<u8>> {
    backend::produce(expected, prepared)
}

/// Bind, canonically decode and independently verify the actual SHA native proof.
pub fn verify(expected: &Expected, bytes: &[u8]) -> Result<()> {
    backend::receive(expected, bytes)
}

/// PUBLIC PP preparation scoped to one independently retained full Expected.
/// No private inputs, producer configuration or proof verdict are retained.
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
    /// Each call consumes fresh guarded inputs and uses fresh private OS entropy.
    pub fn prove(&self, prepared: Prepared) -> Result<Vec<u8>> {
        self.inner.produce(prepared)
    }
}

/// Independently reconstructed public receiving setup for one full Expected.
/// Every invocation decodes and verifies the proof; success and failure are uncached.
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
