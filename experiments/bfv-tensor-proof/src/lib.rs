//! One complete public N8192 tensor stage with an independently built verification key.
//! This experiment cannot issue a CheckedOperation, MulRelin or SQL permit.
#![forbid(unsafe_code)]

pub mod backend;
mod codec;
pub mod fixture;
mod proof;

pub use proof::{CheckedTensor, Generated, ProverTimings, VerifierTimings, prove, verify};

/// Independent stage policy; existing production and NTT/RNS caps stay unchanged.
pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;
/// Checked before any SDK container visitor reserves memory.
pub const MAX_PROOF_SEQUENCE_ELEMENTS: usize = 4096;
/// Shared Serde container slots, including binary Goldilocks byte arrays.
/// A conservative fixed-profile count is below 943000; this is not a RAM bound.
pub const MAX_PROOF_DECODE_ELEMENTS: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Statement,
    Frame,
    ProofLength,
    ProofEncoding,
    ProofResourceLimit,
    TrailingProofBytes,
    SecurityProfile,
    Preprocessing,
    Proving,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Tensor experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
