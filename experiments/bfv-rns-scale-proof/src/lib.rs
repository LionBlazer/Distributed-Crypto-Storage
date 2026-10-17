//! Public-preprocessing STARK for one complete Natural PowerBasis RNS stage.
//! This independent experiment never constructs a production CheckedOperation,
//! accepts a SQL answer, routes an NTT, or proves full BFV multiplication.
#![forbid(unsafe_code)]

pub mod backend;
mod codec;
pub mod fixture;
mod proof;

pub use proof::{CheckedScaling, Generated, ProverTimings, VerifierTimings, prove, verify};

/// A new frame limit for this experiment only; the existing 2 MiB proof limit
/// and its production decoder remain unchanged.
pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;
/// Per-container length checked before the SDK Serde visitor can reserve.
pub const MAX_PROOF_SEQUENCE_ELEMENTS: usize = 4096;
/// Shared count of decoded container slots, not a whole-process memory bound.
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
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "RNS scale experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
