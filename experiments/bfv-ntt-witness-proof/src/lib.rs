//! Full N8192 public NTT through a main-witness multilinear STARK.
//! A checked marker attests one arithmetic relation, never SQL or full MulRelin.
#![forbid(unsafe_code)]
pub mod backend;
mod codec;
pub mod fixture;
mod hashes;
mod proof;
pub use proof::{CheckedNtt, Generated, ProverTimings, VerifierTimings, prove, verify};

/// Independent new-profile policy; no existing proof consumer's limits change.
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROOF_SEQUENCE_ELEMENTS: usize = 16384;
pub const MAX_PROOF_DECODE_ELEMENTS: usize = 8 * 1024 * 1024;
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
        write!(f, "NTT witness experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}
#[cfg(test)]
mod tests;
