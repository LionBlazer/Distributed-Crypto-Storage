//! Public-Aux multilinear proofs of two complete N8192 arithmetic stages.
//! Neither stage proves NTT provenance, key authority, complete Relin, MulRelin or SQL.
#![forbid(unsafe_code)]
mod backend;
mod codec;
#[cfg(test)]
mod fixture;
mod proof;
pub use backend::{PcsSchedule, SecurityReport, Term, analyze, profile_digest, role_name};
pub use proof::{CheckedStage, Generated, ProverTimings, VerifierTimings, prove, verify};
/// Fixed primitive-proof policy; includes the fixed role-sized public Aux.
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
        write!(
            f,
            "Multilinear relinearization arithmetic rejected {self:?}"
        )
    }
}
impl std::error::Error for Error {}
#[cfg(test)]
mod sdk_tests;
#[cfg(test)]
mod tests;
