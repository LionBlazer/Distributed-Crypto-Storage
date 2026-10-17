//! Independently verified complete public relinearization arithmetic stages.
//! Neither checked stage is full relinearization, MulRelin or a SQL permit.
#![forbid(unsafe_code)]
pub mod backend;
mod codec;
pub mod fixture;
mod proof;
use bfv_relinearization_circuit::Role;
pub use proof::{CheckedStage, Generated, ProverTimings, VerifierTimings, prove, verify};
/// All supported container lengths are bounded before SDK allocation.
pub const MAX_PROOF_SEQUENCE_ELEMENTS: usize = 4096;
/// Stage-specific caps leave every existing production/experiment cap unchanged.
pub const fn max_proof_bytes(role: Role) -> usize {
    match role {
        Role::Embed => 8 * 1024 * 1024,
        Role::AccumulateAndAdd => 16 * 1024 * 1024,
    }
}
/// Counts nested container slots including binary Goldilocks byte arrays, not RAM.
pub const fn max_proof_decode_elements(role: Role) -> usize {
    match role {
        Role::Embed => 1024 * 1024,
        Role::AccumulateAndAdd => 2 * 1024 * 1024,
    }
}
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
        write!(f, "Relinearization stage experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}
#[cfg(test)]
mod sdk_tests;
#[cfg(test)]
mod tests;
