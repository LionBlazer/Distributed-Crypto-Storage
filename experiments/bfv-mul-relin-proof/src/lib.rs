//! Exact encrypted coefficient multiplication graph. No SQL or freshness authority.
#![forbid(unsafe_code)]
mod claims;
mod graph;
mod profile;
mod provenance;
mod prover;
mod verifier;
pub use claims::{GraphClaims, NodeOutput};
pub use graph::{Expected, PreparedGraph};
pub use profile::profile_digest;
pub use provenance::{InputEvidence, Provenance};
pub use prover::Prover;
pub use verifier::{CheckedProduct, Verifier};
pub const NODES: usize = 134;
pub const DEGREE: usize = 8192;
pub const MAX_CLAIMS_BYTES: usize = 16 * 1024 * 1024;
pub const PROOF_RECORDS: usize = 118;
pub const RECORD_HEADER: usize = 160;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ATTEMPTS: usize = 2 * (PROOF_RECORDS + 2);
pub const MAX_SESSION_BYTES: usize = provenance::MAX_INPUT_BYTES
    + MAX_CLAIMS_BYTES
    + PROOF_RECORDS * (RECORD_HEADER + MAX_PROOF_BYTES);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Statement,
    ResourceLimit,
    InputVerification,
    Incomplete,
    Stage,
    Cancelled,
    Security,
    Proof,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BFV product rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;
#[cfg(test)]
mod tests;
