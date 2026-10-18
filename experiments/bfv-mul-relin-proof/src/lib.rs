//! Exact encrypted coefficient multiplication graph. No SQL or freshness authority.
#![forbid(unsafe_code)]
mod graph;
mod profile;
mod provenance;
mod prover;
mod verifier;
pub use bfv_mul_relin_circuit::{DEGREE, MAX_CLAIMS_BYTES, NODES};
pub use bfv_mul_relin_circuit::{GraphClaims, NodeOutput};
pub use graph::{Expected, PreparedGraph};
pub use profile::profile_digest;
pub use provenance::{InputEvidence, Provenance};
pub use prover::Prover;
pub use verifier::{CheckedProduct, Verifier};
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
impl From<bfv_mul_relin_circuit::Error> for Error {
    fn from(value: bfv_mul_relin_circuit::Error) -> Self {
        match value {
            bfv_mul_relin_circuit::Error::ResourceLimit => Self::ResourceLimit,
            bfv_mul_relin_circuit::Error::Statement => Self::Statement,
        }
    }
}
pub type Result<T> = core::result::Result<T, Error>;
#[cfg(test)]
mod tests;
