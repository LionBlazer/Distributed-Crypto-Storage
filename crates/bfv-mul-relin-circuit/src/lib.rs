//! Fixed full-vector BFV product routing and proposed claims, never proof admission.
#![forbid(unsafe_code)]

mod bridges;
mod claims;
mod routing;

pub use bfv_fixed_geometry::DEGREE;
pub use bridges::check_ciphertext_bridges;
pub use claims::{GraphClaims, NodeMetadata, NodeOutput, node_metadata};
pub use routing::{NodeRequest, derive_request, require_header};

pub const NODES: usize = 134;
pub const MAX_CLAIMS_BYTES: usize = 16 * 1024 * 1024;
/// Fixed Extend4, Tensor10 and Down3 positions, not a proof-packet schedule.
pub const ARITHMETIC_NODES: [usize; 17] = [
    20, 21, 22, 23, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 84, 85, 86,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Statement,
    ResourceLimit,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BFV graph claims rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests;
