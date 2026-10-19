//! Durable PUBLIC bytes for the fixed input16 / output118 BFV product.
//! A catalog is an untrusted content identity. Replay performs the original
//! cryptographic checks again against independently supplied owner-local pins.
#![forbid(unsafe_code)]

mod catalog;
mod record;
mod replay;
mod storage;

pub use catalog::{CatalogClaim, CatalogId, CatalogReference, MAX_CATALOG_BYTES, profile_digest};
pub use record::{CompletedRecording, RecordedProduct, RecordingVerifier};
pub use replay::ReplayedProduct;
pub use storage::ProductStore;

#[derive(Debug)]
pub enum Error {
    Encoding,
    Association,
    Incomplete,
    Poisoned,
    ResourceLimit,
    Proof(bfv_mul_relin_proof::Error),
    Storage(protocol_storage::Error),
    Io(std::io::Error),
}
impl From<bfv_mul_relin_proof::Error> for Error {
    fn from(error: bfv_mul_relin_proof::Error) -> Self {
        Self::Proof(error)
    }
}
impl From<protocol_storage::Error> for Error {
    fn from(error: protocol_storage::Error) -> Self {
        Self::Storage(error)
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained BFV product rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
