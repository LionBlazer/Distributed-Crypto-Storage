//! Atomic ordered NTT batch, proved as sequential complete two-instance units.
#![forbid(unsafe_code)]
pub mod backend;
mod codec;
pub mod fixture;
mod proof;
mod statement;
pub use proof::{CheckedBatch, Generated, prove, verify};
pub use statement::{Context, Expected, instance_binding};
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16384;
pub const MAX_DECODE_ELEMENTS: usize = 8 * 1024 * 1024;
/// Derived fixed-unit bound; the complete outer frame remains capped at16 MiB.
pub(crate) const MAX_COMPONENT_PROOF_BYTES: usize = 3 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Statement,
    Frame,
    Encoding,
    ResourceLimit,
    Security,
    Preparation,
    Proving,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NTT batch rejected {self:?}")
    }
}
impl std::error::Error for Error {}
#[cfg(test)]
mod tests;
