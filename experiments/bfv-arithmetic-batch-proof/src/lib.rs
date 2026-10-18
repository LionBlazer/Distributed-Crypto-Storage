//! One fixed public arithmetic union, not a DAG, MulRelin or SQL admission.
#![forbid(unsafe_code)]
pub mod backend;
mod codec;
pub mod fixture;
mod machine;
mod proof;
mod statement;
pub use proof::{CheckedBatch, Generated, prove, verify};
pub use statement::{Context, Expected, RelationOutput, RelationRequest, instance_binding};
pub const RELATIONS: usize = 17;
pub const COMPONENTS: usize = 3;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16384;
pub const MAX_DECODE_ELEMENTS: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Statement,
    Frame,
    ResourceLimit,
    Encoding,
    TrailingBytes,
    Preparation,
    Security,
    Proving,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "arithmetic batch rejected {self:?}")
    }
}
impl std::error::Error for Error {}
#[cfg(test)]
mod tests;
