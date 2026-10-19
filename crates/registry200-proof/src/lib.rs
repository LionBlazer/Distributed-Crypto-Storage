//! Bounded cryptographic Registry200 evidence. Application admission is separate.
#![forbid(unsafe_code)]
pub mod admission;
pub mod coefficient_encoding;
pub mod control_kind;
pub mod lifecycle;
pub mod predicate_acquire;
pub mod source;
pub mod wire;
pub mod write;
use bfv_hiding_stark::poseidon;
pub use bfv_hiding_stark::{Error as BackendError, Val};
mod fixed;
#[cfg(test)]
mod tests;
