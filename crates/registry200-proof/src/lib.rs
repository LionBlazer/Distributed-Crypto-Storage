//! Bounded cryptographic Registry200 evidence. Application admission is separate.
#![forbid(unsafe_code)]
pub mod admission;
pub mod lifecycle;
pub mod source;
pub mod wire;
use bfv_hiding_stark::poseidon;
pub use bfv_hiding_stark::{Error as BackendError, Val};
mod fixed;
#[cfg(test)]
mod tests;
