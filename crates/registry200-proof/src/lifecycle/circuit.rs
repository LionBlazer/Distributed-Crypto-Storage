//! Explicit caller-owned mathematical inputs and the single lifecycle trace writer.
//! Mutable claims and native model output are never verification or authorization.
pub mod commitment;
pub mod model;
mod trace;
pub use trace::{Witness, bits, inverse, subtraction, write_state};
