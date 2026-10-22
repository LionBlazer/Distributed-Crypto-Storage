//! Fixed private-witness Goldilocks hiding-FRI suite; operation admission belongs to callers.
#![forbid(unsafe_code)]
mod assessment;
pub mod classical;
pub mod codec;
mod config;
pub mod poseidon;
mod profile;
mod proof;
pub use assessment::*;
pub use config::*;
pub use profile::*;
pub use proof::*;
#[cfg(test)]
mod tests;
