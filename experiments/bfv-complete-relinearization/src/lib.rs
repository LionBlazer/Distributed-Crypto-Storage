//! Complete fixed public level0/0 relinearization composition. Never SQL authority.
#![forbid(unsafe_code)]
mod component;
pub mod demo;
mod error;
mod input;
mod key;
mod profile;
mod prover;
mod spool;
mod state;
mod verifier;
pub use bfv_fixed_geometry::{DEGREE, MODULI};
pub use component::Component;
pub use error::{Error, Result};
pub use input::Input;
pub use key::PreparedKey;
pub use profile::profile_digest;
pub use prover::Prover;
pub use verifier::{CheckedRelinearization, Verifier};
pub const COEFFICIENTS: usize = 5 * DEGREE;
pub const COMPONENTS: usize = 32;
pub const HEADER_BYTES: usize = 192;
pub const MAX_COMPONENT_BYTES: usize = 20 * 1024 * 1024;
/// Exact worst-cap sum: 30 NTT outputs/frames plus Embed/MAC, all old proof caps16MiB.
pub const MAX_STREAM_BYTES: usize = 541_140_544;
/// Includes invalid candidates; retries never obtain a new budget.
pub const MAX_ATTEMPTS: usize = 64;

#[cfg(test)]
mod tests;
