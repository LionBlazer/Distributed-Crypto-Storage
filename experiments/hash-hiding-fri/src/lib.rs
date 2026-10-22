//! Isolated hash-based hiding-FRI candidate over actual existing mathematical AIRs.
//! This experiment grants no live SQL, journal, freshness or security capability.
#![forbid(unsafe_code)]

mod challenger;
mod config;
mod merkle;
pub mod source;

pub use bfv_hiding_stark::{Challenge, Val};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Randomness,
    Shape,
    Encoding,
    ResourceLimit,
    Proving,
    Verification,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for Error {}
