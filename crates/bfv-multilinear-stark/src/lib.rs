//! Fixed public SHA512/WHIR protocol; consumers own statements, keys and proof lifecycles.
#![forbid(unsafe_code)]

mod assessment;
mod config;
mod hashes;

pub use assessment::assess;
pub use config::{
    AirSpec, COLLISION_BITS, Challenge, Challenger, Config, FOLDING, MAX_FINAL_VARIABLES,
    MAX_QUERIES, MAX_QUERY_PHASES, PHASE_BITS, POLICY_BITS, PROTOCOL_DESCRIPTOR, Pcs, PcsSchedule,
    Proof, ProtocolPlan, TableShape, Val, config_for,
};
pub use hashes::{Domains, Sha512Leaf, Sha512Node, Sha512Transcript, sha512};
pub use p3_multi_stark::MultiStarkSecurityReport;
pub use p3_multi_stark::folder::VerifierAir;

/// Configuration or assessment rejection, mapped into the consumer's own errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDomains,
    InvalidShape,
    UnsupportedAir,
    Schedule,
    Security,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "multilinear STARK rejected {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
