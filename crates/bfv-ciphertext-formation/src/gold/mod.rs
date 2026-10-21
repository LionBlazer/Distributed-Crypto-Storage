//! Fixed N4096/Q2 Formation mathematics. Source, key admission and SQL stay with callers.
pub mod data;
mod evidence;
mod expected;
mod fft;
mod geometry;
mod graph;
mod program;
pub mod query;
mod relation;
mod request;
mod setup;
#[cfg(test)]
mod tests;
mod wire;
mod witness;

pub use bfv_hiding_stark::Val;
pub use evidence::{
    MAX_EVIDENCE_BYTES, UnverifiedFormationEvidence, VerifiedFormation, prove, verify,
};
pub use expected::Expected;
pub use geometry::{N, Q, SCALE, T};
pub use request::Request;
use sha2::{Digest, Sha256};
pub use witness::{Prepared, ScaledOpening, SecretOpening};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Arithmetic,
    Binding,
    Resource,
    Security,
    Backend,
    Encoding,
    Proving,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CoreGold Formation rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Mathematical format/profile only: supplies no key, lattice, Source or SQL authority.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/CoreGold/Formation/v1/N4096/Q2/full-private-graph/no-SQL-admission");
    h.update(b"GFMRQ001;PB-unseeded-CT2x2;nonce32;allliteralbytes;Cw4112x2;Cs528-packed6;S/E+-20;K+-524287;already-scaled-W;one-S/four-products;shared-E-per-operand;H8192/MAIN512/PP272/PV36/128originalCount4;sole-terminal0;native0.8-defaultpack;GoldEF5/H8192/Q192/blowup3/salt4/random5/zero-grind");
    for v in [
        N as u64,
        Q[0],
        Q[1],
        T,
        SCALE,
        geometry::DELTA[0],
        geometry::DELTA[1],
        fft::PSI,
    ] {
        h.update(v.to_le_bytes());
    }
    h.update(program::BUS.as_bytes());
    h.finalize().into()
}
