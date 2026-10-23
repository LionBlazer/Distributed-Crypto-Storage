//! Separate fixed SHA-256 Merkle / full-prefix SHA-512 hiding-FRI candidate.
//! Low-level mathematics only; no composed-security, operation or admission grant.
#[cfg(feature = "transcript-audit")]
pub mod audit;
mod challenger;
pub mod codec;
mod config;
mod merkle;
use crate::{EXTENSION_DEGREE, LOG_BLOWUP, QUERIES, RANDOM_CODEWORDS, SALT_ELEMENTS, Val};
pub use challenger::{Challenger, DOMAIN as TRANSCRIPT_DOMAIN};
pub use config::{ChallengeMmcs, Config, Mmcs, Pcs, config};
pub use merkle::{LEAF_DOMAIN, LeafHash, NODE_DOMAIN, NodeCompress};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

/// Fixed low-level suite identity. AIR, height, role, full statement and bounded
/// wire policy must additionally be bound by each closed owning consumer.
pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/hash-hiding-FRI/suite/v1/no-live-admission\0");
    hash.update(LEAF_DOMAIN);
    hash.update(NODE_DOMAIN);
    hash.update(TRANSCRIPT_DOMAIN);
    hash.update(b"p3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c/Gold/EF5/raw32/scalar/rand0.10.3/OS-independent");
    hash.update(b"field1/cap2+count/sample3+counter/draw4+counter+retry/LE64/reject-ge-p");
    for value in [
        EXTENSION_DEGREE as u64,
        LOG_BLOWUP as u64,
        QUERIES as u64,
        RANDOM_CODEWORDS as u64,
        SALT_ELEMENTS as u64,
        32,
        0,
        0,
        1,
        0,
        Val::ORDER_U64,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}

/// Run two independent tasks in the existing native Rayon pool.
///
/// Optional transcript auditing follows the calling scope into both tasks,
/// including new challengers constructed there. This creates no proof settings,
/// verification result, worker pool or additional worker budget. Both tasks finish
/// before returning or propagating a panic, as with the underlying Rayon join.
#[inline]
pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    #[cfg(feature = "transcript-audit")]
    let (a, b) = {
        let left = audit::Context::current();
        let right = left.clone();
        (move || left.run(a), move || right.run(b))
    };
    p3_maybe_rayon::prelude::join(a, b)
}

#[cfg(test)]
mod native_r_tests;
#[cfg(test)]
mod r_deep_tests;
