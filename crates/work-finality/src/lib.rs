//! Checked fixed-target work elections and weighted quorum signature evidence.
//!
//! The integration boundary in [`consensus`] owns bounded explicitly selected
//! single/multi-slot round/lock/POL state and a durable signer. The closed journal
//! adapter is a separate crate; this mathematical core supplies no SQL/lock grant.
//!
//! Weights cannot be nominated through a public record constructor:
//! ```compile_fail
//! let _ = work_finality::ValidatorWeight {
//!     public_key: [1; 32],
//!     work_units: u64::MAX,
//! };
//! ```
//! Cached certificate totals cannot be changed into trusted evidence:
//! ```compile_fail
//! fn forge_total(certificate: &mut work_finality::QuorumCertificate) {
//!     certificate.signed_work_units = u64::MAX;
//! }
//! ```
#![forbid(unsafe_code)]

mod config;
pub mod consensus;
mod election;
mod quorum;
mod wire;

pub use config::{Genesis, Limits, NetworkSeed};
pub use election::{Election, EpochSet, ValidatorWeight, WorkTicket};
pub use quorum::{QuorumCertificate, SignedVote, Step, VoteContext};

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, Error>;

pub const MAX_TICKETS: usize = 4096;
pub const MAX_VALIDATORS: usize = 4096;
pub const MAX_GENESIS_BYTES: usize = 1024 * 1024;
pub const MAX_CERTIFICATE_BYTES: usize = 512 * 1024;
pub const SEED_BYTES: usize = 144;
pub const TICKET_BYTES: usize = 217;
pub const VOTE_BYTES: usize = 290;
pub const CERTIFICATE_HEADER_BYTES: usize = 197;
pub const ENDORSEMENT_BYTES: usize = 96;
const GENESIS_HEADER_BYTES: usize = 8 + 32 + SEED_BYTES + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidEncoding,
    ResourceLimit,
    WrongDomain,
    InvalidKey,
    InvalidWork,
    InvalidSignature,
    DuplicateTicket,
    DuplicateSigner,
    UnknownSigner,
    MixedVotes,
    NilValue,
    NoQuorum,
    ArithmeticOverflow,
    MiningExhausted,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Pins this mathematical protocol, fixed encodings, work unit and hard limits.
/// This is not an application-proof or finality authority.
pub fn profile_digest() -> Hash {
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/profile/v1");
    h.update(b"sha256d-key-bound-fixed-target/unit-per-unique-pow/ed25519-strict");
    h.update(b"DCSWFS01/DCSWFG01/DCSWFT01/DCSWFV01/DCSWFQ01");
    h.update(b"seed144/ticket217/vote290/certificate197+96n/genesis188+217n");
    h.update(b"bootstrap-seed-then-genesis-then-set/successor-context-only");
    h.update(b"same-full-context/non-nil/unique-sorted-signers/3signed>2total");
    h.update(
        b"u32le/u64le/target-big-endian/bootstrap0/successor1/prevote1/precommit2/nil0/value1",
    );
    h.update(b"powid-sorted-tickets/publickey-sorted-weights-and-signers/strict-eof");
    h.update(b"dcs/work-finality/seed/v1/genesis/v1/ticket-pow/v1/ticket-possession/v1/ticket-set/v1/epoch-set/v1/vote/v1");
    for limit in [
        MAX_TICKETS,
        MAX_VALIDATORS,
        MAX_GENESIS_BYTES,
        MAX_CERTIFICATE_BYTES,
        SEED_BYTES,
        TICKET_BYTES,
        VOTE_BYTES,
        CERTIFICATE_HEADER_BYTES,
        ENDORSEMENT_BYTES,
        GENESIS_HEADER_BYTES,
    ] {
        h.update((limit as u64).to_le_bytes());
    }
    h.finalize().into()
}

pub(crate) fn hash(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(profile_digest());
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests;
