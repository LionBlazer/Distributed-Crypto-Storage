//! Closed checkpoint finality for the original Registry200 and separate Joint app.
//!
//! This is a local protocol owner, not a network actor or SQL grant. Independent
//! bootstrap pins and the activated roster's <1/3 Byzantine-weight premise are
//! mandatory. No caller callback can substitute for Source/Lifecycle admission.
#![forbid(unsafe_code)]

mod adapter;
mod binding;
mod codec;
mod follower;
mod participant;
mod pins;
mod store;
mod wire;

mod closed;
pub mod joint;
pub mod progress;
mod public_timings;
pub mod word;

pub use adapter::{FinalizedHead, RegistryFinality};
pub use binding::{Binding, DESCRIPTOR_BYTES, Descriptor, profile_digest};
pub use follower::{Follower, VerifiedCheckpoint};
pub use participant::participant_storage_profile_digest;
pub use public_timings::flush_public_timings;
pub use wire::{
    CandidateBlock, Checkpoint, MAX_BLOCK_BYTES, MAX_CHECKPOINT_BYTES, export_profile_digest,
};

pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidBinding,
    InvalidEncoding,
    WrongContext,
    MissingCandidate,
    ResourceLimit,
    CorruptFloor,
    Poisoned,
    Journal(version_journal::Error),
    Consensus(work_finality::consensus::Error),
    Storage(protocol_storage::Error),
    Io(std::io::Error),
}
impl From<version_journal::Error> for Error {
    fn from(e: version_journal::Error) -> Self {
        Self::Journal(e)
    }
}
impl From<work_finality::consensus::Error> for Error {
    fn from(e: work_finality::consensus::Error) -> Self {
        Self::Consensus(e)
    }
}
impl From<protocol_storage::Error> for Error {
    fn from(e: protocol_storage::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub(crate) fn digest(domain: &[u8], fields: &[&[u8]]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    for field in fields {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field);
    }
    h.finalize().into()
}
