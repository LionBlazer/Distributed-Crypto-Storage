//! Bounded weighted Tendermint and an exclusive durable signer.
//!
//! The application verifier is a trusted integration boundary, not a remote
//! acceptance flag. The closed journal/proof adapter is a separate crate.
//! A decision here is not a `FinalizedHead`, an activated epoch, or a SQL grant.

mod codec;
mod kernel;
mod messages;
mod rules;
mod wal;

pub use messages::{Action, Decision, Input, Proposal, RoundStep, Timeout};
pub use rules::{
    ApplicationContext, ApplicationError, ApplicationVerifier, ConsensusRulesId, Context, Rules,
};
pub use wal::DurableVoter;

use crate::Error as EvidenceError;

pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SHARED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ROUND: u64 = 1_000_000;
pub const MAX_TRACKED_FILES: usize = 4096;
pub(crate) const MAX_ACTIONS: usize = 8;

#[derive(Debug)]
pub enum Error {
    Evidence(EvidenceError),
    InvalidConfig,
    InvalidEncoding,
    WrongContext,
    InvalidProposal,
    WrongProposer,
    ApplicationRejected,
    Stale,
    Equivocation,
    ResourceLimit,
    CorruptWal,
    Poisoned,
    Io(std::io::Error),
}
impl From<EvidenceError> for Error {
    fn from(value: EvidenceError) -> Self {
        Self::Evidence(value)
    }
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<protocol_storage::Error> for Error {
    fn from(value: protocol_storage::Error) -> Self {
        match value {
            protocol_storage::Error::InvalidConfig => Self::InvalidConfig,
            protocol_storage::Error::ResourceLimit => Self::ResourceLimit,
            protocol_storage::Error::Poisoned => Self::Poisoned,
            protocol_storage::Error::Io(error) => Self::Io(error),
            protocol_storage::Error::CorruptFile
            | protocol_storage::Error::Encoding
            | protocol_storage::Error::Identity => Self::CorruptWal,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
