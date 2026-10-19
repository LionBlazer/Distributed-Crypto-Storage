//! Keyless, closed verification of historical Joint computation and Work quorums.
//! No signer, durable floor, fresh SQL grant or arbitrary Journal import exists here.

mod binding;
mod history;
mod wire;

pub use crate::CandidateBlock;
pub use binding::{JointBinding, profile_digest};
pub use history::{JointHistory, VerifiedJointParent};
pub use wire::{CANDIDATE_BYTES, JointCandidate, JointCheckpoint, MAX_CHECKPOINT_BYTES};

pub type Hash = [u8; 32];
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Encoding,
    Binding,
    Context,
    ResourceLimit,
    Poisoned,
    Joint(registry200_joint::Error),
    Journal(version_journal::Error),
    Consensus(work_finality::consensus::Error),
}
impl From<registry200_joint::Error> for Error {
    fn from(e: registry200_joint::Error) -> Self {
        Self::Joint(e)
    }
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
impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::ResourceLimit => Self::ResourceLimit,
            _ => Self::Encoding,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Joint historical checkpoint rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
