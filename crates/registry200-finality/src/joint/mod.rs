//! Closed historical Joint verification and a distinct durable participant owner.
//! Neither path is a fresh SQL grant or accepts an arbitrary supplied Journal.

mod acquire;
mod adapter;
mod binding;
mod bootstrap;
mod control;
pub(crate) mod history;
mod wire;

pub use crate::CandidateBlock;
pub use acquire::{AcquireExpectation, VerifiedJointAcquire};
pub use adapter::{DurableJointFinality, participant_storage_profile_digest};
pub use binding::{JointBinding, durable_profile_digest, profile_digest};
pub use bootstrap::{BootstrapExpectation, JointBootstrapParent, VerifiedJointBootstrap};
pub use control::{ControlExpectation, VerifiedJointControl};
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
    /// Preserve concrete storage, I/O, corrupt-floor and poison ownership.
    Durable(crate::Error),
}
impl From<registry200_joint::Error> for Error {
    fn from(e: registry200_joint::Error) -> Self {
        Self::Joint(e)
    }
}
impl From<registry200_joint::progress::Error> for Error {
    fn from(e: registry200_joint::progress::Error) -> Self {
        use registry200_joint::progress::Error as Progress;
        match e {
            Progress::Encoding => Self::Encoding,
            Progress::Domain => Self::Binding,
            Progress::ResourceLimit => Self::ResourceLimit,
            Progress::Transition | Progress::Verification => {
                Self::Journal(version_journal::Error::RejectedComputationProof)
            }
            Progress::Journal(error) => Self::Journal(error),
            Progress::Storage(error) => Self::Joint(registry200_joint::Error::Storage(error)),
        }
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
            crate::Error::InvalidEncoding => Self::Encoding,
            other => Self::Durable(other),
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Joint checkpoint owner rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
