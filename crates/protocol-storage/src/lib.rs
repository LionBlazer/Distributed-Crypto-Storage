//! Bounded public evidence files and shared actual protocol-file accounting.
//! A content identity is never cryptographic proof or application authority.

mod budget;
mod evidence;
mod participant;

pub use budget::{ByteBudget, CustodyBudget, DepotBudget, FileCharge, FilePermit, Reservation};
pub use evidence::{BlobId, BlobReader, EvidenceStore, StagedBlob, StoreLimits};
pub use participant::{
    ControlFile, CustodyFile, MAX_PARTICIPANT_BYTES, ParticipantQuota, ParticipantUsage,
    participant_profile_digest,
};

pub const MAX_SHARED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TRACKED_FILES: usize = 4096;
pub const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    InvalidConfig,
    ResourceLimit,
    CorruptFile,
    Encoding,
    Identity,
    Poisoned,
    Io(std::io::Error),
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
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
mod participant_tests;
#[cfg(test)]
mod tests;
