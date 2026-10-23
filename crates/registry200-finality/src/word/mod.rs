//! Closed durable voting for original Word mathematics. No SQL/current lock grant.
mod binding;
mod durable;
mod history;
#[cfg(test)]
mod tests;
pub mod transport;
pub(crate) mod verification;
mod wire;
pub use crate::CandidateBlock;
pub use crate::joint::{Error, Hash, Result};
pub use binding::{Binding, profile_digest};
pub use durable::{DurableFinality, VerifiedParent, participant_storage_profile_digest};
pub use history::{History, VerifiedOperation};
pub use wire::{CANDIDATE_BYTES, Candidate, Checkpoint, MAX_CHECKPOINT_BYTES};
/// Maximum immutable public Source proof accepted by the installed Word binding.
pub const MAX_SOURCE_CERTIFICATE_BYTES: usize =
    registry200_proof::source::version::MAX_CERTIFICATE_BYTES;
