//! Closed Registry208 finality. Historical metadata is not a SQL lock lease.
//! Every admission/reopen uses the fixed actual Progress verifier and real QC.
mod binding;
mod durable;
pub(crate) mod history;
mod operation;
mod wire;

pub use crate::CandidateBlock;
pub use crate::joint::{Error, Hash, Result};
pub use binding::{Binding, durable_profile_digest, profile_digest};
pub use durable::{DurableFinality, participant_storage_profile_digest};
pub use history::{BootstrapParent, History, VerifiedParent};
pub use operation::{OperationExpectation, VerifiedOperation};
pub use wire::{CANDIDATE_BYTES, Candidate, Checkpoint, MAX_CHECKPOINT_BYTES};

#[cfg(test)]
pub(crate) mod tests;
