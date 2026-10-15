//! Bounded local encrypted replica storage and atomic in-memory repair batches.
//!
//! The caller supplies independently trusted current heads, authorization, discovered
//! availability and trusted fault-domain labels. This crate provides neither consensus
//! nor proof that domain labels represent independent machines/operators.
#![forbid(unsafe_code)]

mod store;

use compact_store::{Commitment, Limits};
pub use store::ReplicaStore;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidBounds,
    ResourceLimit,
    DuplicatePeer,
    UnknownPeer,
    Unavailable,
    MissingReplica,
    AlreadyPresent,
    Quota,
    InvalidTargets,
    InsufficientDomainsOrCapacity,
    NoAvailableSource(ObjectId),
    StalePlan,
    CurrentTargetsChanged,
    LastAvailableReplica,
    GenerationExhausted,
    Transport,
    Snapshot(compact_store::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<compact_store::Error> for Error {
    fn from(value: compact_store::Error) -> Self {
        Self::Snapshot(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerId(pub u64);
/// Trusted placement information, not a Sybil-resistance or independence proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailureDomainId(pub u64);
/// Caller-owned identity for one canonical encrypted image (e.g. a data or index image).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectId(pub u64);

/// Each stored record charges its eight-byte ObjectId in addition to the FULL
/// canonical image, including its manifest and per-page crypto metadata.
pub const RECORD_METADATA_BYTES: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    pub images: Limits,
    pub max_peers: usize,
    pub max_objects: usize,
    /// Aggregate canonical destination buffers in one batch. Receive/root-validation
    /// temporaries and container overhead are additional, bounded by image/cardinality
    /// limits; this is not an OS/process RAM measurement or guarantee.
    pub max_staged_bytes: usize,
}
impl Default for Bounds {
    fn default() -> Self {
        Self {
            images: Limits::default(),
            max_peers: 64,
            max_objects: 1024,
            max_staged_bytes: 64 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub id: PeerId,
    pub failure_domain: FailureDomainId,
    pub quota_bytes: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaTarget {
    pub object: ObjectId,
    /// Independently trusted CURRENT head supplied by the application, not the peer.
    pub expected: Commitment,
    /// Minimum available copies in DISTINCT declared fault domains. Never zero.
    pub copies: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerUsage {
    pub canonical_bytes: usize,
    pub record_metadata_bytes: usize,
    pub charged_bytes: usize,
    pub quota_bytes: usize,
    pub replicas: usize,
    pub available: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedCopy {
    pub object: ObjectId,
    pub destination: PeerId,
    pub canonical_bytes: usize,
    /// Stable source order; transport responses are revalidated at execution.
    pub sources: Vec<PeerId>,
}
/// Opaque, consuming plan bound to the inventory generation and exact target heads.
/// The caller must supply its still-current targets again at execution.
///
/// ```compile_fail
/// use replica_store::{RepairPlan, ReplicaStore, ReplicaTarget};
/// fn replay(store: &mut ReplicaStore, plan: RepairPlan, current: &[ReplicaTarget])
///     -> replica_store::Result<()> {
///     store.repair_local(plan, current)?;
///     store.repair_local(plan, current)?; // Consumed by the first execution.
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct RepairPlan {
    pub(crate) origin: u64,
    pub(crate) generation: u64,
    pub(crate) targets: Vec<ReplicaTarget>,
    pub(crate) copies: Vec<PlannedCopy>,
}
impl RepairPlan {
    pub fn copies(&self) -> &[PlannedCopy] {
        &self.copies
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFailure {
    Transport,
    WrongLength,
    InvalidImage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejectedSource {
    pub object: ObjectId,
    pub peer: PeerId,
    pub failure: SourceFailure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletedCopy {
    pub object: ObjectId,
    pub source: PeerId,
    pub destination: PeerId,
    pub canonical_bytes: usize,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RepairReport {
    pub copied: Vec<CompletedCopy>,
    pub rejected_sources: Vec<RejectedSource>,
}
