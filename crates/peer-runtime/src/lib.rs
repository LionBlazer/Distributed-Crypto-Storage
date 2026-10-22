//! Authenticated, process-independent ciphertext custody and public-only FHE service.
//! No owner FHE/AEAD secret, GUI, simulation clock or plaintext row type lives here.
#![forbid(unsafe_code)]
mod bootstrap;
mod bytes;
mod client;
mod delta;
pub mod evidence;
pub mod finality;
mod gold_product;
pub mod joint_participant;
mod objects;
mod pages;
pub mod participant;
mod participant_bootstrap;
mod private_product;
pub mod progress_participant;
mod proof_gate;
mod read_image;
mod server;
mod store;
mod wire;
pub mod word_participant;
pub use client::{ActivityPhase, RemotePeer, RpcActivity, Trace};
pub use delta::{
    MAX_STORE_DELTA_PAGES, MAX_STORE_DELTA_REQUEST_BYTES, MAX_STORE_DELTA_RESPONSE_BYTES,
    StoreDeltaPlan, StoreDeltaRequest,
};
pub use evidence::{
    JobVerifier, MAX_EVIDENCE_BYTES, MAX_JOB_BYTES, MAX_JOBS, MutationEvidence, MutationJob,
    MutationManifest,
};
pub use gold_product::{GoldProductReply, GoldProductRequest, MAX_GOLD_PRODUCT_RESPONSE_BYTES};
pub use pages::{
    MAX_PAGE_BATCH_ADDRESSES, MAX_PAGE_BATCH_RESPONSE_BYTES, PageAddress, PageBatch,
    PageBatchRequest, PageError, PageImage,
};
pub use peer_transport::{Connector, Endpoint, Identity, RequestControl, RequestScope};
pub use private_product::{CheckedPrivateProduct, PrivateProductRequest, RecordedPrivateProduct};
pub use proof_gate::{ProofGate, ProofPermit};
pub use read_image::{
    MAX_READ_IMAGE_PREFIX_PAGES, MAX_READ_IMAGE_RESPONSE_BYTES, ReadImage, ReadImageRequest,
};
pub use server::{PeerServer, RunningServer};
pub use wire::{
    JournalBlock, Neighbor, ObjectInfo, Observation, Operation, ProofReply, RemoteError, Request,
    Response, Status,
};

pub use bootstrap::Bootstrap;
pub use objects::{
    CheckedObject, OBJECT_PROFILE_ID, RawBundle, ReceivedVersionBytes, TargetVersion,
};
pub use participant_bootstrap::JointParticipantBootstrap;
pub use participant_bootstrap::ProgressParticipantBootstrap;
pub use participant_bootstrap::WordParticipantBootstrap;
pub use participant_bootstrap::{PARTICIPANT_BOOTSTRAP_BYTES, ParticipantBootstrap};

/// Reject incompatible participant state before a producer writes or launches.
pub fn check_workspace(directory: &std::path::Path) -> std::io::Result<()> {
    store::preflight_directory(directory)
}
