//! Authenticated, process-independent ciphertext custody and public-only FHE service.
//! No owner FHE/AEAD secret, GUI, simulation clock or plaintext row type lives here.
#![forbid(unsafe_code)]
mod client;
pub mod evidence;
mod pages;
mod read_image;
mod server;
mod store;
mod wire;
pub use client::{ActivityPhase, RemotePeer, RpcActivity, Trace};
pub use evidence::{
    JobVerifier, MAX_EVIDENCE_BYTES, MAX_JOB_BYTES, MAX_JOBS, MutationEvidence, MutationJob,
    MutationManifest,
};
pub use pages::{
    MAX_PAGE_BATCH_ADDRESSES, MAX_PAGE_BATCH_RESPONSE_BYTES, PageAddress, PageBatch,
    PageBatchRequest, PageError, PageImage,
};
pub use peer_transport::{Connector, Endpoint, Identity, RequestControl, RequestScope};
pub use read_image::{
    MAX_READ_IMAGE_PREFIX_PAGES, MAX_READ_IMAGE_RESPONSE_BYTES, ReadImage, ReadImageRequest,
};
pub use server::{PeerServer, RunningServer};
pub use wire::{
    Bootstrap, Bundle, JournalBlock, Neighbor, ObjectInfo, Observation, Operation, ProofReply,
    RemoteError, Request, Response, Status,
};
