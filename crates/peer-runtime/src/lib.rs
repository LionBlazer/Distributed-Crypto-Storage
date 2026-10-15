//! Authenticated, process-independent ciphertext custody and public-only FHE service.
//! No owner FHE/AEAD secret, GUI, simulation clock or plaintext row type lives here.
#![forbid(unsafe_code)]
mod client;
pub mod evidence;
mod server;
mod store;
mod wire;
pub use client::{RemotePeer, Trace};
pub use evidence::{
    JobVerifier, MAX_EVIDENCE_BYTES, MAX_JOB_BYTES, MAX_JOBS, MutationEvidence, MutationJob,
    MutationManifest,
};
pub use peer_transport::{Connector, Endpoint, Identity};
pub use server::{PeerServer, RunningServer};
pub use wire::{
    Bootstrap, Bundle, JournalBlock, Neighbor, ObjectInfo, Observation, Operation, ProofReply,
    RemoteError, Request, Response, Status,
};
