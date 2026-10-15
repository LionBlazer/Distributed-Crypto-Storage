//! Authenticated, process-independent ciphertext custody and public-only FHE service.
//! No owner FHE/AEAD secret, GUI, simulation clock or plaintext row type lives here.
#![forbid(unsafe_code)]
mod client;
mod server;
mod store;
mod wire;
pub use client::{RemotePeer, Trace};
pub use peer_transport::{Connector, Endpoint, Identity};
pub use server::{PeerServer, RunningServer};
pub use wire::{
    Bootstrap, Bundle, Neighbor, ObjectInfo, Observation, Operation, RemoteError, Request,
    Response, Status,
};
