//! Compact authenticated encrypted pages and address-based retrieval.
//!
//! The owner keeps all secret keys. A peer receives only an EncryptedSnapshot
//! and can answer page requests with Merkle membership proofs. The requester must
//! supply a commitment obtained independently of that responding peer.
//!
//! This is an observable-address experiment, not FHE, a searchable SQL index,
//! a query-completeness proof, consensus, or concealed access.
#![forbid(unsafe_code)]

mod crypto;
mod format;
mod proof;
mod snapshot;

pub use crypto::{Owner, PlainPage, SecretMask};
pub use format::{
    Commitment, Error, Layout, Limits, MANIFEST_BYTES, PAGE_OVERHEAD, Result, RowAddress,
};
pub use proof::{LookupResponse, VerifiedPage, VerifiedPagePath};
pub use snapshot::{
    AuditWorkers, EncryptedSnapshot, OwnedVerifiedSnapshotBytes, VerifiedSnapshotBytes,
};
