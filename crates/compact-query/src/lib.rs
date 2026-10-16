//! Compact authenticated storage composed with genuine selective FHE evaluation.
//! Owner-assisted index selection and writeback are explicit experimental policy.
//! Historical experiment outputs are unverified; explicit proved BFV methods check
//! genuine arithmetic evidence and complete authenticated input selection.
#![forbid(unsafe_code)]
#[cfg(feature = "bfv-experiment")]
pub mod bfv;
#[cfg(feature = "bfv-experiment")]
pub mod byte_select;
#[cfg(feature = "tfhe-backend")]
mod evaluator;
mod identity;
mod index;
mod read;
pub use identity::{RowId, RowIds, RowReference, RowReferences, TableId};
#[cfg(feature = "bfv-experiment")]
pub use read::ReadView;
pub use read::{PageSource, ReadHeads, ReadRequirements};
#[cfg(feature = "tfhe-backend")]
mod owner;
mod storage;
#[cfg(feature = "tfhe-backend")]
mod wire;

use compact_store::{Commitment, EncryptedSnapshot};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tfhe-backend")]
use tfhe::{ClientKey, ServerKey};

#[cfg(feature = "tfhe-backend")]
pub use wire::{PreparedQuery, UnverifiedOutput};
/// Hard materialization limit, checked before owner mask encryption.
pub const MAX_ROWS: usize = 256;
pub const MAX_TABLE_ROWS: usize = 1_000_000;
pub const ROW_BYTES: u32 = 3;
pub const SCHEMA: [u8; 16] = *b"CQAGEAMOUNT00001";
const INDEX_SCHEMA: [u8; 16] = *b"CQAGEINDEX000003";
const INDEX_HEADER_BYTES: usize = compact_store::MANIFEST_BYTES + 32 + (256 + 257) * 4;
#[cfg(feature = "tfhe-backend")]
const MAX_WIRE_BYTES: u64 = 128 * 1024 * 1024;
const _: () = assert!((MAX_ROWS as u64) * (u16::MAX as u64) <= u32::MAX as u64);

/// Decodes the fixed private-index format using its byte geometry and exact data-row count.
/// The returned head still requires independently trusted provenance and owner authentication.
pub fn decode_index_head(bytes: &[u8], data_rows: u64) -> Result<Commitment> {
    index::decode_head(bytes, data_rows)
}

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Storage(compact_store::Error),
    InvalidRange,
    InvalidSchema,
    InvalidIndex,
    DuplicateAddress,
    SelectionBudget {
        selected: usize,
        budget: usize,
    },
    InvalidInsertSize {
        existing: u64,
        incoming: usize,
        maximum: usize,
    },
    WrongVersion,
    WrongDomain,
    WrongQuery,
    InvalidOutput,
    ComputationProof(String),
    WorkerBudget {
        requested: usize,
        maximum: usize,
    },
    WireLimit,
    Codec(String),
    Randomness,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<compact_store::Error> for Error {
    fn from(error: compact_store::Error) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainRow {
    pub age: u8,
    pub amount: u16,
}
impl zeroize::Zeroize for PlainRow {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.age);
        zeroize::Zeroize::zeroize(&mut self.amount);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeRange {
    pub lower: u8,
    pub upper: u8,
}
impl AgeRange {
    pub fn equal(age: u8) -> Self {
        Self {
            lower: age,
            upper: age,
        }
    }
    pub(crate) fn contains(self, age: u8) -> bool {
        age >= self.lower && age <= self.upper
    }
    fn validate(self) -> Result<()> {
        if self.lower > self.upper {
            Err(Error::InvalidRange)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Complete owner-built age postings; reveals candidate count and addresses.
    IndexedAgeRange(AgeRange),
    /// Every row is converted and evaluated. An insufficient budget is an error.
    FullScan,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    CountSum,
    AddAmount(u16),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aggregate {
    pub count: u32,
    pub sum: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedUpdate {
    pub rejected: bool,
    pub changed_rows: usize,
}

/// Secret keys stay solely here; one owner/evaluator pair may serve many tables.
/// No key export, serialization or Clone API is provided.
#[cfg(feature = "tfhe-backend")]
pub struct Owner {
    store: compact_store::Owner,
    key: ClientKey,
    domain: [u8; 16],
}
/// Peer role: evaluation material only. No plaintext decryption capability.
#[cfg(feature = "tfhe-backend")]
#[derive(Clone)]
pub struct Evaluator {
    server_key: ServerKey,
    domain: [u8; 16],
    row_workers: usize,
}
/// Owner-issued trusted handle. Canonical peer data remains EncryptedSnapshot.
/// The age index contains encrypted counts and padded delta-varint postings, with an exact
/// encrypted table-head binding. Only AddAmount is supported, so age order is stable.
pub struct Table {
    table_id: TableId,
    data: EncryptedSnapshot,
    index: EncryptedSnapshot,
}
impl Table {
    /// Copies only encrypted images and trusted heads for local transactional staging.
    /// The caller must select which resulting head becomes authoritative.
    pub fn fork_for_experiment(&self) -> Self {
        Self {
            table_id: self.table_id,
            data: self.data.clone(),
            index: self.index.clone(),
        }
    }
    pub fn table_id(&self) -> &TableId {
        &self.table_id
    }
    pub fn snapshot(&self) -> &EncryptedSnapshot {
        &self.data
    }
    pub fn encrypted_index(&self) -> &EncryptedSnapshot {
        &self.index
    }
    pub fn commitment(&self) -> &Commitment {
        self.data.commitment()
    }
    pub fn index_commitment(&self) -> &Commitment {
        self.index.commitment()
    }
    pub fn canonical_data_bytes(&self) -> usize {
        self.data.encoded_len()
    }
    pub fn encrypted_index_bytes(&self) -> usize {
        self.index.encoded_len()
    }
    pub fn rebuildable_hash_bytes(&self) -> usize {
        self.data.index_hash_bytes() + self.index.index_hash_bytes()
    }
}

/// Local stage counters; metadata, not security evidence or production telemetry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stages {
    pub owner_index_lookup_proof_decrypt_ms: f64,
    pub owner_index_response_bytes: usize,
    pub owner_data_response_bytes: usize,
    pub owner_data_authenticate_mask_encrypt_ms: f64,
    pub request_serialize_ms: f64,
    pub request_bytes: usize,
    pub peer_request_decode_ms: f64,
    pub row_worker_budget: usize,
    pub peer_lookup_proof_verify_ms: f64,
    pub page_response_bytes: usize,
    pub peer_compact_to_fhe_ms: f64,
    pub peer_fhe_evaluate_ms: f64,
    pub output_serialize_ms: f64,
    pub output_bytes: usize,
}
#[cfg(feature = "tfhe-backend")]
fn ms(start: std::time::Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn random_id() -> Result<[u8; 16]> {
    let mut value = [0; 16];
    getrandom::getrandom(&mut value).map_err(|_| Error::Randomness)?;
    Ok(value)
}
fn check_schema(head: &Commitment) -> Result<()> {
    if head.layout().schema != SCHEMA
        || head.layout().row_width != ROW_BYTES
        || head.layout().row_count > MAX_TABLE_ROWS as u64
    {
        return Err(Error::InvalidSchema);
    }
    Ok(())
}

#[cfg(all(test, feature = "tfhe-backend"))]
mod tests;

#[cfg(feature = "bfv-experiment")]
impl From<bfv_query_core::Error> for Error {
    fn from(error: bfv_query_core::Error) -> Self {
        Self::Codec(format!("BFV experiment: {error}"))
    }
}
