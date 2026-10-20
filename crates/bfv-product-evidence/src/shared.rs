//! One concrete shared owner. No lock guard or reader can escape an operation.
use crate::{CatalogClaim, CatalogId, Error, ProductStore, Result, access::StoreAccess};
use protocol_storage::{BlobId, MAX_BLOB_BYTES};
use std::sync::{Arc, Mutex};

/// Cloneable ownership of ONE already-open public evidence store and ledger.
/// Cloning opens no file, creates no budget and conveys no verification result.
/// Each operation releases its private lock before returning owned public bytes.
#[derive(Clone)]
pub struct SharedProductStore {
    pub(crate) inner: Arc<Mutex<ProductStore>>,
}
impl ProductStore {
    /// Move this actual exclusive store into a shared owner without reopening
    /// its directory or changing its typed depot budget and retained charges.
    pub fn into_shared(self) -> SharedProductStore {
        SharedProductStore {
            inner: Arc::new(Mutex::new(self)),
        }
    }
}
impl SharedProductStore {
    /// Read canonical UNVERIFIED metadata. All referenced proofs still require
    /// genuine replay against independently supplied expected inputs.
    pub fn catalog_claim(&self, id: CatalogId) -> Result<CatalogClaim> {
        StoreAccess::Shared(self.clone()).catalog_claim(id)
    }
    /// Read one bounded blob, checking its complete length, hash and EOF while
    /// holding only this blob's local I/O lock. No public reader is returned.
    pub fn read_public_blob(&self, id: BlobId, cap: usize) -> Result<Vec<u8>> {
        if cap == 0 || cap > MAX_BLOB_BYTES as usize || id.bytes() > cap as u64 {
            return Err(Error::ResourceLimit);
        }
        StoreAccess::Shared(self.clone()).read(id, cap)
    }
    /// Retain bounded PUBLIC bytes in the same immutable store. Content identity
    /// supplies no mathematical, freshness, finality or SQL authority.
    pub fn retain_public_blob(&self, bytes: &[u8]) -> Result<BlobId> {
        if bytes.is_empty() || bytes.len() > MAX_BLOB_BYTES as usize {
            return Err(Error::ResourceLimit);
        }
        StoreAccess::Shared(self.clone()).put(bytes)
    }
}
