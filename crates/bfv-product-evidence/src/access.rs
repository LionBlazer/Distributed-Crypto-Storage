//! Closed storage choices for the SAME recorder and replay implementation.
use crate::{
    CatalogClaim, CatalogId, Error, MAX_CATALOG_BYTES, ProductStore, Result, SharedProductStore,
};
use bfv_mul_relin_proof::Provenance;
use protocol_storage::BlobId;
use sha2::{Digest, Sha256, Sha512};

pub(crate) enum StoreAccess<'a> {
    Exclusive(&'a mut ProductStore),
    Shared(SharedProductStore),
}
impl StoreAccess<'_> {
    pub(crate) fn catalog_claim(&mut self, id: CatalogId) -> Result<CatalogClaim> {
        // Parsing happens after the bounded owned read has released its lock.
        CatalogClaim::decode(&self.read(id.blob_id(), MAX_CATALOG_BYTES)?)
    }
    pub(crate) fn read(&mut self, id: BlobId, cap: usize) -> Result<Vec<u8>> {
        if id.bytes() > cap as u64 {
            return Err(Error::ResourceLimit);
        }
        match self {
            Self::Exclusive(store) => store.read(id, cap),
            Self::Shared(store) => store
                .inner
                .lock()
                .map_err(|_| Error::Poisoned)?
                .read(id, cap),
        }
    }
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<BlobId> {
        match self {
            Self::Exclusive(store) => store.put(bytes),
            Self::Shared(store) => store.inner.lock().map_err(|_| Error::Poisoned)?.put(bytes),
        }
    }
    pub(crate) fn check_setup(
        &mut self,
        ids: &[BlobId],
        setup_len: u64,
        provenance: &Provenance,
    ) -> Result<()> {
        let mut hash = Sha512::new();
        let mut sha256 = Sha256::new();
        let mut count = 0u64;
        for id in ids {
            // Exactly one setup chunk is streamed under each lock. No setup
            // serialization, SDK decode, proof verification or RPC runs here.
            match self {
                Self::Exclusive(store) => {
                    store.hash_setup_part(*id, &mut hash, &mut sha256, &mut count)?
                }
                Self::Shared(store) => store
                    .inner
                    .lock()
                    .map_err(|_| Error::Poisoned)?
                    .hash_setup_part(*id, &mut hash, &mut sha256, &mut count)?,
            }
        }
        if count != setup_len
            || <[u8; 64]>::from(hash.finalize()) != provenance.original_setup_digest()
            || <[u8; 32]>::from(sha256.finalize()) != provenance.anchor().full_setup_id()
        {
            return Err(Error::Association);
        }
        Ok(())
    }
}
