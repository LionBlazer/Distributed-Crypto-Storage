use crate::{CatalogClaim, CatalogId, Error, MAX_CATALOG_BYTES, Result};
use bfv_mul_relin_proof::Provenance;
use protocol_storage::{BlobId, DepotBudget, EvidenceStore, MAX_BLOB_BYTES, StoreLimits};
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;

/// The fixed PUBLIC evidence depot. Its sole constructor requires the NEW
/// participant's typed depot budget; it cannot borrow a control/WAL allowance.
/// Stores no secret, decoded proof, backend, verified bit or eviction policy.
pub struct ProductStore {
    pub(crate) inner: EvidenceStore,
}
impl ProductStore {
    pub fn open(budget: DepotBudget) -> Result<Self> {
        Ok(Self {
            inner: EvidenceStore::open_depot(
                budget,
                StoreLimits::new(MAX_BLOB_BYTES, protocol_storage::MAX_TRACKED_FILES - 2)?,
            )?,
        })
    }
    /// Read and decode unverified catalog metadata with the same canonical
    /// parser used by replay. Referenced blobs and proofs are not checked here.
    pub fn catalog_claim(&mut self, id: CatalogId) -> Result<CatalogClaim> {
        CatalogClaim::decode(&self.read(id.blob_id(), MAX_CATALOG_BYTES)?)
    }
    /// Read bounded public bytes, checking their exact length, SHA256 and EOF.
    /// Content identity conveys no proof, freshness or application authority.
    /// Invalid caps reject before opening a file or allocating its buffer.
    pub fn read_public_blob(&mut self, id: BlobId, cap: usize) -> Result<Vec<u8>> {
        if cap == 0 || cap > MAX_BLOB_BYTES as usize {
            return Err(Error::ResourceLimit);
        }
        self.read(id, cap)
    }
    /// Retain nonempty public bytes in this same typed depot and shared ledger.
    /// This performs immutable storage only; it does not verify their contents.
    /// Empty/oversized input rejects before hashing or creating a stage.
    pub fn retain_public_blob(&mut self, bytes: &[u8]) -> Result<BlobId> {
        if bytes.is_empty() || bytes.len() > MAX_BLOB_BYTES as usize {
            return Err(Error::ResourceLimit);
        }
        self.put(bytes)
    }
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<BlobId> {
        let id = BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64)?;
        let mut stage = self.inner.stage(id)?;
        for chunk in bytes.chunks(64 * 1024) {
            stage.write_chunk(chunk)?;
        }
        Ok(stage.finish()?)
    }
    pub(crate) fn read(&mut self, id: BlobId, cap: usize) -> Result<Vec<u8>> {
        if id.bytes() > cap as u64 {
            return Err(Error::ResourceLimit);
        }
        let mut reader = self.inner.reader(id)?;
        let mut out = vec![0; usize::try_from(id.bytes()).map_err(|_| Error::ResourceLimit)?];
        reader.read_exact(&mut out)?;
        reader.finish()?;
        Ok(out)
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
        let mut buffer = [0; 64 * 1024];
        for id in ids {
            let mut reader = self.inner.reader(*id)?;
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or(Error::ResourceLimit)?;
                hash.update(&buffer[..n]);
                sha256.update(&buffer[..n]);
            }
            reader.finish()?;
        }
        // Catalog decoding has already required the exact canonical one/two
        // chunk extents. The complete streamed SHA512 and independent full ID
        // bind original bytes AND their length; do not serialize another 64-MiB
        // setup merely to recover a length already checked by that identity.
        if count != setup_len
            || <[u8; 64]>::from(hash.finalize()) != provenance.original_setup_digest()
            || <[u8; 32]>::from(sha256.finalize()) != provenance.anchor().full_setup_id()
        {
            return Err(Error::Association);
        }
        Ok(())
    }
}

pub(crate) fn binding(object: [u8; 32], p: &Provenance, request: &[u8]) -> Result<[u8; 64]> {
    require_request(p, request)?;
    let claim = p.encode_claim()?;
    let mut h = Sha512::new();
    h.update(b"DCS/retained-BFV-product/independent-local-pins/v1");
    h.update(crate::profile_digest());
    h.update(bfv_mul_relin_proof::profile_digest());
    h.update(object);
    h.update(p.anchor().full_setup_id());
    h.update(p.original_setup_digest());
    for bytes in [claim.as_slice(), request] {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    Ok(h.finalize().into())
}
fn require_request(p: &Provenance, request: &[u8]) -> Result<()> {
    if request.len() > bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES {
        return Err(Error::ResourceLimit);
    }
    let view = p
        .setup()
        .private_coefficient_request(request)
        .map_err(|_| Error::Association)?;
    let source = p.encodings()[0].expected.source_claim();
    if view.query() != p.query()
        || view.context().data_head() != source.heads[0]
        || view.context().index_head() != source.heads[1]
        || view.ciphertexts() != p.ciphertexts().each_ref().map(Vec::as_slice)
    {
        return Err(Error::Association);
    }
    Ok(())
}
pub(crate) fn require_response(p: &Provenance, request: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > bfv_query_core::MAX_PRIVATE_COEFFICIENT_RESPONSE_BYTES {
        return Err(Error::ResourceLimit);
    }
    let response = bfv_query_core::EvaluatedPrivateCoefficientPredicate {
        output: bytes.to_vec(),
        ct_ct_multiplications: 1,
    };
    response
        .require_request(p.setup(), request)
        .map_err(|_| Error::Association)?;
    Ok(response
        .ciphertext_for_experiment()
        .map_err(|_| Error::Association)?
        .to_vec())
}
