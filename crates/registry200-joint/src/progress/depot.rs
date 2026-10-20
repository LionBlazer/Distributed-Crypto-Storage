//! One concrete byte store/typed ledger, privately bound to this new application.
use super::{Descriptor, Error, Result};
use bfv_product_evidence::{CatalogClaim, CatalogId, ProductStore, SharedProductStore};
use bfv_query_core::PublicSetup;
use protocol_storage::{BlobId, DepotBudget, MAX_BLOB_BYTES};
pub const MAX_SETUP_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SETUP_CLAIM_BYTES: usize = 136;
const MAGIC: &[u8; 8] = b"DCSPST02";

/// Untrusted durable public references. Host custody/authentication is separate;
/// original full setup hashes are always checked against the fixed Descriptor.
#[derive(Clone)]
pub struct SetupClaim {
    application: [u8; 32],
    bytes: u64,
    parts: Vec<BlobId>,
}
impl SetupClaim {
    pub fn application_id(&self) -> [u8; 32] {
        self.application
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn parts(&self) -> &[BlobId] {
        &self.parts
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(56 + 40 * self.parts.len());
        b.extend(MAGIC);
        b.extend(self.application);
        b.extend(self.bytes.to_le_bytes());
        b.push(self.parts.len() as u8);
        b.extend([0; 7]);
        for id in &self.parts {
            b.extend(id.sha256());
            b.extend(id.bytes().to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if ![96, 136].contains(&b.len()) || &b[..8] != MAGIC || b[49..56] != [0; 7] {
            return Err(Error::Encoding);
        }
        let n = b[48] as usize;
        let bytes = u64::from_le_bytes(b[40..48].try_into().unwrap());
        if bytes == 0 || bytes > MAX_SETUP_BYTES as u64 {
            return Err(Error::ResourceLimit);
        }
        if !(1..=2).contains(&n)
            || b.len() != 56 + 40 * n
            || n != usize::from(bytes > MAX_BLOB_BYTES) + 1
        {
            return Err(Error::Encoding);
        }
        let mut parts = Vec::with_capacity(n);
        for (i, part) in b[56..].as_chunks::<40>().0.iter().enumerate() {
            let len = u64::from_le_bytes(part[32..40].try_into().unwrap());
            if len != (bytes - i as u64 * MAX_BLOB_BYTES).min(MAX_BLOB_BYTES) {
                return Err(Error::Encoding);
            }
            parts.push(
                BlobId::new(part[..32].try_into().unwrap(), len)
                    .map_err(|_| Error::ResourceLimit)?,
            );
        }
        let x = Self {
            application: b[8..40].try_into().unwrap(),
            bytes,
            parts,
        };
        if x.encode() != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
}

/// Pins this application around ONE actual public-byte store. Sharing opens no
/// store or budget and transfers no old application/proof acceptance authority.
/// ```compile_fail
/// fn expose(d: registry200_joint::progress::ProgressDepot) { let _ = d.inner; }
/// ```
pub struct ProgressDepot {
    descriptor: Descriptor,
    inner: SharedProductStore,
}
#[derive(Clone)]
pub struct ProgressEvidenceIngress {
    application: [u8; 32],
    inner: SharedProductStore,
}
impl ProgressDepot {
    pub fn open(budget: DepotBudget, descriptor: &Descriptor) -> Result<Self> {
        let descriptor = Descriptor::decode(&descriptor.encode())?;
        Ok(Self {
            descriptor,
            inner: ProductStore::open(budget)?.into_shared(),
        })
    }
    /// Reuse the exact already-open concrete store/typed ledger. The descriptor
    /// is independently installed and canonical; arbitrary stored bytes and old
    /// application labels confer no authority in this new application.
    pub fn share(store: SharedProductStore, descriptor: &Descriptor) -> Result<Self> {
        Ok(Self {
            descriptor: Descriptor::decode(&descriptor.encode())?,
            inner: store,
        })
    }
    pub fn ingress(&self) -> ProgressEvidenceIngress {
        ProgressEvidenceIngress {
            application: self.descriptor.id(),
            inner: self.inner.clone(),
        }
    }
    pub fn retain_setup(&self, setup: &PublicSetup) -> Result<SetupClaim> {
        self.descriptor.require_setup(setup)?;
        let bytes = setup.to_bytes().map_err(|_| Error::Domain)?;
        let mut parts = Vec::with_capacity(2);
        for part in bytes.chunks(MAX_BLOB_BYTES as usize) {
            parts.push(self.inner.retain_public_blob(part)?);
        }
        SetupClaim::decode(
            &SetupClaim {
                application: self.descriptor.id(),
                bytes: bytes.len() as u64,
                parts,
            }
            .encode(),
        )
    }
    pub(super) fn require_descriptor(&self, descriptor: &Descriptor) -> Result<()> {
        if self.descriptor.encode() != descriptor.encode() {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub(super) fn store(&self) -> &SharedProductStore {
        &self.inner
    }
    pub(super) fn load_setup(
        &self,
        descriptor: &Descriptor,
        claim: &SetupClaim,
    ) -> Result<PublicSetup> {
        self.require_descriptor(descriptor)?;
        let claim = SetupClaim::decode(&claim.encode())?;
        if claim.application != descriptor.id() {
            return Err(Error::Domain);
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(claim.bytes).map_err(|_| Error::ResourceLimit)?);
        for part in claim.parts {
            bytes.extend(self.inner.read_public_blob(part, MAX_BLOB_BYTES as usize)?);
        }
        if bytes.len() as u64 != claim.bytes {
            return Err(Error::Encoding);
        }
        descriptor.require_setup_bytes(&bytes)?; // BOTH independent hashes BEFORE SDK decode.
        let setup = PublicSetup::from_bytes(&bytes).map_err(|_| Error::Domain)?;
        descriptor.require_setup(&setup)?;
        Ok(setup)
    }
}
impl ProgressEvidenceIngress {
    /// Metadata only; every clone still uses the SAME concrete store and ledger.
    pub fn application_id(&self) -> [u8; 32] {
        self.application
    }
    /// Byte storage/recording capability, never a checked-proof capability.
    pub fn recording_store(&self) -> SharedProductStore {
        self.inner.clone()
    }
    pub fn catalog_claim(&self, id: CatalogId) -> Result<CatalogClaim> {
        Ok(self.inner.catalog_claim(id)?)
    }
    pub fn retain_public_blob(&self, bytes: &[u8]) -> Result<BlobId> {
        if bytes.is_empty() || bytes.len() > MAX_BLOB_BYTES as usize {
            return Err(Error::ResourceLimit);
        }
        Ok(self.inner.retain_public_blob(bytes)?)
    }
    pub fn read_public_blob(&self, id: BlobId, cap: usize) -> Result<Vec<u8>> {
        if cap == 0 || cap > MAX_BLOB_BYTES as usize {
            return Err(Error::ResourceLimit);
        }
        Ok(self.inner.read_public_blob(id, cap)?)
    }
}
