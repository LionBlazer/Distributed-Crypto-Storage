//! One concrete typed depot ledger shared by bounded ingress and fixed verification.
use crate::{Descriptor, Error, Result};
use bfv_product_evidence::{CatalogClaim, CatalogId, ProductStore, SharedProductStore};
use bfv_query_core::PublicSetup;
use protocol_storage::{BlobId, DepotBudget, MAX_BLOB_BYTES};

pub const MAX_SETUP_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SETUP_CLAIM_BYTES: usize = 136;
const MAGIC: &[u8; 8] = b"DCSJSP01";
/// Untrusted original setup references. Authentication of this small local
/// record is the host's responsibility; hashes are checked against Descriptor.
#[derive(Clone)]
pub struct SetupClaim {
    application: [u8; 32],
    bytes: u64,
    parts: Vec<BlobId>,
}
impl SetupClaim {
    /// Unverified application label; the fixed verifier checks the Descriptor.
    pub fn application_id(&self) -> [u8; 32] {
        self.application
    }
    /// Claimed complete setup length, bounded by the existing setup grammar.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Canonically ordered chunk references. Borrowing these performs no I/O,
    /// allocation, hashing, SDK decoding or verification.
    pub fn parts(&self) -> &[BlobId] {
        &self.parts
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(56 + 40 * self.parts.len());
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&self.application);
        b.extend_from_slice(&self.bytes.to_le_bytes());
        b.push(self.parts.len() as u8);
        b.extend_from_slice(&[0; 7]);
        for id in &self.parts {
            b.extend_from_slice(id.sha256());
            b.extend_from_slice(&id.bytes().to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if ![96, 136].contains(&b.len()) || &b[..8] != MAGIC || b[49..56] != [0; 7] {
            return Err(Error::Encoding);
        }
        let n = b[48] as usize;
        if !(1..=2).contains(&n) || b.len() != 56 + 40 * n {
            return Err(Error::Encoding);
        }
        let bytes = u64::from_le_bytes(b[40..48].try_into().unwrap());
        if bytes == 0 || bytes > MAX_SETUP_BYTES as u64 {
            return Err(Error::ResourceLimit);
        }
        let expected = usize::from(bytes > MAX_BLOB_BYTES) + 1;
        if n != expected {
            return Err(Error::Encoding);
        }
        let mut parts = Vec::with_capacity(n);
        for (i, part) in b[56..].as_chunks::<40>().0.iter().enumerate() {
            let len = u64::from_le_bytes(part[32..40].try_into().unwrap());
            let required = (bytes - i as u64 * MAX_BLOB_BYTES).min(MAX_BLOB_BYTES);
            if len != required {
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

pub struct JointDepot {
    inner: SharedProductStore,
}
/// Cloneable PUBLIC-byte ingress. It neither exposes a mutable store/lock guard
/// nor confers proof success. All clones share one store lock and typed ledger;
/// the host separately owns and shares its one actual native resource gate.
#[derive(Clone)]
pub struct JointEvidenceIngress {
    inner: SharedProductStore,
}
impl JointDepot {
    pub fn open(budget: DepotBudget) -> Result<Self> {
        Ok(Self {
            inner: ProductStore::open(budget)?.into_shared(),
        })
    }
    pub fn ingress(&self) -> JointEvidenceIngress {
        JointEvidenceIngress {
            inner: self.inner.clone(),
        }
    }
    pub fn retain_setup(&self, descriptor: &Descriptor, setup: &PublicSetup) -> Result<SetupClaim> {
        descriptor.require_setup(setup)?;
        let bytes = setup.to_bytes().map_err(|_| Error::Domain)?;
        let mut parts = Vec::with_capacity(2);
        for part in bytes.chunks(MAX_BLOB_BYTES as usize) {
            parts.push(self.inner.retain_public_blob(part)?);
        }
        let claim = SetupClaim {
            application: descriptor.id(),
            bytes: bytes.len() as u64,
            parts,
        };
        SetupClaim::decode(&claim.encode())
    }
    pub(crate) fn store(&self) -> &SharedProductStore {
        &self.inner
    }
    pub(crate) fn load_setup(
        &self,
        descriptor: &Descriptor,
        claim: &SetupClaim,
    ) -> Result<PublicSetup> {
        let claim = SetupClaim::decode(&claim.encode())?;
        if claim.application != descriptor.id() {
            return Err(Error::Domain);
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(claim.bytes).map_err(|_| Error::ResourceLimit)?);
        for id in claim.parts {
            bytes.extend(self.inner.read_public_blob(id, MAX_BLOB_BYTES as usize)?);
        }
        if bytes.len() as u64 != claim.bytes {
            return Err(Error::Encoding);
        }
        // Independent full hash and exact extents are checked BEFORE SDK decode.
        descriptor.require_setup_bytes(&bytes)?;
        let setup = PublicSetup::from_bytes(&bytes).map_err(|_| Error::Domain)?;
        descriptor.require_setup(&setup)?;
        Ok(setup)
    }
}
impl JointEvidenceIngress {
    /// Clone the SAME concrete store for actual product recording. This opens
    /// no directory or budget, exposes no lock, and supplies no proof result.
    /// Keep this handle before moving the depot into the fixed verifier.
    pub fn recording_store(&self) -> SharedProductStore {
        self.inner.clone()
    }
    /// Read bounded UNVERIFIED catalog metadata through the same store and
    /// canonical parser used by product replay. Referenced blobs and proofs
    /// remain unchecked; use their references only for bounded prefetch.
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
