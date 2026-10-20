//! Fixed two-role byte references. Root commitments do not reveal step status.
use super::{Error, Lane, Result, contract_digest};
use protocol_storage::BlobId;
const MAGIC: &[u8; 8] = b"DCSPMF02";
pub const MANIFEST_BYTES: usize = 192;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestRole {
    Source,
    Bootstrap803,
    Control815,
    ProductCatalog,
    Predicate896,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestReference {
    role: ManifestRole,
    ordinal: usize,
    blob: BlobId,
    cap: usize,
}
impl ManifestReference {
    pub fn role(&self) -> ManifestRole {
        self.role
    }
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub fn blob_id(&self) -> BlobId {
        self.blob
    }
    pub fn byte_cap(&self) -> usize {
        self.cap
    }
}
pub struct Manifest {
    lane: Lane,
    next: [u8; 32],
    result: [u8; 32],
    refs: [BlobId; 2],
}
impl Manifest {
    pub fn bootstrap(next: [u8; 32], source: BlobId, child: BlobId) -> Result<Self> {
        Self::checked(Lane::Bootstrap, next, [0; 32], [source, child])
    }
    pub fn control(
        next: [u8; 32],
        result: [u8; 32],
        source: BlobId,
        child: BlobId,
    ) -> Result<Self> {
        Self::checked(Lane::Control, next, result, [source, child])
    }
    pub fn predicate(
        next: [u8; 32],
        result: [u8; 32],
        catalog: bfv_product_evidence::CatalogId,
        child: BlobId,
    ) -> Result<Self> {
        Self::checked(Lane::Predicate, next, result, [catalog.blob_id(), child])
    }
    fn checked(lane: Lane, next: [u8; 32], result: [u8; 32], refs: [BlobId; 2]) -> Result<Self> {
        for root in [next, result] {
            let _ = registry200_proof::source::statement::decode_digest(root)
                .map_err(|_| Error::Encoding)?;
        }
        if lane == Lane::Bootstrap && result != [0; 32] {
            return Err(Error::Encoding);
        }
        let x = Self {
            lane,
            next,
            result,
            refs,
        };
        for (i, reference) in refs.iter().enumerate() {
            if reference.bytes() == 0 || reference.bytes() > x.cap(i) as u64 {
                return Err(Error::ResourceLimit);
            }
        }
        Ok(x)
    }
    pub fn lane(&self) -> Lane {
        self.lane
    }
    pub fn next_root(&self) -> [u8; 32] {
        self.next
    }
    pub fn result_root(&self) -> [u8; 32] {
        self.result
    }
    pub fn references(
        &self,
    ) -> impl ExactSizeIterator<Item = ManifestReference>
    + DoubleEndedIterator
    + std::iter::FusedIterator
    + '_ {
        (0..2).map(move |i| ManifestReference {
            role: match (self.lane, i) {
                (Lane::Bootstrap | Lane::Control, 0) => ManifestRole::Source,
                (Lane::Bootstrap, 1) => ManifestRole::Bootstrap803,
                (Lane::Control, 1) => ManifestRole::Control815,
                (Lane::Predicate, 0) => ManifestRole::ProductCatalog,
                (Lane::Predicate, 1) => ManifestRole::Predicate896,
                _ => unreachable!(),
            },
            ordinal: i,
            blob: self.refs[i],
            cap: self.cap(i),
        })
    }
    pub(super) fn reference(&self, i: usize) -> BlobId {
        self.refs[i]
    }
    pub(super) fn cap(&self, i: usize) -> usize {
        match (self.lane, i) {
            (Lane::Bootstrap | Lane::Control, 0) => {
                registry200_proof::wire::frame::MAX_SOURCE_BYTES
            }
            (_, 1) => registry200_proof::registry_progress::bootstrap::MAX_FRAME,
            (Lane::Predicate, 0) => bfv_product_evidence::MAX_CATALOG_BYTES,
            _ => unreachable!(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MANIFEST_BYTES);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&contract_digest());
        b.push(self.lane.tag());
        b.extend([0; 7]);
        b.extend(self.next);
        b.extend(self.result);
        for id in self.refs {
            b.extend(id.sha256());
            b.extend(id.bytes().to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != MANIFEST_BYTES
            || &b[..8] != MAGIC
            || b[8..40] != contract_digest()
            || b[41..48] != [0; 7]
        {
            return Err(Error::Encoding);
        }
        let mut refs = Vec::with_capacity(2);
        for chunk in b[112..].as_chunks::<40>().0 {
            refs.push(
                BlobId::new(
                    chunk[..32].try_into().unwrap(),
                    u64::from_le_bytes(chunk[32..].try_into().unwrap()),
                )
                .map_err(|_| Error::ResourceLimit)?,
            );
        }
        let x = Self::checked(
            Lane::decode(b[40])?,
            b[48..80].try_into().unwrap(),
            b[80..112].try_into().unwrap(),
            refs.try_into().map_err(|_| Error::Encoding)?,
        )?;
        if x.encode() != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
}
