//! Small immutable references in the signed Body. References have no proof authority.
use crate::{Error, Lane, Result, contract_digest};
use protocol_storage::BlobId;
pub const MANIFEST_BYTES: usize = 232;
const MAGIC: &[u8; 8] = b"DCSJMF01";

/// Fixed local evidence roles, not new wire tags or proof authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestRole {
    LifecyclePair,
    ControlKind,
    ProductCatalog,
    LifecycleChild,
    PredicateAcquire,
}

/// One unverified content reference from a canonical manifest.
/// Private fields cannot change the role's existing byte cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestReference {
    role: ManifestRole,
    ordinal: usize,
    blob_id: BlobId,
    byte_cap: usize,
}
impl ManifestReference {
    pub fn role(&self) -> ManifestRole {
        self.role
    }
    /// Zero-based position in this manifest's fixed reference sequence.
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub fn blob_id(&self) -> BlobId {
        self.blob_id
    }
    pub fn byte_cap(&self) -> usize {
        self.byte_cap
    }
}

pub struct Manifest {
    lane: Lane,
    next: [u8; 32],
    result: [u8; 32],
    refs: [Option<BlobId>; 3],
}
impl Manifest {
    pub fn bootstrap(next: [u8; 32], pair: BlobId) -> Result<Self> {
        Self::checked(Lane::Bootstrap, next, [0; 32], [Some(pair), None, None])
    }
    pub fn control(next: [u8; 32], result: [u8; 32], pair: BlobId, kind: BlobId) -> Result<Self> {
        Self::checked(Lane::Control, next, result, [Some(pair), Some(kind), None])
    }
    pub fn acquire(
        next: [u8; 32],
        result: [u8; 32],
        catalog: bfv_product_evidence::CatalogId,
        lifecycle_child: BlobId,
        link: BlobId,
    ) -> Result<Self> {
        Self::checked(
            Lane::Acquire,
            next,
            result,
            [Some(catalog.blob_id()), Some(lifecycle_child), Some(link)],
        )
    }
    fn checked(
        lane: Lane,
        next: [u8; 32],
        result: [u8; 32],
        refs: [Option<BlobId>; 3],
    ) -> Result<Self> {
        for digest in [next, result] {
            let _ = registry200_proof::source::statement::decode_digest(digest)
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
        for (i, id) in x.refs.iter().enumerate() {
            match (x.cap(i), id) {
                (Some(cap), Some(id)) if id.bytes() != 0 && id.bytes() <= cap as u64 => {}
                (None, None) => {}
                _ => return Err(Error::ResourceLimit),
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
    /// Enumerate every mandatory reference in canonical order without allocation,
    /// I/O or proof verification. Prefetch must finish before a Journal lock;
    /// the actual fixed verifier must still replay all mandatory evidence.
    pub fn references(
        &self,
    ) -> impl ExactSizeIterator<Item = ManifestReference>
    + DoubleEndedIterator
    + std::iter::FusedIterator
    + '_ {
        let count = match self.lane {
            Lane::Bootstrap => 1,
            Lane::Control => 2,
            Lane::Acquire => 3,
        };
        (0..count).map(move |ordinal| ManifestReference {
            role: match (self.lane, ordinal) {
                (Lane::Bootstrap | Lane::Control, 0) => ManifestRole::LifecyclePair,
                (Lane::Control, 1) => ManifestRole::ControlKind,
                (Lane::Acquire, 0) => ManifestRole::ProductCatalog,
                (Lane::Acquire, 1) => ManifestRole::LifecycleChild,
                (Lane::Acquire, 2) => ManifestRole::PredicateAcquire,
                _ => unreachable!("canonical manifest reference"),
            },
            ordinal,
            blob_id: self.refs[ordinal].expect("canonical manifest reference"),
            byte_cap: self.cap(ordinal).expect("canonical manifest role cap"),
        })
    }
    pub(crate) fn reference(&self, i: usize) -> Result<BlobId> {
        self.refs.get(i).copied().flatten().ok_or(Error::Encoding)
    }
    pub(crate) fn cap(&self, i: usize) -> Option<usize> {
        use registry200_proof::{control_kind, predicate_acquire, wire};
        match (self.lane, i) {
            (Lane::Bootstrap | Lane::Control, 0) => Some(wire::maximum_bundle_bytes()),
            (Lane::Control, 1) => Some(control_kind::wire::MAX_FRAME),
            (Lane::Acquire, 0) => Some(bfv_product_evidence::MAX_CATALOG_BYTES),
            (Lane::Acquire, 1) => Some(wire::frame::MAX_CHILD_BYTES),
            (Lane::Acquire, 2) => Some(predicate_acquire::wire::MAX_FRAME),
            _ => None,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MANIFEST_BYTES);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&contract_digest());
        b.push(self.lane.tag());
        b.extend_from_slice(&[0; 7]);
        b.extend_from_slice(&self.next);
        b.extend_from_slice(&self.result);
        for id in self.refs {
            match id {
                Some(id) => {
                    b.extend_from_slice(id.sha256());
                    b.extend_from_slice(&id.bytes().to_le_bytes());
                }
                None => b.extend_from_slice(&[0; 40]),
            }
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
        let mut refs = [None; 3];
        for (i, bytes) in b[112..].as_chunks::<40>().0.iter().enumerate() {
            if *bytes != [0; 40] {
                refs[i] = Some(
                    BlobId::new(
                        bytes[..32].try_into().unwrap(),
                        u64::from_le_bytes(bytes[32..].try_into().unwrap()),
                    )
                    .map_err(|_| Error::ResourceLimit)?,
                );
            }
        }
        let x = Self::checked(
            Lane::decode(b[40])?,
            b[48..80].try_into().unwrap(),
            b[80..112].try_into().unwrap(),
            refs,
        )?;
        if x.encode() != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
}
