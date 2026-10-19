use crate::{Error, Result};
use bfv_mul_relin_proof::{MAX_CLAIMS_BYTES, PROOF_RECORDS};
use protocol_storage::{BlobId, MAX_BLOB_BYTES};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"DCSFPE01";
const HEADER: usize = 256;
const ENTRY: usize = 44;
pub(crate) const MAX_SETUP_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const INPUT_START: usize = 3;
pub(crate) const CLAIMS: usize = 19;
pub(crate) const RECORDS: usize = 20;
pub(crate) const PARTS: usize = RECORDS + PROOF_RECORDS;
const LAST_PART: usize = PARTS - 1;
pub const MAX_CATALOG_BYTES: usize = HEADER + (2 + PARTS) * ENTRY;

/// Untrusted SHA256/length identity of a bounded catalog blob. Anyone may supply
/// this value; neither construction nor successful storage verifies any proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogId(BlobId);
impl CatalogId {
    pub fn from_blob(id: BlobId) -> Result<Self> {
        if !(HEADER as u64..=MAX_CATALOG_BYTES as u64).contains(&id.bytes()) {
            return Err(Error::ResourceLimit);
        }
        Ok(Self(id))
    }
    pub fn blob_id(self) -> BlobId {
        self.0
    }
}

/// The storage grammar is separate from every unchanged proof profile. This
/// digest names identities/ordering only, not a proof or finality certificate.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-product-evidence/v1/fixed139-or140/setup32Mi-chunks/input16-dedup/output118/EOF-before-catalog/no-receipts");
    h.update(bfv_mul_relin_proof::profile_digest());
    h.finalize().into()
}

/// One unverified fixed-role content reference from a canonical catalog.
/// Its private fields have no proof, storage-custody or application authority.
pub struct CatalogReference {
    role: u16,
    ordinal: u16,
    blob_id: BlobId,
    byte_cap: usize,
}
impl CatalogReference {
    /// Existing canonical wire role code, not a caller-selected permission.
    pub fn role(&self) -> u16 {
        self.role
    }
    pub fn ordinal(&self) -> u16 {
        self.ordinal
    }
    pub fn blob_id(&self) -> BlobId {
        self.blob_id
    }
    /// The unchanged maximum blob byte length for this fixed role.
    pub fn byte_cap(&self) -> usize {
        self.byte_cap
    }
}

/// Unverified references decoded from the canonical product catalog. These
/// labels identify public bytes only: no getter verifies a proof, authorizes
/// an application transition or establishes an agreed fresh head.
pub struct CatalogClaim {
    pub(crate) setup_len: u64,
    pub(crate) setup: Vec<BlobId>,
    pub(crate) parts: [BlobId; PARTS],
    pub(crate) binding: [u8; 64],
    pub(crate) graph: [u8; 64],
}
impl CatalogClaim {
    /// Original setup chunks in canonical byte order; the claims remain unverified.
    pub fn setup_parts(&self) -> &[BlobId] {
        &self.setup
    }
    /// Claimed complete setup length, bounded by the unchanged 64-MiB policy.
    pub fn setup_bytes(&self) -> u64 {
        self.setup_len
    }
    pub fn provenance(&self) -> BlobId {
        self.parts[0]
    }
    pub fn request(&self) -> BlobId {
        self.parts[1]
    }
    pub fn response(&self) -> BlobId {
        self.parts[2]
    }
    /// Shared original Source bytes used by both encoding pairs.
    pub fn source(&self) -> BlobId {
        self.parts[4]
    }
    /// The PrivateMask encoding child, without its shared Source bytes.
    pub fn query_child(&self) -> BlobId {
        self.parts[6]
    }
    /// Claimed graph identity. Only actual replay can check the associated proofs.
    pub fn graph_identity(&self) -> [u8; 64] {
        self.graph
    }
    /// All 139/140 canonical references, including original setup chunks and
    /// every input/output proof premise. This performs no I/O or verification.
    /// A consumer can prefetch under the SAME depot ledger before its Journal
    /// lock, but must still genuinely replay all mandatory evidence afterward.
    pub fn references(
        &self,
    ) -> impl ExactSizeIterator<Item = CatalogReference>
    + DoubleEndedIterator
    + std::iter::FusedIterator
    + '_ {
        (0..self.setup.len() + PARTS).map(move |index| {
            // Public claims can only be obtained through the canonical checked
            // parser. The same private table already accepted these indices,
            // role extents and the exact one/two setup count during decoding.
            let (role, ordinal, byte_cap) =
                role(index, self.setup.len()).expect("canonical catalog reference");
            let blob_id = if index < self.setup.len() {
                self.setup[index]
            } else {
                self.parts[index - self.setup.len()]
            };
            CatalogReference {
                role,
                ordinal,
                blob_id,
                byte_cap,
            }
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = Vec::with_capacity(HEADER + (self.setup.len() + PARTS) * ENTRY);
        out.extend(MAGIC);
        out.extend(profile_digest());
        out.extend(bfv_mul_relin_proof::profile_digest());
        out.extend(self.graph);
        out.extend(self.binding);
        out.extend(self.setup_len.to_le_bytes());
        out.extend(((self.setup.len() + PARTS) as u16).to_le_bytes());
        out.extend([0; 14]);
        for (i, id) in self.setup.iter().chain(&self.parts).enumerate() {
            let (role, ordinal, _) = role(i, self.setup.len())?;
            out.extend(role.to_le_bytes());
            out.extend(ordinal.to_le_bytes());
            out.extend(id.bytes().to_le_bytes());
            out.extend(id.sha256());
        }
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if !(HEADER..=MAX_CATALOG_BYTES).contains(&bytes.len()) {
            return Err(Error::ResourceLimit);
        }
        if bytes[..8] != *MAGIC
            || bytes[8..40] != profile_digest()
            || bytes[40..104] != bfv_mul_relin_proof::profile_digest()
            || bytes[242..HEADER] != [0; 14]
        {
            return Err(Error::Encoding);
        }
        let setup_len = u64::from_le_bytes(bytes[232..240].try_into().unwrap());
        let setup_count = setup_count(setup_len)?;
        let count = usize::from(u16::from_le_bytes(bytes[240..242].try_into().unwrap()));
        if count != setup_count + PARTS || bytes.len() != HEADER + count * ENTRY {
            return Err(Error::Encoding);
        }
        let mut ids = Vec::with_capacity(count);
        for (i, entry) in bytes[HEADER..].as_chunks::<ENTRY>().0.iter().enumerate() {
            let (r, ordinal, cap) = role(i, setup_count)?;
            let len = u64::from_le_bytes(entry[4..12].try_into().unwrap());
            if entry[..2] != r.to_le_bytes() || entry[2..4] != ordinal.to_le_bytes() {
                return Err(Error::Encoding);
            }
            if len == 0 || len > cap as u64 {
                return Err(Error::ResourceLimit);
            }
            ids.push(BlobId::new(entry[12..44].try_into().unwrap(), len)?);
        }
        let parts = ids
            .split_off(setup_count)
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let catalog = Self {
            setup_len,
            setup: ids,
            parts,
            graph: bytes[104..168].try_into().unwrap(),
            binding: bytes[168..232].try_into().unwrap(),
        };
        catalog.check()?;
        Ok(catalog)
    }
    fn check(&self) -> Result<()> {
        let count = setup_count(self.setup_len)?;
        if self.setup.len() != count {
            return Err(Error::Encoding);
        }
        for (i, id) in self.setup.iter().enumerate() {
            let expected = (self.setup_len - i as u64 * MAX_BLOB_BYTES).min(MAX_BLOB_BYTES);
            if id.bytes() != expected {
                return Err(Error::Encoding);
            }
        }
        for (i, id) in self.parts.iter().enumerate() {
            if id.bytes() == 0 || id.bytes() > role(count + i, count)?.2 as u64 {
                return Err(Error::ResourceLimit);
            }
        }
        Ok(())
    }
}
fn setup_count(len: u64) -> Result<usize> {
    if len == 0 || len > MAX_SETUP_BYTES as u64 {
        return Err(Error::ResourceLimit);
    }
    Ok(if len > MAX_BLOB_BYTES { 2 } else { 1 })
}
fn role(index: usize, setup: usize) -> Result<(u16, u16, usize)> {
    if index < setup {
        return Ok((1, index as u16, MAX_BLOB_BYTES as usize));
    }
    let p = index - setup;
    let (role, ordinal, cap) = match p {
        0 => (2, 0, bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES),
        1 => (3, 0, bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES),
        2 => (4, 0, bfv_query_core::MAX_PRIVATE_COEFFICIENT_RESPONSE_BYTES),
        3 => (5, 0, bfv_mul_relin_proof::input_frame_limit(0).unwrap()),
        4 => (
            6,
            0,
            registry200_proof::coefficient_encoding::wire::MAX_SOURCE,
        ),
        5..=6 => (
            7,
            (p - 5) as u16,
            registry200_proof::coefficient_encoding::wire::MAX_CHILD,
        ),
        7..=16 => (
            8,
            (p - 7) as u16,
            bfv_mul_relin_proof::input_frame_limit(3).unwrap(),
        ),
        17..=18 => (
            9,
            (p - 17) as u16,
            bfv_mul_relin_proof::input_frame_limit(13).unwrap(),
        ),
        CLAIMS => (10, 0, MAX_CLAIMS_BYTES),
        RECORDS..=LAST_PART => (
            11,
            (p - RECORDS) as u16,
            bfv_mul_relin_proof::RECORD_HEADER + bfv_mul_relin_proof::MAX_PROOF_BYTES,
        ),
        _ => return Err(Error::Encoding),
    };
    if cap > MAX_BLOB_BYTES as usize {
        return Err(Error::ResourceLimit);
    }
    Ok((role, ordinal, cap))
}
