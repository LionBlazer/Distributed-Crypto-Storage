use crate::format::{hash, leaf, parent};
use crate::{
    Commitment, Error, Limits, LookupResponse, MANIFEST_BYTES, PAGE_OVERHEAD, Result, VerifiedPage,
};
use std::sync::Arc;

/// Peer-owned opaque ciphertext pages plus a rebuildable in-memory Merkle index.
/// Clones share immutable ciphertext allocations, with independent slots and trees.
/// Does not contain plaintext or secret keys. Addresses and lengths are public.
#[derive(Clone)]
pub struct EncryptedSnapshot {
    commitment: Commitment,
    pages: Vec<Packet>,
    levels: Vec<Vec<[u8; 32]>>,
}

// The packet allocation is never exposed or mutated after admission. A new
// version replaces its own slot; old snapshots retain their exact ciphertext.
#[derive(Clone)]
struct Packet(Arc<[u8]>);
impl Packet {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::from(bytes))
    }
    fn from_slice(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }
    fn bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl EncryptedSnapshot {
    pub(crate) fn from_owner(commitment: Commitment, pages: Vec<Vec<u8>>) -> Self {
        Self::from_packets(commitment, pages.into_iter().map(Packet::new).collect())
    }

    fn from_packets(mut commitment: Commitment, pages: Vec<Packet>) -> Self {
        let levels = build_tree(&pages);
        commitment.root = commitment.with_tree_root(tree_root(&levels));
        Self {
            commitment,
            pages,
            levels,
        }
    }

    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Canonical live disk bytes, including manifest, nonce, revision and AEAD tag.
    pub fn encoded_len(&self) -> usize {
        MANIFEST_BYTES
            + self
                .pages
                .iter()
                .map(|page| page.bytes().len())
                .sum::<usize>()
    }

    /// Hash payload of the rebuildable index; allocator/Vec overhead is separate.
    pub fn index_hash_bytes(&self) -> usize {
        self.levels.iter().map(|level| level.len() * 32).sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.commitment.encode());
        for packet in &self.pages {
            bytes.extend_from_slice(packet.bytes());
        }
        bytes
    }

    /// Imports ciphertext only for an independently trusted, exact read head.
    /// Rejects another version before allocating pages, then checks every page's
    /// contribution to the root. The caller still owns the head's provenance and
    /// freshness; accepting an old trusted head intentionally permits an old image.
    pub fn decode_for_head(bytes: &[u8], expected: &Commitment, limits: Limits) -> Result<Self> {
        Ok(VerifiedSnapshotBytes::decode_for_head(bytes, expected, limits)?.into_snapshot())
    }

    /// Parses exact, tightly bounded storage, rebuilding and checking its root.
    /// The embedded root's provenance still needs an independent trust source.
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self> {
        Ok(VerifiedSnapshotBytes::parse(bytes, None, limits)?.into_snapshot())
    }

    /// O(log pages) proof construction from the cached tree. Exact page index
    /// is visible to the peer, as are repeated accesses and response size.
    pub fn lookup(&self, index: u64, limits: Limits) -> Result<LookupResponse> {
        self.commitment.layout.validate(limits)?;
        let index = usize::try_from(index).map_err(|_| Error::InvalidPage)?;
        let packet = self.pages.get(index).ok_or(Error::InvalidPage)?.bytes();
        lookup_packet(&self.levels, index, packet, limits)
    }

    /// Reconstructs an exact target image from an already authenticated base.
    /// Every replacement must belong to `next`; omitted changes fail the final
    /// complete-root check. This consumes ciphertext only, supplies no owner
    /// authorization or SQL proof, and cannot alter the caller's durable base.
    /// An unchanged image accepts only its exact old head and no replacements.
    pub fn apply_verified_replacements(
        mut self,
        expected: &Commitment,
        next: &Commitment,
        replacements: Vec<VerifiedPage>,
        limits: Limits,
    ) -> Result<Self> {
        if self.commitment() != expected {
            return Err(Error::WrongVersion);
        }
        expected.layout.validate(limits)?;
        next.layout.validate(limits)?;
        if expected == next && replacements.is_empty() {
            return Ok(self);
        }
        if expected.database != next.database
            || expected.domain != next.domain
            || expected.layout != next.layout
            || expected.revision.checked_add(1) != Some(next.revision)
        {
            return Err(Error::WrongVersion);
        }
        if replacements.is_empty() || replacements.len() > self.pages.len() {
            return Err(Error::InvalidPage);
        }
        let mut seen = std::collections::BTreeSet::new();
        for page in &replacements {
            if page.commitment() != next {
                return Err(Error::WrongVersion);
            }
            if !seen.insert(page.index)
                || page.packet.len() != next.layout.page_plaintext_len(page.index)? + PAGE_OVERHEAD
            {
                return Err(Error::InvalidPage);
            }
            if page.page_revision() > next.revision {
                return Err(Error::WrongVersion);
            }
        }
        for page in replacements {
            self.replace_from_owner(next.clone(), page.index as usize, page.packet);
        }
        if self.commitment() != next {
            return Err(Error::InvalidProof);
        }
        Ok(self)
    }

    pub(crate) fn replace_from_owner(
        &mut self,
        mut next: Commitment,
        index: usize,
        packet: Vec<u8>,
    ) {
        self.pages[index] = Packet::new(packet);
        self.levels[0][index] = leaf(index, self.pages[index].bytes());
        let mut position = index;
        for level in 1..self.levels.len() {
            position /= 2;
            let children = &self.levels[level - 1];
            let left = &children[position * 2];
            let right = &children[(position * 2 + 1).min(children.len() - 1)];
            self.levels[level][position] = parent(left, right);
        }
        next.root = next.with_tree_root(tree_root(&self.levels));
        self.commitment = next;
    }
}

/// Fully audited canonical image bytes borrowed for this local operation.
/// The private constructor checks every packet and the complete root. No Clone,
/// Deserialize or mutable bytes API can manufacture or change this lineage.
/// Independently trusted heads and owner AEAD checks remain the caller's work.
/// Materialization consumes the audit and retains its checked Merkle levels.
///
/// The input must remain immutable while the audit can still be used:
/// ```compile_fail
/// use compact_store::{Commitment, Limits, VerifiedSnapshotBytes};
/// fn change(bytes: &mut [u8], head: &Commitment) {
///     let checked = VerifiedSnapshotBytes::decode_for_head(bytes, head, Limits::default()).unwrap();
///     bytes[112] ^= 1;
///     let _ = checked.into_snapshot();
/// }
/// ```
/// The audit cannot outlive its input:
/// ```compile_fail
/// use compact_store::{Commitment, Limits, VerifiedSnapshotBytes};
/// fn escape(head: &Commitment) -> VerifiedSnapshotBytes<'static> {
///     let bytes = vec![0; 112];
///     VerifiedSnapshotBytes::decode_for_head(&bytes, head, Limits::default()).unwrap()
/// }
/// ```
pub struct VerifiedSnapshotBytes<'a> {
    bytes: &'a [u8],
    commitment: Commitment,
    levels: Vec<Vec<[u8; 32]>>,
}
impl<'a> VerifiedSnapshotBytes<'a> {
    pub fn decode_for_head(bytes: &'a [u8], expected: &Commitment, limits: Limits) -> Result<Self> {
        Self::parse(bytes, Some(expected), limits)
    }
    // One canonical parser for borrowed validation and owned snapshot imports.
    fn parse(bytes: &'a [u8], expected: Option<&Commitment>, limits: Limits) -> Result<Self> {
        if bytes.len() > limits.max_image_bytes {
            return Err(Error::ResourceLimit);
        }
        let manifest = bytes.get(..MANIFEST_BYTES).ok_or(Error::InvalidFormat)?;
        let commitment = Commitment::decode(manifest, limits)?;
        if expected.is_some_and(|expected| &commitment != expected) {
            return Err(Error::WrongVersion);
        }
        if bytes.len() != commitment.layout.encoded_len()? {
            return Err(Error::InvalidFormat);
        }
        let mut leaves = Vec::with_capacity(commitment.layout.page_count()?);
        for (index, packet) in packets(bytes, commitment.layout).enumerate() {
            if u64::from_le_bytes(packet[..8].try_into().unwrap()) > commitment.revision {
                return Err(Error::InvalidFormat);
            }
            leaves.push(leaf(index, packet));
        }
        let levels = build_levels(leaves);
        if commitment.with_tree_root(tree_root(&levels)) != commitment.root {
            return Err(Error::InvalidProof);
        }
        Ok(Self {
            bytes,
            commitment,
            levels,
        })
    }
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
    /// Ordinary owned membership response, subject to the caller's current caps.
    /// The caller still verifies its independently expected head and address.
    pub fn lookup(&self, index: u64, limits: Limits) -> Result<LookupResponse> {
        self.commitment.layout.validate(limits)?;
        let index = usize::try_from(index).map_err(|_| Error::InvalidPage)?;
        let packet = packets(self.bytes, self.commitment.layout)
            .nth(index)
            .ok_or(Error::InvalidPage)?;
        lookup_packet(&self.levels, index, packet, limits)
    }
    /// Copies packet payloads only when an owned snapshot is actually needed.
    /// The complete checked tree moves with the consumed audit; no second hash pass.
    pub fn into_snapshot(self) -> EncryptedSnapshot {
        let pages = packets(self.bytes, self.commitment.layout)
            .map(Packet::from_slice)
            .collect();
        EncryptedSnapshot {
            commitment: self.commitment,
            pages,
            levels: self.levels,
        }
    }
}

// Called only after exact image length and layout validation. All but the final
// packet have this public full capacity; the final packet can be shorter.
fn packets(bytes: &[u8], layout: crate::Layout) -> std::slice::Chunks<'_, u8> {
    let capacity = layout.row_width as usize * layout.rows_per_page as usize + PAGE_OVERHEAD;
    bytes[MANIFEST_BYTES..].chunks(capacity)
}
fn lookup_packet(
    levels: &[Vec<[u8; 32]>],
    index: usize,
    packet: &[u8],
    limits: Limits,
) -> Result<LookupResponse> {
    let height = levels.len().saturating_sub(1);
    if 16 + packet.len() + height * 32 > limits.max_response_bytes {
        return Err(Error::ResourceLimit);
    }
    let mut siblings = Vec::with_capacity(height);
    let mut position = index;
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling = (position ^ 1).min(level.len() - 1);
        siblings.push(level[sibling]);
        position /= 2;
    }
    let response = LookupResponse {
        index: index as u64,
        packet: packet.to_vec(),
        siblings,
    };
    if response.encoded_len() > limits.max_response_bytes {
        return Err(Error::ResourceLimit);
    }
    Ok(response)
}
fn build_tree(pages: &[Packet]) -> Vec<Vec<[u8; 32]>> {
    build_levels(
        pages
            .iter()
            .enumerate()
            .map(|(index, page)| leaf(index, page.bytes()))
            .collect(),
    )
}
fn build_levels(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let next = previous
            .chunks(2)
            .map(|pair| parent(&pair[0], pair.get(1).unwrap_or(&pair[0])))
            .collect();
        levels.push(next);
    }
    levels
}

fn tree_root(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    levels
        .last()
        .map(|level| level[0])
        .unwrap_or_else(|| hash(&[b"compact-store/empty/v1"]))
}
