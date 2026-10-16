use crate::format::{hash, leaf, parent};
use crate::{
    Commitment, Error, Limits, LookupResponse, MANIFEST_BYTES, PAGE_OVERHEAD, Result, VerifiedPage,
};

/// Peer-owned opaque ciphertext pages plus a rebuildable in-memory Merkle index.
/// Does not contain plaintext or secret keys. Addresses and lengths are public.
#[derive(Clone)]
pub struct EncryptedSnapshot {
    commitment: Commitment,
    pages: Vec<Vec<u8>>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl EncryptedSnapshot {
    pub(crate) fn from_owner(mut commitment: Commitment, pages: Vec<Vec<u8>>) -> Self {
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
        MANIFEST_BYTES + self.pages.iter().map(Vec::len).sum::<usize>()
    }

    /// Hash payload of the rebuildable index; allocator/Vec overhead is separate.
    pub fn index_hash_bytes(&self) -> usize {
        self.levels.iter().map(|level| level.len() * 32).sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.commitment.encode());
        for packet in &self.pages {
            bytes.extend_from_slice(packet);
        }
        bytes
    }

    /// Imports ciphertext only for an independently trusted, exact read head.
    /// Rejects another version before allocating pages, then checks every page's
    /// contribution to the root. The caller still owns the head's provenance and
    /// freshness; accepting an old trusted head intentionally permits an old image.
    pub fn decode_for_head(bytes: &[u8], expected: &Commitment, limits: Limits) -> Result<Self> {
        if bytes.len() > limits.max_image_bytes {
            return Err(Error::ResourceLimit);
        }
        let manifest = bytes.get(..MANIFEST_BYTES).ok_or(Error::InvalidFormat)?;
        let received = Commitment::decode(manifest, limits)?;
        if &received != expected {
            return Err(Error::WrongVersion);
        }
        Self::decode(bytes, limits)
    }

    /// Parses exact, tightly bounded storage, rebuilding and checking its root.
    /// The embedded root's provenance still needs an independent trust source.
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self> {
        if bytes.len() > limits.max_image_bytes {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < MANIFEST_BYTES {
            return Err(Error::InvalidFormat);
        }
        let commitment = Commitment::decode(&bytes[..MANIFEST_BYTES], limits)?;
        if bytes.len() != commitment.layout.encoded_len()? {
            return Err(Error::InvalidFormat);
        }
        let count = commitment.layout.page_count()?;
        let mut pages = Vec::with_capacity(count);
        let mut offset = MANIFEST_BYTES;
        for index in 0..count {
            let len = commitment.layout.page_plaintext_len(index as u64)? + PAGE_OVERHEAD;
            let packet = &bytes[offset..offset + len];
            if u64::from_le_bytes(packet[..8].try_into().unwrap()) > commitment.revision {
                return Err(Error::InvalidFormat);
            }
            pages.push(packet.to_vec());
            offset += len;
        }
        let snapshot = Self::from_owner(commitment.clone(), pages);
        if snapshot.commitment != commitment {
            return Err(Error::InvalidProof);
        }
        Ok(snapshot)
    }

    /// O(log pages) proof construction from the cached tree. Exact page index
    /// is visible to the peer, as are repeated accesses and response size.
    pub fn lookup(&self, index: u64, limits: Limits) -> Result<LookupResponse> {
        self.commitment.layout.validate(limits)?;
        let index = usize::try_from(index).map_err(|_| Error::InvalidPage)?;
        let packet = self.pages.get(index).ok_or(Error::InvalidPage)?;
        let height = self.levels.len().saturating_sub(1);
        if 16 + packet.len() + height * 32 > limits.max_response_bytes {
            return Err(Error::ResourceLimit);
        }
        let mut siblings = Vec::with_capacity(height);
        let mut position = index;
        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let sibling = (position ^ 1).min(level.len() - 1);
            siblings.push(level[sibling]);
            position /= 2;
        }
        let response = LookupResponse {
            index: index as u64,
            packet: packet.clone(),
            siblings,
        };
        if response.encoded_len() > limits.max_response_bytes {
            return Err(Error::ResourceLimit);
        }
        Ok(response)
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
        self.pages[index] = packet;
        self.levels[0][index] = leaf(index, &self.pages[index]);
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

fn build_tree(pages: &[Vec<u8>]) -> Vec<Vec<[u8; 32]>> {
    if pages.is_empty() {
        return Vec::new();
    }
    let mut levels = vec![
        pages
            .iter()
            .enumerate()
            .map(|(i, page)| leaf(i, page))
            .collect::<Vec<_>>(),
    ];
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
