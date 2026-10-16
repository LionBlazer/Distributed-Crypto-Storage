use crate::format::{leaf, parent, proof_height};
use crate::{Commitment, Error, Limits, PAGE_OVERHEAD, Result};

/// Untrusted peer response. Decoding does not authenticate it.
/// Wire format: index:u64, packet_len:u32, sibling_count:u32, packet, hashes.
#[derive(Clone)]
pub struct LookupResponse {
    pub(crate) index: u64,
    pub(crate) packet: Vec<u8>,
    pub(crate) siblings: Vec<[u8; 32]>,
}

/// Ciphertext authenticated for one exact address against the requested head.
/// This type proves page retrieval, not decryption, computation, SQL completeness,
/// authorization of the supplied head, or consensus freshness.
pub struct VerifiedPage {
    pub(crate) commitment: Commitment,
    pub(crate) index: u64,
    pub(crate) packet: Vec<u8>,
}

impl VerifiedPage {
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
    pub fn page_index(&self) -> u64 {
        self.index
    }
    pub fn page_revision(&self) -> u64 {
        u64::from_le_bytes(self.packet[..8].try_into().unwrap())
    }
    pub fn nonce(&self) -> [u8; 24] {
        self.packet[8..32].try_into().unwrap()
    }
    /// Public encrypted payload, excluding nonce, page revision and AEAD tag.
    /// A future independently validated transciphering adapter can consume this.
    pub fn ciphertext(&self) -> &[u8] {
        &self.packet[32..self.packet.len() - 16]
    }
    pub fn authentication_tag(&self) -> [u8; 16] {
        self.packet[self.packet.len() - 16..].try_into().unwrap()
    }
}

/// Authenticated page and Merkle path retained solely for owner page reissue.
/// Fields stay private; possession grants no authorization, freshness or SQL proof.
/// The caller supplies the independently trusted expected head again at reissue.
/// This value is consumed; an old public proof can still be verified again for an
/// explicitly selected historical head. There is no global spent-head registry.
///
/// ```compile_fail
/// use compact_store::{Commitment, Limits, Owner, VerifiedPagePath};
/// fn twice(owner: &Owner, source: VerifiedPagePath, head: &Commitment) {
///     let _ = owner.reissue_page(source, head, &[], Limits::default());
///     let _ = owner.reissue_page(source, head, &[], Limits::default());
/// }
/// ```
pub struct VerifiedPagePath {
    page: VerifiedPage,
    siblings: Vec<[u8; 32]>,
}
impl VerifiedPagePath {
    pub(crate) fn page(&self) -> &VerifiedPage {
        &self.page
    }
    pub(crate) fn encoded_len(&self) -> usize {
        16 + self.page.packet.len() + self.siblings.len() * 32
    }
    pub(crate) fn reissue(
        self,
        mut next: Commitment,
        packet: Vec<u8>,
    ) -> Result<(Commitment, LookupResponse)> {
        let mut position = usize::try_from(self.page.index).map_err(|_| Error::InvalidPage)?;
        let mut width = self.page.commitment.layout.page_count()?;
        let mut node = leaf(position, &packet);
        let mut siblings = Vec::with_capacity(self.siblings.len());
        for old_sibling in self.siblings {
            // Old duplicate-self siblings were checked by ordinary verification.
            // A new missing sibling must duplicate the NEW node at this level.
            let sibling = if position % 2 == 0 && position + 1 == width {
                node
            } else {
                old_sibling
            };
            siblings.push(sibling);
            node = if position % 2 == 0 {
                parent(&node, &sibling)
            } else {
                parent(&sibling, &node)
            };
            position /= 2;
            width = width.div_ceil(2);
        }
        next.root = next.with_tree_root(node);
        Ok((
            next,
            LookupResponse {
                index: self.page.index,
                packet,
                siblings,
            },
        ))
    }
}

impl LookupResponse {
    pub fn encoded_len(&self) -> usize {
        16 + self.packet.len() + self.siblings.len() * 32
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&(self.packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.packet);
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling);
        }
        bytes
    }

    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self> {
        if bytes.len() > limits.max_response_bytes {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < 16 {
            return Err(Error::InvalidFormat);
        }
        let size = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        if size
            > limits
                .max_page_plaintext_bytes
                .saturating_add(PAGE_OVERHEAD)
            || count > proof_height(limits.max_pages as usize)
        {
            return Err(Error::ResourceLimit);
        }
        let expected_len = 16usize
            .checked_add(size)
            .and_then(|n| n.checked_add(count * 32))
            .ok_or(Error::ResourceLimit)?;
        if size < PAGE_OVERHEAD || bytes.len() != expected_len {
            return Err(Error::InvalidFormat);
        }
        Ok(Self {
            index: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            packet: bytes[16..16 + size].to_vec(),
            siblings: bytes[16 + size..].as_chunks::<32>().0.to_vec(),
        })
    }

    /// Expected must be the independently obtained current/snapshot head.
    /// Index is part of the request; accepting the responder's address is unsafe.
    pub fn verify(
        &self,
        expected: &Commitment,
        index: u64,
        limits: Limits,
    ) -> Result<VerifiedPage> {
        expected.layout.validate(limits)?;
        if self.encoded_len() > limits.max_response_bytes {
            return Err(Error::ResourceLimit);
        }
        if self.index != index {
            return Err(Error::InvalidProof);
        }
        let pages = expected.layout.page_count()?;
        let plaintext_len = expected.layout.page_plaintext_len(index)?;
        if self.packet.len() != plaintext_len + PAGE_OVERHEAD
            || self.siblings.len() != proof_height(pages)
        {
            return Err(Error::InvalidProof);
        }
        let revision = u64::from_le_bytes(self.packet[..8].try_into().unwrap());
        if revision > expected.revision {
            return Err(Error::WrongVersion);
        }
        let mut position = usize::try_from(index).map_err(|_| Error::InvalidPage)?;
        let mut width = pages;
        let mut node = leaf(position, &self.packet);
        for sibling in &self.siblings {
            if position % 2 == 0 {
                if position + 1 == width && *sibling != node {
                    return Err(Error::InvalidProof);
                }
                node = parent(&node, sibling);
            } else {
                node = parent(sibling, &node);
            }
            position /= 2;
            width = width.div_ceil(2);
        }
        if expected.with_tree_root(node) != expected.root {
            return Err(Error::InvalidProof);
        }
        Ok(VerifiedPage {
            commitment: expected.clone(),
            index,
            packet: self.packet.clone(),
        })
    }

    /// Runs ordinary exact-head membership verification, retaining its path for
    /// owner reissue. No raw path or unchecked construction API is exposed.
    pub fn verify_for_reissue(
        &self,
        expected: &Commitment,
        index: u64,
        limits: Limits,
    ) -> Result<VerifiedPagePath> {
        let page = self.verify(expected, index, limits)?;
        Ok(VerifiedPagePath {
            page,
            siblings: self.siblings.clone(),
        })
    }
}
