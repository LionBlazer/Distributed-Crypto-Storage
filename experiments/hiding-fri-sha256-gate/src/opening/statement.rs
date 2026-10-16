use super::{DATA_BYTES, DATA_SCHEMA, INDEX_BYTES, INDEX_SCHEMA};
use crate::backend::{Error, Val, profile_digest};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use compact_store::{Commitment, Layout, Limits, VerifiedSnapshotBytes};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
pub(crate) const HEADS: usize = 16;
#[cfg(test)]
pub(crate) const PACKETS: usize = 72;
pub(crate) const KEY_COMMITMENT: usize = 683;
pub(crate) const OPEN_COMMITMENT: usize = 687;
pub(crate) const PUBLIC_VALUES: usize = 691;

/// Checked PUBLIC statement only: no key, salt, plaintext or trace method.
/// Expected heads and the stable key commitment must be authorized independently.
/// Canonical/root validation supplies no consensus, custody or logical-index proof.
#[derive(Clone)]
pub(crate) struct Statement {
    pub(super) request: [u8; 32],
    pub(super) heads: [[u8; 112]; 2],
    pub(super) packets: [Vec<u8>; 2],
    pub(super) key_commitment: [Val; 4],
    pub(super) open_commitment: [Val; 4],
}
impl Statement {
    pub(crate) fn checked(
        images: [&[u8]; 2],
        expected: [&Commitment; 2],
        request: [u8; 32],
        key: [u8; 32],
        opening: [u8; 32],
    ) -> Result<Self, Error> {
        // Complete canonical audits use the core's single parser and full roots.
        // Bound total public geometry before any AIR, trace or commitment work.
        if images[0].len() != 172 || images[1].len() != 2496 {
            return Err(Error::Shape);
        }
        for page in 0..2 {
            VerifiedSnapshotBytes::decode_for_head(images[page], expected[page], limits())
                .map_err(|_| Error::Shape)?;
            let wanted = if page == 0 {
                Layout {
                    schema: DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                }
            } else {
                Layout {
                    schema: INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: INDEX_BYTES as u64,
                }
            };
            if expected[page].layout() != wanted {
                return Err(Error::Shape);
            }
        }
        if expected[0].database() != expected[1].database()
            || expected[0].key_domain() != expected[1].key_domain()
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            request,
            heads: expected.map(Commitment::encode),
            packets: images.map(|bytes| bytes[112..].to_vec()),
            key_commitment: decode_digest(key)?,
            open_commitment: decode_digest(opening)?,
        })
    }
    pub(super) fn nonce(&self, page: usize) -> [u8; 24] {
        self.packets[page][8..32].try_into().unwrap()
    }
    pub(super) fn ciphertext(&self, page: usize) -> &[u8] {
        let n = if page == 0 { DATA_BYTES } else { INDEX_BYTES };
        &self.packets[page][32..32 + n]
    }
    pub(super) fn tag(&self, page: usize) -> [u32; 4] {
        let p = &self.packets[page];
        core::array::from_fn(|w| {
            u32::from_le_bytes(
                p[p.len() - 16 + 4 * w..p.len() - 12 + 4 * w]
                    .try_into()
                    .unwrap(),
            )
        })
    }
    pub(super) fn aad(&self, page: usize) -> Vec<u8> {
        let mut out = b"compact-store/page-aead/v1".to_vec();
        let h = &self.heads[page];
        out.extend_from_slice(&h[8..56]);
        out.extend_from_slice(&h[64..80]);
        out.extend_from_slice(&0_u64.to_le_bytes());
        out.extend_from_slice(&self.packets[page][..8]);
        assert_eq!(out.len(), 106);
        out
    }
    pub(super) fn mac_block(&self, page: usize, block: usize) -> [u8; 16] {
        let cipher = self.ciphertext(page);
        let blocks = cipher.len().div_ceil(16);
        if block < 7 {
            let aad = self.aad(page);
            core::array::from_fn(|b| aad.get(block * 16 + b).copied().unwrap_or(0))
        } else if block < 7 + blocks {
            core::array::from_fn(|b| cipher.get((block - 7) * 16 + b).copied().unwrap_or(0))
        } else {
            assert_eq!(block, 7 + blocks);
            let mut result = [0; 16];
            result[..8].copy_from_slice(&106_u64.to_le_bytes());
            result[8..].copy_from_slice(&(cipher.len() as u64).to_le_bytes());
            result
        }
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::PairOpening
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Opening(Box::new(super::air::OpeningAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        words(&profile_digest(Kind::PairOpening))
            .chain(words(&self.request))
            .chain(self.heads.iter().flat_map(|h| words(h)))
            .chain(self.packets.iter().flat_map(|p| words(p)))
            .chain(self.key_commitment)
            .chain(self.open_commitment)
            .collect()
    }
}
pub(super) fn words(bytes: &[u8]) -> impl Iterator<Item = Val> + '_ {
    assert_eq!(bytes.len() % 4, 0);
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| Val::from_u32(u32::from_le_bytes(*b)))
}
pub(super) fn decode_digest(bytes: [u8; 32]) -> Result<[Val; 4], Error> {
    let mut out = [Val::ZERO; 4];
    for (v, b) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
        let n = u64::from_le_bytes(*b);
        if n >= Val::ORDER_U64 {
            return Err(Error::Shape);
        }
        *v = Val::from_u64(n);
    }
    Ok(out)
}
pub(super) fn encode_digest(digest: [Val; 4]) -> [u8; 32] {
    let mut out = [0; 32];
    for (b, v) in out.as_chunks_mut::<8>().0.iter_mut().zip(digest) {
        *b = v.as_canonical_u64().to_le_bytes();
    }
    out
}
pub(super) fn limits() -> Limits {
    Limits {
        max_rows: 2336,
        max_pages: 1,
        max_page_plaintext_bytes: 4096,
        max_image_bytes: 2496,
        max_response_bytes: 4096,
    }
}
