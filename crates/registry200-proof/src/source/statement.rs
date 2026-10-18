use super::profile_digest;
use super::{DATA_BYTES, DATA_SCHEMA, INDEX_BYTES, INDEX_SCHEMA, Relation};
use bfv_hiding_stark::{Error, Val};
use compact_store::{Commitment, Layout, Limits, VerifiedSnapshotBytes};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
pub const HEADS: usize = 16;
pub const PACKETS: usize = 72;
pub const KEY_COMMITMENT: usize = 683;
pub const OPEN_COMMITMENT: usize = 687;
pub const PUBLIC_VALUES: usize = 691;

/// PUBLIC mathematical claim only: no key, salt, plaintext or trace method.
/// Expected heads and the stable key commitment must be authorized independently.
/// Canonical/root validation supplies no consensus, custody or logical-index proof.
#[derive(Clone)]
pub struct Statement {
    pub relation: Relation,
    pub request: [u8; 32],
    pub heads: [[u8; 112]; 2],
    pub packets: [Vec<u8>; 2],
    pub key_commitment: [Val; 4],
    pub open_commitment: [Val; 4],
}
impl Statement {
    /// Rechecks mutable public geometry and complete canonical ciphertext images.
    /// This supplies no AEAD, index, key-possession or proof authority.
    pub fn reaudit(&self) -> Result<(), Error> {
        if self.packets[0].len() != 60 || self.packets[1].len() != 2384 {
            return Err(Error::Shape);
        }
        let heads = [
            Commitment::decode(&self.heads[0], limits()).map_err(|_| Error::Shape)?,
            Commitment::decode(&self.heads[1], limits()).map_err(|_| Error::Shape)?,
        ];
        let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
            self.heads[i]
                .iter()
                .chain(&self.packets[i])
                .copied()
                .collect()
        });
        Self::checked_relation(
            self.relation,
            [&images[0], &images[1]],
            [&heads[0], &heads[1]],
            self.request,
            encode_digest(self.key_commitment),
            encode_digest(self.open_commitment),
        )?;
        Ok(())
    }
    pub fn checked(
        images: [&[u8]; 2],
        expected: [&Commitment; 2],
        request: [u8; 32],
        key: [u8; 32],
        opening: [u8; 32],
    ) -> Result<Self, Error> {
        Self::checked_relation(Relation::Bytes, images, expected, request, key, opening)
    }
    pub fn checked_relation(
        relation: Relation,
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
            relation,
            request,
            heads: expected.map(Commitment::encode),
            packets: images.map(|bytes| bytes[112..].to_vec()),
            key_commitment: decode_digest(key)?,
            open_commitment: decode_digest(opening)?,
        })
    }
    pub fn nonce(&self, page: usize) -> [u8; 24] {
        self.packets[page][8..32].try_into().unwrap()
    }
    pub fn ciphertext(&self, page: usize) -> &[u8] {
        let n = if page == 0 { DATA_BYTES } else { INDEX_BYTES };
        &self.packets[page][32..32 + n]
    }
    pub fn tag(&self, page: usize) -> [u32; 4] {
        let p = &self.packets[page];
        core::array::from_fn(|w| {
            u32::from_le_bytes(
                p[p.len() - 16 + 4 * w..p.len() - 12 + 4 * w]
                    .try_into()
                    .unwrap(),
            )
        })
    }
    pub fn aad(&self, page: usize) -> Vec<u8> {
        let mut out = b"compact-store/page-aead/v1".to_vec();
        let h = &self.heads[page];
        out.extend_from_slice(&h[8..56]);
        out.extend_from_slice(&h[64..80]);
        out.extend_from_slice(&0_u64.to_le_bytes());
        out.extend_from_slice(&self.packets[page][..8]);
        assert_eq!(out.len(), 106);
        out
    }
    pub fn mac_block(&self, page: usize, block: usize) -> [u8; 16] {
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
impl Statement {
    pub fn values(&self) -> Vec<Val> {
        words(&profile_digest(self.relation))
            .chain(words(&self.request))
            .chain(self.heads.iter().flat_map(|h| words(h)))
            .chain(self.packets.iter().flat_map(|p| words(p)))
            .chain(self.key_commitment)
            .chain(self.open_commitment)
            .collect()
    }
}
pub fn words(bytes: &[u8]) -> impl Iterator<Item = Val> + '_ {
    assert_eq!(bytes.len() % 4, 0);
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| Val::from_u32(u32::from_le_bytes(*b)))
}
pub fn decode_digest(bytes: [u8; 32]) -> Result<[Val; 4], Error> {
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
pub fn encode_digest(digest: [Val; 4]) -> [u8; 32] {
    let mut out = [0; 32];
    for (b, v) in out.as_chunks_mut::<8>().0.iter_mut().zip(digest) {
        *b = v.as_canonical_u64().to_le_bytes();
    }
    out
}
pub fn limits() -> Limits {
    Limits {
        max_rows: 2336,
        max_pages: 1,
        max_page_plaintext_bytes: 4096,
        max_image_bytes: 2496,
        max_response_bytes: 4096,
    }
}
