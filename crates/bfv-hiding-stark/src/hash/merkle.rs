//! Scalar SHA-256 Merkle candidate with disjoint leaf and binary-node encodings.
//!
//! This framing is conditional on the ordinary SHA-256 random-oracle model. It
//! creates neither salts nor an RNG, and supplies no live proof admission. The
//! caller owns the hiding-MMCS configuration and its unpredictable salt stream.

use crate::Val;
use p3_field::PrimeField64;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use sha2::{Digest, Sha256};

/// Fixed leaf identity; changing this prefix changes the candidate protocol.
pub const LEAF_DOMAIN: &[u8] = b"DCS/research/hash-hiding-FRI/SHA256/leaf/ValLE8/countLE64/v1\0";
/// Fixed node identity, distinct from and not a prefix of the leaf identity.
pub const NODE_DOMAIN: &[u8] = b"DCS/research/hash-hiding-FRI/SHA256/node/binary32/v1\0";

/// Hash `LEAF_DOMAIN || canonical_field_LE8* || field_count_LE64` in one pass.
/// Fixed-width canonical words and the final count make this encoding injective.
#[derive(Clone, Copy, Debug, Default)]
pub struct LeafHash;

impl CryptographicHasher<Val, [u8; 32]> for LeafHash {
    /// Panics rather than wrapping if the stream exceeds the leaf count encoding
    /// or SHA-256's maximum representable message bit length.
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = Val>,
    {
        let mut hash = Sha256::new();
        hash.update(LEAF_DOMAIN);
        let mut count = 0u64;
        for field in input {
            count = next_leaf_count(count);
            hash.update(field.as_canonical_u64().to_le_bytes());
        }
        hash.update(count.to_le_bytes());
        hash.finalize().into()
    }
}

fn next_leaf_count(count: u64) -> u64 {
    let next = count.checked_add(1).expect("leaf field count overflow");
    let domain_bytes = u64::try_from(LEAF_DOMAIN.len()).expect("fixed leaf domain fits u64");
    let message_bytes = next
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(domain_bytes))
        .and_then(|bytes| bytes.checked_add(8))
        .expect("leaf byte count overflow");
    assert!(
        message_bytes <= u64::MAX / 8,
        "leaf exceeds SHA-256 message bit-length limit"
    );
    next
}

/// Hash `NODE_DOMAIN || left_digest32 || right_digest32`, preserving child order.
/// Digests remain all 256 SHA bits; no field conversion or reduction is applied.
#[derive(Clone, Copy, Debug, Default)]
pub struct NodeCompress;

impl PseudoCompressionFunction<[u8; 32], 2> for NodeCompress {
    fn compress(&self, input: [[u8; 32]; 2]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(NODE_DOMAIN);
        for child in input {
            hash.update(child);
        }
        hash.finalize().into()
    }
}

#[cfg(test)]
mod tests;
