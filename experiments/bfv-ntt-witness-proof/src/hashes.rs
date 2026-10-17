//! Standard SHA512 adapters for the existing P3 hash interfaces.
use p3_symmetric::CryptographicHasher;
use sha2::{Digest, Sha512};

fn words(bytes: [u8; 64]) -> [u64; 8] {
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Leaf;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Node;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Transcript;
fn hash_words(input: impl IntoIterator<Item = u64>, domain: &[u8]) -> [u64; 8] {
    let mut h = Sha512::new();
    h.update(domain);
    for word in input {
        h.update(word.to_le_bytes());
    }
    words(h.finalize().into())
}
impl CryptographicHasher<u64, [u64; 8]> for Leaf {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 8] {
        hash_words(input, b"DCS/NTT-WITNESS/v1/MERKLE-LEAF/LE64/")
    }
}
impl CryptographicHasher<u64, [u64; 8]> for Node {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 8] {
        hash_words(input, b"DCS/NTT-WITNESS/v1/MERKLE-NODE/LE64/")
    }
}
impl CryptographicHasher<u8, [u8; 64]> for Transcript {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(b"DCS/NTT-WITNESS/v1/FIAT-SHAMIR/BYTES/");
        for byte in input {
            h.update([byte]);
        }
        h.finalize().into()
    }
}
