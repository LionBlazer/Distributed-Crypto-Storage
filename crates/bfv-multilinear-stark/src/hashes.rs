//! All 512 output bits are retained; application domains remain consumer-owned.
use crate::Error;
use p3_symmetric::CryptographicHasher;
use sha2::{Digest, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domains {
    leaf: &'static [u8],
    node: &'static [u8],
    transcript: &'static [u8],
    statement: &'static [u8],
}
impl Domains {
    /// Fixed labels must be nonempty and pairwise prefix-free, including the seed label.
    pub fn new(
        leaf: &'static [u8],
        node: &'static [u8],
        transcript: &'static [u8],
        statement: &'static [u8],
    ) -> Result<Self, Error> {
        let labels = [leaf, node, transcript, statement];
        for (i, a) in labels.iter().enumerate() {
            if a.is_empty()
                || labels[i + 1..]
                    .iter()
                    .any(|b| a.starts_with(b) || b.starts_with(a))
            {
                return Err(Error::InvalidDomains);
            }
        }
        Ok(Self {
            leaf,
            node,
            transcript,
            statement,
        })
    }
    pub const fn leaf_hasher(&self) -> Sha512Leaf {
        Sha512Leaf(self.leaf)
    }
    pub const fn node_hasher(&self) -> Sha512Node {
        Sha512Node(self.node)
    }
    pub const fn transcript_hasher(&self) -> Sha512Transcript {
        Sha512Transcript(self.transcript)
    }
    pub const fn leaf(&self) -> &'static [u8] {
        self.leaf
    }
    pub const fn node(&self) -> &'static [u8] {
        self.node
    }
    pub const fn transcript(&self) -> &'static [u8] {
        self.transcript
    }
    pub const fn statement(&self) -> &'static [u8] {
        self.statement
    }
}

pub fn sha512(bytes: &[u8]) -> [u8; 64] {
    Sha512::digest(bytes).into()
}

/// Public for the linked PCS associated type; construction is internal to Config.
#[derive(Clone, Copy, Debug)]
pub struct Sha512Leaf(pub(crate) &'static [u8]);
/// Public for the linked PCS associated type; construction is internal to Config.
#[derive(Clone, Copy, Debug)]
pub struct Sha512Node(pub(crate) &'static [u8]);
/// Public for the linked challenger associated type; construction is internal to Config.
#[derive(Clone, Copy, Debug)]
pub struct Sha512Transcript(pub(crate) &'static [u8]);
fn hash_words(input: impl IntoIterator<Item = u64>, domain: &[u8]) -> [u64; 8] {
    let mut h = Sha512::new();
    h.update(domain);
    for word in input {
        h.update(word.to_le_bytes());
    }
    let bytes: [u8; 64] = h.finalize().into();
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}
impl CryptographicHasher<u64, [u64; 8]> for Sha512Leaf {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 8] {
        hash_words(input, self.0)
    }
}
impl CryptographicHasher<u64, [u64; 8]> for Sha512Node {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 8] {
        hash_words(input, self.0)
    }
}
impl CryptographicHasher<u8, [u8; 64]> for Sha512Transcript {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(self.0);
        for byte in input {
            h.update([byte]);
        }
        h.finalize().into()
    }
}
