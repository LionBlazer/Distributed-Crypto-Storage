use p3_field::PrimeCharacteristicRing;
use p3_sha256_air::SHA256_IV;
use sha2::{Digest, Sha256};

use crate::backend::{Val, profile_digest};

pub(crate) const COMPRESSION_WORDS: usize = 32;
pub(crate) const ID_WORDS: usize = 8;
pub(crate) const PUBLIC_VALUES: usize = ID_WORDS + COMPRESSION_WORDS;

/// Public primitive fixture only. No SQL, CSTORE plaintext or owner keys enter this gate.
#[derive(Clone)]
pub(crate) struct Statement {
    pub(crate) request: [u8; 32],
    pub(crate) block: [u32; 16],
    pub(crate) state: [u32; 8],
    pub(crate) output: [u32; 8],
}

impl Statement {
    pub(crate) fn fixture() -> Self {
        let block = core::array::from_fn(|i| (i as u32).wrapping_mul(0x1020_3041));
        let state = SHA256_IV;
        let output = reference_output(block, state);
        Self {
            request: [0x42; 32],
            block,
            state,
            output,
        }
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"dcs/experiment/hiding-sha256-statement/v1");
        hash.update(profile_digest());
        hash.update(self.request);
        for word in self.block.iter().chain(&self.state).chain(&self.output) {
            hash.update(word.to_be_bytes());
        }
        hash.finalize().into()
    }

    pub(crate) fn identity_values(&self) -> [Val; ID_WORDS] {
        let identity = self.identity();
        core::array::from_fn(|i| {
            Val::from_u32(u32::from_be_bytes(
                identity[i * 4..i * 4 + 4].try_into().unwrap(),
            ))
        })
    }

    pub(crate) fn public_values(&self) -> Vec<Val> {
        self.identity_values()
            .into_iter()
            .chain(
                self.block
                    .iter()
                    .chain(&self.state)
                    .chain(&self.output)
                    .copied()
                    .map(Val::from_u32),
            )
            .collect()
    }

    pub(crate) fn trace_input(&self) -> [u32; 24] {
        let mut input = [0; 24];
        input[..16].copy_from_slice(&self.block);
        input[16..].copy_from_slice(&self.state);
        input
    }
}

/// Independent RustCrypto compression oracle; this does not compute SHA padding/chaining.
pub(crate) fn reference_output(block: [u32; 16], mut state: [u32; 8]) -> [u32; 8] {
    let mut bytes = [0; 64];
    for (word, encoded) in block.iter().zip(bytes.as_chunks_mut::<4>().0) {
        encoded.copy_from_slice(&word.to_be_bytes());
    }
    sha2::compress256(&mut state, &[bytes.into()]);
    state
}
