use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, consts::U10},
    hchacha,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha256};

use super::{CONSTANTS, WORDS, air::ChaChaAir};
use crate::backend::{Val, profile_digest};
use crate::primitive::{Kind, PrimitiveAir, PrimitiveStatement, PublicStatement};
use crate::statement::ID_WORDS;

pub(crate) const PUBLIC_VALUES: usize = ID_WORDS + 2 * WORDS;

/// Every byte is an explicitly PUBLIC NONSECRET RFC/draft fixture. This type
/// must never be reused as an owner-key witness or a network request.
#[derive(Clone)]
pub(crate) struct Statement {
    pub(crate) kind: Kind,
    pub(crate) request: [u8; 32],
    pub(crate) input: [u32; WORDS],
    // HChaCha uses the first eight words; the remaining words must be zero.
    pub(crate) output: [u32; WORDS],
}

impl Statement {
    pub(crate) fn hchacha_fixture() -> Self {
        let mut input = [0; WORDS];
        input[..4].copy_from_slice(&CONSTANTS);
        for (i, word) in input[4..12].iter_mut().enumerate() {
            *word = u32::from_le_bytes(core::array::from_fn(|j| (i * 4 + j) as u8));
        }
        input[12..].copy_from_slice(&[0x0900_0000, 0x4a00_0000, 0, 0x2759_4131]);
        let mut statement = Self {
            kind: Kind::HChaCha20,
            request: [0x48; 32],
            input,
            output: [0; WORDS],
        };
        statement.output = reference_output(&statement);
        statement
    }

    pub(crate) fn chacha_fixture() -> Self {
        let mut statement = Self::hchacha_fixture();
        statement.kind = Kind::ChaCha20;
        statement.request = [0x43; 32];
        statement.input[12..].copy_from_slice(&[1, 0x0900_0000, 0x4a00_0000, 0]);
        statement.output = reference_output(&statement);
        statement
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"dcs/experiment/public-chacha-statement/v1");
        hash.update(profile_digest(self.kind));
        hash.update(self.request);
        for word in self.input.iter().chain(&self.output) {
            hash.update(word.to_le_bytes());
        }
        hash.finalize().into()
    }

    pub(crate) fn identity_values(&self) -> [Val; ID_WORDS] {
        let digest = self.identity();
        core::array::from_fn(|i| {
            Val::from_u32(u32::from_le_bytes(
                digest[i * 4..i * 4 + 4].try_into().unwrap(),
            ))
        })
    }
}

impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        self.kind
    }

    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::ChaCha(ChaChaAir::new(self))
    }

    fn public_values(&self) -> Vec<Val> {
        self.identity_values()
            .into_iter()
            .chain(
                self.input
                    .iter()
                    .chain(&self.output)
                    .copied()
                    .map(Val::from_u32),
            )
            .collect()
    }
}

/// Independent pinned RustCrypto oracle. It does not share the AIR's round code.
pub(crate) fn reference_output(statement: &Statement) -> [u32; WORDS] {
    let mut key = [0; 32];
    for (word, bytes) in statement.input[4..12]
        .iter()
        .zip(key.as_chunks_mut::<4>().0)
    {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    let mut result = [0; WORDS];
    match statement.kind {
        Kind::HChaCha20 => {
            let mut nonce = [0; 16];
            for (word, bytes) in statement.input[12..]
                .iter()
                .zip(nonce.as_chunks_mut::<4>().0)
            {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            let output = hchacha::<U10>(&key.into(), &nonce.into());
            for (word, bytes) in result.iter_mut().zip(output.as_chunks::<4>().0) {
                *word = u32::from_le_bytes(*bytes);
            }
        }
        Kind::ChaCha20 => {
            let mut nonce = [0; 12];
            for (word, bytes) in statement.input[13..]
                .iter()
                .zip(nonce.as_chunks_mut::<4>().0)
            {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            let mut output = [0; 64];
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            cipher.seek(u64::from(statement.input[12]) * 64);
            cipher.apply_keystream(&mut output);
            for (word, bytes) in result.iter_mut().zip(output.as_chunks::<4>().0) {
                *word = u32::from_le_bytes(*bytes);
            }
        }
        Kind::Sha256
        | Kind::Poly1305Raw
        | Kind::Poly1305Padded
        | Kind::PairOpening
        | Kind::CanonicalIndexOpening
        | Kind::SelectionOpening
        | Kind::PackedCanonicalIndexOpening
        | Kind::FactorizedPackedCanonicalIndexOpening
        | Kind::StateCertificate
        | Kind::VersionSelection
        | Kind::SelectedEncoding
        | Kind::LockingSelection => {
            unreachable!("SHA has a separate typed fixture")
        }
    }
    result
}

impl PrimitiveStatement for Statement {
    fn trace(&self) -> RowMajorMatrix<Val> {
        ChaChaAir::trace(self)
    }
}
