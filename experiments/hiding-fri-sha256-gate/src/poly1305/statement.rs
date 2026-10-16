use ::poly1305::Poly1305;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha256};
use universal_hash::{KeyInit, UniversalHash};

use super::air::Poly1305Air;
use super::{BLOCK_BYTES, MAX_BLOCKS, MAX_BYTES, MAX_SEGMENTS};
use crate::backend::{Error, Val, profile_digest};
use crate::primitive::{Kind, PrimitiveAir, PrimitiveStatement};
use crate::statement::ID_WORDS;

pub(crate) const KEY_PUBLIC: usize = ID_WORDS;
pub(crate) const PAYLOAD_PUBLIC: usize = KEY_PUBLIC + 32;
pub(crate) const META_PUBLIC: usize = PAYLOAD_PUBLIC + MAX_BYTES;
pub(crate) const TAG_PUBLIC: usize = META_PUBLIC + MAX_SEGMENTS + 2;
pub(crate) const PUBLIC_VALUES: usize = TAG_PUBLIC + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Raw,
    PaddedSegments,
}
impl Mode {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::PaddedSegments => 1,
        }
    }
    fn kind(self) -> Kind {
        match self {
            Self::Raw => Kind::Poly1305Raw,
            Self::PaddedSegments => Kind::Poly1305Padded,
        }
    }
}

/// Mapping contains positions, never an independently supplied message block.
#[derive(Clone, Copy)]
pub(crate) struct Block {
    pub(crate) payload: [Option<usize>; BLOCK_BYTES],
    pub(crate) appended_bit: usize,
}
#[derive(Clone)]
pub(crate) struct Layout {
    pub(crate) mode: Mode,
    pub(crate) lengths: [usize; MAX_SEGMENTS],
    pub(crate) segments: usize,
    pub(crate) bytes: usize,
    pub(crate) blocks: [Block; MAX_BLOCKS],
    pub(crate) active: usize,
}
impl Layout {
    fn checked(mode: Mode, segments: &[&[u8]]) -> Result<Self, Error> {
        // Bound descriptor count separately: arbitrarily many empty slices must
        // not bypass the three-block resource policy.
        if segments.len() > MAX_SEGMENTS || (mode == Mode::Raw && segments.len() != 1) {
            return Err(Error::Shape);
        }
        let mut result = Self {
            mode,
            lengths: [0; MAX_SEGMENTS],
            segments: segments.len(),
            bytes: 0,
            blocks: [Block {
                payload: [None; BLOCK_BYTES],
                appended_bit: 0,
            }; MAX_BLOCKS],
            active: 0,
        };
        for (segment, bytes) in segments.iter().enumerate() {
            if bytes.len() > MAX_BYTES {
                return Err(Error::Shape);
            }
            let blocks = bytes.len().div_ceil(BLOCK_BYTES);
            if result.active + blocks > MAX_BLOCKS || result.bytes + bytes.len() > MAX_BYTES {
                return Err(Error::Shape);
            }
            result.lengths[segment] = bytes.len();
            for (block, chunk) in bytes.chunks(BLOCK_BYTES).enumerate() {
                result.blocks[result.active + block] = Block {
                    payload: core::array::from_fn(|byte| {
                        (byte < chunk.len()).then_some(result.bytes + block * BLOCK_BYTES + byte)
                    }),
                    appended_bit: if mode == Mode::Raw {
                        chunk.len() * 8
                    } else {
                        128
                    },
                };
            }
            result.active += blocks;
            result.bytes += bytes.len();
        }
        Ok(result)
    }
}

/// All bytes are explicitly PUBLIC NONSECRET. Checked construction pins the
/// original segment boundaries before any oracle, trace or proof allocation.
#[derive(Clone)]
pub(crate) struct Statement {
    pub(crate) request: [u8; 32],
    pub(crate) key: [u8; 32],
    pub(crate) tag: [u8; 16],
    payload: [u8; MAX_BYTES],
    layout: Layout,
}
impl Statement {
    pub(crate) fn raw(key: [u8; 32], payload: &[u8]) -> Result<Self, Error> {
        Self::new(key, Mode::Raw, &[payload])
    }
    pub(crate) fn padded(key: [u8; 32], segments: &[&[u8]]) -> Result<Self, Error> {
        Self::new(key, Mode::PaddedSegments, segments)
    }
    fn new(key: [u8; 32], mode: Mode, segments: &[&[u8]]) -> Result<Self, Error> {
        let layout = Layout::checked(mode, segments)?;
        let mut payload = [0; MAX_BYTES];
        let mut offset = 0;
        for segment in segments {
            payload[offset..offset + segment.len()].copy_from_slice(segment);
            offset += segment.len();
        }
        let mut result = Self {
            request: [0x50; 32],
            key,
            tag: [0; 16],
            payload,
            layout,
        };
        result.tag = reference_tag(&result);
        Ok(result)
    }
    pub(crate) fn raw_fixture() -> Self {
        Self::raw(public_key(), b"Cryptographic Forum Research Group").unwrap()
    }
    pub(crate) fn padded_fixture() -> Self {
        Self::padded(public_key(), &[b"public aad", b"public ciphertext"]).unwrap()
    }
    pub(crate) fn layout(&self) -> &Layout {
        &self.layout
    }
    pub(crate) fn payload(&self) -> &[u8; MAX_BYTES] {
        &self.payload
    }
    pub(crate) fn identity(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"dcs/experiment/public-poly1305-statement/v1");
        hash.update(profile_digest(self.kind()));
        hash.update(self.request);
        hash.update(self.key);
        hash.update([self.layout.mode.code(), self.layout.segments as u8]);
        for length in self.layout.lengths {
            hash.update((length as u64).to_le_bytes());
        }
        hash.update(self.payload);
        hash.update(self.tag);
        hash.finalize().into()
    }
    pub(crate) fn identity_values(&self) -> [Val; ID_WORDS] {
        let digest = self.identity();
        core::array::from_fn(|word| {
            Val::from_u32(u32::from_le_bytes(
                digest[word * 4..word * 4 + 4].try_into().unwrap(),
            ))
        })
    }
}
impl PrimitiveStatement for Statement {
    fn kind(&self) -> Kind {
        self.layout.mode.kind()
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Poly1305(Box::new(Poly1305Air::new(self)))
    }
    fn trace(&self) -> RowMajorMatrix<Val> {
        Poly1305Air::trace(self)
    }
    fn public_values(&self) -> Vec<Val> {
        self.identity_values()
            .into_iter()
            .chain(self.key.into_iter().map(Val::from_u8))
            .chain(self.payload.into_iter().map(Val::from_u8))
            .chain(self.layout.lengths.into_iter().map(Val::from_usize))
            .chain([
                Val::from_usize(self.layout.segments),
                Val::from_u8(self.layout.mode.code()),
            ])
            .chain(
                self.tag
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|bytes| Val::from_u32(u32::from_le_bytes(*bytes))),
            )
            .collect()
    }
}

/// Independent RustCrypto oracle; it shares neither radix arithmetic nor AIR.
pub(crate) fn reference_tag(statement: &Statement) -> [u8; 16] {
    let mut mac = Poly1305::new(&statement.key.into());
    let output = match statement.layout.mode {
        Mode::Raw => mac.compute_unpadded(&statement.payload[..statement.layout.bytes]),
        Mode::PaddedSegments => {
            let mut offset = 0;
            for length in &statement.layout.lengths[..statement.layout.segments] {
                mac.update_padded(&statement.payload[offset..offset + length]);
                offset += length;
            }
            mac.finalize()
        }
    };
    output.into()
}

/// RFC 8439 section 2.5.2 test key, public and nonsecret.
pub(crate) fn public_key() -> [u8; 32] {
    [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ]
}
