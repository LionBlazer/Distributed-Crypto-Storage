//! Public nonsecret Poly1305 research relation, never a private source or AEAD proof.
pub(crate) mod air;
pub(crate) use registry200_proof::source::poly1305 as arithmetic;
pub(crate) mod statement;
#[cfg(test)]
mod tests;

pub(crate) const BLOCK_BYTES: usize = 16;
/// Small-fixture experiment policy, not a production page/message limit.
pub(crate) const MAX_BLOCKS: usize = 3;
pub(crate) const MAX_SEGMENTS: usize = 3;
pub(crate) const MAX_BYTES: usize = MAX_BLOCKS * BLOCK_BYTES;
pub(crate) use registry200_proof::source::poly1305::{CLAMP, LIMB_BITS, LIMBS, MASK, RADIX};
