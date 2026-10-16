//! Public nonsecret Poly1305 research relation, never a private source or AEAD proof.
pub(crate) mod air;
pub(crate) mod arithmetic;
pub(crate) mod statement;
#[cfg(test)]
mod tests;

pub(crate) const LIMBS: usize = 5;
pub(crate) const LIMB_BITS: usize = 26;
pub(crate) const RADIX: u64 = 1 << LIMB_BITS;
pub(crate) const MASK: u64 = RADIX - 1;
pub(crate) const BLOCK_BYTES: usize = 16;
/// Small-fixture experiment policy, not a production page/message limit.
pub(crate) const MAX_BLOCKS: usize = 3;
pub(crate) const MAX_SEGMENTS: usize = 3;
pub(crate) const MAX_BYTES: usize = MAX_BLOCKS * BLOCK_BYTES;
pub(crate) const CLAMP: [u8; 16] = [
    255, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15,
];
