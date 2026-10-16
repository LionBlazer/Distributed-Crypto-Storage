//! Full public HChaCha20/ChaCha20 primitive relations, not AEAD or source proofs.
pub(crate) mod air;
pub(crate) mod statement;
#[cfg(test)]
mod tests;

pub(crate) const WORDS: usize = 16;
pub(crate) const BITS: usize = 32;
pub(crate) const QUARTER_ROUNDS: usize = 80;
pub(crate) const SCHEDULE: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];
pub(crate) const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
pub(crate) const HCHACHA_OUTPUT: [usize; 8] = [0, 1, 2, 3, 12, 13, 14, 15];
