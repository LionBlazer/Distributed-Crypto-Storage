//! Explicit private Boolean bank, followed by twelve private field salts.
use bfv_hiding_stark::poseidon;
pub const CP: usize = poseidon::WIDTH;
pub const BANK: usize = CP + 12;
pub const MASK: usize = BANK;
pub const TX: usize = MASK + 256;
pub const CONTROLLER: usize = TX + 64;
pub const REV: usize = CONTROLLER + 256;
pub const SEQ: usize = REV + 64;
pub const PRINCIPAL: usize = SEQ + 64;
pub const MODE: usize = PRINCIPAL + 2;
pub const WAIT: usize = MODE + 4;
pub const OFFSET: usize = WAIT + 3;
pub const LIMIT: usize = OFFSET + 3;
pub const PROJECTION: usize = LIMIT + 3;
pub const FLAGS: usize = PROJECTION + 2;
pub const SALTS: usize = FLAGS + 12;
pub const WIDTH: usize = SALTS + 12;
pub const END: usize = 44;
const _: () = assert!(SALTS - BANK == 733 && WIDTH == 1005);
#[derive(Clone, Copy)]
pub enum Stream {
    Mask,
    Command,
    Result,
}
pub fn absorb(row: usize) -> Option<(Stream, usize)> {
    match row {
        0..=5 => Some((Stream::Mask, row)),
        6..=25 => Some((Stream::Command, row - 6)),
        26..=43 => Some((Stream::Result, row - 26)),
        _ => None,
    }
}
pub fn reset(row: usize) -> bool {
    matches!(row, 0 | 6 | 26)
}
