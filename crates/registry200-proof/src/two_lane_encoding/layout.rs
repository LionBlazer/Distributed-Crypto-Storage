//! Fixed mathematical row ABI, never a caller-selected proof geometry.
use bfv_hiding_stark::poseidon;
pub const P2: usize = poseidon::WIDTH;
pub const OPEN_CP: usize = 3 * P2;
pub const VECTOR_CP: usize = OPEN_CP + 12;
pub const CARRY: usize = VECTOR_CP + 12;
pub const BANK: usize = CARRY + 8;
pub const WORDS: usize = BANK;
pub const DATA: usize = WORDS + 256;
pub const TABLE: usize = DATA + 96;
pub const IDS: usize = TABLE + 8;
pub const SOURCE_SALT: usize = IDS + 32;
pub const SOURCE_ENC_SALT: usize = SOURCE_SALT + 4;
pub const WEIGHTS: usize = SOURCE_ENC_SALT + 4;
pub const EQUALITY: usize = WEIGHTS + 8 * 49;
pub const SOURCE_WIDTH: usize = EQUALITY + 8 * 11;
pub const MASK: usize = BANK;
pub const COMMAND_SALT: usize = MASK + 256;
pub const QUERY_ENC_SALT: usize = COMMAND_SALT + 4;
pub const QUERY_WIDTH: usize = QUERY_ENC_SALT + 4;
pub const PERIODICS: usize = 512;
pub const SOURCE_PV: usize = 8;
pub const KEY_METADATA: usize = 699;
pub const CONTEXT: usize = 728;
pub const ENCODED: usize = 736;
pub const SQL_IDENTITY: usize = 740;
pub const PUBLIC_NONCE: usize = 748;
pub const COMMAND: usize = 756;
const _: () = assert!(BANK == 776 && SOURCE_WIDTH == 1656 && QUERY_WIDTH == 1040);
pub fn weight(row: usize, field: usize) -> usize {
    assert!(row < 4 && field < 2);
    WEIGHTS + (2 * row + field) * 49
}
