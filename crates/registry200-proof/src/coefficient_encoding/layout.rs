//! Mathematical circuit ABI for caller-owned trace writers, never an admission token.
use bfv_hiding_stark::poseidon;
pub const P2: usize = poseidon::WIDTH;
pub const OPEN_CP: usize = 4 * P2;
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
pub const EQUALITY: usize = WEIGHTS + 8 * 50;
pub const SOURCE_WIDTH: usize = EQUALITY + 16 * 11;
pub const MASK: usize = BANK;
pub const COMMAND_SALT: usize = MASK + 256;
pub const QUERY_ENC_SALT: usize = COMMAND_SALT + 4;
pub const QUERY_WIDTH: usize = QUERY_ENC_SALT + 4;
pub const PERIODICS: usize = 512;
pub const PROFILE: usize = 0;
pub const SOURCE_PV: usize = 8;
pub const FULL_SETUP: usize = 699;
pub const KEY_PV: usize = 707;
pub const CONTEXT: usize = 740;
pub const ENCODED: usize = 748;
pub const SQL_IDENTITY: usize = 752;
pub const PUBLIC_NONCE: usize = 760;
pub const COMMAND: usize = 768;
const _: () = assert!(SOURCE_WIDTH == 2000 && QUERY_WIDTH == 1288 && BANK == 1024);
pub fn weight(row: usize, field: usize) -> usize {
    assert!(row < 4 && field < 2);
    WEIGHTS + (2 * row + field) * 50
}
