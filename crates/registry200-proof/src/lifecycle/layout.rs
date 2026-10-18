//! Explicit Boolean banks. Every u64 is two independently packed u32 limbs.
use crate::poseidon;
pub const CP: usize = poseidon::WIDTH;
pub const WORDS: usize = CP + 12;
pub const TABLE: usize = WORDS + 256;
pub const IDS: usize = TABLE + 8;
pub const CONTROLLERS: usize = IDS + 32;
pub const SALTS: usize = CONTROLLERS + 512;
pub const CTRL_INV: usize = SALTS + 24;
pub const OLD: usize = CTRL_INV + 2;
pub const STATE: usize = 2052;
pub const NEW: usize = OLD + STATE;
pub const REV: usize = 0;
pub const ALLOC: usize = 64;
pub const TX: usize = 128;
pub const SLOT: usize = 962;
pub const PRESENT: usize = 0;
pub const ID: usize = 1;
pub const PRINCIPAL: usize = 65;
pub const SEQ: usize = 67;
pub const FAILED: usize = 131;
pub const SNAPSHOT: usize = 132;
pub const HELD: usize = 388;
pub const SP: usize = 408;
pub const FRAME: usize = 277;
pub const NAME: usize = 1;
pub const SAVED: usize = 257;
pub const OP: usize = NEW + STATE;
pub const ACTOR: usize = OP + 7;
pub const PRINCIPAL_CMD: usize = ACTOR + 2;
pub const ID_CMD: usize = PRINCIPAL_CMD + 2;
pub const NAME_CMD: usize = ID_CMD + 64;
pub const MASK: usize = NAME_CMD + 256;
pub const AGES: usize = MASK + 256;
pub const MODE: usize = AGES + 32;
pub const WAIT: usize = MODE + 4;
pub const OFFSET: usize = WAIT + 3;
pub const LIMIT: usize = OFFSET + 3;
pub const PROJECTION: usize = LIMIT + 3;
pub const ABORT: usize = PROJECTION + 2;
pub const CAND_REV: usize = ABORT + 1;
pub const CAND_ALLOC: usize = CAND_REV + 64;
pub const CAND_SEQ: usize = CAND_ALLOC + 64;
pub const CARRY: usize = CAND_SEQ + 64;
pub const COMPARE: usize = CARRY + 3;
// For each state: allocator<=revision, id0<=allocator,id1<=allocator,id0<id1.
pub const NONZERO: usize = COMPARE + 8 * 65;
// Each state/slot has nonzero ID and sequence population inverses.
pub const EQ_NAME: usize = NONZERO + 8;
// Two frames: eight (zero,inverse) pairs, nine prefix bits.
pub const TARGET: usize = EQ_NAME + 2 * 25;
pub const MATCHES: usize = TARGET + 2;
pub const ACC: usize = MATCHES + 4;
pub const EQUALITY: usize = ACC + 4;
pub const SEARCH: usize = EQUALITY + 44;
pub const ATTEMPT: usize = SEARCH + 4;
pub const CONFLICT: usize = ATTEMPT + 4;
pub const VISIT: usize = CONFLICT + 4;
pub const SKIP: usize = VISIT + 4;
pub const RETURN: usize = SKIP + 4;
pub const BLOCK: usize = RETURN + 4;
pub const LIMIT_CMP: usize = BLOCK + 4;
pub const OFFSET_CMP: usize = LIMIT_CMP + 16;
pub const DESIRED: usize = OFFSET_CMP + 16;
pub const SUCCESS: usize = DESIRED + 20;
pub const WIDTH: usize = SUCCESS + 1;
pub fn slot(state: usize, t: usize) -> usize {
    state + TX + t * SLOT
}
pub fn held(slot: usize, r: usize, m: usize) -> usize {
    slot + HELD + 5 * r + m
}
pub fn frame(slot: usize, f: usize) -> usize {
    slot + SP + f * FRAME
}
