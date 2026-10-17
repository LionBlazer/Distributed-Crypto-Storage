//! Explicit Boolean banks. Every u64 is two independently packed u32 limbs.
use crate::opening::poseidon;
pub(super) const CP: usize = poseidon::WIDTH;
pub(super) const WORDS: usize = CP + 12;
pub(super) const TABLE: usize = WORDS + 256;
pub(super) const IDS: usize = TABLE + 8;
pub(super) const CONTROLLERS: usize = IDS + 32;
pub(super) const SALTS: usize = CONTROLLERS + 512;
pub(super) const CTRL_INV: usize = SALTS + 24;
pub(super) const OLD: usize = CTRL_INV + 2;
pub(super) const STATE: usize = 2052;
pub(super) const NEW: usize = OLD + STATE;
pub(super) const REV: usize = 0;
pub(super) const ALLOC: usize = 64;
pub(super) const TX: usize = 128;
pub(super) const SLOT: usize = 962;
pub(super) const PRESENT: usize = 0;
pub(super) const ID: usize = 1;
pub(super) const PRINCIPAL: usize = 65;
pub(super) const SEQ: usize = 67;
pub(super) const FAILED: usize = 131;
pub(super) const SNAPSHOT: usize = 132;
pub(super) const HELD: usize = 388;
pub(super) const SP: usize = 408;
pub(super) const FRAME: usize = 277;
pub(super) const NAME: usize = 1;
pub(super) const SAVED: usize = 257;
pub(super) const OP: usize = NEW + STATE;
pub(super) const ACTOR: usize = OP + 7;
pub(super) const PRINCIPAL_CMD: usize = ACTOR + 2;
pub(super) const ID_CMD: usize = PRINCIPAL_CMD + 2;
pub(super) const NAME_CMD: usize = ID_CMD + 64;
pub(super) const MASK: usize = NAME_CMD + 256;
pub(super) const AGES: usize = MASK + 256;
pub(super) const MODE: usize = AGES + 32;
pub(super) const WAIT: usize = MODE + 4;
pub(super) const OFFSET: usize = WAIT + 3;
pub(super) const LIMIT: usize = OFFSET + 3;
pub(super) const PROJECTION: usize = LIMIT + 3;
pub(super) const ABORT: usize = PROJECTION + 2;
pub(super) const CAND_REV: usize = ABORT + 1;
pub(super) const CAND_ALLOC: usize = CAND_REV + 64;
pub(super) const CAND_SEQ: usize = CAND_ALLOC + 64;
pub(super) const CARRY: usize = CAND_SEQ + 64;
pub(super) const COMPARE: usize = CARRY + 3;
// For each state: allocator<=revision, id0<=allocator,id1<=allocator,id0<id1.
pub(super) const NONZERO: usize = COMPARE + 8 * 65;
// Each state/slot has nonzero ID and sequence population inverses.
pub(super) const EQ_NAME: usize = NONZERO + 8;
// Two frames: eight (zero,inverse) pairs, nine prefix bits.
pub(super) const TARGET: usize = EQ_NAME + 2 * 25;
pub(super) const MATCHES: usize = TARGET + 2;
pub(super) const ACC: usize = MATCHES + 4;
pub(super) const EQUALITY: usize = ACC + 4;
pub(super) const SEARCH: usize = EQUALITY + 44;
pub(super) const ATTEMPT: usize = SEARCH + 4;
pub(super) const CONFLICT: usize = ATTEMPT + 4;
pub(super) const VISIT: usize = CONFLICT + 4;
pub(super) const SKIP: usize = VISIT + 4;
pub(super) const RETURN: usize = SKIP + 4;
pub(super) const BLOCK: usize = RETURN + 4;
pub(super) const LIMIT_CMP: usize = BLOCK + 4;
pub(super) const OFFSET_CMP: usize = LIMIT_CMP + 16;
pub(super) const DESIRED: usize = OFFSET_CMP + 16;
pub(super) const SUCCESS: usize = DESIRED + 20;
pub(crate) const WIDTH: usize = SUCCESS + 1;
pub(super) fn slot(state: usize, t: usize) -> usize {
    state + TX + t * SLOT
}
pub(super) fn held(slot: usize, r: usize, m: usize) -> usize {
    slot + HELD + 5 * r + m
}
pub(super) fn frame(slot: usize, f: usize) -> usize {
    slot + SP + f * FRAME
}
