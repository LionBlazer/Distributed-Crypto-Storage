//! Fixed one-registry, complete four-original-row layout. Offsets are circuit ABI only.
use crate::{
    lifecycle::{layout as registry, opening, registry::Columns},
    poseidon,
};
pub const CP: usize = poseidon::WIDTH;
pub const WORDS: usize = CP + 12;
pub const DATA: usize = WORDS + 256;
pub const TABLE: usize = DATA + 96;
pub const IDS: usize = TABLE + 8;
pub const CONTROLLERS: usize = IDS + 32;
pub const SALTS: usize = CONTROLLERS + 512;
pub const CTRL_INV: usize = SALTS + 20;
pub const STATE: usize = CTRL_INV + 2;
pub const COMPARE: usize = STATE + registry::STATE;
pub const STATE_INV: usize = COMPARE + 4 * 65;
pub const ACTOR: usize = STATE_INV + 4;
pub const PRINCIPAL: usize = ACTOR + 2;
pub const TXID: usize = PRINCIPAL + 2;
pub const REV: usize = TXID + 64;
pub const SEQ: usize = REV + 64;
pub const MASK: usize = SEQ + 64;
pub const DELTA: usize = MASK + 256;
pub const NEW_AMOUNTS: usize = DELTA + 16;
pub const MATCHES: usize = NEW_AMOUNTS + 64;
pub const ACC: usize = MATCHES + 4;
pub const EQUALITY: usize = ACC + 4;
pub const NEXT_REV: usize = EQUALITY + 44;
pub const NEXT_SEQ: usize = NEXT_REV + 64;
pub const CARRY: usize = NEXT_SEQ + 64;
pub const WIDTH: usize = CARRY + 2;
const _: () = assert!(WIDTH == 4216);
pub fn registry_columns() -> Columns {
    Columns {
        state: STATE,
        comparisons: COMPARE,
        inverses: STATE_INV,
    }
}
pub fn banks() -> opening::Banks {
    opening::Banks {
        words: WORDS,
        table: TABLE,
        ids: IDS,
        controllers: CONTROLLERS,
    }
}
