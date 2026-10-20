//! Legacy base-bank offsets remain unchanged. All new private state is appended.
pub(super) use crate::lifecycle::layout::*;
pub(super) const OLD_PROGRESS: usize = WIDTH;
pub(super) const NEW_PROGRESS: usize = OLD_PROGRESS + 10;
pub(super) const CLIENT: usize = NEW_PROGRESS + 10;
pub(super) const CALL: usize = CLIENT + 256;
pub(super) const INVOCATION: usize = CALL + 64;
pub(super) const ORIGINAL_SQL: usize = INVOCATION + 256;
pub(super) const QUERY_MASK: usize = ORIGINAL_SQL + 256;
pub(super) const QUERY_MODE: usize = QUERY_MASK + 256;
pub(super) const QUERY_WAIT: usize = QUERY_MODE + 4;
pub(super) const QUERY_OFFSET: usize = QUERY_WAIT + 3;
pub(super) const QUERY_LIMIT: usize = QUERY_OFFSET + 3;
pub(super) const QUERY_PROJECTION: usize = QUERY_LIMIT + 3;
pub(super) const STMT_ROOT: usize = QUERY_PROJECTION + 2;
pub(super) const EXTRA_SALTS: usize = STMT_ROOT + 4; // Statement, oldP, newP, Cmd48.
pub(super) const RESUME: usize = EXTRA_SALTS + 16;
pub(super) const STATUS: usize = RESUME + 1; // Parked, Done, Error.
pub(super) const OLD_CURSOR: usize = STATUS + 3; // onehot 0..4
pub(super) const NEW_CURSOR: usize = OLD_CURSOR + 5;
pub(super) const OLD_MICRO: usize = NEW_CURSOR + 5;
pub(super) const NEW_MICRO: usize = OLD_MICRO + 64;
pub(super) const MICRO_CARRY: usize = NEW_MICRO + 64;
pub(super) const OLD_VISITED: usize = MICRO_CARRY + 1;
pub(super) const OLD_SELECTED: usize = OLD_VISITED + 4;
pub(super) const NEW_VISITED: usize = OLD_SELECTED + 4;
pub(super) const NEW_SELECTED: usize = NEW_VISITED + 4;
pub(super) const OLD_HOLDER: usize = NEW_SELECTED + 4;
pub(super) const OLD_HOLDER_MODE: usize = OLD_HOLDER + 64; // onehot 1..4
pub(super) const OLD_BLOCK_REV: usize = OLD_HOLDER_MODE + 4;
pub(super) const BLOCK_REV_COMPARE: usize = OLD_BLOCK_REV + 64;
pub(super) const OLD_OFFSET_CMP: usize = BLOCK_REV_COMPARE + 65;
pub(super) const OLD_LIMIT_CMP: usize = OLD_OFFSET_CMP + 16;
pub(super) const POP_INVERSES: usize = OLD_LIMIT_CMP + 4; // client/call/invocation/oldmicro/holder/differentid
pub const TRACE_WIDTH: usize = POP_INVERSES + 6;
pub(super) fn progress(at: usize, slot: usize) -> usize {
    at + 5 * slot
}
