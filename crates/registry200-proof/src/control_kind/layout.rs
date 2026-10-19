//! One original hash stream and one immutable private opening bank.
use bfv_hiding_stark::poseidon;
pub const CP: usize = poseidon::WIDTH;
pub const BANK: usize = CP + 12;
pub const OPCODE: usize = BANK;
pub const SUFFIX: usize = OPCODE + 6;
pub const WIDTH: usize = SUFFIX + 49;
pub const END: usize = 20;
/// Existing Lifecycle opcode ABI, not a public claimed operation.
pub const CONTROL_OPCODES: [u8; 6] = [0, 2, 3, 4, 5, 6];
const _: () = assert!(WIDTH == 315);
