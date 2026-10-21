//! Closed H2048 fused geometry. No old profile is relabeled.
pub(super) const DOMAIN: &[u8] = b"DCS/research/CoreGold/FusedQuery57/H2048/PP708/v1";
pub(super) const H: usize = 2048;
pub(super) const LOG_H: usize = 11;
pub(super) const W: usize = 512;
pub(super) const PP: usize = 708;
pub(super) const PV: usize = 32;
pub(super) const SLOTS: usize = 57;
pub(super) const GATES: usize = 81920;
pub(super) const GRAPH_ROWS: usize = GATES.div_ceil(SLOTS);
pub(super) const CW_FIRST: usize = GRAPH_ROWS;
pub(super) const CS_FIRST: usize = CW_FIRST + 514;
pub(super) const STMT_FIRST: usize = CS_FIRST + 66;
pub(super) const HASH_END: usize = STMT_FIRST + 12;
pub(super) const GRAPH_PORTS: usize = 4 * SLOTS;
pub(super) const RANGE_PORTS: usize = 19;
pub(super) const WORD_PORT: usize = GRAPH_PORTS + RANGE_PORTS;
pub(super) const PORTS: usize = WORD_PORT + 1;
pub(super) const RANGE_VALUES: usize = 248;
pub(super) const BITS: usize = 267;
pub(super) const RANGE_BITS: usize = 196;
pub(super) const CHECKPOINT: usize = 496;
pub(super) const ACCUMULATOR: usize = 508;
pub(super) const MASK_ACC: usize = 509;
pub(super) const MASK_WORD: usize = 510;
pub(super) const COEFFICIENTS: usize = PORTS;
pub(super) const RANGE_C0: usize = COEFFICIENTS + GRAPH_PORTS;
pub(super) const POWER: usize = RANGE_C0 + 4;
pub(super) const CONTEXT: usize = POWER + 1;
pub(super) const ROOT: usize = CONTEXT + 8;
pub(super) const FLAGS: usize = ROOT + 4;
pub(super) const ACTIVE: usize = FLAGS + 16;
pub(super) const POINTWISE: usize = ACTIVE + SLOTS;
pub(super) const FANOUT: usize = POINTWISE + SLOTS;
pub(super) const STMT_LOOKUP: usize = FANOUT + SLOTS;
pub(super) const FIXED: usize = STMT_LOOKUP + 8;
pub(super) const FIXED_VALUE: usize = FIXED + 8;
pub(super) const MASK_ACTIVE: usize = FIXED_VALUE + 8;
pub(super) const MASK_RESET: usize = MASK_ACTIVE + 1;
pub(super) const MASK_EMIT: usize = MASK_RESET + 1;
pub(super) const MASK_POWER: usize = MASK_EMIT + 1;
pub(super) const BUS: &str = "dcs/research/fused-query57/v1/node-value";
pub(super) const NATIVE_MAGIC: &[u8; 8] = b"DCSGQF01";
pub(super) const FRAME_DOMAIN: &[u8] = b"DCS/research/fused-query57/actual-native-frame/v1\0";
pub(super) const FRAME_SHAPE:&[u8]=b"H2048/MAIN512/PP708/PV32;degree12/default83/AUX420/chunks8;MAIN2/AUX2/PP1;all5rounds;all4096-W/Stmt96/Cw4112/Cs528;12FRI;terminal0+actualnative;freshOSprivate/PUBLIC-PPonly;boundedPostcard+canonicalGold+reencode+EOF;NO-admission";
pub(super) const PACKED: usize = 83;
pub(super) const AUX: usize = 420;
pub(super) const GOLD_BOUND: usize = 360000;
pub(super) const EXT_BOUND: usize = 5200;
const _: () = assert!(
    GRAPH_ROWS == 1438
        && STMT_FIRST == 2018
        && HASH_END == 2030
        && MASK_POWER + 1 == PP
        && PORTS == 248
);

pub(super) const SCALE_INVERSE: u64 = 11905010191115873962;
