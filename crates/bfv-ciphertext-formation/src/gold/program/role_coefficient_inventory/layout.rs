//! Closed NEW profile; none of the old Dense, Data or Pair identities are reused.
pub(super) const DOMAIN: &[u8] =
    b"DCS/research/CoreGold/RoleCoefficientHash/Data56+PublicCoeff/H2048/v1";
pub(super) const BUS: &str = "dcs/research/gold-role-coefficient-hash/v1/node-value";
pub(super) const N: usize = 4096;
pub(super) const H: usize = 2048;
pub(super) const LOG_H: usize = 11;
pub(super) const W: usize = 512;
pub(super) const PP: usize = 656;
pub(super) const PV: usize = 48;
pub(super) const HASH_W: usize = 260;
pub(super) const HASH_PP: usize = 10;
pub(super) const HASH_PV: usize = 4;
pub(super) const HASH_PORTS: usize = 8;
pub(super) const COEFFICIENT_WORDS: usize = 4 * N;
pub(super) const SLOTS: usize = 56;
pub(super) const GATES: usize = 81920;
pub(super) const GRAPH_ROWS: usize = GATES.div_ceil(SLOTS);
pub(super) const CW_FIRST: usize = GRAPH_ROWS;
pub(super) const CS_FIRST: usize = CW_FIRST + 514;
pub(super) const RANGE_ONLY_FIRST: usize = CS_FIRST + 66;
pub(super) const GRAPH_PORTS: usize = 4 * SLOTS;
pub(super) const RANGE_PORTS: usize = 19;
pub(super) const ORIGINAL_PORTS: usize = GRAPH_PORTS + RANGE_PORTS;
pub(super) const C0_PORTS: usize = 4;
pub(super) const PORTS: usize = ORIGINAL_PORTS + C0_PORTS;
pub(super) const RANGE_VALUES: usize = 248;
pub(super) const BITS: usize = 267;
pub(super) const RANGE_BITS: usize = 196;
pub(super) const C0_VALUES: usize = 463;
pub(super) const LABELS: usize = 467;
pub(super) const CHECKPOINT: usize = 496;
pub(super) const ACCUMULATOR: usize = 508;
pub(super) const COEFFICIENTS: usize = PORTS;
pub(super) const POWER: usize = COEFFICIENTS + GRAPH_PORTS;
pub(super) const FLAGS: usize = POWER + 1;
pub(super) const ACTIVE: usize = FLAGS + 16;
pub(super) const POINTWISE: usize = ACTIVE + SLOTS;
pub(super) const FANOUT: usize = POINTWISE + SLOTS;
pub(super) const HASH_FIRST: usize = 8;
pub(super) const HASH_LAST: usize = 9;
// Old graph vectors0..38, W39 and Cs40. These new PUBLIC sources are disjoint.
pub(super) const FREQ_TAG: usize = 41;
pub(super) const C0_TAG: usize = 43;
pub(super) fn node(tag: usize, at: usize) -> super::Result<u64> {
    if tag > 44 || at >= N || (tag == 40 && at >= 512) {
        return Err(super::Error::Shape);
    }
    Ok(1 + tag as u64 * 65536 + at as u64)
}
