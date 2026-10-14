//! Local client/manager experiments. Peers are logical shards in this process.
//! FHE results remain unverified; this is not a networking or consensus protocol.

#![forbid(unsafe_code)]

mod engine;
mod sql;

pub use engine::{
    DatabaseDraft, LabEngine, LabError, LabSnapshot, MAX_LAB_ROWS, MAX_PEERS, PeerAggregate,
    PeerInfo, QueryOutcome, format_rows, parse_rows, sample_rows,
};
pub use sql::{PRESETS, Predicate, Preset, QueryPlan, parse_sql};
