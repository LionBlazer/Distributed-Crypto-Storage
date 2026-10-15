//! Local client/manager experiments. Peers are logical shards in this process.
//! FHE results remain unverified. Local packet transport composes the reusable
//! peer protocol; production networking, consensus, and query proofs are absent.

#![forbid(unsafe_code)]

mod engine;
mod simulation;
mod sql;

pub use peer_protocol::{NodeId, NodeRole, RequestId};
pub use simulation::{
    Delivery, DemoNetwork, MAX_CLIENTS, NetworkLink, NetworkLog, NetworkNode, NetworkPacket,
    NetworkSnapshot, PacketKind,
};

pub use compact_query::PlainRow;
pub use engine::{
    BackendInfo, DatabaseDraft, LabEngine, LabError, LabProgress, LabSnapshot, LogicalShardInfo,
    MAX_LAB_ROWS, MAX_PEERS, PeerAggregate, PeerConfig, PeerHeads, PeerInfo, QueryOutcome,
    ReplicaLocation, ReplicationInfo, format_rows, parse_rows, sample_rows,
};
pub use sql::{
    Column, Comparison, PRESETS, Predicate, Preset, PresetGroup, Projection, QueryPlan, parse_sql,
};
