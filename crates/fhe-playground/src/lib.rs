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

pub use engine::{
    DatabaseDraft, LabEngine, LabError, LabProgress, LabSnapshot, MAX_LAB_ROWS, MAX_PEERS,
    PeerAggregate, PeerConfig, PeerInfo, QueryOutcome, format_rows, parse_rows, sample_rows,
};
pub use sql::{PRESETS, Predicate, Preset, QueryPlan, parse_sql};
