use std::collections::BTreeMap;
use std::fmt;

use crate::PlainRow;
use compact_query::bfv as backend;
use compact_query::{self as cq, AgeRange, Table};
use compact_store::Limits;

use sql_plan::{Column, Projection, QueryPlan, parse_sql};

pub const MAX_PEERS: usize = 16;
pub const MAX_LAB_ROWS: usize = 128;
const ROWS_PER_PAGE: u32 = 256;

mod replication;
pub use replication::{LogicalShardInfo, ReplicaLocation, ReplicationInfo};

#[derive(Debug)]
pub enum LabError {
    NoDatabase,
    InvalidInput(String),
    UnsupportedSql(String),
    UnavailableShards(Vec<usize>),
    Replication(String),
    Cryptography(String),
}
impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDatabase => write!(f, "Create a test database first."),
            Self::InvalidInput(message)
            | Self::UnsupportedSql(message)
            | Self::Replication(message) => f.write_str(message),
            Self::Cryptography(message) => write!(f, "FHE operation failed: {message}"),
            Self::UnavailableShards(shards) => write!(
                f,
                "Logical shards {shards:?} have no current online replica. No fixture fallback or partial result was accepted."
            ),
        }
    }
}
impl std::error::Error for LabError {}
impl From<sql_plan::Error> for LabError {
    fn from(error: sql_plan::Error) -> Self {
        match error {
            sql_plan::Error::InvalidInput(message) => Self::InvalidInput(message),
            sql_plan::Error::UnsupportedSql(message) => Self::UnsupportedSql(message),
        }
    }
}
impl From<cq::Error> for LabError {
    fn from(error: cq::Error) -> Self {
        Self::Cryptography(error.to_string())
    }
}

pub struct DatabaseDraft {
    pub name: String,
    pub rows: Vec<PlainRow>,
    pub peers: Vec<PeerConfig>,
}

/// Local settings. Disk quota counts both canonical data and the encrypted index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub name: String,
    pub storage_limit_bytes: usize,
    /// Artificial packet delay, independent of measured CPU latency.
    pub delay_ms: u64,
}
impl PeerConfig {
    pub fn numbered(id: usize) -> Self {
        Self {
            name: format!("Peer {id:02}"),
            storage_limit_bytes: 4 * 1024 * 1024,
            delay_ms: 0,
        }
    }
    pub fn validate(&self) -> Result<(), LabError> {
        if self.name.trim().is_empty()
            || self.name.len() > 48
            || self.name.chars().any(char::is_control)
        {
            return Err(LabError::InvalidInput(
                "Peer name must contain 1..48 bytes, without control characters.".into(),
            ));
        }
        if !(1024..=64 * 1024 * 1024).contains(&self.storage_limit_bytes) || self.delay_ms > 1000 {
            return Err(LabError::InvalidInput(
                "Peer quota must be 1 KiB..64 MiB; simulated delay must be 0..1000 ms.".into(),
            ));
        }
        Ok(())
    }
    fn check_size(&self, bytes: usize) -> Result<(), LabError> {
        if bytes > self.storage_limit_bytes {
            return Err(LabError::InvalidInput(format!(
                "{} needs {bytes} B, exceeding its {} B storage quota. No changes were applied.",
                self.name, self.storage_limit_bytes
            )));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct LabProgress {
    pub message: String,
    pub peer_id: usize,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: usize,
    pub config: PeerConfig,
    pub online: bool,
    pub rows: usize,
    /// Actual stored row payload, including retained stale physical copies.
    pub logical_bytes: usize,
    /// Canonical encrypted data including its manifest, nonces and tags.
    pub data_bytes: usize,
    /// Complete encrypted posting index including its table-head binding.
    pub index_bytes: usize,
    /// Physical encrypted objects plus durable journals; historical replicated
    /// mode also charges16B/copy record IDs. In-memory keys and caches are excluded.
    pub stored_bytes: usize,
    /// Actual on-disk version/proof journal bytes, zero for unmetered historical views.
    pub journal_bytes: usize,
    /// Serialized public setup held in memory, not disk quota or peak whole-process RAM.
    /// Zero in historical views that do not report this measurement.
    pub public_setup_bytes: usize,
    /// Owner-only inspector mapping, never plaintext provided to a peer.
    pub owner_row_indices: Vec<usize>,
}
#[derive(Clone, Debug)]
pub struct LabSnapshot {
    pub name: String,
    pub revision: u64,
    pub owner_rows: Vec<PlainRow>,
    pub peers: Vec<PeerInfo>,
    pub replication: Option<ReplicationInfo>,
}
/// Opaque current commitments for headless failure-model checks; no plaintext or key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHeads {
    pub id: usize,
    pub data: compact_store::Commitment,
    pub index: compact_store::Commitment,
}
/// Public parameter/key counts only; no secret bytes are exposed or retained.
pub struct BackendInfo {
    pub profile: backend::ParameterProfile,
    pub public_setup_bytes: backend::PublicSetupBytes,
    pub secret_key_serialized_bytes: usize,
}
#[derive(Clone, Debug)]
pub struct PeerAggregate {
    pub id: usize,
    pub count: u32,
    pub sum: u32,
    pub elapsed_ms: f64,
}
#[derive(Clone, Debug)]
pub enum QueryOutcome {
    /// Nullable wide scalar display cells; assurance belongs to the outer result.
    Aggregated {
        columns: Vec<String>,
        values: Vec<Option<u64>>,
    },
    Aggregate {
        count: u32,
        sum: u32,
        peers: Vec<PeerAggregate>,
    },
    Count {
        count: u32,
        peers: Vec<PeerAggregate>,
    },
    Sum {
        sum: u32,
        peers: Vec<PeerAggregate>,
    },
    /// Row-shaped display data, with cells in the requested column order.
    /// Verification/version assurance belongs to the consumer's operation wrapper;
    /// historical LabEngine outputs carry no network computation proof.
    Selected {
        columns: Vec<Column>,
        rows: Vec<Vec<u32>>,
    },
    Updated {
        /// The statement succeeded; a constant-false predicate is a successful no-op.
        committed: bool,
    },
    /// Display count; this shape alone attests no transport, proof or publication.
    Inserted {
        count: u32,
    },
}

/// Honest local owner/manager composition. Peer storage contains compact pages
/// and an encrypted index; FHE inputs exist only for the current selected operation.
#[derive(Default)]
pub struct LabEngine {
    database: Option<Database>,
    prepared: Option<PreparedUpdate>,
}
struct Database {
    name: String,
    revision: u64,
    owner: backend::Owner,
    evaluator: backend::Evaluator,
    owner_rows: Vec<PlainRow>,
    peers: Vec<Peer>,
    failure_domains: BTreeMap<usize, u64>,
    replication: replication::Replication,
}
struct Peer {
    id: usize,
    config: PeerConfig,
    evaluator: backend::Evaluator,
    online: bool,
}
struct PreparedUpdate {
    rows: Vec<PlainRow>,
    replication: replication::Replication,
}

impl LabEngine {
    pub fn create(&mut self, draft: DatabaseDraft) -> Result<LabSnapshot, LabError> {
        let ids = (1..=draft.peers.len()).collect();
        self.create_with_peer_ids(draft, ids)
    }
    /// Validate and stage replacement state before changing the live database.
    pub fn create_with_peer_ids(
        &mut self,
        draft: DatabaseDraft,
        ids: Vec<usize>,
    ) -> Result<LabSnapshot, LabError> {
        let name = draft.name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(LabError::InvalidInput(
                "Database name must contain 1..64 bytes, without control characters.".into(),
            ));
        }
        validate_profiles(&draft.peers, &ids)?;
        if draft.rows.len() > MAX_LAB_ROWS {
            return Err(LabError::InvalidInput(
                "The GUI experiment allows at most 128 rows.".into(),
            ));
        }
        let (owner, evaluator) = backend::Owner::generate(*b"playground-db-v1")?;
        let profiles = ids
            .into_iter()
            .zip(draft.peers)
            .map(|(id, config)| (id, config, true))
            .collect();
        let peers = build_peers(&evaluator, profiles);
        let replication = replication::Replication::initial(&owner, &draft.rows, &peers, 1)?;
        self.database = Some(Database {
            name: name.into(),
            revision: 0,
            owner,
            evaluator,
            owner_rows: draft.rows,
            failure_domains: peers.iter().map(|peer| (peer.id, peer.id as u64)).collect(),
            replication,
            peers,
        });
        self.prepared = None;
        Ok(self.snapshot().expect("database was just created"))
    }
    pub fn snapshot(&self) -> Option<LabSnapshot> {
        self.database.as_ref().map(|db| LabSnapshot {
            name: db.name.clone(),
            revision: db.revision,
            owner_rows: db.owner_rows.clone(),
            replication: Some(db.replication.info(db)),
            peers: db
                .peers
                .iter()
                .map(|peer| db.replication.peer_info(peer))
                .collect(),
        })
    }
    /// Physical heads outside query timing. Replicated mode may repeat peer IDs
    /// for different shards, including stale copies; logical current heads are in snapshot.
    pub fn peer_heads_for_experiment(&self) -> Result<Vec<PeerHeads>, LabError> {
        let db = self.database.as_ref().ok_or(LabError::NoDatabase)?;
        Ok(db.replication.physical_heads())
    }
    /// Diagnostic accounting outside query timers. Peers share the same public setup via Arc.
    pub fn backend_info_for_experiment(&self) -> Result<BackendInfo, LabError> {
        let db = self.database.as_ref().ok_or(LabError::NoDatabase)?;
        Ok(BackendInfo {
            profile: db.owner.profile(),
            public_setup_bytes: db.evaluator.public_setup_bytes()?,
            secret_key_serialized_bytes: db.owner.secret_key_serialized_bytes(),
        })
    }
    pub fn set_peer_online(&mut self, id: usize, online: bool) -> Result<(), LabError> {
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let peer = db
            .peers
            .iter_mut()
            .find(|peer| peer.id == id)
            .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?;
        peer.online = online;
        self.prepared = None;
        Ok(())
    }
    pub fn set_peer_config(&mut self, id: usize, mut config: PeerConfig) -> Result<(), LabError> {
        config.validate()?;
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let replicated_bytes = db.replication.charged_bytes(id);
        let peer = db
            .peers
            .iter_mut()
            .find(|peer| peer.id == id)
            .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?;
        config.check_size(replicated_bytes)?;
        config.name = config.name.trim().into();
        peer.config = config;
        self.prepared = None;
        Ok(())
    }
    pub fn configure_peers(&mut self, configs: Vec<PeerConfig>) -> Result<(), LabError> {
        let db = self.database.as_ref().ok_or(LabError::NoDatabase)?;
        let mut next = db.peers.iter().map(|peer| peer.id).max().unwrap_or(0);
        let profiles = configs
            .into_iter()
            .enumerate()
            .map(|(index, config)| {
                if let Some(peer) = db.peers.get(index) {
                    Ok((peer.id, config, peer.online))
                } else {
                    next = next.checked_add(1).ok_or_else(|| {
                        LabError::InvalidInput(
                            "Peer identity space exhausted; no topology changed.".into(),
                        )
                    })?;
                    Ok((next, config, true))
                }
            })
            .collect::<Result<Vec<_>, LabError>>()?;
        self.repartition(profiles)
    }
    /// Synchronize physical custody only. Never rebuild missing ciphertext from the inspector.
    pub fn repartition(
        &mut self,
        profiles: Vec<(usize, PeerConfig, bool)>,
    ) -> Result<(), LabError> {
        let configs: Vec<_> = profiles
            .iter()
            .map(|(_, config, _)| config.clone())
            .collect();
        let ids: Vec<_> = profiles.iter().map(|(id, _, _)| *id).collect();
        validate_profiles(&configs, &ids)?;
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        replication::synchronize_peers(db, profiles)?;
        self.prepared = None;
        Ok(())
    }
    pub fn execute(&mut self, sql: &str) -> Result<QueryOutcome, LabError> {
        self.execute_with_progress(sql, |_| {})
    }
    pub fn execute_with_progress(
        &mut self,
        sql: &str,
        progress: impl Fn(LabProgress),
    ) -> Result<QueryOutcome, LabError> {
        let result = self.prepare_query(sql, progress)?;
        self.commit_prepared();
        Ok(result)
    }
    /// All new compact images stay staged until the transport accepts delivery.
    pub fn prepare_query(
        &mut self,
        sql: &str,
        progress: impl Fn(LabProgress),
    ) -> Result<QueryOutcome, LabError> {
        self.prepared = None;
        let plan = parse_sql(sql)?;
        replication::admitted_range(&plan)?;
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        db.replication.ensure_available(db)?;
        let (outcome, prepared) = replication::execute(db, plan, &progress)?;
        self.prepared = prepared;
        Ok(outcome)
    }
    pub fn discard_prepared(&mut self) {
        self.prepared = None;
    }
    pub fn commit_prepared(&mut self) {
        if let Some(update) = self.prepared.take() {
            let db = self
                .database
                .as_mut()
                .expect("prepared update owns database");
            db.replication = update.replication;
            db.owner_rows = update.rows;
            db.revision += 1;
        }
    }
}

fn aggregate_outcome(
    plan: QueryPlan,
    count: u32,
    sum: u32,
    peers: Vec<PeerAggregate>,
) -> QueryOutcome {
    match plan {
        QueryPlan::Count { .. } => QueryOutcome::Count { count, peers },
        QueryPlan::Sum { .. } => QueryOutcome::Sum { sum, peers },
        _ => QueryOutcome::Aggregate { count, sum, peers },
    }
}
// LIMIT bounds returned cells only. Every complete indexed selection must pass
// authentication and availability checks before this function receives any rows.
fn project_rows(
    mut selected: Vec<(usize, Vec<u32>)>,
    projection: Projection,
    limit: Option<usize>,
) -> QueryOutcome {
    selected.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    let output_limit = limit.unwrap_or(selected.len());
    let columns = projection.columns();
    let rows = selected
        .into_iter()
        .take(output_limit)
        .map(|(_, cells)| cells)
        .collect();
    QueryOutcome::Selected { columns, rows }
}
fn evaluate_selected_rows(
    owner: &backend::Owner,
    evaluator: &backend::Evaluator,
    table: &Table,
    range: AgeRange,
    projection: Projection,
) -> Result<Vec<(u64, Vec<u32>)>, LabError> {
    let encrypted_projection = match projection {
        Projection::Age => backend::RowProjection::Age,
        Projection::Amount => backend::RowProjection::Amount,
        Projection::AgeAmount | Projection::AmountAge => backend::RowProjection::AgeAmount,
    };
    let query = owner.prepare_exact_select_for_experiment(
        table,
        range,
        encrypted_projection,
        MAX_LAB_ROWS,
        Limits::default(),
    )?;
    let evaluated = evaluator.evaluate_indexed_select(query.request())?;
    let result =
        owner.complete_exact_select_unverified_for_experiment(table, query, &evaluated.output)?;
    result
        .rows
        .into_iter()
        .map(|row| {
            let cells = projection
                .columns()
                .into_iter()
                .map(|column| {
                    match column {
                        Column::Age => row.age.map(u32::from),
                        Column::Amount => row.amount.map(u32::from),
                    }
                    .ok_or_else(|| {
                        LabError::Cryptography("Missing encrypted projection column.".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((row.ordinal, cells))
        })
        .collect()
}
fn validate_profiles(configs: &[PeerConfig], ids: &[usize]) -> Result<(), LabError> {
    if configs.len() > MAX_PEERS
        || ids.len() != configs.len()
        || ids.contains(&0)
        || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
    {
        return Err(LabError::InvalidInput(
            "Use at most 16 peers with unique nonzero IDs.".into(),
        ));
    }
    for config in configs {
        config.validate()?;
    }
    Ok(())
}
fn build_peers(
    evaluator: &backend::Evaluator,
    profiles: Vec<(usize, PeerConfig, bool)>,
) -> Vec<Peer> {
    profiles
        .into_iter()
        .map(|(id, mut config, online)| {
            config.name = config.name.trim().into();
            Peer {
                id,
                config,
                evaluator: evaluator.clone(),
                online,
            }
        })
        .collect()
}
