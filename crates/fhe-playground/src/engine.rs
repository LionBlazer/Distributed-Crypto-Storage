use std::fmt;
use std::time::Instant;

use crate::PlainRow;
use compact_query::bfv as backend;
use compact_query::{self as cq, AgeRange, Table};
use compact_store::Limits;

use crate::{QueryPlan, parse_sql};

pub const MAX_PEERS: usize = 16;
pub const MAX_LAB_ROWS: usize = 128;
const ROWS_PER_PAGE: u32 = 256;

#[derive(Debug)]
pub enum LabError {
    NoDatabase,
    InvalidInput(String),
    UnsupportedSql(String),
    Unavailable(Vec<usize>),
    Cryptography(String),
}
impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDatabase => write!(f, "Create a test database first."),
            Self::InvalidInput(message) | Self::UnsupportedSql(message) => f.write_str(message),
            Self::Unavailable(peers) => write!(
                f,
                "Required shards are offline on peers {peers:?}. No incomplete result or partial update was accepted."
            ),
            Self::Cryptography(message) => write!(f, "FHE operation failed: {message}"),
        }
    }
}
impl std::error::Error for LabError {}
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
    /// Canonical encrypted data including its manifest, nonces and tags.
    pub data_bytes: usize,
    /// Complete encrypted posting index including its table-head binding.
    pub index_bytes: usize,
    /// Data plus index; excludes shared evaluation keys and in-memory hash trees.
    pub stored_bytes: usize,
    /// Owner-only inspector mapping, never plaintext provided to a peer.
    pub owner_row_indices: Vec<usize>,
}
#[derive(Clone, Debug)]
pub struct LabSnapshot {
    pub name: String,
    pub revision: u64,
    pub owner_rows: Vec<PlainRow>,
    pub peers: Vec<PeerInfo>,
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
    Aggregate {
        count: u32,
        sum: u32,
        peers: Vec<PeerAggregate>,
    },
    Updated {
        /// The statement succeeded; a constant-false predicate is a successful no-op.
        committed: bool,
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
}
struct Peer {
    id: usize,
    config: PeerConfig,
    evaluator: backend::Evaluator,
    table: Table,
    online: bool,
}
impl Peer {
    fn rows(&self) -> usize {
        self.table.commitment().layout().row_count as usize
    }
    fn stored_bytes(&self) -> usize {
        self.table.canonical_data_bytes() + self.table.encrypted_index_bytes()
    }
}
struct PreparedUpdate {
    tables: Vec<Table>,
    rows: Vec<PlainRow>,
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
        let peers = build_peers(&owner, &evaluator, &draft.rows, profiles)?;
        self.database = Some(Database {
            name: name.into(),
            revision: 0,
            owner,
            evaluator,
            owner_rows: draft.rows,
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
            peers: db
                .peers
                .iter()
                .enumerate()
                .map(|(index, peer)| PeerInfo {
                    id: peer.id,
                    config: peer.config.clone(),
                    online: peer.online,
                    rows: peer.rows(),
                    data_bytes: peer.table.canonical_data_bytes(),
                    index_bytes: peer.table.encrypted_index_bytes(),
                    stored_bytes: peer.stored_bytes(),
                    owner_row_indices: (index..db.owner_rows.len())
                        .step_by(db.peers.len())
                        .collect(),
                })
                .collect(),
        })
    }
    /// Public current heads only; diagnostic copies are outside query timing.
    pub fn peer_heads_for_experiment(&self) -> Result<Vec<PeerHeads>, LabError> {
        let db = self.database.as_ref().ok_or(LabError::NoDatabase)?;
        Ok(db
            .peers
            .iter()
            .map(|peer| PeerHeads {
                id: peer.id,
                data: peer.table.commitment().clone(),
                index: peer.table.index_commitment().clone(),
            })
            .collect())
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
        let peer = db
            .peers
            .iter_mut()
            .find(|peer| peer.id == id)
            .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?;
        config.check_size(peer.stored_bytes())?;
        config.name = config.name.trim().into();
        peer.config = config;
        self.prepared = None;
        Ok(())
    }
    pub fn configure_peers(&mut self, configs: Vec<PeerConfig>) -> Result<(), LabError> {
        let db = self.database.as_ref().ok_or(LabError::NoDatabase)?;
        let mut next = db.peers.iter().map(|peer| peer.id).max().unwrap_or(0) + 1;
        let profiles = configs
            .into_iter()
            .enumerate()
            .map(|(index, config)| {
                if let Some(peer) = db.peers.get(index) {
                    (peer.id, config, peer.online)
                } else {
                    let id = next;
                    next += 1;
                    (id, config, true)
                }
            })
            .collect();
        self.repartition(profiles)
    }
    /// Explicit manager-driven rebuild using live owner data and the same key authority.
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
        let peers = build_peers(&db.owner, &db.evaluator, &db.owner_rows, profiles)?;
        db.peers = peers;
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
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        if db.peers.is_empty() {
            return Err(LabError::InvalidInput(
                "No storage peers are available. Add a peer to rebuild encrypted shards.".into(),
            ));
        }
        let missing: Vec<_> = db
            .peers
            .iter()
            .filter(|peer| !peer.online && peer.rows() != 0)
            .map(|peer| peer.id)
            .collect();
        if !missing.is_empty() {
            return Err(LabError::Unavailable(missing));
        }
        match plan {
            QueryPlan::Aggregate { predicate } => match predicate.age_range() {
                Some(range) => db.aggregate(range, &progress),
                // Public domain reasoning only. No stored row is inspected or FHE claimed.
                None => Ok(QueryOutcome::Aggregate {
                    count: 0,
                    sum: 0,
                    peers: Vec::new(),
                }),
            },
            QueryPlan::AddAmount { predicate, delta } => {
                let Some(range) = predicate.age_range() else {
                    return Ok(QueryOutcome::Updated { committed: true });
                };
                let (result, prepared) = db.add_amount(range, delta, &progress)?;
                self.prepared = prepared;
                Ok(result)
            }
        }
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
            for (peer, table) in db.peers.iter_mut().zip(update.tables) {
                peer.table = table;
            }
            db.owner_rows = update.rows;
            db.revision += 1;
        }
    }
}

impl Database {
    fn aggregate(
        &self,
        range: AgeRange,
        progress: &impl Fn(LabProgress),
    ) -> Result<QueryOutcome, LabError> {
        let mut contributions = Vec::new();
        let (mut count, mut sum) = (0, 0);
        for peer in &self.peers {
            if peer.rows() == 0 {
                continue;
            }
            progress(LabProgress {
                peer_id: peer.id,
                message: format!(
                    "Evaluating selected encrypted rows on peer {} / {}...",
                    peer.id,
                    self.peers.len()
                ),
            });
            let start = Instant::now();
            let query = self.owner.prepare_exact_aggregate_for_experiment(
                &peer.table,
                range,
                MAX_LAB_ROWS,
                Limits::default(),
            )?;
            let evaluated = peer.evaluator.evaluate_exact_aggregate(query.request())?;
            let result = self
                .owner
                .complete_exact_aggregate_unverified_for_experiment(
                    &peer.table,
                    query,
                    &evaluated.output,
                )?;
            count += result.count;
            sum += result.sum;
            contributions.push(PeerAggregate {
                id: peer.id,
                count: result.count,
                sum: result.sum,
                elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
            });
        }
        Ok(QueryOutcome::Aggregate {
            count,
            sum,
            peers: contributions,
        })
    }
    fn add_amount(
        &self,
        range: AgeRange,
        delta: u16,
        progress: &impl Fn(LabProgress),
    ) -> Result<(QueryOutcome, Option<PreparedUpdate>), LabError> {
        let mut candidates = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let mut table = peer.table.fork_for_experiment();
            if peer.rows() != 0 {
                progress(LabProgress {
                    peer_id: peer.id,
                    message: format!(
                        "Staging compact encrypted update on peer {} / {}...",
                        peer.id,
                        self.peers.len()
                    ),
                });
                let query = self.owner.prepare_exact_update_for_experiment(
                    &peer.table,
                    range,
                    delta,
                    MAX_LAB_ROWS,
                    Limits::default(),
                )?;
                let evaluated = peer.evaluator.evaluate_indexed_update(query.request())?;
                let applied = self.owner.apply_exact_update_checked_for_experiment(
                    &mut table,
                    query,
                    &evaluated.output,
                    Limits::default(),
                )?;
                if applied.rejected {
                    return Ok((QueryOutcome::Updated { committed: false }, None));
                }
            }
            peer.config
                .check_size(table.canonical_data_bytes() + table.encrypted_index_bytes())?;
            candidates.push(table);
        }
        // The inspector mirrors actual staged ciphertexts, not a plaintext SQL fallback.
        let mut owner_rows = self.owner_rows.clone();
        for (shard, table) in candidates.iter().enumerate() {
            for (local, global) in (shard..owner_rows.len())
                .step_by(candidates.len())
                .enumerate()
            {
                let row = self.owner.decrypt_row_for_experiment(
                    table,
                    local as u64,
                    Limits::default(),
                )?;
                owner_rows[global] = row;
            }
        }
        Ok((
            QueryOutcome::Updated { committed: true },
            Some(PreparedUpdate {
                tables: candidates,
                rows: owner_rows,
            }),
        ))
    }
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
    owner: &backend::Owner,
    evaluator: &backend::Evaluator,
    rows: &[PlainRow],
    profiles: Vec<(usize, PeerConfig, bool)>,
) -> Result<Vec<Peer>, LabError> {
    let count = profiles.len();
    let mut partitions = vec![Vec::new(); count];
    for (index, row) in rows.iter().enumerate() {
        if count != 0 {
            partitions[index % count].push(*row);
        }
    }
    let mut peers = Vec::with_capacity(count);
    for (rows, (id, mut config, online)) in partitions.into_iter().zip(profiles) {
        config.name = config.name.trim().into();
        let table = owner.seal(&rows, ROWS_PER_PAGE, Limits::default())?;
        config.check_size(table.canonical_data_bytes() + table.encrypted_index_bytes())?;
        peers.push(Peer {
            id,
            config,
            evaluator: evaluator.clone(),
            table,
            online,
        });
    }
    Ok(peers)
}
/// Public synthetic data only. Each GUI run generates fresh secret keys in memory.
pub fn sample_rows(count: usize) -> Result<Vec<PlainRow>, LabError> {
    if count > MAX_LAB_ROWS {
        return Err(LabError::InvalidInput(
            "Use at most 128 sample rows.".into(),
        ));
    }
    let pattern = [
        PlainRow {
            age: 17,
            amount: 10,
        },
        PlainRow {
            age: 18,
            amount: 20,
        },
        PlainRow {
            age: 42,
            amount: 30,
        },
        PlainRow { age: 7, amount: 40 },
    ];
    Ok((0..count)
        .map(|index| pattern[index % pattern.len()])
        .collect())
}

pub fn format_rows(rows: &[PlainRow]) -> String {
    rows.iter()
        .map(|row| format!("{},{}", row.age, row.amount))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parses owner-entered age,amount lines before key generation or database replacement.
pub fn parse_rows(text: &str) -> Result<Vec<PlainRow>, LabError> {
    if text.len() > 16_384 {
        return Err(LabError::InvalidInput(
            "Fixture exceeds 16384 bytes.".into(),
        ));
    }
    let mut rows = Vec::new();
    for (line, value) in text.lines().enumerate() {
        if value.trim().is_empty() {
            continue;
        }
        if rows.len() == MAX_LAB_ROWS {
            return Err(LabError::InvalidInput("Use at most 128 rows.".into()));
        }
        let error = || {
            LabError::InvalidInput(format!(
                "Line {}: expected age 0..255,amount 0..65535.",
                line + 1
            ))
        };
        let (age, amount) = value.split_once(',').ok_or_else(error)?;
        rows.push(PlainRow {
            age: age.trim().parse().map_err(|_| error())?,
            amount: amount.trim().parse().map_err(|_| error())?,
        });
    }
    Ok(rows)
}
