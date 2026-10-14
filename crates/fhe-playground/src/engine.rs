use std::fmt;
use std::time::Instant;

use fhe_prototype::{Comparison, EncryptedTable, Evaluator, Owner, PlainRow};

use crate::{Predicate, QueryPlan, parse_sql};

pub const MAX_PEERS: usize = 16;
pub const MAX_LAB_ROWS: usize = 128;

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

impl From<fhe_prototype::Error> for LabError {
    fn from(error: fhe_prototype::Error) -> Self {
        Self::Cryptography(error.to_string())
    }
}

pub struct DatabaseDraft {
    pub name: String,
    pub rows: Vec<PlainRow>,
    pub peers: Vec<PeerConfig>,
}

/// Local experiment settings. Quota covers the compressed shard, not process RAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub name: String,
    pub storage_limit_bytes: usize,
    /// Artificial packet delay applied by the demo transport, not measured ping.
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
    pub compressed_bytes: usize,
    /// Indices into the owner's fixture for the inspector; never peer plaintext.
    pub owner_row_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct LabSnapshot {
    pub name: String,
    pub revision: u64,
    /// The owner's editable fixture, not plaintext supplied to peer evaluators.
    pub owner_rows: Vec<PlainRow>,
    pub peers: Vec<PeerInfo>,
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
        committed: bool,
    },
}

/// Owns the client keys and one local database. Each peer holds an encrypted shard
/// and evaluation material only. This is an honest local simulation, not P2P/BFT.
#[derive(Default)]
pub struct LabEngine {
    database: Option<Database>,
    prepared: Option<PreparedUpdate>,
}

struct Database {
    name: String,
    revision: u64,
    owner: Owner,
    evaluator: Evaluator,
    owner_rows: Vec<PlainRow>,
    peers: Vec<Peer>,
}

struct Peer {
    id: usize,
    config: PeerConfig,
    evaluator: Evaluator,
    table: EncryptedTable,
    online: bool,
    compressed_bytes: usize,
}

struct PreparedUpdate {
    tables: Vec<(EncryptedTable, usize)>,
    rows: Vec<PlainRow>,
}

impl LabEngine {
    /// Builds replacement state first. Validation or FHE errors retain the old database.
    pub fn create(&mut self, draft: DatabaseDraft) -> Result<LabSnapshot, LabError> {
        let ids = (1..=draft.peers.len()).collect();
        self.create_with_peer_ids(draft, ids)
    }

    /// The manager supplies stable storage identities independently of graph IDs.
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
        if draft.peers.len() > MAX_PEERS
            || ids.len() != draft.peers.len()
            || ids.contains(&0)
            || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
        {
            return Err(LabError::InvalidInput(
                "Use at most 16 peers with unique nonzero IDs.".into(),
            ));
        }
        for config in &draft.peers {
            config.validate()?;
        }
        if draft.rows.len() > MAX_LAB_ROWS {
            return Err(LabError::InvalidInput(
                "The GUI experiment allows at most 128 rows.".into(),
            ));
        }
        let (owner, evaluator) = Owner::generate()?;
        let mut partitions = vec![Vec::new(); draft.peers.len()];
        for (index, row) in draft.rows.iter().copied().enumerate() {
            if !partitions.is_empty() {
                partitions[index % draft.peers.len()].push(row);
            }
        }
        let mut peers = Vec::with_capacity(draft.peers.len());
        for ((rows, mut config), id) in partitions.into_iter().zip(draft.peers).zip(ids) {
            config.name = config.name.trim().into();
            let table = owner.encrypt_table(&rows)?;
            let image = evaluator.compress_table(&table)?;
            config.check_size(image.len())?;
            drop(table);
            let table = evaluator.restore_trusted_image(&image)?;
            peers.push(Peer {
                id,
                config,
                evaluator: evaluator.clone(),
                table,
                online: true,
                compressed_bytes: image.len(),
            });
        }
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
                    rows: peer.table.len(),
                    compressed_bytes: peer.compressed_bytes,
                    owner_row_indices: (index..db.owner_rows.len())
                        .step_by(db.peers.len())
                        .collect(),
                })
                .collect(),
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
        config.check_size(peer.compressed_bytes)?;
        config.name = config.name.trim().into();
        peer.config = config;
        self.prepared = None;
        Ok(())
    }

    /// Repartitions the owner's live fixture using the existing keys. All new
    /// ciphertexts and quota checks are staged before replacing the layout.
    /// This is manager-driven local rebuilding, not network recovery/replication.
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

    /// Explicit local manager operation. Retained owner data can rebuild shards,
    /// including after the last peer is removed; this is not network recovery.
    pub fn repartition(
        &mut self,
        profiles: Vec<(usize, PeerConfig, bool)>,
    ) -> Result<(), LabError> {
        if profiles.len() > MAX_PEERS
            || profiles.iter().any(|(id, _, _)| *id == 0)
            || profiles
                .iter()
                .map(|(id, _, _)| id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != profiles.len()
        {
            return Err(LabError::InvalidInput(
                "Use at most 16 peers with unique nonzero IDs.".into(),
            ));
        }
        for (_, config, _) in &profiles {
            config.validate()?;
        }
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let evaluator = db.evaluator.clone();
        let configs_len = profiles.len();
        let mut partitions = vec![Vec::new(); configs_len];
        for (index, row) in db.owner_rows.iter().copied().enumerate() {
            if !partitions.is_empty() {
                partitions[index % configs_len].push(row);
            }
        }
        let mut candidates = Vec::with_capacity(configs_len);
        for (rows, (id, mut config, online)) in partitions.into_iter().zip(profiles) {
            config.name = config.name.trim().into();
            let table = db.owner.encrypt_table(&rows)?;
            let image = evaluator.compress_table(&table)?;
            config.check_size(image.len())?;
            drop(table);
            candidates.push(Peer {
                id,
                config,
                evaluator: evaluator.clone(),
                table: evaluator.restore_trusted_image(&image)?,
                online,
                compressed_bytes: image.len(),
            });
        }
        db.peers = candidates;
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

    /// Computes ciphertext results but retains updates until response delivery is
    /// accepted by the transport controller. Cancellation discards every shard.
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
            .filter(|peer| !peer.online && !peer.table.is_empty())
            .map(|peer| peer.id)
            .collect();
        if !missing.is_empty() {
            return Err(LabError::Unavailable(missing));
        }
        match plan {
            QueryPlan::Aggregate { predicate } => db.aggregate(predicate, &progress),
            QueryPlan::AddAmount { predicate, delta } => {
                let (result, prepared) = db.add_amount(predicate, delta, &progress)?;
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
            for (peer, (table, bytes)) in db.peers.iter_mut().zip(update.tables) {
                peer.table = table;
                peer.compressed_bytes = bytes;
            }
            db.owner_rows = update.rows;
            db.revision += 1;
        }
    }
}

impl Database {
    fn aggregate(
        &self,
        predicate: Predicate,
        progress: &impl Fn(LabProgress),
    ) -> Result<QueryOutcome, LabError> {
        let encrypted = self
            .owner
            .encrypt_predicate(predicate.comparison, predicate.threshold)?;
        let mut contributions = Vec::new();
        let (mut count, mut sum) = (0, 0);
        for peer in &self.peers {
            if peer.table.is_empty() {
                continue;
            }
            progress(LabProgress {
                peer_id: peer.id,
                message: format!(
                    "Evaluating encrypted shard on peer {} / {}...",
                    peer.id,
                    self.peers.len()
                ),
            });
            let start = Instant::now();
            let unverified = peer.evaluator.aggregate(&peer.table, &encrypted)?;
            let (peer_count, peer_sum) =
                self.owner.decrypt_aggregate_for_experiment(&unverified)?;
            count += peer_count;
            sum += peer_sum;
            contributions.push(PeerAggregate {
                id: peer.id,
                count: peer_count,
                sum: peer_sum,
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
        &mut self,
        predicate: Predicate,
        delta: u16,
        progress: &impl Fn(LabProgress),
    ) -> Result<(QueryOutcome, Option<PreparedUpdate>), LabError> {
        let encrypted_predicate = self
            .owner
            .encrypt_predicate(predicate.comparison, predicate.threshold)?;
        let encrypted_delta = self.owner.encrypt_delta(delta)?;
        let mut candidates = Vec::with_capacity(self.peers.len());
        // Stage every shard separately. Until all updates and round trips succeed,
        // the original database remains unchanged, including on cross-shard overflow.
        for peer in &self.peers {
            let before = peer.evaluator.compress_table(&peer.table)?;
            let mut table = peer.evaluator.restore_trusted_image(&before)?;
            if peer.table.is_empty() {
                candidates.push((table, before.len()));
                continue;
            }
            progress(LabProgress {
                peer_id: peer.id,
                message: format!(
                    "Staging encrypted update on peer {} / {}...",
                    peer.id,
                    self.peers.len()
                ),
            });
            let outcome =
                peer.evaluator
                    .add_amount(&mut table, &encrypted_predicate, &encrypted_delta)?;
            if self
                .owner
                .decrypt_update_rejection_for_experiment(&outcome)?
            {
                return Ok((QueryOutcome::Updated { committed: false }, None));
            }
            let after = peer.evaluator.compress_table(&table)?;
            peer.config.check_size(after.len())?;
            drop(table);
            candidates.push((peer.evaluator.restore_trusted_image(&after)?, after.len()));
        }
        // The owner's fixture mirrors a successful FHE update for editing/display;
        // query results above always come from the ciphertexts, not this reference.
        let mut owner_rows = self.owner_rows.clone();
        for row in &mut owner_rows {
            if matches_row(row, predicate) {
                row.amount = row.amount.checked_add(delta).ok_or_else(|| {
                    LabError::Cryptography(
                        "FHE overflow status disagrees with the owner fixture.".into(),
                    )
                })?;
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

fn matches_row(row: &PlainRow, predicate: Predicate) -> bool {
    match predicate.comparison {
        Comparison::Equal => row.age == predicate.threshold,
        Comparison::AtLeast => row.age >= predicate.threshold,
    }
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
