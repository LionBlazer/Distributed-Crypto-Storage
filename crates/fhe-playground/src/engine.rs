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
    pub peer_count: usize,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: usize,
    pub online: bool,
    pub rows: usize,
    pub compressed_bytes: usize,
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
}

struct Database {
    name: String,
    revision: u64,
    owner: Owner,
    owner_rows: Vec<PlainRow>,
    peers: Vec<Peer>,
}

struct Peer {
    evaluator: Evaluator,
    table: EncryptedTable,
    online: bool,
    compressed_bytes: usize,
}

impl LabEngine {
    /// Builds replacement state first. Validation or FHE errors retain the old database.
    pub fn create(&mut self, draft: DatabaseDraft) -> Result<LabSnapshot, LabError> {
        let name = draft.name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(LabError::InvalidInput(
                "Database name must contain 1..64 bytes, without control characters.".into(),
            ));
        }
        if !(1..=MAX_PEERS).contains(&draft.peer_count) {
            return Err(LabError::InvalidInput("Use 1..16 simulated peers.".into()));
        }
        if draft.rows.len() > MAX_LAB_ROWS {
            return Err(LabError::InvalidInput(
                "The GUI experiment allows at most 128 rows.".into(),
            ));
        }
        let (owner, evaluator) = Owner::generate()?;
        let mut partitions = vec![Vec::new(); draft.peer_count];
        for (index, row) in draft.rows.iter().copied().enumerate() {
            partitions[index % draft.peer_count].push(row);
        }
        let mut peers = Vec::with_capacity(draft.peer_count);
        for rows in partitions {
            let table = owner.encrypt_table(&rows)?;
            let image = evaluator.compress_table(&table)?;
            drop(table);
            let table = evaluator.restore_trusted_image(&image)?;
            peers.push(Peer {
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
            owner_rows: draft.rows,
            peers,
        });
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
                    id: index + 1,
                    online: peer.online,
                    rows: peer.table.len(),
                    compressed_bytes: peer.compressed_bytes,
                })
                .collect(),
        })
    }

    pub fn set_peer_online(&mut self, id: usize, online: bool) -> Result<(), LabError> {
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let peer = id
            .checked_sub(1)
            .and_then(|index| db.peers.get_mut(index))
            .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?;
        peer.online = online;
        Ok(())
    }

    pub fn execute(&mut self, sql: &str) -> Result<QueryOutcome, LabError> {
        self.execute_with_progress(sql, |_| {})
    }

    pub fn execute_with_progress(
        &mut self,
        sql: &str,
        progress: impl Fn(String),
    ) -> Result<QueryOutcome, LabError> {
        let plan = parse_sql(sql)?;
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let missing: Vec<_> = db
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| !peer.online && !peer.table.is_empty())
            .map(|(index, _)| index + 1)
            .collect();
        if !missing.is_empty() {
            return Err(LabError::Unavailable(missing));
        }
        match plan {
            QueryPlan::Aggregate { predicate } => db.aggregate(predicate, &progress),
            QueryPlan::AddAmount { predicate, delta } => db.add_amount(predicate, delta, &progress),
        }
    }
}

impl Database {
    fn aggregate(
        &self,
        predicate: Predicate,
        progress: &impl Fn(String),
    ) -> Result<QueryOutcome, LabError> {
        let encrypted = self
            .owner
            .encrypt_predicate(predicate.comparison, predicate.threshold)?;
        let mut contributions = Vec::new();
        let (mut count, mut sum) = (0, 0);
        for (index, peer) in self.peers.iter().enumerate() {
            if peer.table.is_empty() {
                continue;
            }
            progress(format!(
                "Evaluating encrypted shard on peer {} / {}...",
                index + 1,
                self.peers.len()
            ));
            let start = Instant::now();
            let unverified = peer.evaluator.aggregate(&peer.table, &encrypted)?;
            let (peer_count, peer_sum) =
                self.owner.decrypt_aggregate_for_experiment(&unverified)?;
            count += peer_count;
            sum += peer_sum;
            contributions.push(PeerAggregate {
                id: index + 1,
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
        progress: &impl Fn(String),
    ) -> Result<QueryOutcome, LabError> {
        let encrypted_predicate = self
            .owner
            .encrypt_predicate(predicate.comparison, predicate.threshold)?;
        let encrypted_delta = self.owner.encrypt_delta(delta)?;
        let mut candidates = Vec::with_capacity(self.peers.len());
        // Stage every shard separately. Until all updates and round trips succeed,
        // the original database remains unchanged, including on cross-shard overflow.
        for (index, peer) in self.peers.iter().enumerate() {
            progress(format!(
                "Staging encrypted update on peer {} / {}...",
                index + 1,
                self.peers.len()
            ));
            let before = peer.evaluator.compress_table(&peer.table)?;
            let mut table = peer.evaluator.restore_trusted_image(&before)?;
            let outcome =
                peer.evaluator
                    .add_amount(&mut table, &encrypted_predicate, &encrypted_delta)?;
            if self
                .owner
                .decrypt_update_rejection_for_experiment(&outcome)?
            {
                return Ok(QueryOutcome::Updated { committed: false });
            }
            let after = peer.evaluator.compress_table(&table)?;
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
        for (peer, (table, bytes)) in self.peers.iter_mut().zip(candidates) {
            peer.table = table;
            peer.compressed_bytes = bytes;
        }
        self.owner_rows = owner_rows;
        self.revision += 1;
        Ok(QueryOutcome::Updated { committed: true })
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
