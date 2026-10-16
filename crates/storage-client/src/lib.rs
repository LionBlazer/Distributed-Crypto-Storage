//! Owner/client orchestration over authenticated peers. Stored rows and FHE evaluation
//! live in peer processes; the owner retains keys and exact trusted heads only.
//! Missing computation proofs fail closed before any result or write is accepted.
#![forbid(unsafe_code)]
use compact_query::{AgeRange, PlainRow, Table, bfv as backend};
use compact_store::{Commitment, Limits};
use peer_runtime::{Bundle, Operation, RemotePeer, Request, Response, Status};
use sql_plan::{Projection, QueryPlan};
use std::{fmt, io};
mod proof;
pub mod relational;
mod script;
mod session;
pub use script::{
    MAX_SCRIPT_BYTES, MAX_SCRIPT_STATEMENTS, ScriptError, ScriptResult, SqlScript, SqlStatement,
    StatementOutcome, StatementResult,
};
pub use session::{AggregateProjection, Session, VerifiedResult};

#[derive(Debug)]
pub enum Error {
    InvalidInput(String),
    Transport(io::Error),
    Cryptography(String),
    MissingComputationProof,
    UnavailableShard(u64),
    /// The exact authorized mutation is retained in this live Session. Retry the
    /// same SQL or call resume_pending; a new SQL statement must not replay it.
    PendingMutation {
        query_binding: [u8; 32],
        submitted: Option<Box<version_journal::HeadRef>>,
        reason: String,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::Cryptography(message) => f.write_str(message),
            Self::Transport(error) => write!(f, "Peer transport: {error}"),
            Self::MissingComputationProof => f.write_str(concat!(
                "Encrypted peer execution completed, but no cryptographic proof of correctness/completeness was supplied. ",
                "Requirements 11–13 prohibit accepting the result or committing a write."
            )),
            Self::UnavailableShard(id) => write!(f, "Logical shard {id} has no reachable authenticated ciphertext holder"),
            Self::PendingMutation { query_binding, submitted, reason } => {
                let id: String = query_binding.iter().map(|byte| format!("{byte:02x}")).collect();
                write!(f, "Mutation {id} remains pending")?;
                if let Some(head) = submitted { write!(f, " at submitted height {}", head.height)?; }
                write!(f, ": {reason}. Retry the same SQL or call Session::resume_pending; do not submit a different statement")
            }
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Transport(e)
    }
}
impl From<compact_query::Error> for Error {
    fn from(e: compact_query::Error) -> Self {
        Self::Cryptography(e.to_string())
    }
}
impl From<sql_plan::Error> for Error {
    fn from(e: sql_plan::Error) -> Self {
        Self::InvalidInput(e.to_string())
    }
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone)]
pub struct Participant {
    pub id: u64,
    pub remote: RemotePeer,
}
#[derive(Clone, Debug)]
pub struct ShardInfo {
    pub id: u64,
    pub object: [u8; 32],
    pub holders: Vec<u64>,
    pub rows: usize,
    pub data_head: Commitment,
    pub index_head: Commitment,
}
struct Shard {
    info: ShardInfo,
    peers: Vec<Participant>,
}
/// This type has no constructor for a fabricated or unverified accepted result.
#[derive(Debug)]
pub enum AcceptedResult {}
pub struct Database {
    name: String,
    owner: backend::Owner,
    setup: Vec<u8>,
    setup_id: [u8; 32],
    shards: Vec<Shard>,
}
impl Database {
    pub fn create(name: String, rows: &[PlainRow], peers: Vec<Participant>) -> Result<Self> {
        if name.trim().is_empty()
            || name.len() > 64
            || peers.is_empty()
            || peers.len() > 32
            || rows.len() > 1_000_000
        {
            return Err(Error::InvalidInput(
                "Use a database name, 1..32 distinct peers and at most 1000000 input rows".into(),
            ));
        }
        if peers
            .iter()
            .map(|p| p.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != peers.len()
        {
            return Err(Error::InvalidInput("Duplicate participant identity".into()));
        }
        let mut domain = [0u8; 16];
        getrandom::getrandom(&mut domain).map_err(|e| Error::Cryptography(e.to_string()))?;
        let (owner, evaluator) = backend::Owner::generate(domain)?;
        let setup = evaluator.encode_public_setup_for_experiment()?;
        // The public evaluator created for parameter generation is never used to execute a query.
        drop(evaluator);
        let mut setup_id = None;
        let mut shards = Vec::new();
        for (slot, peer) in peers.iter().enumerate() {
            let current = install(&peer.remote, &setup)?;
            if setup_id.is_some_and(|id| id != current) {
                return Err(Error::Cryptography("Public setup identity mismatch".into()));
            }
            setup_id = Some(current);
            let part: Vec<_> = rows
                .iter()
                .skip(slot)
                .step_by(peers.len())
                .copied()
                .collect();
            let table = owner.seal(&part, 256, Limits::default())?;
            let bundle = Bundle {
                data_head: table.commitment().encode().to_vec(),
                index_head: table.index_commitment().encode().to_vec(),
                data: table.snapshot().encode(),
                index: table.encrypted_index().encode(),
            };
            let object = bundle.id();
            match peer.remote.call(Request::Store(bundle))? {
                Response::Stored(info) if info.id == object => {}
                _ => return Err(Error::Cryptography("Invalid store acknowledgement".into())),
            }
            shards.push(Shard {
                info: ShardInfo {
                    id: peer.id,
                    object,
                    holders: vec![peer.id],
                    rows: part.len(),
                    data_head: table.commitment().clone(),
                    index_head: table.index_commitment().clone(),
                },
                peers: vec![peer.clone()],
            });
        }
        Ok(Self {
            name,
            owner,
            setup,
            setup_id: setup_id.unwrap(),
            shards,
        })
    }
    pub fn replace_participant(&mut self, participant: Participant) -> Result<()> {
        install(&participant.remote, &self.setup)?;
        for shard in &mut self.shards {
            if let Some(peer) = shard
                .peers
                .iter_mut()
                .find(|peer| peer.id == participant.id)
            {
                *peer = participant.clone();
            }
        }
        Ok(())
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn shards(&self) -> Vec<ShardInfo> {
        self.shards.iter().map(|s| s.info.clone()).collect()
    }
    pub fn rows(&self) -> usize {
        self.shards.iter().map(|s| s.info.rows).sum()
    }
    pub fn statuses(&self) -> Vec<(u64, io::Result<Status>)> {
        let mut peers = std::collections::BTreeMap::new();
        for shard in &self.shards {
            for peer in &shard.peers {
                peers.entry(peer.id).or_insert_with(|| peer.remote.clone());
            }
        }
        peers
            .into_iter()
            .map(|(id, peer)| (id, peer.status()))
            .collect()
    }
    fn fetch(&self, shard: &Shard) -> Result<(RemotePeer, Table)> {
        for peer in &shard.peers {
            if let Ok(Response::Bundle(bundle)) = peer.remote.call(Request::Fetch {
                object: shard.info.object,
            }) {
                if bundle.id() != shard.info.object
                    || bundle.data_head != shard.info.data_head.encode()
                    || bundle.index_head != shard.info.index_head.encode()
                {
                    continue;
                }
                let Ok(table) = self.owner.restore_table_for_experiment(
                    &bundle.data,
                    &bundle.index,
                    &shard.info.data_head,
                    &shard.info.index_head,
                    Limits::default(),
                ) else {
                    continue;
                };
                return Ok((peer.remote.clone(), table));
            }
        }
        Err(Error::UnavailableShard(shard.info.id))
    }
    /// Actually transfers ciphertext directly from a live source process to the
    /// target process. This is an explicit owner action, not decentralized placement.
    pub fn copy_shard(&mut self, shard_id: u64, target: Participant) -> Result<()> {
        let shard = self
            .shards
            .iter_mut()
            .find(|s| s.info.id == shard_id)
            .ok_or_else(|| Error::InvalidInput("Unknown shard".into()))?;
        if shard.peers.iter().any(|p| p.id == target.id)
            && matches!(target.remote.call(Request::Fetch { object: shard.info.object }), Ok(Response::Bundle(bundle)) if bundle.id() == shard.info.object)
        {
            return Ok(());
        }
        install(&target.remote, &self.setup)?;
        let mut copied = false;
        for source in &shard.peers {
            if matches!(target.remote.call(Request::Copy{source:source.remote.endpoint().clone(),object:shard.info.object}),Ok(Response::Stored(info)) if info.id==shard.info.object)
            {
                copied = true;
                break;
            }
        }
        if !copied {
            return Err(Error::UnavailableShard(shard_id));
        }
        if !shard.info.holders.contains(&target.id) {
            shard.info.holders.push(target.id);
        }
        if let Some(existing) = shard.peers.iter_mut().find(|peer| peer.id == target.id) {
            *existing = target;
        } else {
            shard.peers.push(target);
        }
        Ok(())
    }
    /// Wire replies currently contain no computation proof. The only implemented
    /// reply case is rejected; it can never produce AcceptedResult or advance heads.
    pub fn execute(&self, sql: &str) -> Result<AcceptedResult> {
        let plan = sql_plan::parse_sql(sql)?;
        let shards: Vec<_> = if matches!(plan, QueryPlan::Insert { .. }) {
            vec![self.shards.iter().min_by_key(|s| s.info.rows).unwrap()]
        } else {
            self.shards.iter().collect()
        };
        for shard in shards {
            let (peer, table) = self.fetch(shard)?;
            let (operation, ciphertext) = match plan {
                QueryPlan::Select {
                    predicate,
                    projection,
                    ..
                } => {
                    let Some(range) = predicate.age_range() else {
                        return Err(Error::MissingComputationProof);
                    };
                    let projection = match projection {
                        Projection::Age => backend::RowProjection::Age,
                        Projection::Amount => backend::RowProjection::Amount,
                        _ => backend::RowProjection::AgeAmount,
                    };
                    let prepared = self.owner.prepare_exact_select_for_experiment(
                        &table,
                        AgeRange {
                            lower: range.lower,
                            upper: range.upper,
                        },
                        projection,
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Select, prepared.request().to_vec())
                }
                QueryPlan::Aggregate { predicate }
                | QueryPlan::Count { predicate }
                | QueryPlan::Sum { predicate } => {
                    let Some(range) = predicate.age_range() else {
                        return Err(Error::MissingComputationProof);
                    };
                    let prepared = self.owner.prepare_exact_aggregate_for_experiment(
                        &table,
                        AgeRange {
                            lower: range.lower,
                            upper: range.upper,
                        },
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Aggregate, prepared.request().to_vec())
                }
                QueryPlan::AddAmount { predicate, delta } => {
                    let Some(range) = predicate.age_range() else {
                        return Err(Error::MissingComputationProof);
                    };
                    let prepared = self.owner.prepare_exact_update_for_experiment(
                        &table,
                        AgeRange {
                            lower: range.lower,
                            upper: range.upper,
                        },
                        delta,
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Update, prepared.request().to_vec())
                }
                QueryPlan::Insert { row } => {
                    let prepared = self.owner.prepare_insert_for_experiment(
                        &table,
                        PlainRow {
                            age: row.age,
                            amount: row.amount,
                        },
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Insert, prepared.request().to_vec())
                }
            };
            match peer.call(Request::Evaluate {
                object: shard.info.object,
                setup: self.setup_id,
                operation,
                ciphertext,
            })? {
                Response::UnverifiedCiphertext(_) => {}
                _ => return Err(Error::Cryptography("Unexpected FHE response".into())),
            }
        }
        Err(Error::MissingComputationProof)
    }
}
fn install(peer: &RemotePeer, setup: &[u8]) -> Result<[u8; 32]> {
    match peer.call(Request::InstallSetup(setup.to_vec()))? {
        Response::Setup(id) => Ok(id),
        _ => Err(Error::Cryptography(
            "Missing public-setup acknowledgement".into(),
        )),
    }
}
