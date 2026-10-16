//! Owner/client orchestration over authenticated peers. Stored rows and FHE evaluation
//! live in peer processes; the owner retains keys and exact trusted heads only.
//! Missing computation proofs fail closed before any result or write is accepted.
#![forbid(unsafe_code)]
use compact_query::{AgeRange, PlainRow, Table, bfv as backend};
use compact_store::{Commitment, Limits};
use peer_runtime::{Operation, RawBundle, RemotePeer, Request, Response, Status};
use sql_plan::{Projection, QueryPlan};
use std::{fmt, io};
mod jobs;
mod query_rpc;
pub mod relational;
mod script;
mod session;
pub use script::{
    MAX_SCRIPT_BYTES, MAX_SCRIPT_INSERTED_ROWS, MAX_SCRIPT_STATEMENTS, ScriptError, ScriptResult,
    SqlScript, SqlStatement, StatementOutcome, StatementResult,
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
    table_id: compact_query::TableId,
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
        let owner = owner.with_audit_workers(owner_audit_workers());
        let setup = evaluator.encode_public_setup_for_experiment()?;
        // The public evaluator created for parameter generation is never used to execute a query.
        drop(evaluator);
        let table_id = compact_query::TableId::generate()?;
        let assignments: Vec<_> = (0..rows.len()).map(|row| row % peers.len()).collect();
        let row_ids =
            compact_query::RowIds::generate(rows.len())?.partition(&assignments, peers.len())?;
        drop(assignments);
        let mut sealed = Vec::new();
        for (slot, (peer, ids)) in peers.iter().zip(row_ids).enumerate() {
            let part: Vec<_> = rows
                .iter()
                .skip(slot)
                .step_by(peers.len())
                .copied()
                .collect();
            let table = owner.seal_partition(&table_id, &part, ids, 256, Limits::default())?;
            let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index())
                .map_err(|e| Error::Cryptography(e.to_string()))?;
            sealed.push((peer, table, bundle, part.len()));
        }
        let mut setup_id = None;
        let mut shards = Vec::new();
        for (peer, table, bundle, rows) in sealed {
            let current = install(&peer.remote, &setup)?;
            if setup_id.is_some_and(|id| id != current) {
                return Err(Error::Cryptography("Public setup identity mismatch".into()));
            }
            setup_id = Some(current);
            let object = *bundle
                .target_version()
                .map_err(|e| Error::Cryptography(e.to_string()))?
                .object();
            match peer.remote.call(Request::Store(bundle))? {
                Response::Stored(info) if info.id == object => {}
                _ => return Err(Error::Cryptography("Invalid store acknowledgement".into())),
            }
            shards.push(Shard {
                info: ShardInfo {
                    id: peer.id,
                    object,
                    holders: vec![peer.id],
                    rows,
                    data_head: table.commitment().clone(),
                    index_head: table.index_commitment().clone(),
                },
                peers: vec![peer.clone()],
            });
        }
        Ok(Self {
            name,
            table_id,
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
            if let Ok(Response::RawBundle(bundle)) = peer.remote.call(Request::Fetch {
                object: shard.info.object,
            }) {
                if !bundle
                    .target_version()
                    .is_ok_and(|version| version.object() == &shard.info.object)
                    || bundle.data_head != shard.info.data_head.encode()
                    || bundle.index_head != shard.info.index_head.encode()
                {
                    continue;
                }
                let Ok(table) = self.owner.restore_table_for_experiment(
                    &bundle.data,
                    &bundle.index,
                    &self.table_id,
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
            && holds_object(
                target.remote.call(Request::Fetch {
                    object: shard.info.object,
                }),
                shard.info.object,
                &shard.info.data_head.encode(),
                &shard.info.index_head.encode(),
            )
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
        if matches!(&plan, QueryPlan::Select { window, .. } if window.offset != 0) {
            return Err(Error::InvalidInput("The historical unverified adapter does not execute OFFSET; use the proof-backed Session".into()));
        }
        let range = match &plan {
            QueryPlan::Insert { .. } => None,
            QueryPlan::Select { predicate, .. }
            | QueryPlan::Aggregate { predicate }
            | QueryPlan::Count { predicate }
            | QueryPlan::Sum { predicate }
            | QueryPlan::AddAmount { predicate, .. } => {
                let mask = compact_query::AgeSet256::from_bytes(predicate.age_mask());
                let ages: Vec<_> = mask.ages().collect();
                let Some((&lower, &upper)) = ages.first().zip(ages.last()) else {
                    return Err(Error::MissingComputationProof);
                };
                if ages.len() != usize::from(upper) - usize::from(lower) + 1 {
                    return Err(Error::InvalidInput("This historical unverified adapter accepts only contiguous age sets; use Session for proved boolean predicates".into()));
                }
                Some(AgeRange { lower, upper })
            }
        };
        let shards: Vec<_> = if matches!(plan, QueryPlan::Insert { .. }) {
            vec![self.shards.iter().min_by_key(|s| s.info.rows).unwrap()]
        } else {
            self.shards.iter().collect()
        };
        for shard in shards {
            let (peer, table) = self.fetch(shard)?;
            let (operation, ciphertext) = match &plan {
                QueryPlan::Select { projection, .. } => {
                    let range = range.expect("non-insert range admitted before fetching");
                    let projection = match projection {
                        Projection::Age => backend::RowProjection::Age,
                        Projection::Amount => backend::RowProjection::Amount,
                        _ => backend::RowProjection::AgeAmount,
                    };
                    let prepared = self.owner.prepare_exact_select_for_experiment(
                        &table,
                        range,
                        projection,
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Select, prepared.request().to_vec())
                }
                QueryPlan::Aggregate { .. } | QueryPlan::Count { .. } | QueryPlan::Sum { .. } => {
                    let range = range.expect("non-insert range admitted before fetching");
                    let prepared = self.owner.prepare_exact_aggregate_for_experiment(
                        &table,
                        range,
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Aggregate, prepared.request().to_vec())
                }
                QueryPlan::AddAmount { delta, .. } => {
                    let range = range.expect("non-insert range admitted before fetching");
                    let prepared = self.owner.prepare_exact_update_for_experiment(
                        &table,
                        range,
                        *delta,
                        256,
                        Limits::default(),
                    )?;
                    (Operation::Update, prepared.request().to_vec())
                }
                QueryPlan::Insert { rows } => {
                    let incoming = zeroize::Zeroizing::new(
                        rows.iter()
                            .map(|row| PlainRow {
                                age: row.age,
                                amount: row.amount,
                            })
                            .collect::<Vec<_>>(),
                    );
                    let prepared = self.owner.prepare_insert_for_experiment(
                        &table,
                        &incoming,
                        compact_query::RowIds::generate(incoming.len())?,
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

// Product CPU policy stays outside compact-query and compact-store hard caps.
fn owner_audit_workers() -> compact_store::AuditWorkers {
    static WORKERS: std::sync::OnceLock<compact_store::AuditWorkers> = std::sync::OnceLock::new();
    *WORKERS.get_or_init(|| {
        let available = std::thread::available_parallelism().map_or(1, usize::from);
        let requested = std::env::var("RAYON_NUM_THREADS").ok();
        resolve_owner_audit_workers(available, requested.as_deref())
    })
}
fn resolve_owner_audit_workers(
    available: usize,
    requested: Option<&str>,
) -> compact_store::AuditWorkers {
    if proof_acceleration::worker_budget(available, requested) == 1 {
        compact_store::AuditWorkers::One
    } else {
        compact_store::AuditWorkers::Two
    }
}

// Recovered holder credit needs complete custody, independently pinned ID and
// both heads. Neither a binding-only TargetVersion nor TLS is sufficient.
fn holds_object(
    response: io::Result<Response>,
    object: [u8; 32],
    data: &[u8],
    index: &[u8],
) -> bool {
    let Ok(Response::RawBundle(raw)) = response else {
        return false;
    };
    let Ok(checked) = peer_runtime::CheckedObject::audit(raw) else {
        return false;
    };
    checked.version().object() == &object
        && checked.version().data_head().encode() == data
        && checked.version().index_head().encode() == index
}

#[cfg(test)]
mod audit_policy_tests {
    use super::*;
    #[test]
    fn owner_audit_workers_respect_the_existing_cpu_budget_without_environment_races() {
        use compact_store::AuditWorkers::{One, Two};
        for (available, requested, expected) in [
            (0, None, One),
            (1, Some("8"), One),
            (64, Some("1"), One),
            (64, Some(" 1 "), One),
            (64, Some("2"), Two),
            (2, Some("999"), Two),
            (64, None, Two),
            (64, Some("0"), Two),
            (64, Some("invalid"), Two),
            (1, Some("invalid"), One),
        ] {
            assert_eq!(resolve_owner_audit_workers(available, requested), expected);
        }
    }
}

#[cfg(test)]
mod holder_tests {
    use super::*;
    #[test]
    fn recovered_holder_requires_both_complete_images_and_exact_object_and_heads() {
        let owner = compact_store::Owner::generate([95; 16]).unwrap();
        let image = owner
            .seal(
                compact_store::Layout {
                    schema: [96; 16],
                    row_width: 1,
                    rows_per_page: 3,
                    row_count: 7,
                },
                &[1; 7],
                Limits::default(),
            )
            .unwrap();
        let raw = RawBundle::from_snapshots(&image, &image).unwrap();
        let version = raw.target_version().unwrap();
        let id = *version.object();
        let head = image.commitment().encode();
        assert!(holds_object(
            Ok(Response::RawBundle(raw.clone())),
            id,
            &head,
            &head
        ));
        for field in 0..4 {
            let mut bad = raw.clone();
            match field {
                0 => *bad.data.last_mut().unwrap() ^= 1,
                1 => *bad.index.last_mut().unwrap() ^= 1,
                2 => bad.nonce[0] ^= 1,
                _ => bad.data_head[56] ^= 1,
            }
            assert!(!holds_object(
                Ok(Response::RawBundle(bad)),
                id,
                &head,
                &head
            ));
        }
        let mut wrong = head;
        wrong[56] ^= 1;
        assert!(!holds_object(
            Ok(Response::RawBundle(raw.clone())),
            id,
            &wrong,
            &head
        ));
        assert!(!holds_object(
            Ok(Response::RawBundle(raw)),
            id,
            &head,
            &wrong
        ));
    }
}
