//! Local physical ciphertext custody; logical heads never come from the inspector fixture.
use super::*;
use compact_store::Commitment;
use replica_store::{BundleId, FailureDomainId, ObjectId, PeerId, ReplicaStore, ReplicaTarget};
use std::collections::BTreeSet;
use std::time::Instant;

const COPY_METADATA_BYTES: usize = 2 * replica_store::RECORD_METADATA_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaLocation {
    pub peer_id: usize,
    pub failure_domain: u64,
    pub online: bool,
    pub current: bool,
    pub data_bytes: usize,
    pub index_bytes: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalShardInfo {
    pub id: usize,
    pub rows: usize,
    pub data_head: Commitment,
    pub index_head: Commitment,
    pub replicas: Vec<ReplicaLocation>,
    pub executor: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationInfo {
    pub desired_copies: usize,
    pub shards: Vec<LogicalShardInfo>,
    pub failure_domains: Vec<(usize, u64)>,
    pub read_peers: Vec<usize>,
    pub write_peers: Vec<usize>,
    pub unavailable_shards: Vec<usize>,
}

pub(super) struct Replication {
    desired: usize,
    shards: Vec<Shard>,
}
struct Shard {
    id: usize,
    table_id: compact_query::TableId,
    rows: Vec<usize>,
    data: Commitment,
    index: Commitment,
    holders: BTreeMap<usize, Table>,
}
impl Shard {
    fn current(&self, table: &Table) -> bool {
        table.commitment() == &self.data && table.index_commitment() == &self.index
    }
    fn executor(&self, db: &Database) -> Option<usize> {
        db.peers
            .iter()
            .filter(|peer| {
                peer.online
                    && self
                        .holders
                        .get(&peer.id)
                        .is_some_and(|table| self.current(table))
            })
            .min_by_key(|peer| (peer.config.delay_ms, peer.id))
            .map(|peer| peer.id)
    }
    fn materialize(&self, db: &Database, peer: usize) -> Result<Table, LabError> {
        let table = self
            .holders
            .get(&peer)
            .ok_or_else(|| LabError::UnavailableShards(vec![self.id]))?;
        Ok(db.owner.restore_table_for_experiment(
            &table.snapshot().encode(),
            &table.encrypted_index().encode(),
            &self.table_id,
            &self.data,
            &self.index,
            Limits::default(),
        )?)
    }
}
impl Replication {
    pub(super) fn initial(
        owner: &backend::Owner,
        rows: &[PlainRow],
        peers: &[Peer],
        desired: usize,
    ) -> Result<Self, LabError> {
        if peers.is_empty() {
            return Err(LabError::InvalidInput(
                "At least one storage peer is required to create encrypted shards.".into(),
            ));
        }
        let table_id = compact_query::TableId::generate()?;
        let assignments: Vec<_> = (0..rows.len()).map(|row| row % peers.len()).collect();
        let ids =
            compact_query::RowIds::generate(rows.len())?.partition(&assignments, peers.len())?;
        let shards = peers
            .iter()
            .zip(ids)
            .enumerate()
            .map(|(position, (peer, ids))| {
                let indices: Vec<_> = (position..rows.len()).step_by(peers.len()).collect();
                let plaintext: Vec<_> = indices.iter().map(|index| rows[*index]).collect();
                let table = owner.seal_partition(
                    &table_id,
                    &plaintext,
                    ids,
                    ROWS_PER_PAGE,
                    Limits::default(),
                )?;
                peer.config.check_size(
                    table.canonical_data_bytes()
                        + table.encrypted_index_bytes()
                        + COPY_METADATA_BYTES,
                )?;
                Ok(Shard {
                    id: peer.id,
                    table_id,
                    rows: indices,
                    data: table.commitment().clone(),
                    index: table.index_commitment().clone(),
                    holders: BTreeMap::from([(peer.id, table)]),
                })
            })
            .collect::<Result<Vec<_>, LabError>>()?;
        Ok(Self { desired, shards })
    }
    fn fork(&self) -> Self {
        Self {
            desired: self.desired,
            shards: self
                .shards
                .iter()
                .map(|shard| Shard {
                    id: shard.id,
                    table_id: shard.table_id,
                    rows: shard.rows.clone(),
                    data: shard.data.clone(),
                    index: shard.index.clone(),
                    holders: shard
                        .holders
                        .iter()
                        .map(|(id, table)| (*id, table.fork_for_experiment()))
                        .collect(),
                })
                .collect(),
        }
    }
    pub(super) fn ensure_available(&self, db: &Database) -> Result<(), LabError> {
        let missing: Vec<_> = self
            .shards
            .iter()
            .filter(|shard| shard.executor(db).is_none())
            .map(|shard| shard.id)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(LabError::UnavailableShards(missing))
        }
    }
    pub(super) fn charged_bytes(&self, peer: usize) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.holders.get(&peer))
            .map(|table| {
                table.canonical_data_bytes() + table.encrypted_index_bytes() + COPY_METADATA_BYTES
            })
            .sum()
    }
    fn check_quotas(&self, db: &Database) -> Result<(), LabError> {
        for peer in &db.peers {
            peer.config.check_size(self.charged_bytes(peer.id))?;
        }
        Ok(())
    }
    pub(super) fn peer_info(&self, peer: &Peer) -> PeerInfo {
        let mut data_bytes = 0;
        let mut index_bytes = 0;
        let mut logical_bytes = 0;
        let mut indices = Vec::new();
        for shard in &self.shards {
            if let Some(table) = shard.holders.get(&peer.id) {
                data_bytes += table.canonical_data_bytes();
                index_bytes += table.encrypted_index_bytes();
                let count = table.commitment().layout().row_count as usize;
                logical_bytes += table
                    .commitment()
                    .layout()
                    .logical_bytes()
                    .expect("validated stored layout");
                indices.extend_from_slice(&shard.rows[..count]);
            }
        }
        indices.sort_unstable();
        PeerInfo {
            id: peer.id,
            config: peer.config.clone(),
            online: peer.online,
            rows: indices.len(),
            logical_bytes,
            data_bytes,
            index_bytes,
            stored_bytes: self.charged_bytes(peer.id),
            journal_bytes: 0,
            public_setup_bytes: 0,
            owner_row_indices: indices,
        }
    }
    pub(super) fn info(&self, db: &Database) -> ReplicationInfo {
        let shards: Vec<_> = self
            .shards
            .iter()
            .map(|shard| LogicalShardInfo {
                id: shard.id,
                rows: shard.rows.len(),
                data_head: shard.data.clone(),
                index_head: shard.index.clone(),
                executor: shard.executor(db),
                replicas: shard
                    .holders
                    .iter()
                    .map(|(id, table)| ReplicaLocation {
                        peer_id: *id,
                        failure_domain: db.failure_domains[id],
                        online: db.peers.iter().any(|peer| peer.id == *id && peer.online),
                        current: shard.current(table),
                        data_bytes: table.canonical_data_bytes(),
                        index_bytes: table.encrypted_index_bytes(),
                    })
                    .collect(),
            })
            .collect();
        let read_peers = shards
            .iter()
            .filter_map(|shard| shard.executor)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let write_peers = shards
            .iter()
            .flat_map(|shard| shard.replicas.iter())
            .filter(|copy| copy.online && copy.current)
            .map(|copy| copy.peer_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let unavailable_shards = shards
            .iter()
            .filter(|shard| shard.executor.is_none())
            .map(|shard| shard.id)
            .collect();
        ReplicationInfo {
            desired_copies: self.desired,
            shards,
            failure_domains: db.failure_domains.iter().map(|(p, d)| (*p, *d)).collect(),
            read_peers,
            write_peers,
            unavailable_shards,
        }
    }
    /// Physical records; a peer ID may occur for several logical shards or stale versions.
    pub(super) fn physical_heads(&self) -> Vec<PeerHeads> {
        self.shards
            .iter()
            .flat_map(|shard| {
                shard.holders.iter().map(|(peer, table)| PeerHeads {
                    id: *peer,
                    data: table.commitment().clone(),
                    index: table.index_commitment().clone(),
                })
            })
            .collect()
    }
    fn repaired(&self, db: &Database) -> Result<Self, LabError> {
        self.ensure_available(db)?;
        let mut store = ReplicaStore::new(replica_store::Bounds {
            max_peers: MAX_PEERS,
            max_objects: MAX_PEERS * 2,
            ..Default::default()
        })
        .map_err(replica_error)?;
        for peer in &db.peers {
            store
                .register_peer(replica_store::PeerConfig {
                    id: PeerId(peer.id as u64),
                    failure_domain: FailureDomainId(db.failure_domains[&peer.id]),
                    quota_bytes: peer.config.storage_limit_bytes,
                })
                .map_err(replica_error)?;
            if !peer.online {
                store
                    .set_available(PeerId(peer.id as u64), false)
                    .map_err(replica_error)?;
            }
        }
        let mut targets = Vec::with_capacity(self.shards.len() * 2);
        for (slot, shard) in self.shards.iter().enumerate() {
            let (data, index) = objects(slot);
            for (peer, table) in &shard.holders {
                if !db.peers.iter().any(|p| p.id == *peer && p.online) {
                    continue;
                }
                // Offline bytes never enter this ephemeral repair source inventory.
                store
                    .seed(
                        PeerId(*peer as u64),
                        data,
                        table.commitment(),
                        &table.snapshot().encode(),
                    )
                    .map_err(replica_error)?;
                store
                    .seed(
                        PeerId(*peer as u64),
                        index,
                        table.index_commitment(),
                        &table.encrypted_index().encode(),
                    )
                    .map_err(replica_error)?;
            }
            for (object, expected) in [(data, &shard.data), (index, &shard.index)] {
                targets.push(ReplicaTarget {
                    object,
                    expected: expected.clone(),
                    copies: self.desired,
                    bundle: Some(BundleId(slot as u64 + 1)),
                });
            }
        }
        let plan = store.plan_repair(&targets).map_err(replica_error)?;
        store.repair_local(plan, &targets).map_err(replica_error)?;
        let mut next = self.fork();
        for (slot, shard) in next.shards.iter_mut().enumerate() {
            let (data, index) = objects(slot);
            for peer in db.peers.iter().filter(|peer| peer.online) {
                let (Ok(data), Ok(index)) = (
                    store.ciphertext(PeerId(peer.id as u64), data),
                    store.ciphertext(PeerId(peer.id as u64), index),
                ) else {
                    continue;
                };
                // Stale, unselected records remain charged and visibly stale, not promoted.
                if !data.starts_with(&shard.data.encode())
                    || !index.starts_with(&shard.index.encode())
                {
                    continue;
                }
                let table = db.owner.restore_table_for_experiment(
                    data,
                    index,
                    &shard.table_id,
                    &shard.data,
                    &shard.index,
                    Limits::default(),
                )?;
                shard.holders.insert(peer.id, table);
            }
        }
        next.check_quotas(db)?;
        Ok(next)
    }
}
fn objects(slot: usize) -> (ObjectId, ObjectId) {
    (ObjectId(slot as u64 * 2 + 1), ObjectId(slot as u64 * 2 + 2))
}
fn replica_error(error: replica_store::Error) -> LabError {
    LabError::Replication(format!("Replica repair failed: {error}"))
}

impl LabEngine {
    /// Configure desired redundancy; cross-peer copying occurs only in repair_replicas.
    /// Once enabled, lowering to one retains logical shard identities and existing copies.
    pub fn set_replication(&mut self, copies: usize) -> Result<(), LabError> {
        if !(1..=MAX_PEERS).contains(&copies) {
            return Err(LabError::InvalidInput(
                "Use 1..=16 replicas in distinct declared failure domains.".into(),
            ));
        }
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        db.replication.desired = copies;
        self.prepared = None;
        Ok(())
    }
    /// Local ciphertext copy only: caller owns discovery/routes/time and maintenance policy.
    pub fn repair_replicas(&mut self) -> Result<(), LabError> {
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let next = db.replication.repaired(db)?;
        db.replication = next;
        self.prepared = None;
        Ok(())
    }
    /// Trusted placement fact, not evidence of real independence; no implicit copy.
    pub fn set_failure_domain(&mut self, peer: usize, domain: u64) -> Result<(), LabError> {
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        if !db.peers.iter().any(|p| p.id == peer) {
            return Err(LabError::InvalidInput("Unknown peer.".into()));
        }
        db.failure_domains.insert(peer, domain);
        self.prepared = None;
        Ok(())
    }
}

pub(super) fn synchronize_peers(
    db: &mut Database,
    profiles: Vec<(usize, PeerConfig, bool)>,
) -> Result<(), LabError> {
    let replicas = &db.replication;
    for (id, config, _) in &profiles {
        config.check_size(replicas.charged_bytes(*id))?;
    }
    let ids: BTreeSet<_> = profiles.iter().map(|(id, _, _)| *id).collect();
    let peers = profiles
        .into_iter()
        .map(|(id, mut config, online)| {
            config.name = config.name.trim().into();
            Peer {
                id,
                config,
                online,
                evaluator: db.evaluator.clone(),
            }
        })
        .collect();
    for shard in &mut db.replication.shards {
        shard.holders.retain(|peer, _| ids.contains(peer));
    }
    db.failure_domains.retain(|peer, _| ids.contains(peer));
    for id in ids {
        db.failure_domains.entry(id).or_insert(id as u64);
    }
    db.peers = peers;
    Ok(())
}

pub(super) fn execute(
    db: &Database,
    plan: QueryPlan,
    progress: &impl Fn(LabProgress),
) -> Result<(QueryOutcome, Option<PreparedUpdate>), LabError> {
    let replicas = &db.replication;
    if let QueryPlan::Insert { rows } = &plan {
        let incoming: Vec<_> = rows
            .iter()
            .map(|row| PlainRow {
                age: row.age,
                amount: row.amount,
            })
            .collect();
        return insert(db, replicas, &incoming, progress);
    }
    if let QueryPlan::Select {
        predicate,
        projection,
        limit,
    } = plan
    {
        let mut selected = Vec::new();
        if let Some(range) = predicate.age_range().map(|range| AgeRange {
            lower: range.lower,
            upper: range.upper,
        }) {
            for shard in &replicas.shards {
                let executor = shard
                    .executor(db)
                    .ok_or_else(|| LabError::UnavailableShards(vec![shard.id]))?;
                progress(LabProgress {
                    peer_id: executor,
                    message: format!(
                        "Evaluating encrypted row projection of logical shard {} on peer {executor}...",
                        shard.id
                    ),
                });
                let table = shard.materialize(db, executor)?;
                let evaluator = &db
                    .peers
                    .iter()
                    .find(|peer| peer.id == executor)
                    .expect("current executor")
                    .evaluator;
                let rows = evaluate_selected_rows(&db.owner, evaluator, &table, range, projection)?;
                for (ordinal, row) in rows {
                    let global = *shard.rows.get(ordinal as usize).ok_or_else(|| {
                        LabError::Cryptography("Invalid logical row ordinal.".into())
                    })?;
                    selected.push((global, row));
                }
            }
        }
        return Ok((project_rows(selected, projection, limit), None));
    }
    let (predicate, delta) = match plan {
        QueryPlan::Aggregate { predicate }
        | QueryPlan::Count { predicate }
        | QueryPlan::Sum { predicate } => (predicate, None),
        QueryPlan::AddAmount { predicate, delta } => (predicate, Some(delta)),
        QueryPlan::Select { .. } => unreachable!("row reads returned above"),
        QueryPlan::Insert { .. } => unreachable!("insert returned above"),
    };
    let Some(range) = predicate.age_range().map(|range| AgeRange {
        lower: range.lower,
        upper: range.upper,
    }) else {
        return Ok((
            if delta.is_some() {
                QueryOutcome::Updated { committed: true }
            } else {
                aggregate_outcome(plan, 0, 0, Vec::new())
            },
            None,
        ));
    };
    if let Some(delta) = delta {
        return update(db, replicas, range, delta, progress);
    }
    let (mut count, mut sum) = (0, 0);
    let mut contributions = Vec::new();
    for shard in &replicas.shards {
        let executor = shard
            .executor(db)
            .ok_or_else(|| LabError::UnavailableShards(vec![shard.id]))?;
        let start = Instant::now();
        progress(LabProgress {
            peer_id: executor,
            message: format!(
                "Evaluating logical shard {} on replica peer {executor}...",
                shard.id
            ),
        });
        let table = shard.materialize(db, executor)?;
        let query = db.owner.prepare_exact_aggregate_for_experiment(
            &table,
            range,
            MAX_LAB_ROWS,
            Limits::default(),
        )?;
        let peer = db
            .peers
            .iter()
            .find(|p| p.id == executor)
            .expect("current executor");
        let evaluated = peer.evaluator.evaluate_exact_aggregate(query.request())?;
        let answer = db
            .owner
            .complete_exact_aggregate_unverified_for_experiment(&table, query, &evaluated.output)?;
        count += answer.count;
        sum += answer.sum;
        contributions.push(PeerAggregate {
            id: executor,
            count: answer.count,
            sum: answer.sum,
            elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        });
    }
    Ok((aggregate_outcome(plan, count, sum, contributions), None))
}
fn insert(
    db: &Database,
    replicas: &Replication,
    incoming: &[PlainRow],
    progress: &impl Fn(LabProgress),
) -> Result<(QueryOutcome, Option<PreparedUpdate>), LabError> {
    let total: usize = replicas.shards.iter().map(|shard| shard.rows.len()).sum();
    let end = total
        .checked_add(incoming.len())
        .filter(|end| *end <= MAX_LAB_ROWS)
        .ok_or_else(|| {
            LabError::InvalidInput("INSERT would exceed the 128-row laboratory bound.".into())
        })?;
    if incoming.is_empty() {
        return Err(LabError::InvalidInput(
            "INSERT requires a nonempty batch.".into(),
        ));
    }
    let (slot, shard) = replicas
        .shards
        .iter()
        .enumerate()
        .min_by_key(|(_, shard)| (shard.rows.len(), shard.id))
        .ok_or_else(|| LabError::InvalidInput("No logical shard exists for INSERT.".into()))?;
    let executor = shard
        .executor(db)
        .ok_or_else(|| LabError::UnavailableShards(vec![shard.id]))?;
    progress(LabProgress {
        peer_id: executor,
        message: format!(
            "Homomorphically appending {} encrypted rows to logical shard {}...",
            incoming.len(),
            shard.id
        ),
    });
    let mut table = shard.materialize(db, executor)?;
    let query = db.owner.prepare_insert_for_experiment(
        &table,
        incoming,
        compact_query::RowIds::generate(incoming.len())?,
        MAX_LAB_ROWS,
        Limits::default(),
    )?;
    let peer = db
        .peers
        .iter()
        .find(|peer| peer.id == executor)
        .expect("current executor");
    let evaluated = peer.evaluator.evaluate_indexed_insert(query.request())?;
    db.owner.apply_insert_checked_for_experiment(
        &mut table,
        query,
        &evaluated.output,
        Limits::default(),
    )?;
    let actual = (shard.rows.len()..shard.rows.len() + incoming.len())
        .map(|ordinal| {
            db.owner
                .decrypt_row_for_experiment(&table, ordinal as u64, Limits::default())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut next = replicas.fork();
    let staged = &mut next.shards[slot];
    for peer in db.peers.iter().filter(|peer| peer.online) {
        if shard
            .holders
            .get(&peer.id)
            .is_some_and(|table| shard.current(table))
        {
            staged.holders.insert(peer.id, table.fork_for_experiment());
        }
    }
    staged.rows.extend(total..end);
    staged.data = table.commitment().clone();
    staged.index = table.index_commitment().clone();
    next.check_quotas(db)?;
    let mut rows = db.owner_rows.clone();
    rows.extend(actual);
    Ok((
        QueryOutcome::Inserted {
            count: incoming.len() as u32,
        },
        Some(PreparedUpdate {
            rows,
            replication: next,
        }),
    ))
}
fn update(
    db: &Database,
    replicas: &Replication,
    range: AgeRange,
    delta: u16,
    progress: &impl Fn(LabProgress),
) -> Result<(QueryOutcome, Option<PreparedUpdate>), LabError> {
    let mut next = replicas.fork();
    let mut rows = db.owner_rows.clone();
    let mut changed = false;
    for (slot, shard) in replicas.shards.iter().enumerate() {
        let executor = shard
            .executor(db)
            .ok_or_else(|| LabError::UnavailableShards(vec![shard.id]))?;
        progress(LabProgress {
            peer_id: executor,
            message: format!(
                "Staging logical shard {} from replica peer {executor}...",
                shard.id
            ),
        });
        let original = shard.materialize(db, executor)?;
        let query = db.owner.prepare_exact_update_for_experiment(
            &original,
            range,
            delta,
            MAX_LAB_ROWS,
            Limits::default(),
        )?;
        let peer = db
            .peers
            .iter()
            .find(|p| p.id == executor)
            .expect("current executor");
        let evaluated = peer.evaluator.evaluate_indexed_update(query.request())?;
        let mut table = original;
        let applied = db.owner.apply_exact_update_checked_for_experiment(
            &mut table,
            query,
            &evaluated.output,
            Limits::default(),
        )?;
        if applied.rejected {
            return Ok((QueryOutcome::Updated { committed: false }, None));
        }
        if applied.changed_rows == 0 {
            continue;
        }
        changed = true;
        let staged = &mut next.shards[slot];
        for peer in db.peers.iter().filter(|peer| peer.online) {
            if shard
                .holders
                .get(&peer.id)
                .is_some_and(|table| shard.current(table))
            {
                staged.holders.insert(peer.id, table.fork_for_experiment());
            }
        }
        staged.data = table.commitment().clone();
        staged.index = table.index_commitment().clone();
        for (local, global) in shard.rows.iter().enumerate() {
            rows[*global] =
                db.owner
                    .decrypt_row_for_experiment(&table, local as u64, Limits::default())?;
        }
    }
    if !changed {
        return Ok((QueryOutcome::Updated { committed: true }, None));
    }
    next.check_quotas(db)?;
    Ok((
        QueryOutcome::Updated { committed: true },
        Some(PreparedUpdate {
            rows,
            replication: next,
        }),
    ))
}
