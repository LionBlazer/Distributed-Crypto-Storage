use super::*;
use crate::proof::{ProofJob, ProofRequests};
use sql_plan::QueryPlan;

impl Session {
    /// Snapshot preparation, complete private index authentication, one executor's
    /// genuine proof and a second freshness check precede every successful result.
    pub fn execute(&mut self, sql: &str) -> Result<VerifiedResult> {
        // Retry previously unreachable endpoints on each new operation, but do not
        // repeatedly pay their connection timeout at every phase of this one.
        self.unavailable_this_operation.clear();
        if let Some(pending) = self.pending_mutation.as_ref() {
            if pending.sql_digest != version_journal::hash(sql.as_bytes()) {
                return Err(self.pending_error("A different SQL statement cannot run while the original mutation awaits its outcome; call resume_pending first"));
            }
            return self
                .resume_pending_record()?
                .ok_or_else(|| protocol("Missing retained mutation result"));
        }
        let plan = sql_plan::parse_sql(sql)?;
        let initial = self.synchronize()?;
        match plan {
            QueryPlan::Aggregate { predicate } => {
                return self.execute_aggregate(initial, predicate, AggregateProjection::CountSum);
            }
            QueryPlan::Count { predicate } => {
                return self.execute_aggregate(initial, predicate, AggregateProjection::Count);
            }
            QueryPlan::Sum { predicate } => {
                return self.execute_aggregate(initial, predicate, AggregateProjection::Sum);
            }
            _ => {}
        }
        if let QueryPlan::Select {
            predicate,
            projection,
            limit,
        } = plan
        {
            return self.execute_select(initial, predicate, projection, limit);
        }
        let requests = ProofRequests::default();
        let before: Vec<_> = self
            .data
            .shards
            .iter()
            .map(|s| ShardState {
                id: s.info.id,
                heads: heads(&s.info),
            })
            .collect();
        let mut stages = Vec::new();
        let mut jobs = Vec::new();
        let mut proofs = Vec::new();
        let mut changed_rows = 0;
        match plan {
            QueryPlan::AddAmount { predicate, delta } => {
                for staged in self.prepare_update_shards(predicate, delta, &requests)? {
                    changed_rows += staged.changed_rows;
                    if let Some(table) = staged.table {
                        stages.push((staged.slot, table));
                    }
                    jobs.push(staged.job);
                    proofs.push(staged.proof);
                }
            }
            QueryPlan::Insert { row } => {
                let slot = self
                    .data
                    .shards
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| (s.info.rows, s.info.id))
                    .unwrap()
                    .0;
                let shard = &self.data.shards[slot];
                let (remote, table) = self.fetch_online(shard)?;
                let prepared = self.data.owner.prepare_insert_for_experiment(
                    &table,
                    PlainRow {
                        age: row.age,
                        amount: row.amount,
                    },
                    256,
                    Limits::default(),
                )?;
                let request = prepared.request().to_vec();
                let (reply, checked) = requests.request(
                    &remote,
                    &shard.peers,
                    ProofJob {
                        object: shard.info.object,
                        setup: self.data.setup_id,
                        operation: Operation::Insert,
                        ciphertext: &request,
                    },
                    |reply| {
                        self.verifier
                            .check_job(Operation::Insert, &request, reply)
                            .map_err(protocol)
                    },
                )?;
                let next = self.data.owner.stage_checked_insert(
                    &table,
                    prepared,
                    &reply.output,
                    checked,
                    Limits::default(),
                )?;
                stages.push((slot, next));
                jobs.push(MutationJob {
                    shard: shard.info.id,
                    request,
                });
                proofs.push(reply);
            }
            _ => unreachable!("unsupported proof operations rejected before execution"),
        }
        if stages.is_empty() {
            return Ok(VerifiedResult::Updated {
                changed_rows: 0,
                version: self.finish_read(initial)?,
            });
        }
        // Check the source version again before creating physical staged copies.
        self.finish_read(initial)?;
        let parent = self.journal.best_validated();
        if self.journal.validated_shards(parent).map_err(protocol)? != before {
            return Err(protocol("An unconfirmed state conflicts with this update"));
        }
        let mut updates = Vec::new();
        let mut published = Vec::new();
        for (slot, table) in stages {
            let old = &self.data.shards[slot];
            let bundle = Bundle {
                data_head: table.commitment().encode().to_vec(),
                index_head: table.index_commitment().encode().to_vec(),
                data: table.snapshot().encode(),
                index: table.encrypted_index().encode(),
            };
            let object = bundle.id();
            let mut candidates = old.peers.clone();
            for participant in &self.participants {
                if !candidates.iter().any(|p| p.id == participant.id) {
                    candidates.push(participant.clone());
                }
            }
            let mut holders = Vec::new();
            for peer in candidates {
                if self.unavailable_this_operation.contains(&peer.id) {
                    continue;
                }
                if matches!(peer.remote.call(Request::Store(bundle.clone())),Ok(Response::Stored(ref info)) if info.id==object)
                {
                    holders.push(peer);
                }
                if holders.len() >= 2.min(self.participants.len()) {
                    break;
                }
            }
            if holders.is_empty() {
                return Err(Error::UnavailableShard(old.info.id));
            }
            let new = HeadPair {
                data: table.commitment().encode(),
                index: table.index_commitment().encode(),
            };
            updates.push(ShardUpdate {
                id: old.info.id,
                old: heads(&old.info),
                new,
            });
            published.push(StoredMutation {
                slot,
                object,
                heads: new,
                holders,
            });
        }
        let operation = if matches!(plan, QueryPlan::Insert { .. }) {
            Operation::Insert
        } else {
            Operation::Update
        };
        let mut query_salt = [0; 32];
        getrandom::getrandom(&mut query_salt).map_err(protocol)?;
        let mut query_identity = query_salt.to_vec();
        query_identity.extend_from_slice(sql.as_bytes());
        let query_binding = version_journal::hash(&query_identity);
        query_salt.fill(0);
        query_identity.fill(0);
        let manifest = MutationManifest {
            query_binding,
            operation,
            previous_shards: before,
            jobs,
        };
        let evidence = MutationEvidence { jobs: proofs };
        let mut transition = AuthorizedTransition {
            parent: parent.block,
            request: manifest.encode().map_err(protocol)?,
            updates,
            proof: evidence.encode().map_err(protocol)?,
            owner_signature: [0; 64],
        };
        // Authorization is issued only AFTER complete selection, STARK checks,
        // decryption/overflow checks and construction of the exact new ciphertext.
        transition.sign(self.journal.genesis_id(), &self.signer);
        let outcome = match plan {
            QueryPlan::Insert { .. } => MutationOutcome::Inserted { count: 1 },
            QueryPlan::AddAmount { .. } => MutationOutcome::Updated { changed_rows },
            _ => unreachable!(),
        };
        // Retain exact authorization, result identity and physical-holder metadata
        // BEFORE mining/publication. Every later failure can resume this operation
        // without preparing, proving or applying the SQL mutation a second time.
        self.pending_mutation = Some(PendingMutation {
            sql_digest: version_journal::hash(sql.as_bytes()),
            query_binding,
            transition,
            submitted: None,
            outcome,
            stored: published,
        });
        self.resume_pending_record()?
            .ok_or_else(|| protocol("Missing retained mutation result"))
    }
}
