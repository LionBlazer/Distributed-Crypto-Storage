use super::*;
use crate::query_rpc::Requests;
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
        let read_requests = matches!(
            plan,
            QueryPlan::Select { .. }
                | QueryPlan::Aggregate { .. }
                | QueryPlan::Count { .. }
                | QueryPlan::Sum { .. }
        )
        .then(Requests::read_query);
        let initial = self.synchronize_using(read_requests.as_ref())?;
        match &plan {
            QueryPlan::Aggregate { predicate } => {
                return self.execute_aggregate(
                    initial,
                    *predicate,
                    AggregateProjection::CountSum,
                    read_requests.as_ref().expect("Aggregate read scope"),
                );
            }
            QueryPlan::Count { predicate } => {
                return self.execute_aggregate(
                    initial,
                    *predicate,
                    AggregateProjection::Count,
                    read_requests.as_ref().expect("Aggregate read scope"),
                );
            }
            QueryPlan::Sum { predicate } => {
                return self.execute_aggregate(
                    initial,
                    *predicate,
                    AggregateProjection::Sum,
                    read_requests.as_ref().expect("Aggregate read scope"),
                );
            }
            _ => {}
        }
        if let QueryPlan::Select {
            predicate,
            projection,
            window,
        } = &plan
        {
            return self.execute_select(
                initial,
                *predicate,
                *projection,
                *window,
                read_requests.as_ref().expect("SELECT read scope"),
            );
        }
        let operation = if matches!(plan, QueryPlan::Insert { .. }) {
            Operation::Insert
        } else {
            Operation::Update
        };
        let mut writeback =
            super::writeback::Writeback::freeze(self, operation == Operation::Update)?;
        let requests = Requests::default();
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
        let mut affected_rows = 0;
        let mut inserted_rows = 0;
        match &plan {
            QueryPlan::AddAmount { predicate, delta } => {
                for staged in
                    self.prepare_update_shards(*predicate, *delta, &requests, &writeback)?
                {
                    affected_rows += staged.affected_rows;
                    if let Some(images) = staged.images {
                        stages.push((staged.slot, images));
                    }
                    jobs.push(staged.job);
                    proofs.push(staged.proof);
                }
            }
            QueryPlan::Insert { rows } => {
                for staged in self.prepare_insert_shards(rows, &requests)? {
                    stages.push((
                        staged.slot,
                        super::writeback::StagedImages::Full {
                            table: staged.table,
                            replacements: None,
                        },
                    ));
                    jobs.push(staged.job);
                    proofs.push(staged.proof);
                }
                inserted_rows = rows.len();
            }
            _ => unreachable!("unsupported proof operations rejected before execution"),
        }
        if stages.is_empty() {
            return Ok(VerifiedResult::Updated {
                affected_rows,
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
        let mut uploads = Vec::new();
        for (slot, images) in stages {
            updates.push(ShardUpdate {
                id: self.data.shards[slot].info.id,
                old: heads(&self.data.shards[slot].info),
                new: images.heads(),
            });
            uploads.push(writeback.prepare(slot, images)?);
        }
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
        let unsigned = Body::Transition(AuthorizedTransition {
            parent: parent.block,
            request: manifest.encode().map_err(protocol)?,
            updates,
            proof: evidence.encode().map_err(protocol)?,
            owner_signature: [0; 64],
        });
        // All immutable wire/profile budgets must pass before the first Store,
        // signature or pending record. A deterministic local rejection cannot
        // become an ambiguous write that blocks every later operation.
        unsigned.encode(self.journal.profile()).map_err(protocol)?;
        let Body::Transition(mut transition) = unsigned else {
            unreachable!("the exact unsigned mutation was constructed above");
        };
        let mut published = Vec::new();
        for upload in uploads {
            published.push(upload.store(&self.unavailable_this_operation)?);
        }
        // Authorization is issued only AFTER complete selection, STARK checks,
        // decryption/overflow checks and construction of the exact new ciphertext.
        transition.sign(self.journal.genesis_id(), &self.signer);
        let outcome = match plan {
            QueryPlan::Insert { .. } => MutationOutcome::Inserted {
                count: inserted_rows,
            },
            QueryPlan::AddAmount { .. } => MutationOutcome::Updated { affected_rows },
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
