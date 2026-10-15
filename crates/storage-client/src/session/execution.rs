use super::*;
use sql_plan::{Projection, QueryPlan};

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
        if matches!(
            plan,
            QueryPlan::Aggregate { .. } | QueryPlan::Count { .. } | QueryPlan::Sum { .. }
        ) {
            return Err(Error::InvalidInput(
                "COUNT/SUM computation proofs are not implemented; no query was executed".into(),
            ));
        }
        let initial = self.synchronize()?;
        let before: Vec<_> = self
            .data
            .shards
            .iter()
            .map(|s| ShardState {
                id: s.info.id,
                heads: heads(&s.info),
            })
            .collect();
        let indices: Vec<_> = if matches!(plan, QueryPlan::Insert { .. }) {
            vec![
                self.data
                    .shards
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| (s.info.rows, s.info.id))
                    .unwrap()
                    .0,
            ]
        } else {
            (0..self.data.shards.len()).collect()
        };
        let mut selected = Vec::new();
        let mut stages = Vec::new();
        let mut jobs = Vec::new();
        let mut proofs = Vec::new();
        let mut changed_rows = 0;
        for slot in indices {
            let shard = &self.data.shards[slot];
            let (remote, table) = self.fetch_online(shard)?;
            match plan {
                QueryPlan::Select {
                    predicate,
                    projection,
                    ..
                } => {
                    let kind = match projection {
                        Projection::Age => backend::RowProjection::Age,
                        Projection::Amount => backend::RowProjection::Amount,
                        _ => backend::RowProjection::AgeAmount,
                    };
                    let prepared = self.data.owner.prepare_provable_select(
                        &table,
                        predicate.age_range().map(|r| AgeRange {
                            lower: r.lower,
                            upper: r.upper,
                        }),
                        kind,
                        256,
                        Limits::default(),
                    )?;
                    let (reply, checked) = request_proof(
                        &remote,
                        &shard.peers,
                        shard.info.object,
                        self.data.setup_id,
                        Operation::Select,
                        prepared.request(),
                        |reply| {
                            self.data
                                .owner
                                .check_select_proof(&table, &prepared, &reply.output, &reply.proof)
                                .map_err(Error::from)
                        },
                    )?;
                    let answer = self.data.owner.complete_checked_select(
                        &table,
                        prepared,
                        &reply.output,
                        checked,
                    )?;
                    for row in answer.into_rows() {
                        let values = projection
                            .columns()
                            .into_iter()
                            .map(|column| match column {
                                sql_plan::Column::Age => row.age.map(u32::from),
                                sql_plan::Column::Amount => row.amount.map(u32::from),
                            })
                            .collect::<Option<Vec<_>>>()
                            .ok_or_else(|| {
                                protocol("Proved projection omitted a requested column")
                            })?;
                        selected.push((
                            row.ordinal * self.data.shards.len() as u64 + slot as u64,
                            values,
                        ));
                    }
                }
                QueryPlan::AddAmount { predicate, delta } => {
                    let prepared = self.data.owner.prepare_provable_update(
                        &table,
                        predicate.age_range().map(|r| AgeRange {
                            lower: r.lower,
                            upper: r.upper,
                        }),
                        delta,
                        256,
                        Limits::default(),
                    )?;
                    let request = prepared.request().to_vec();
                    let (reply, checked) = request_proof(
                        &remote,
                        &shard.peers,
                        shard.info.object,
                        self.data.setup_id,
                        Operation::Update,
                        &request,
                        |reply| {
                            self.data
                                .owner
                                .check_update_proof(&table, &prepared, &reply.output, &reply.proof)
                                .map_err(Error::from)
                        },
                    )?;
                    let stage = self.data.owner.stage_checked_update(
                        &table,
                        prepared,
                        &reply.output,
                        checked,
                        Limits::default(),
                    )?;
                    if stage.overflowed() {
                        return Err(Error::InvalidInput(
                            "UPDATE overflowed; no shard was published".into(),
                        ));
                    }
                    changed_rows += stage.changed_rows();
                    let next = stage
                        .into_table()
                        .ok_or_else(|| protocol("Missing proved update"))?;
                    if next.commitment() != table.commitment() {
                        stages.push((slot, next));
                    }
                    jobs.push(MutationJob {
                        shard: shard.info.id,
                        request,
                    });
                    proofs.push(reply);
                }
                QueryPlan::Insert { row } => {
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
                    let (reply, checked) = request_proof(
                        &remote,
                        &shard.peers,
                        shard.info.object,
                        self.data.setup_id,
                        Operation::Insert,
                        &request,
                        |reply| {
                            self.data
                                .owner
                                .check_insert_proof(&table, &prepared, &reply.output, &reply.proof)
                                .map_err(Error::from)
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
        }
        if let QueryPlan::Select {
            projection, limit, ..
        } = plan
        {
            let version = self.finish_read(initial)?;
            selected.sort_by_key(|(ordinal, _)| *ordinal);
            let mut rows: Vec<_> = selected.into_iter().map(|(_, row)| row).collect();
            if let Some(limit) = limit {
                rows.truncate(limit);
            }
            return Ok(VerifiedResult::Selected {
                columns: projection.columns(),
                rows,
                version,
            });
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
fn request_proof<T>(
    preferred: &RemotePeer,
    peers: &[Participant],
    object: [u8; 32],
    setup: [u8; 32],
    operation: Operation,
    request: &[u8],
    verify: impl Fn(&ProofReply) -> Result<T>,
) -> Result<(ProofReply, T)> {
    let mut candidates = vec![preferred];
    candidates.extend(
        peers
            .iter()
            .map(|peer| &peer.remote)
            .filter(|peer| peer.endpoint() != preferred.endpoint()),
    );
    let mut last_error = None;
    for remote in candidates {
        match call_bounded(remote, || Request::Prove {
            object,
            setup,
            operation,
            ciphertext: request.to_vec(),
        }) {
            Ok(Response::Proved(reply)) => match verify(&reply) {
                Ok(checked) => return Ok((reply, checked)),
                Err(error) => last_error = Some(error),
            },
            Ok(Response::UnverifiedCiphertext(_)) => {
                last_error = Some(Error::MissingComputationProof)
            }
            Ok(_) => last_error = Some(protocol("Executor supplied no genuine proof reply")),
            Err(error) => last_error = Some(Error::Transport(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| protocol("No proof executor available")))
}
