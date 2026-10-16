//! Retry one exact owner-authorized mutation without rerunning its SQL or FHE jobs.
use super::*;

pub(super) enum MutationOutcome {
    Updated { affected_rows: usize },
    Inserted { count: usize },
}
pub(super) struct StoredMutation {
    pub slot: usize,
    pub object: [u8; 32],
    pub heads: HeadPair,
    pub holders: Vec<Participant>,
}
pub(super) struct PendingMutation {
    pub sql_digest: [u8; 32],
    pub query_binding: [u8; 32],
    pub transition: AuthorizedTransition,
    pub submitted: Option<HeadRef>,
    pub outcome: MutationOutcome,
    pub stored: Vec<StoredMutation>,
}

impl Session {
    pub(super) fn pending_error(&self, reason: impl Into<String>) -> Error {
        match &self.pending_mutation {
            Some(pending) => Error::PendingMutation {
                query_binding: pending.query_binding,
                submitted: pending.submitted.map(Box::new),
                reason: reason.into(),
            },
            None => protocol(reason.into()),
        }
    }

    /// Continue publication and confirmation of exactly the retained mutation.
    /// This never prepares SQL, runs new FHE jobs, resigns or changes its old/new
    /// roots. Failures retain the pending operation and return its stable identity.
    /// The pending record is in memory; owner restart recovery is not implemented.
    pub fn resume_pending(&mut self) -> Result<Option<VerifiedResult>> {
        self.unavailable_this_operation.clear();
        self.resume_pending_record()
    }

    pub(super) fn resume_pending_record(&mut self) -> Result<Option<VerifiedResult>> {
        if self.pending_mutation.is_none() {
            return Ok(None);
        }
        match self.resume_pending_inner() {
            Ok(result) => Ok(Some(result)),
            Err(error) => Err(self.pending_error(error.to_string())),
        }
    }

    fn resume_pending_inner(&mut self) -> Result<VerifiedResult> {
        // This flushes any locally validated but not yet remotely acknowledged
        // block first, then imports real journal data and authenticates snapshots.
        self.synchronize()?;

        if self
            .pending_mutation
            .as_ref()
            .is_some_and(|p| p.submitted.is_none())
        {
            let transition = self
                .pending_mutation
                .as_ref()
                .ok_or_else(|| protocol("Missing pending mutation"))?
                .transition
                .clone();
            let body = Body::Transition(transition.clone());
            let wire = body.encode(self.journal.profile()).map_err(protocol)?;
            let expected_hash = version_journal::hash(&wire);
            let best = self.journal.best_validated();
            // A peer may have mined/published the exact signed transition even
            // when the original MineBlock response did not reach this client.
            let known = self
                .journal
                .validated_blocks()
                .into_iter()
                .filter(|(header, bytes)| {
                    header.parent == transition.parent
                        && header.body_hash == expected_hash
                        && *bytes == wire
                })
                .map(|(header, _)| HeadRef {
                    genesis: self.journal.genesis_id(),
                    database: self.journal.genesis().database,
                    block: header.id(),
                    height: header.height,
                    state_root: header.state_root,
                })
                .find(|head| self.journal.is_ancestor(head.block, best.block));
            if let Some(head) = known {
                self.pending_mutation
                    .as_mut()
                    .ok_or_else(|| protocol("Missing pending mutation"))?
                    .submitted = Some(head);
            } else {
                if best.block != transition.parent {
                    return Err(protocol(
                        "The original mutation parent is no longer the validated tip; the exact authorized mutation was not resubmitted on a different branch",
                    ));
                }
                // mine_body records the exact submitted HeadRef immediately after
                // validation, before attempting any durable remote publication.
                self.mine_body(body)?;
            }
        }

        let submitted = self
            .pending_mutation
            .as_ref()
            .and_then(|p| p.submitted)
            .ok_or_else(|| protocol("The pending mutation has no validated submitted block"))?;
        let required_height = submitted
            .height
            .checked_add(u64::from(self.journal.profile().confirmation_depth))
            .ok_or_else(|| protocol("Confirmation height overflow"))?;

        loop {
            let best = self.journal.best_validated();
            if !self.journal.is_ancestor(submitted.block, best.block) {
                return Err(protocol(
                    "The exact submitted mutation was reorganized off the validated branch",
                ));
            }
            if best.height >= required_height {
                break;
            }
            // Existing descendants count; retry never starts a second mutation
            // and never mines confirmations that are already present.
            self.mine_body(Body::Empty)?;
            self.synchronize()?;
        }
        self.synchronize()?;
        let version = self
            .journal
            .resolve(Freshness::AtLeast(submitted))
            .map_err(protocol)?;
        let pending = self
            .pending_mutation
            .take()
            .ok_or_else(|| protocol("Missing pending mutation"))?;
        self.restore_mutation_holders(&pending.stored);
        for participant in &self.participants {
            if !self.unavailable_this_operation.contains(&participant.id) {
                let _ = participant.remote.call(Request::CollectJournal {
                    network: self.journal.genesis_id(),
                });
            }
        }
        Ok(match pending.outcome {
            MutationOutcome::Updated { affected_rows } => VerifiedResult::Updated {
                affected_rows,
                version,
            },
            MutationOutcome::Inserted { count } => VerifiedResult::Inserted { count, version },
        })
    }

    fn restore_mutation_holders(&mut self, stored: &[StoredMutation]) {
        for recorded in stored {
            let Some(shard) = self.data.shards.get_mut(recorded.slot) else {
                continue;
            };
            // A later agreed mutation may already supersede these heads. Never
            // restore an older object or holder list over that newer snapshot.
            if heads(&shard.info) != recorded.heads || shard.info.object != recorded.object {
                continue;
            }
            // Keep the actual authenticated holder found by synchronize. Refresh
            // recorded endpoints after restarts, and add replicas only after I/O.
            for original in &recorded.holders {
                let Some(peer) = self.participants.iter().find(|p| p.id == original.id) else {
                    continue;
                };
                if shard.peers.iter().any(|p| p.id == peer.id) {
                    continue;
                }
                if matches!(peer.remote.call(Request::Fetch { object: recorded.object }), Ok(Response::Bundle(ref bundle))
                    if bundle.id() == recorded.object && bundle.data_head == recorded.heads.data && bundle.index_head == recorded.heads.index)
                {
                    shard.peers.push(peer.clone());
                }
            }
            shard.info.holders = shard.peers.iter().map(|p| p.id).collect();
        }
    }
}
