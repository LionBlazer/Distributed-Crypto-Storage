//! One concrete private phase engine. Durable pending always keeps its original intent.
use super::*;
use bfv_mul_relin_proof::InputEvidence;
#[path = "live.rs"]
mod live;

impl JointSqlNetworkHost {
    pub(super) fn drive(
        &mut self,
        call: &JointSqlCall,
        sql: &str,
        input: &JointSqlNetworkInput<'_>,
        operation: &Operation,
    ) -> NetworkResult<JointSqlNetworkOutcome> {
        let result = self.drive_owned(call, sql, input, operation);
        // A Control draft is deliberately not durable. Every path that returns
        // before Body fsync must release that draft and its terminal lease. A
        // saved Compute/Body/Completed is NEVER cleared by this private helper.
        self.host.abandon_unpublished();
        result
    }
    fn drive_owned(
        &mut self,
        call: &JointSqlCall,
        sql: &str,
        input: &JointSqlNetworkInput<'_>,
        operation: &Operation,
    ) -> NetworkResult<JointSqlNetworkOutcome> {
        if let Err(reason) = operation.check() {
            return self.pending(reason);
        }
        let order = if matches!(
            self.host.phase()?,
            OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown
        ) {
            upload::SubmissionOrder::SavedOriginal
        } else {
            upload::SubmissionOrder::Fresh
        };
        match self.host.existing(call)? {
            Some(JointSqlPreparation::HistoricalLast { record_sequence }) => {
                let ready = self.host.vault.replayed_clients[call.slot]
                    .as_ref()
                    .is_some_and(|reply| {
                        JointSqlHost::matches_call(call, reply.call)
                            && reply.record == record_sequence
                    });
                let cursor = self.host.cursor()?;
                return if ready {
                    Ok(JointSqlNetworkOutcome::Completed {
                        cursor,
                        reply: Box::new(self.host.take_recovered_reply(call)?),
                    })
                } else {
                    Ok(JointSqlNetworkOutcome::NeedsReopen {
                        cursor,
                        record_sequence,
                    })
                };
            }
            Some(JointSqlPreparation::ExistingPending(_)) | None => {}
            Some(_) => return Err(OwnerVaultError::Phase.into()),
        }
        if call.verb == Verb::Acquire && self.host.phase()? == OwnerVaultPhase::Idle {
            return live::execute(self, call, sql, input, operation);
        }
        if matches!(
            self.host.phase()?,
            OwnerVaultPhase::Idle | OwnerVaultPhase::AcquireComputePrepared
        ) {
            let Ok(permit) = self.gate.try_acquire() else {
                return self.pending(JointSqlNetworkPending::Busy);
            };
            if let Err(reason) = operation.check() {
                return self.pending(reason);
            }
            let prepared = if self.host.phase()? == OwnerVaultPhase::Idle {
                if call.verb == Verb::Acquire {
                    self.host.prepare_acquire(
                        call,
                        sql,
                        input.source,
                        again(&input.fetched),
                        input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?,
                    )?
                } else {
                    self.host
                        .prepare_control(call, input.source, again(&input.fetched))?
                }
            } else {
                let cursor = self.host.cursor()?;
                match self.host.acquire_draft(call, cursor) {
                    Ok(draft) => JointSqlPreparation::ControlDraft(Box::new(draft)),
                    Err(OwnerVaultError::Phase) => {
                        JointSqlPreparation::AcquireWork(Box::new(self.host.acquire_work(
                            call,
                            cursor,
                            again(&input.fetched),
                            input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?,
                        )?))
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let draft = match prepared {
                JointSqlPreparation::ControlDraft(draft) => *draft,
                JointSqlPreparation::AcquireWork(work) => {
                    if let Err(reason) = operation.check() {
                        return self.pending(reason);
                    }
                    let cursor = work.cursor();
                    let object = work.object();
                    let (provenance, request, frames) = work.into_parts();
                    let inputs = InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice))
                        .map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    let store = self.host.evidence_ingress()?.recording_store();
                    // This existing RPC performs real native input/output proof
                    // verification. The SAME actual permit stays owned until
                    // it has returned and its heavy checked output is dropped.
                    let recorded = operation.remote.prove_private_product_recorded_shared(
                        object, provenance, &request, &inputs, store,
                    );
                    drop(frames);
                    drop(request);
                    let recorded = match recorded {
                        Ok(recorded) => recorded,
                        Err(error) => return self.rpc_failure(error, operation),
                    };
                    let (checked, catalog) = recorded.into_parts();
                    drop(checked);
                    if let Err(reason) = operation.check() {
                        return self.pending(reason);
                    }
                    self.host.save_acquire_catalog(
                        call,
                        cursor,
                        catalog,
                        again(&input.fetched),
                        input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?,
                    )?
                }
                _ => return Err(OwnerVaultError::Phase.into()),
            };
            drop(permit);
            let Some(block) = self.signed_candidate(&draft, operation)? else {
                return self.pending(
                    operation
                        .check()
                        .err()
                        .unwrap_or(JointSqlNetworkPending::Cancelled),
                );
            };
            if let Err(reason) = operation.check() {
                return self.pending(reason);
            }
            let Ok(permit) = self.gate.try_acquire() else {
                return self.pending(JointSqlNetworkPending::Busy);
            };
            if call.verb == Verb::Acquire {
                self.host.seal_acquire_body(
                    call,
                    self.host.cursor()?,
                    block,
                    again(&input.fetched),
                    input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?,
                )?;
            } else {
                self.host.seal_body(call, self.host.cursor()?, block)?;
            }
            drop(permit);
        }
        if let Err(reason) = operation.check() {
            return self.pending(reason);
        }
        let cursor = self.host.cursor()?;
        let saved = self.host.submission(call, cursor)?;
        let block = CandidateBlock::new(saved.header().clone(), saved.body().to_vec())?;
        // Ordinary finality RPCs hold no proof permit, Host/state/store mutex or
        // borrowed Vault submission. A missing quorum cannot complete the bank.
        let Some(checkpoint) = self.network_round(operation, &block, order)? else {
            return self.pending(
                operation
                    .check()
                    .err()
                    .unwrap_or(JointSqlNetworkPending::Unavailable),
            );
        };
        if let Err(reason) = operation.check() {
            return self.pending(reason);
        }
        let Ok(permit) = self.gate.try_acquire() else {
            return self.pending(JointSqlNetworkPending::Busy);
        };
        let reply = if call.verb == Verb::Acquire {
            self.host.complete_acquire(
                call,
                cursor,
                again(&input.fetched),
                input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?,
                &checkpoint,
            )?
        } else {
            self.host.complete_control(
                call,
                cursor,
                input.source,
                again(&input.fetched),
                &checkpoint,
            )?
        };
        drop(permit);
        let cursor = self.host.cursor()?;
        if operation.check().is_err() {
            let record_sequence = reply.completed_record_sequence();
            drop(reply);
            return Ok(JointSqlNetworkOutcome::NeedsReopen {
                cursor,
                record_sequence,
            });
        }
        Ok(JointSqlNetworkOutcome::Completed {
            cursor,
            reply: Box::new(reply),
        })
    }
    fn rpc_failure(
        &self,
        error: io::Error,
        operation: &Operation,
    ) -> NetworkResult<JointSqlNetworkOutcome> {
        if let Err(reason) = operation.check() {
            return self.pending(reason);
        }
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::NotConnected
                | io::ErrorKind::Interrupted
        ) {
            self.pending(JointSqlNetworkPending::Unavailable)
        } else {
            Err(error.into())
        }
    }
}
