//! Private same-execute ownership; every yielded/restarted operation uses full restore.
use super::super::super::super::acquire::live::{Original, Preparation};
use super::*;

// Borrow the WHOLE concrete driver, not a caller-selected Vault/store pair.
// Neither this capability nor its original private objects escape execute.
struct LiveAcquire<'driver, 'call> {
    driver: &'driver mut JointSqlNetworkHost,
    call: &'call JointSqlCall,
    operation: &'call Operation,
    original: Box<Original>,
}

pub(super) fn execute(
    driver: &mut JointSqlNetworkHost,
    call: &JointSqlCall,
    sql: &str,
    input: &JointSqlNetworkInput<'_>,
    operation: &Operation,
) -> NetworkResult<JointSqlNetworkOutcome> {
    let Ok(permit) = driver.gate.try_acquire() else {
        return driver.pending(JointSqlNetworkPending::Busy);
    };
    if let Err(reason) = operation.check() {
        return driver.pending(reason);
    }
    let (work, original) = driver.host.prepare_live(call, sql, input)?;
    let live = LiveAcquire {
        driver,
        call,
        operation,
        original,
    };
    live.run(*work, input, permit)
}

impl JointSqlHost {
    fn prepare_live(
        &mut self,
        call: &JointSqlCall,
        sql: &str,
        input: &JointSqlNetworkInput<'_>,
    ) -> NetworkResult<(Box<OwnerVaultAcquireWork>, Box<Original>)> {
        // Same original call/sequence/SQL and fresh Idle guards as prepare_acquire.
        let client = JointSqlClient {
            host: call.host,
            slot: call.slot,
        };
        let exact = self.call(&client, call.sequence, sql)?;
        if exact.digest != call.digest || call.verb != Verb::Acquire {
            return Err(OwnerVaultError::Pins.into());
        }
        if self.existing(call)?.is_some() {
            return Err(OwnerVaultError::Phase.into());
        }
        self.start(call, input.source, again(&input.fetched))?;
        let transaction = self
            .vault
            .managed_draft
            .as_ref()
            .ok_or(OwnerVaultError::Phase)?
            .call
            .transaction;
        let principal = self.managed()?.clients[call.slot].binding.principal;
        let prepared = self.vault.prepare_acquire_original(
            self.vault.cursor()?,
            again(&input.fetched),
            input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?,
            sql,
            transaction,
            principal,
        );
        match prepared {
            Ok(Preparation::Prepared(work, original)) => Ok((work, original)),
            Ok(Preparation::NonAdmitted(_)) => {
                self.abandon_unpublished();
                Err(OwnerVaultError::Phase.into())
            }
            Err(error) => {
                self.abandon_unpublished();
                Err(error.into())
            }
        }
    }
}

impl LiveAcquire<'_, '_> {
    fn run(
        mut self,
        work: OwnerVaultAcquireWork,
        input: &JointSqlNetworkInput<'_>,
        permit: peer_runtime::ProofPermit,
    ) -> NetworkResult<JointSqlNetworkOutcome> {
        let material = input.acquire.ok_or(OwnerVaultError::RecoveryRequired)?;
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        self.original.require_work(&self.driver.host.vault, &work)?;
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        let object = work.object();
        let (provenance, request, frames) = work.into_parts();
        let inputs = InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        // Only THIS fixed invocation can supply the recorded mathematical result.
        // The store is obtained from the exclusively borrowed driver's SAME Host.
        let recorded = self.operation.remote.prove_private_product_recorded_shared(
            object,
            provenance,
            &request,
            &inputs,
            self.driver.host.evidence_ingress()?.recording_store(),
        );
        drop(frames);
        drop(request);
        let recorded = match recorded {
            Ok(recorded) => recorded,
            Err(error) => return self.driver.rpc_failure(error, self.operation),
        };
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        self.driver.host.require_pending(self.call)?;
        let draft = self
            .original
            .save_recorded(&mut self.driver.host.vault, recorded, material)?;
        drop(permit); // actual native work has returned; no permit spans QC RPCs
        let Some(block) = self.driver.signed_candidate(&draft, self.operation)? else {
            return self.driver.pending(
                self.operation
                    .check()
                    .err()
                    .unwrap_or(JointSqlNetworkPending::Cancelled),
            );
        };
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        let Ok(permit) = self.driver.gate.try_acquire() else {
            return self.driver.pending(JointSqlNetworkPending::Busy);
        };
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        self.driver.host.require_pending(self.call)?;
        self.original.seal(&mut self.driver.host.vault, block)?;
        drop(permit);
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        let cursor = self.driver.host.cursor()?;
        let saved = self.driver.host.submission(self.call, cursor)?;
        let block = CandidateBlock::new(saved.header().clone(), saved.body().to_vec())?;
        let Some(checkpoint) =
            self.driver
                .network_round(self.operation, &block, upload::SubmissionOrder::Fresh)?
        else {
            return self.driver.pending(
                self.operation
                    .check()
                    .err()
                    .unwrap_or(JointSqlNetworkPending::Unavailable),
            );
        };
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        let Ok(permit) = self.driver.gate.try_acquire() else {
            return self.driver.pending(JointSqlNetworkPending::Busy);
        };
        if let Err(reason) = self.operation.check() {
            return self.driver.pending(reason);
        }
        self.driver.host.require_pending(self.call)?;
        let result = (*self.original).complete(
            &mut self.driver.host.vault,
            again(&input.fetched),
            material,
            &checkpoint,
        )?;
        let reply = self.driver.host.reply(ReplyValue::Acquire(result))?;
        drop(permit);
        let cursor = self.driver.host.cursor()?;
        if self.operation.check().is_err() {
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
}
