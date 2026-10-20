//! One exclusive-open replay of one exact original Acquire phase chain.
//! The plan is unverified metadata. No result survives this open's stack frame.
use super::*;
use std::{iter::Peekable, vec::IntoIter};

/// At most Compute, Catalog, Body, Completed and ACK. Records retain their
/// original positions; planning neither rewrites the WAL nor accepts proofs.
struct AcquireRunPlan {
    records: Vec<Snapshot>,
    tail: OwnerVaultPhase,
}
impl AcquireRunPlan {
    fn collect(
        idle: &Snapshot,
        sequence: u64,
        first: Snapshot,
        rest: &mut Peekable<IntoIter<Snapshot>>,
    ) -> VaultResult<Self> {
        let first_state = first.acquire.as_ref().ok_or(OwnerVaultError::Encoding)?;
        if idle.phase != OwnerVaultPhase::Idle
            || first.phase != OwnerVaultPhase::AcquireComputePrepared
            || first.generation != idle.generation
            || first.stamp != idle.stamp
            || first.idle.as_ref() != idle.idle.as_ref()
            || first_state.before_idle.as_ref() != idle.idle.as_ref()
            || first_state.before_stamp != idle.stamp
            || first_state.catalog.is_some()
        {
            return Err(OwnerVaultError::Encoding);
        }
        Self::managed(
            idle,
            &first,
            sequence
                .checked_add(1)
                .ok_or(OwnerVaultError::ResourceLimit)?,
        )?;
        let mut records = vec![first];
        let mut tail = OwnerVaultPhase::AcquireComputePrepared;
        while let Some(next) = rest.peek() {
            let previous = records.last().unwrap();
            if previous.phase == OwnerVaultPhase::Idle {
                break;
            }
            if records.len() == 5 {
                return Err(OwnerVaultError::Encoding);
            }
            Self::transition(previous, next)?;
            Self::managed(
                previous,
                next,
                sequence
                    .checked_add(records.len() as u64 + 1)
                    .ok_or(OwnerVaultError::ResourceLimit)?,
            )?;
            let next = rest.next().unwrap();
            if next.acquire.is_some() {
                tail = next.phase;
            }
            records.push(next);
        }
        Ok(Self { records, tail })
    }
    fn transition(old: &Snapshot, next: &Snapshot) -> VaultResult<()> {
        if old.phase == OwnerVaultPhase::Completed {
            if next.phase != OwnerVaultPhase::Idle
                || next.acquire.is_some()
                || next.generation != old.generation
                || next.stamp != old.stamp
                || next.idle.as_ref() != old.idle.as_ref()
            {
                return Err(OwnerVaultError::Encoding);
            }
            return Ok(());
        }
        let prior = old.acquire.as_ref().ok_or(OwnerVaultError::Encoding)?;
        let incoming = next.acquire.as_ref().ok_or(OwnerVaultError::Encoding)?;
        if next.pending != old.pending {
            return Err(OwnerVaultError::Pins);
        }
        match (old.phase, next.phase) {
            (OwnerVaultPhase::AcquireComputePrepared, OwnerVaultPhase::AcquireComputePrepared) => {
                if prior.catalog.is_some() || incoming.catalog.is_none() {
                    return Err(OwnerVaultError::Encoding);
                }
                let mut neutral = incoming.copy()?;
                neutral.catalog = None;
                if neutral.encode()?.as_slice() != prior.encode()?.as_slice() {
                    return Err(OwnerVaultError::Pins);
                }
            }
            (OwnerVaultPhase::AcquireComputePrepared, OwnerVaultPhase::SubmittedUnknown) => {
                if prior.catalog.is_none()
                    || incoming.encode()?.as_slice() != prior.encode()?.as_slice()
                {
                    return Err(OwnerVaultError::Pins);
                }
            }
            (OwnerVaultPhase::SubmittedUnknown, OwnerVaultPhase::Completed) => {
                if next.generation
                    != old
                        .generation
                        .checked_add(1)
                        .ok_or(OwnerVaultError::ResourceLimit)?
                    || incoming.encode()?.as_slice() != prior.encode()?.as_slice()
                    || !same_block(
                        next.block.as_ref().ok_or(OwnerVaultError::Encoding)?,
                        old.block.as_ref().ok_or(OwnerVaultError::Encoding)?,
                    )
                {
                    return Err(OwnerVaultError::Pins);
                }
                return Ok(());
            }
            _ => return Err(OwnerVaultError::Encoding),
        }
        if next.generation != old.generation
            || next.stamp != old.stamp
            || next.idle.as_ref() != old.idle.as_ref()
        {
            return Err(OwnerVaultError::Pins);
        }
        Ok(())
    }
    fn managed(old: &Snapshot, next: &Snapshot, sequence: u64) -> VaultResult<()> {
        if sequence > MAX_RECORDS as u64 {
            return Err(OwnerVaultError::ResourceLimit);
        }
        match (&old.managed, &next.managed) {
            (None, None) => Ok(()),
            (Some(old), Some(actual)) => {
                let expected = if next.phase == OwnerVaultPhase::Idle {
                    old.acknowledged()
                } else if next.phase == OwnerVaultPhase::Completed {
                    old.completed(sequence, next.outcome)?
                } else if old.call.is_none() {
                    let call = actual.call.ok_or(OwnerVaultError::Encoding)?;
                    if call.verb != host::state::Verb::Acquire {
                        return Err(OwnerVaultError::Pins);
                    }
                    old.start(call)?
                } else {
                    old.clone()
                };
                if &expected != actual {
                    return Err(OwnerVaultError::Pins);
                }
                Ok(())
            }
            _ => Err(OwnerVaultError::Pins),
        }
    }
    fn state(&self) -> &AcquireState {
        self.records
            .iter()
            .rev()
            .find_map(|r| r.acquire.as_ref())
            .unwrap()
    }
    fn body(&self) -> VaultResult<&CandidateBlock> {
        self.records
            .iter()
            .rev()
            .find_map(|r| r.block.as_ref())
            .ok_or(OwnerVaultError::Encoding)
    }
}

impl OwnerVault {
    pub(in crate::private_predicate::source::locking::joint::vault) fn replay_acquire_run(
        &mut self,
        first: Snapshot,
        rest: &mut Peekable<IntoIter<Snapshot>>,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        external: (&[OwnerVaultReplay<'_>], &mut usize),
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<()> {
        let (external, at) = external;
        let plan = AcquireRunPlan::collect(&self.saved, self.replay_sequence, first, rest)?;
        let before = parent(&self.history, &self.pins.binding)?;
        let saved = plan.state();
        let public = saved.load(&self.ingress, &self.pins.binding, material)?;
        let mut restored = Some(restore(
            saved,
            &self.pins.binding,
            &before,
            again(&fetched),
            material,
            &public,
        )?);
        self.require_managed_acquire(&plan.records[0], &restored.as_ref().unwrap().2)?;
        let expected = if matches!(
            plan.tail,
            OwnerVaultPhase::SubmittedUnknown | OwnerVaultPhase::Completed
        ) {
            Some(saved.expectation(&public, &self.pins.binding, &before)?)
        } else {
            None
        };
        match plan.tail {
            OwnerVaultPhase::AcquireComputePrepared if saved.catalog.is_some() => {
                drop(restored.take());
                let (provenance, request) = public.into_product_inputs();
                drop(
                    self.ingress
                        .recording_store()
                        .replay(
                            saved.catalog.ok_or(OwnerVaultError::Encoding)?,
                            self.pins.binding.application_descriptor().source_object(),
                            provenance,
                            &request,
                        )
                        .map_err(owner_error)?,
                );
                drop(request);
            }
            OwnerVaultPhase::SubmittedUnknown => {
                drop(restored.take());
                drop(public);
                self.history
                    .check_acquire_candidate(plan.body()?, expected.as_ref().unwrap())?;
            }
            OwnerVaultPhase::Completed => drop(public),
            OwnerVaultPhase::AcquireComputePrepared => {
                drop(restored.take());
                drop(public);
            }
            _ => return Err(OwnerVaultError::Encoding),
        }
        self.pending_parent = Some(before);
        for next in plan.records {
            if next.phase == OwnerVaultPhase::Completed {
                self.replay_completed_run(
                    next,
                    again(&fetched),
                    (external, &mut *at),
                    material,
                    expected.as_ref().ok_or(OwnerVaultError::Encoding)?,
                    restored.take().ok_or(OwnerVaultError::Encoding)?,
                )?;
            } else {
                if next.phase == OwnerVaultPhase::Idle {
                    self.acquire_result = None;
                }
                // These pending records retain only the already root-checked OLD
                // bank. A Completed tail's output/QC is checked below before any
                // successor or reply is adopted. The entire owner is still local
                // to open_engine: no API/callback can observe an unfinished run.
                self.check_managed_record(&next, source, again(&fetched))?;
                self.saved = next;
            }
        }
        Ok(())
    }

    fn replay_completed_run(
        &mut self,
        next: Snapshot,
        fetched: FetchedSource<'_>,
        external: (&[OwnerVaultReplay<'_>], &mut usize),
        material: &OwnerVaultAcquireMaterial<'_>,
        expected: &AcquireExpectation,
        restored: (
            Owner,
            bfv_query_core::PreparedPrivateCoefficientPredicate,
            JointLockingCandidates,
        ),
    ) -> VaultResult<()> {
        let (external, at) = external;
        let (owner, pending, candidates) = restored;
        let block = next.block.as_ref().ok_or(OwnerVaultError::Encoding)?;
        let operation = self.history.apply_acquire(
            next.checkpoint.as_ref().ok_or(OwnerVaultError::Encoding)?,
            block,
            expected,
        )?;
        let completed = candidates.complete_acquire(&owner, pending, operation)?;
        drop(owner);
        let (rows, opening) = completed.into_opening();
        let result = OwnerVaultAcquireCompletion {
            cursor: OwnerVaultCursor {
                generation: next.generation,
                pending: next.pending,
                digest: [0; 32],
            },
            invocation: next.pending,
            recovered: true,
            rows,
        };
        let after = parent(&self.history, &self.pins.binding)?;
        state::require_idle_parent(&opening, &after)?;
        if state::encode_idle(&opening)?.as_ref() != next.idle.as_ref()
            || current_stamp(&self.history, &self.pins.binding)? != next.stamp
        {
            return Err(OwnerVaultError::Pins);
        }
        let source = material.source(again(&fetched))?;
        drop(state::restore_idle(
            next.idle.as_ref(),
            &source,
            again(&fetched),
            &after,
        )?);
        self.pending_parent = None;
        self.acquire_result = Some(result);
        if let Some(entry) = external.get(*at)
            && same_block(block, entry.block)
        {
            // The independent external QC retains its original full fresh replay.
            self.history.apply(entry.checkpoint, entry.block)?;
            *at += 1;
        }
        self.check_managed_record(&next, &source, fetched)?;
        self.saved = next;
        Ok(())
    }
}
