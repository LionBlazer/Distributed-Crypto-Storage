//! Bounded typed Progress RPC scheduling. One independently checked QC suffices.
//! These definitions perform no I/O at module initialization. Every destination
//! is the caller-configured pinned Endpoint; no private owner witness is sent.
use super::*;
use peer_runtime::finality::{ProgressFinalityClient, ProgressProofBlobSelector};
use protocol_storage::BlobId;
use registry200_finality::progress::{Candidate, Checkpoint};
use registry200_joint::progress::{Lane, Manifest, ManifestRole, ProgressEvidenceIngress};
use std::thread;
use std::{
    collections::VecDeque,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        mpsc,
    },
};
use version_journal::Body;
use work_finality::consensus::Context;

const BLOB_SLOTS: usize = 3;

pub(super) enum SubmissionOrder {
    Fresh,
    SavedOriginal,
}

#[derive(Debug)]
pub(super) enum PeerFailure {
    Local(Error),
    Remote(io::Error),
}
pub(super) type PeerResult<T> = core::result::Result<T, PeerFailure>;
fn local<T, E>(result: core::result::Result<T, E>) -> PeerResult<T>
where
    E: core::fmt::Display,
{
    result.map_err(|error| PeerFailure::Local(crypto(error)))
}
struct UploadPart {
    selector: ProgressProofBlobSelector,
    id: BlobId,
    cap: usize,
}
struct UploadPlan {
    parts: Vec<UploadPart>,
}
impl UploadPlan {
    // One bounded metadata plan per immutable Round. No proof bytes or success
    // result are cached; each actual turn reads only its one current blob.
    fn new(
        block: &CandidateBlock,
        ingress: &ProgressEvidenceIngress,
        binding: &Binding,
    ) -> PeerResult<Self> {
        let Body::Transition(body) = local(Body::decode(
            block.body(),
            &binding.journal_genesis().profile,
        ))?
        else {
            return Err(PeerFailure::Local(
                io::Error::new(io::ErrorKind::InvalidData, "Owner transition required").into(),
            ));
        };
        let manifest = local(Manifest::decode(&body.proof))?;
        let mut parts = Vec::new();
        for reference in manifest.references() {
            let ordinal = reference
                .ordinal()
                .try_into()
                .map_err(|_| PeerFailure::Local(Error::Shape))?;
            parts.push(UploadPart {
                selector: local(ProgressProofBlobSelector::manifest(ordinal))?,
                id: reference.blob_id(),
                cap: reference.byte_cap(),
            });
        }
        if manifest.lane() == Lane::Predicate {
            let id = manifest
                .references()
                .find(|r| r.role() == ManifestRole::ProductCatalog)
                .ok_or_else(|| {
                    PeerFailure::Local(
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Predicate catalog reference missing",
                        )
                        .into(),
                    )
                })?
                .blob_id();
            let catalog = bfv_product_evidence::CatalogId::from_blob(id).map_err(|e| {
                PeerFailure::Local(io::Error::new(io::ErrorKind::InvalidData, e.to_string()).into())
            })?;
            let claim = local(ingress.catalog_claim(catalog))?;
            for reference in claim.references() {
                parts.push(UploadPart {
                    selector: local(ProgressProofBlobSelector::catalog(
                        reference.role(),
                        reference.ordinal(),
                    ))?,
                    id: reference.blob_id(),
                    cap: reference.byte_cap(),
                });
            }
        }
        if parts.len() > 142 {
            return Err(PeerFailure::Local(Error::ResourceLimit));
        }
        Ok(Self { parts })
    }
}

// Private ordinary-I/O scheduling only. A returned checkpoint is UNVERIFIED;
// Round::observed_checkpoint remains the mandatory concrete weighted-QC check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PeerAction {
    Original,
    Blob(usize),
    Submit,
    Checkpoint,
}
pub(super) enum StepReply {
    Stopped,
    Completed(Option<Box<Checkpoint>>),
}
pub(super) fn require_checkpoint(
    binding: &Binding,
    context: &Context,
    block: &CandidateBlock,
    qc: &Checkpoint,
) -> Result<()> {
    let expected =
        Candidate::for_context(binding, context, block.header().clone()).map_err(crypto)?;
    let received = Candidate::for_context(binding, context, qc.candidate().header().clone())
        .map_err(crypto)?;
    // Check the WHOLE context/binding/header encoding before actual signatures.
    if received.encode() != qc.candidate().encode() {
        return Err(Error::Cryptography);
    }
    context
        .verify_commit(&qc.candidate().encode(), qc.round(), qc.certificate())
        .map_err(crypto)?;
    if qc.candidate().encode() != expected.encode() {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
pub(super) struct PeerProgress {
    stage: AtomicU8,
    ordinal: AtomicUsize,
    original_attempted: AtomicBool,
}
impl PeerProgress {
    pub(super) fn new() -> Self {
        Self {
            stage: AtomicU8::new(0),
            ordinal: AtomicUsize::new(0),
            original_attempted: AtomicBool::new(false),
        }
    }
    pub(super) fn position(&self) -> (u8, usize, bool) {
        (
            self.stage.load(Ordering::Acquire),
            self.ordinal.load(Ordering::Acquire),
            self.original_attempted.load(Ordering::Acquire),
        )
    }
    pub(super) fn perform(
        &self,
        order: &SubmissionOrder,
        parts: usize,
        active: impl Fn() -> bool,
        mut call: impl FnMut(PeerAction) -> PeerResult<StepReply>,
    ) -> PeerResult<Option<Checkpoint>> {
        if !active() {
            return Ok(None);
        }
        let action = match self.stage.load(Ordering::Acquire) {
            0 => {
                if matches!(order, SubmissionOrder::SavedOriginal)
                    && !self.original_attempted.swap(true, Ordering::AcqRel)
                {
                    PeerAction::Original
                } else {
                    let ordinal = self.ordinal.load(Ordering::Acquire);
                    if ordinal == parts {
                        self.stage.store(1, Ordering::Release);
                        return Ok(None);
                    }
                    PeerAction::Blob(ordinal)
                }
            }
            1 => PeerAction::Submit,
            2 => PeerAction::Checkpoint,
            _ => return Ok(None),
        };
        let result = call(action);
        let reply = if action == PeerAction::Original {
            // Exact original observation happens at most once per peer/Round.
            // Neither ACK nor rejection authorizes a proof or a changed intent.
            let _ = result;
            StepReply::Completed(None)
        } else {
            result?
        };
        let StepReply::Completed(checkpoint) = reply else {
            return Ok(None);
        };
        match action {
            PeerAction::Blob(ordinal) => {
                // Advance only after the actual current PUT returned success.
                // BUSY/lost ACK leaves this exact ordinal unchanged.
                self.ordinal.store(ordinal + 1, Ordering::Release);
                if ordinal + 1 == parts {
                    self.stage.store(1, Ordering::Release);
                }
            }
            PeerAction::Submit => self.stage.store(2, Ordering::Release),
            PeerAction::Original | PeerAction::Checkpoint => {}
        }
        // A returned QC MUST reach the concrete signature/context classifier,
        // even if cancellation raced the RPC. Only its classified success may
        // subsequently be suppressed by the cancellation tail.
        Ok(checkpoint.map(|checkpoint| *checkpoint))
    }
}
// Ordinary-I/O admission only. Each configured peer has one worker; only
// a current read+PUT owns one of these three payload slots. No mutex spans I/O.
struct BlobState {
    available: usize,
    waiting: VecDeque<usize>,
    requested: Vec<bool>,
    held: Vec<bool>,
}
pub(super) struct BlobSlots {
    state: Mutex<BlobState>,
    changed: Condvar,
    stopped: AtomicBool,
    broken: AtomicBool,
    capacity: usize,
}
pub(super) struct BlobPermit<'a> {
    slots: &'a BlobSlots,
    peer: usize,
}
impl BlobSlots {
    pub(super) fn new(peers: usize) -> Result<Self> {
        if peers == 0 || peers > peer_runtime::finality::MAX_PEERS {
            return Err(Error::Shape);
        }
        let capacity = peers.min(BLOB_SLOTS);
        Ok(Self {
            state: Mutex::new(BlobState {
                available: capacity,
                waiting: VecDeque::with_capacity(peers),
                requested: vec![false; peers],
                held: vec![false; peers],
            }),
            changed: Condvar::new(),
            stopped: AtomicBool::new(false),
            broken: AtomicBool::new(false),
            capacity,
        })
    }
    fn poisoned() -> Error {
        io::Error::other("Progress blob admission poisoned").into()
    }
    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.changed.notify_all();
    }
    pub(super) fn acquire(
        &self,
        peer: usize,
        active: impl Fn() -> bool,
    ) -> Result<Option<BlobPermit<'_>>> {
        let mut state = self.state.lock().map_err(|_| Self::poisoned())?;
        if peer >= state.requested.len() || state.requested[peer] || state.held[peer] {
            return Err(Error::Shape);
        }
        state.requested[peer] = true;
        state.waiting.push_back(peer);
        self.changed.notify_all();
        loop {
            if self.stopped() || !active() {
                state.waiting.retain(|waiting| *waiting != peer);
                state.requested[peer] = false;
                self.changed.notify_all();
                return Ok(None);
            }
            if state.available != 0 && state.waiting.front() == Some(&peer) {
                state.waiting.pop_front();
                state.requested[peer] = false;
                state.held[peer] = true;
                state.available -= 1;
                self.changed.notify_all();
                return Ok(Some(BlobPermit { slots: self, peer }));
            }
            // The same operation check observes external cancellation/deadline;
            // stop()/permit release also wake admission immediately. No new or
            // renewed RPC/operation deadline is introduced by this local wait.
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(10))
                .map_err(|_| Self::poisoned())?
                .0;
        }
    }
    pub(super) fn finish(&self) -> Result<()> {
        if self.broken.load(Ordering::Acquire) {
            return Err(Self::poisoned());
        }
        let state = self.state.lock().map_err(|_| Self::poisoned())?;
        if state.available != self.capacity
            || !state.waiting.is_empty()
            || state.requested.iter().any(|held| *held)
            || state.held.iter().any(|held| *held)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn wait_queued(&self, peer: usize, expires: std::time::Instant) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Self::poisoned())?;
        while !state.waiting.contains(&peer) {
            let remaining = expires
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| Error::Io(io::Error::from(io::ErrorKind::TimedOut)))?;
            state = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| Self::poisoned())?
                .0;
        }
        Ok(())
    }
}
impl Drop for BlobPermit<'_> {
    fn drop(&mut self) {
        match self.slots.state.lock() {
            Ok(mut state) => {
                if !state.held[self.peer] || state.available >= self.slots.capacity {
                    self.slots.broken.store(true, Ordering::Release);
                    self.slots.stop();
                } else {
                    state.held[self.peer] = false;
                    state.available += 1;
                }
            }
            Err(_) => {
                self.slots.broken.store(true, Ordering::Release);
                self.slots.stop();
            }
        }
        self.slots.changed.notify_all();
    }
}
struct StopGuard<'a, S: Fn()> {
    stop: &'a S,
    panic_only: bool,
}
impl<S: Fn()> Drop for StopGuard<'_, S> {
    fn drop(&mut self) {
        if !self.panic_only || thread::panicking() {
            (self.stop)();
        }
    }
}
// Private ordinary concurrency, not a verifier or receipt factory. Production
// work is Round::run_peer, whose only Some is the concretely checked real QC.
// Tests use public I/O tokens, never a fabricated accepted Checkpoint/proof.
pub(super) fn run_peer_workers<T: Send>(
    count: usize,
    first: usize,
    work: impl Fn(usize) -> Result<Option<T>> + Sync,
    stop: impl Fn() + Sync,
    selected: impl Fn(&T),
) -> Result<Option<T>> {
    if count == 0 || count > peer_runtime::finality::MAX_PEERS {
        return Err(Error::Shape);
    }
    thread::scope(|scope| {
        // Declared before all worker owners: unwinding cancels I/O before the
        // enclosing thread::scope joins anything that is still running.
        let _stop = StopGuard {
            stop: &stop,
            panic_only: false,
        };
        let (sent, received) = mpsc::sync_channel(count);
        let mut workers = Vec::with_capacity(count);
        let mut failure = None;
        for ordinal in 0..count {
            let index = (first % count + ordinal) % count;
            let sent = sent.clone();
            let work = &work;
            let stop = &stop;
            match thread::Builder::new()
                .name("progress-owner-peer".into())
                .spawn_scoped(scope, move || {
                    let _panic = StopGuard {
                        stop,
                        panic_only: true,
                    };
                    let result = work(index);
                    let _ = sent.send(result);
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    failure = Some(error.into());
                    stop();
                    break;
                }
            }
        }
        drop(sent);
        let mut value = None;
        if failure.is_none() {
            for result in &received {
                match result {
                    Ok(Some(next)) => {
                        selected(&next);
                        value = Some(next);
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
        }
        stop();
        let mut panicked = false;
        for worker in workers {
            panicked |= worker.join().is_err();
        }
        // Each worker sends at most once into capacity=count. All senders have
        // now joined, so draining is bounded and cannot wait for another RPC.
        for result in received.try_iter() {
            if let Err(error) = result
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        if panicked {
            return Err(io::Error::other("Owner peer worker panicked").into());
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(value)
    })
}
pub(super) fn after_observation<T>(
    result: PeerResult<Option<T>>,
    active: bool,
) -> PeerResult<Option<T>> {
    let observed = result?; // Never hide an actual local/foreign-QC error.
    Ok(if active { observed } else { None })
}

pub(super) fn observe_peer(
    progress: &PeerProgress,
    result: PeerResult<Option<Checkpoint>>,
) -> Result<Option<Checkpoint>> {
    match result {
        Ok(value) => Ok(value),
        Err(PeerFailure::Remote(error)) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(PeerFailure::Remote(_)) => {
            progress.stage.store(3, Ordering::Release);
            Ok(None)
        }
        Err(PeerFailure::Local(error)) => Err(error),
    }
}

struct Round<'a> {
    operation: &'a Operation,
    block: &'a CandidateBlock,
    ingress: &'a ProgressEvidenceIngress,
    binding: &'a Binding,
    context: &'a Context,
    order: &'a SubmissionOrder,
    plan: &'a UploadPlan,
    slots: &'a BlobSlots,
    #[cfg(test)]
    started: std::time::Instant,
}
impl Round<'_> {
    fn run_peer(&self, index: usize) -> Result<Option<Checkpoint>> {
        let progress = PeerProgress::new();
        while !self.slots.stopped() && self.operation.check().is_ok() {
            if progress.position().0 == 3 {
                return Ok(None);
            }
            let client = &self.operation.clients[index];
            let before = progress.position();
            #[cfg(test)]
            let turn_started = std::time::Instant::now();
            let result = self.turn(client, &progress, index);
            #[cfg(test)]
            if result.is_err() {
                eprintln!(
                    "progress_upload phase=turn_rejected slot={} peer={} before_stage={} before_ordinal={} duration_ms={}",
                    self.context.slot(),
                    index,
                    before.0,
                    before.1,
                    turn_started.elapsed().as_millis()
                );
            }
            if let Some(qc) = observe_peer(&progress, result)? {
                return Ok(Some(qc));
            }
            if progress.position().0 == 3 {
                return Ok(None);
            }
            if progress.position() == before {
                thread::park_timeout(Duration::from_millis(50));
            }
        }
        Ok(None)
    }
    fn turn(
        &self,
        client: &ProgressFinalityClient,
        progress: &PeerProgress,
        peer: usize,
    ) -> PeerResult<Option<Checkpoint>> {
        let checkpoint = progress.perform(
            self.order,
            self.plan.parts.len(),
            || self.operation.check().is_ok(),
            |action| match action {
                PeerAction::Original | PeerAction::Submit => {
                    #[cfg(test)]
                    let rpc_started=std::time::Instant::now();
                    #[cfg(test)]
                    eprintln!("progress_upload phase=submit_start slot={} peer={} action={action:?} elapsed_ms={}",self.context.slot(),peer,self.started.elapsed().as_millis());
                    client.submit(self.block).map_err(PeerFailure::Remote)?;
                    #[cfg(test)]
                    eprintln!("progress_upload phase=submit_end slot={} peer={} duration_ms={} elapsed_ms={}",self.context.slot(),peer,rpc_started.elapsed().as_millis(),self.started.elapsed().as_millis());
                    Ok(StepReply::Completed(None))
                }
                PeerAction::Blob(ordinal) => {
                    let Some(_slot) = self.slots.acquire(peer, || {
                        self.operation.check().is_ok() && !self.slots.stopped()
                    }).map_err(PeerFailure::Local)? else { return Ok(StepReply::Stopped); };
                    let part = self
                        .plan
                        .parts
                        .get(ordinal)
                        .ok_or(PeerFailure::Local(Error::Shape))?;
                    let bytes = local(self.ingress.read_public_blob(part.id, part.cap))?;
                    if self.operation.check().is_err() {
                        return Ok(StepReply::Stopped);
                    }
                    #[cfg(test)]
                    let rpc_started=std::time::Instant::now();
                    #[cfg(test)]
                    if ordinal==0 || ordinal+1==self.plan.parts.len(){eprintln!("progress_upload phase=PUT_start slot={} peer={} ordinal={} first={} last={} elapsed_ms={}",self.context.slot(),peer,ordinal,ordinal==0,ordinal+1==self.plan.parts.len(),self.started.elapsed().as_millis());}
                    client
                        .put_proof_blob(self.block, part.selector, part.id, &bytes)
                        .map_err(PeerFailure::Remote)?;
                    #[cfg(test)]
                    if ordinal==0 || ordinal+1==self.plan.parts.len(){eprintln!("progress_upload phase=PUT_success slot={} peer={} ordinal={} duration_ms={} elapsed_ms={}",self.context.slot(),peer,ordinal,rpc_started.elapsed().as_millis(),self.started.elapsed().as_millis());}
                    Ok(StepReply::Completed(None))
                }
                PeerAction::Checkpoint => {
                    let slot = self
                        .context
                        .slot()
                        .checked_sub(1)
                        .ok_or(PeerFailure::Local(Error::Shape))?;
                    #[cfg(test)]
                    let rpc_started=std::time::Instant::now();
                    let result=client.checkpoint_after(slot);
                    #[cfg(test)]
                    if !matches!(&result,Ok(None)){eprintln!("progress_upload phase=checkpoint_observation slot={} peer={} present={} ok={} duration_ms={} elapsed_ms={}",self.context.slot(),peer,matches!(&result,Ok(Some(_))),result.is_ok(),rpc_started.elapsed().as_millis(),self.started.elapsed().as_millis());}
                    result.map(|checkpoint|StepReply::Completed(checkpoint.map(Box::new))).map_err(PeerFailure::Remote)
                }
            },
        )?;
        // Classify every actually returned QC before cancellation can suppress
        // success. Local loss/genuine foreign-current QC remains a hard error.
        let observed = self.observed_checkpoint(Ok(checkpoint));
        after_observation(observed, self.operation.check().is_ok())
    }
    fn observed_checkpoint(
        &self,
        result: io::Result<Option<Checkpoint>>,
    ) -> PeerResult<Option<Checkpoint>> {
        match result.map_err(PeerFailure::Remote)? {
            Some(qc) => {
                #[cfg(test)]
                let verified_started = std::time::Instant::now();
                match require_checkpoint(self.binding, self.context, self.block, &qc) {
                    Ok(()) => {}
                    Err(Error::RecoveryRequired) => {
                        return Err(PeerFailure::Local(Error::RecoveryRequired));
                    }
                    Err(error) => {
                        return Err(PeerFailure::Remote(io::Error::new(
                            io::ErrorKind::InvalidData,
                            error.to_string(),
                        )));
                    }
                }
                #[cfg(test)]
                eprintln!(
                    "progress_upload phase=QC_verified_valid slot={} duration_ms={} elapsed_ms={}",
                    self.context.slot(),
                    verified_started.elapsed().as_millis(),
                    self.started.elapsed().as_millis()
                );
                Ok(Some(qc))
            }
            None => Ok(None),
        }
    }
}

impl Driver {
    pub(super) fn network_round(
        &mut self,
        operation: &Operation,
        block: &CandidateBlock,
        saved_original: bool,
    ) -> Result<Option<Checkpoint>> {
        let binding = self.owner.pins.binding.clone();
        let context = self.owner.history.context().map_err(crypto)?.clone();
        let ingress = self.owner.ingress.clone();
        let body =
            Body::decode(block.body(), &binding.journal_genesis().profile).map_err(crypto)?;
        let a = self.owner.attempt.as_ref().ok_or(Error::Phase)?;
        OperationExpectation::transition(
            &binding,
            self.owner
                .history
                .checked_parent()
                .map_err(crypto)?
                .ok_or(Error::Phase)?,
            &context,
            &a.request,
            a.manifest()?,
            &body,
        )
        .map_err(crypto)?;
        let plan = UploadPlan::new(block, &ingress, &binding).map_err(|failure| match failure {
            PeerFailure::Local(error) => error,
            PeerFailure::Remote(error) => error.into(),
        })?;
        let count = operation.clients.len();
        let slots = BlobSlots::new(count)?;
        let first = self.next_peer;
        self.next_peer = (self.next_peer + 1) % count;
        let order = if saved_original {
            SubmissionOrder::SavedOriginal
        } else {
            SubmissionOrder::Fresh
        };
        let round = Round {
            operation,
            block,
            ingress: &ingress,
            binding: &binding,
            context: &context,
            order: &order,
            plan: &plan,
            slots: &slots,
            #[cfg(test)]
            started: std::time::Instant::now(),
        };
        // Every configured route owns one joined worker (MAX_PEERS=16). Only
        // read+PUT holds a fair slot; at most three original blob buffers exist.
        // Slow metadata RPCs cannot occupy another route's worker or blob slot.
        let result = run_peer_workers(
            count,
            first,
            |index| round.run_peer(index),
            || {
                slots.stop();
                operation.stop_network();
            },
            |_| {
                #[cfg(test)]
                eprintln!(
                    "progress_upload phase=first_valid_QC_selected slot={} elapsed_ms={}",
                    context.slot(),
                    round.started.elapsed().as_millis()
                );
            },
        );
        let released = slots.finish();
        #[cfg(test)]
        eprintln!(
            "progress_upload phase=all_workers_joined slot={} elapsed_ms={} selected={}",
            context.slot(),
            round.started.elapsed().as_millis(),
            matches!(&result, Ok(Some(_)))
        );
        match (result, released) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            (Ok(checkpoint), Ok(())) => Ok(checkpoint),
        }
    }
}
