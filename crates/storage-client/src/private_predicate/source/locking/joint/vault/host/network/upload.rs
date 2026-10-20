//! Bounded ordinary RPC scheduling. A single independently checked QC is sufficient.
//! These definitions perform no I/O at module initialization. Every destination
//! is the caller-configured pinned Endpoint; no private owner witness is sent.
use super::*;
use peer_runtime::finality::ProofBlobSelector;
use protocol_storage::BlobId;
use registry200_joint::{JointEvidenceIngress, Lane, Manifest, ManifestRole};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    mpsc,
};
use version_journal::Body;
use work_finality::consensus::Context;

const LANES: usize = 3;

pub(super) enum SubmissionOrder {
    Fresh,
    SavedOriginal,
}

#[derive(Debug)]
enum PeerFailure {
    Local(JointSqlNetworkError),
    Remote(io::Error),
}
type PeerResult<T> = core::result::Result<T, PeerFailure>;
fn local<T, E>(result: core::result::Result<T, E>) -> PeerResult<T>
where
    JointSqlNetworkError: From<E>,
{
    result.map_err(|error| PeerFailure::Local(error.into()))
}
struct UploadPart {
    selector: ProofBlobSelector,
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
        ingress: &JointEvidenceIngress,
        binding: &JointBinding,
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
                .map_err(|_| PeerFailure::Local(JointSqlNetworkError::Configuration))?;
            parts.push(UploadPart {
                selector: local(ProofBlobSelector::manifest(ordinal))?,
                id: reference.blob_id(),
                cap: reference.byte_cap(),
            });
        }
        if manifest.lane() == Lane::Acquire {
            let id = manifest
                .references()
                .find(|r| r.role() == ManifestRole::ProductCatalog)
                .ok_or_else(|| {
                    PeerFailure::Local(
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Acquire catalog reference missing",
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
                    selector: local(ProofBlobSelector::catalog(
                        reference.role(),
                        reference.ordinal(),
                    ))?,
                    id: reference.blob_id(),
                    cap: reference.byte_cap(),
                });
            }
        }
        Ok(Self { parts })
    }
}

// Private ordinary-I/O scheduling only. A returned checkpoint is UNVERIFIED;
// Round::observed_checkpoint remains the mandatory concrete weighted-QC check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerAction {
    Original,
    Blob(usize),
    Submit,
    Checkpoint,
}
enum StepReply {
    Stopped,
    Completed(Option<Box<JointCheckpoint>>),
}
pub(super) fn require_checkpoint(
    binding: &JointBinding,
    context: &Context,
    block: &CandidateBlock,
    qc: &JointCheckpoint,
) -> NetworkResult<()> {
    let expected = registry200_finality::joint::JointCandidate::for_context(
        binding,
        context,
        block.header().clone(),
    )?;
    require_expected(context, &expected, qc)
}
fn require_expected(
    context: &Context,
    expected: &registry200_finality::joint::JointCandidate,
    qc: &JointCheckpoint,
) -> NetworkResult<()> {
    if qc.candidate().encode() != expected.encode() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Checkpoint is not this exact candidate/context",
        )
        .into());
    }
    context
        .verify_commit(&qc.candidate().encode(), qc.round(), qc.certificate())
        .map_err(|e| JointSqlNetworkError::Joint(e.into()))?;
    Ok(())
}
struct PeerProgress {
    busy: AtomicBool,
    stage: AtomicU8,
    ordinal: AtomicUsize,
    original_attempted: AtomicBool,
}
impl PeerProgress {
    fn position(&self) -> (u8, usize, bool) {
        (
            self.stage.load(Ordering::Acquire),
            self.ordinal.load(Ordering::Acquire),
            self.original_attempted.load(Ordering::Acquire),
        )
    }
    fn perform(
        &self,
        order: &SubmissionOrder,
        parts: usize,
        active: impl Fn() -> bool,
        mut call: impl FnMut(PeerAction) -> PeerResult<StepReply>,
    ) -> PeerResult<Option<JointCheckpoint>> {
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
        if !active() {
            return Ok(None);
        }
        Ok(checkpoint.map(|checkpoint| *checkpoint))
    }
}
struct Scheduler {
    next: AtomicUsize,
    stopped: AtomicBool,
    peers: Vec<PeerProgress>,
}
struct PeerTurn<'a>(&'a AtomicBool);
impl Drop for PeerTurn<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Scheduler {
    fn claim(&self) -> Option<(usize, PeerTurn<'_>)> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.peers.len();
        let progress = &self.peers[index];
        if progress.stage.load(Ordering::Acquire) == 3
            || progress
                .busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        Some((index, PeerTurn(&progress.busy)))
    }
}
fn observe_peer(
    progress: &PeerProgress,
    result: PeerResult<Option<JointCheckpoint>>,
) -> NetworkResult<Option<JointCheckpoint>> {
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
    ingress: &'a JointEvidenceIngress,
    binding: &'a JointBinding,
    context: &'a Context,
    order: &'a SubmissionOrder,
    plan: &'a UploadPlan,
    scheduler: &'a Scheduler,
}
struct WorkerExit<'a> {
    scheduler: &'a Scheduler,
    operation: &'a Operation,
}
impl Drop for WorkerExit<'_> {
    fn drop(&mut self) {
        self.scheduler.stopped.store(true, Ordering::Release);
        self.operation.stop_network();
    }
}
impl Round<'_> {
    fn run(&self) -> NetworkResult<Option<JointCheckpoint>> {
        while !self.scheduler.stopped.load(Ordering::Acquire) && self.operation.check().is_ok() {
            if self
                .scheduler
                .peers
                .iter()
                .all(|p| p.stage.load(Ordering::Acquire) == 3)
            {
                return Ok(None);
            }
            let Some((index, _turn)) = self.scheduler.claim() else {
                thread::park_timeout(Duration::from_millis(10));
                continue;
            };
            let progress = &self.scheduler.peers[index];
            let client = &self.operation.clients[index];
            let before = progress.position();
            if let Some(qc) = observe_peer(progress, self.turn(client, progress))? {
                return Ok(Some(qc));
            }
            if progress.position() == before {
                // Successful one-blob/stage turns yield immediately. Retain the
                // existing backoff only for BUSY or a checkpoint not yet present.
                thread::park_timeout(Duration::from_millis(50));
            }
        }
        Ok(None)
    }
    fn turn(
        &self,
        client: &JointFinalityClient,
        progress: &PeerProgress,
    ) -> PeerResult<Option<JointCheckpoint>> {
        let checkpoint = progress.perform(
            self.order,
            self.plan.parts.len(),
            || self.operation.check().is_ok(),
            |action| match action {
                PeerAction::Original | PeerAction::Submit => {
                    client.submit(self.block).map_err(PeerFailure::Remote)?;
                    Ok(StepReply::Completed(None))
                }
                PeerAction::Blob(ordinal) => {
                    let part = self
                        .plan
                        .parts
                        .get(ordinal)
                        .ok_or(PeerFailure::Local(JointSqlNetworkError::Configuration))?;
                    let bytes = local(self.ingress.read_public_blob(part.id, part.cap))?;
                    if self.operation.check().is_err() {
                        return Ok(StepReply::Stopped);
                    }
                    client
                        .put_proof_blob(self.block, part.selector, part.id, &bytes)
                        .map_err(PeerFailure::Remote)?;
                    Ok(StepReply::Completed(None))
                }
                PeerAction::Checkpoint => {
                    let slot = self
                        .context
                        .slot()
                        .checked_sub(1)
                        .ok_or(PeerFailure::Local(JointSqlNetworkError::Configuration))?;
                    client
                        .checkpoint_after(slot)
                        .map(|checkpoint| StepReply::Completed(checkpoint.map(Box::new)))
                        .map_err(PeerFailure::Remote)
                }
            },
        )?;
        let result = self.observed_checkpoint(Ok(checkpoint));
        if self.operation.check().is_err() {
            return Ok(None);
        }
        result
    }
    fn observed_checkpoint(
        &self,
        result: io::Result<Option<JointCheckpoint>>,
    ) -> PeerResult<Option<JointCheckpoint>> {
        match result.map_err(PeerFailure::Remote)? {
            Some(qc) => {
                require_checkpoint(self.binding, self.context, self.block, &qc).map_err(|e| {
                    PeerFailure::Remote(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
                })?;
                Ok(Some(qc))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[path = "upload_tests.rs"]
mod tests;
impl JointSqlNetworkHost {
    pub(super) fn network_round(
        &mut self,
        operation: &Operation,
        block: &CandidateBlock,
        order: SubmissionOrder,
    ) -> NetworkResult<Option<JointCheckpoint>> {
        let binding = self.host.vault.pins.binding.clone();
        let context = self.host.vault.history.context()?.clone();
        let ingress = self.host.evidence_ingress()?;
        let plan = UploadPlan::new(block, &ingress, &binding).map_err(|failure| match failure {
            PeerFailure::Local(error) => error,
            PeerFailure::Remote(error) => error.into(),
        })?;
        let count = operation.clients.len().min(LANES);
        let scheduler = Scheduler {
            next: AtomicUsize::new(self.next_peer),
            stopped: AtomicBool::new(false),
            peers: (0..operation.clients.len())
                .map(|_| PeerProgress {
                    busy: AtomicBool::new(false),
                    stage: AtomicU8::new(0),
                    ordinal: AtomicUsize::new(0),
                    original_attempted: AtomicBool::new(false),
                })
                .collect(),
        };
        self.next_peer = (self.next_peer + 1) % operation.clients.len();
        let round = Round {
            operation,
            block,
            ingress: &ingress,
            binding: &binding,
            context: &context,
            order: &order,
            plan: &plan,
            scheduler: &scheduler,
        };
        // At most three scoped workers, one bounded public blob each (32 MiB).
        // Every configured destination participates in the SAME operation's
        // round-robin queue; this is not first-three endpoint selection. A slow
        // RPC remains subject to the existing I/O and whole-operation budgets.
        // Tiny atomic bookkeeping never spans a Host/state/store mutex.
        thread::scope(|scope| -> NetworkResult<Option<JointCheckpoint>> {
            let (sent, received) = mpsc::sync_channel(count);
            let mut workers = Vec::with_capacity(count);
            for _ in 0..count {
                let sent = sent.clone();
                let round = &round;
                match thread::Builder::new()
                    .name("joint-owner-peer".into())
                    .spawn_scoped(scope, move || {
                        let _stop = WorkerExit {
                            scheduler: round.scheduler,
                            operation: round.operation,
                        };
                        let result = round.run();
                        let _ = sent.send(result);
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        scheduler.stopped.store(true, Ordering::Release);
                        operation.stop_network();
                        for worker in workers {
                            let _ = worker.join();
                        }
                        return Err(error.into());
                    }
                }
            }
            drop(sent);
            let mut selected = None;
            let mut failure = None;
            for result in received {
                match result {
                    Ok(Some(qc)) => {
                        selected = Some(qc);
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            scheduler.stopped.store(true, Ordering::Release);
            operation.stop_network();
            let mut panicked = false;
            for worker in workers {
                panicked |= worker.join().is_err();
            }
            if panicked {
                return Err(io::Error::other("Owner peer worker panicked").into());
            }
            if let Some(error) = failure {
                return Err(error);
            }
            Ok(selected)
        })
    }
}
