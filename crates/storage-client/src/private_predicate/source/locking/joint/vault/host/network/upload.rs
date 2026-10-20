//! Bounded ordinary RPC scheduling. A single independently checked QC is sufficient.
//! These definitions perform no I/O at module initialization. Every destination
//! is the caller-configured pinned Endpoint; no private owner witness is sent.
use super::*;
use peer_runtime::finality::ProofBlobSelector;
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
fn upload(
    client: &JointFinalityClient,
    block: &CandidateBlock,
    ingress: &JointEvidenceIngress,
    binding: &JointBinding,
) -> PeerResult<()> {
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
    for reference in manifest.references() {
        let bytes = local(ingress.read_public_blob(reference.blob_id(), reference.byte_cap()))?;
        let ordinal = reference
            .ordinal()
            .try_into()
            .map_err(|_| PeerFailure::Local(JointSqlNetworkError::Configuration))?;
        let selector = local(ProofBlobSelector::manifest(ordinal))?;
        client
            .put_proof_blob(block, selector, reference.blob_id(), &bytes)
            .map_err(PeerFailure::Remote)?;
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
            let bytes = local(ingress.read_public_blob(reference.blob_id(), reference.byte_cap()))?;
            let selector = local(ProofBlobSelector::catalog(
                reference.role(),
                reference.ordinal(),
            ))?;
            client
                .put_proof_blob(block, selector, reference.blob_id(), &bytes)
                .map_err(PeerFailure::Remote)?;
        }
    }
    Ok(())
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
            if let Some(qc) = observe_peer(progress, self.turn(client, progress))? {
                return Ok(Some(qc));
            }
            thread::park_timeout(Duration::from_millis(50));
        }
        Ok(None)
    }
    fn turn(
        &self,
        client: &JointFinalityClient,
        progress: &PeerProgress,
    ) -> PeerResult<Option<JointCheckpoint>> {
        let stage = progress.stage.load(Ordering::Acquire);
        if stage == 0 {
            if matches!(self.order, SubmissionOrder::SavedOriginal) {
                // Fixed recovery sequence: observe the exact original submit
                // FIRST, independently of its result. No rejection is classified
                // as a missing-proof claim or accepted as permission. The SAME
                // authorized public references are then staged, and admission
                // is attempted again with unchanged full server verification.
                let _ = client.submit(self.block);
                if self.operation.check().is_err() {
                    return Ok(None);
                }
            }
            upload(client, self.block, self.ingress, self.binding)?;
            progress.stage.store(1, Ordering::Release);
        }
        if self.operation.check().is_err() {
            return Ok(None);
        }
        if progress.stage.load(Ordering::Acquire) == 1 {
            client.submit(self.block).map_err(PeerFailure::Remote)?;
            progress.stage.store(2, Ordering::Release);
        }
        if self.operation.check().is_err() {
            return Ok(None);
        }
        let slot = self
            .context
            .slot()
            .checked_sub(1)
            .ok_or(PeerFailure::Local(JointSqlNetworkError::Configuration))?;
        self.observed_checkpoint(client.checkpoint_after(slot))
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
        let count = operation.clients.len().min(LANES);
        let scheduler = Scheduler {
            next: AtomicUsize::new(self.next_peer),
            stopped: AtomicBool::new(false),
            peers: (0..operation.clients.len())
                .map(|_| PeerProgress {
                    busy: AtomicBool::new(false),
                    stage: AtomicU8::new(0),
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
