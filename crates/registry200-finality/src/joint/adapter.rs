//! Concrete durable Joint owner. No supplied verifier, journal, key getter or
//! successor exists. All evidence must already be local in the SAME depot.
use super::history::{
    candidate_control, parent_heads, require_candidate_context, verify_candidate,
};
use super::{
    Error, Hash, JointBinding, JointCandidate, JointCheckpoint, Result, VerifiedJointParent,
    durable_profile_digest,
};
use crate::{
    CandidateBlock, digest,
    participant::{self, Paths},
    pins::Pins,
    store::FloorLog,
};
use ed25519_dalek::SigningKey;
use protocol_storage::{FileCharge, ParticipantQuota};
use registry200_joint::{JointDepot, JointEvidenceIngress, JointVerifier};
use registry200_journal::Control;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use version_journal::{DurableJournal, HeadRef, Header};
use work_finality::consensus::{
    Action, ApplicationContext, ApplicationError, ApplicationVerifier, Context, Decision,
    DurableVoter, FreshDecision, Input, Timeout,
};

// The shared bounded floor stores the same complete candidate width, never a
// truncated or relabelled value. Distinct formats still have distinct domains.
const _: [(); crate::DESCRIPTOR_BYTES] = [(); super::CANDIDATE_BYTES];

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;

pub fn participant_storage_profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/joint-participant-storage/v1", &[
        &durable_profile_digest(), &protocol_storage::participant_profile_digest(),
        b"typed-four-control-files/binding+signer-id/metadata-last/new-only/existing-only/no-adoption",
        b"journal76+G/floor168/wal144/all-writes-precharged/owned-IO-poisons-global-ledger",
        &(participant::META_BYTES as u64).to_le_bytes(),
    ])
}

struct Historical {
    context: Hash,
    parent: HeadRef,
}
// Only a synchronous drive registers a frame. This channel contains no result
// between drives and is never consulted to skip an application verification.
#[derive(Default)]
struct DriveHandoff {
    active: Mutex<Option<Arc<DriveFrame>>>,
}
struct DriveFrame {
    context: Hash,
    checked: Mutex<Option<CheckedApplication>>,
}
// Fixed public metadata from a completed cold State::verify, never proof/SDK
// buffers or a serialized success bit. There is deliberately no Clone impl.
struct CheckedApplication {
    binding: Hash,
    context: Hash,
    candidate: [u8; super::CANDIDATE_BYTES],
    parent: HeadRef,
    floor: HeadRef,
    head: HeadRef,
    control: Control,
}
struct DriveCapture<'drive> {
    channel: &'drive DriveHandoff,
    frame: Arc<DriveFrame>,
}
struct CheckedForFloor<'drive> {
    channel: &'drive DriveHandoff,
    frame: &'drive Arc<DriveFrame>,
    application: CheckedApplication,
}
impl DriveHandoff {
    fn begin(&self, context: Hash) -> Result<DriveCapture<'_>> {
        let mut active = self.active.lock().map_err(|_| Error::Poisoned)?;
        if active.is_some() {
            return Err(Error::Poisoned);
        }
        let frame = Arc::new(DriveFrame {
            context,
            checked: Mutex::new(None),
        });
        *active = Some(frame.clone());
        Ok(DriveCapture {
            channel: self,
            frame,
        })
    }
    fn record(&self, application: CheckedApplication) -> Result<()> {
        let active = self.active.lock().map_err(|_| Error::Poisoned)?;
        if let Some(frame) = active.as_ref() {
            if application.context != frame.context {
                return Err(Error::Context);
            }
            // Every call has ALREADY run the real verifier, even if another
            // check in this same Machine::apply concerned the same value.
            *frame.checked.lock().map_err(|_| Error::Poisoned)? = Some(application);
        }
        Ok(())
    }
}
impl DriveCapture<'_> {
    fn take(&self) -> Result<CheckedForFloor<'_>> {
        let application = self
            .frame
            .checked
            .lock()
            .map_err(|_| Error::Poisoned)?
            .take()
            .ok_or(Error::Context)?;
        Ok(CheckedForFloor {
            channel: self.channel,
            frame: &self.frame,
            application,
        })
    }
}
impl Drop for DriveCapture<'_> {
    fn drop(&mut self) {
        // Cleanup must also happen on unwinding. Recovering a poisoned lock
        // here only removes this frame; it does not clear the poison flag.
        let mut active = self
            .channel
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if active
            .as_ref()
            .is_some_and(|frame| Arc::ptr_eq(frame, &self.frame))
        {
            *active = None;
        }
        let _ = self
            .frame
            .checked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}
struct State {
    binding: JointBinding,
    journal: DurableJournal,
    charge: FileCharge,
    verifier: JointVerifier,
    history: BTreeMap<u64, Historical>,
    current: Context,
    last_context: Option<Context>,
    finalized: Option<VerifiedJointParent>,
    handoff: Arc<DriveHandoff>,
    #[cfg(test)]
    completed_application_checks: std::sync::atomic::AtomicUsize,
}

// A same-call handoff, never a reusable proof receipt. The exclusive State
// borrow keeps the actual MutexGuard alive until this value is consumed.
struct PreparedFinalization<'state, 'decision> {
    state: &'state mut State,
    decision: &'decision Decision,
    head: HeadRef,
    control: Control,
    next: Context,
}
impl PreparedFinalization<'_, '_> {
    fn install(self) -> Result<()> {
        let Self {
            state,
            decision,
            head,
            control,
            next,
        } = self;
        // No proof or successor verification is repeated here. These exact
        // outputs and original Decision came from preflight. The exclusive
        // borrow has prevented any intervening State mutation or guard release.
        state.journal.restrict_ancestry_floor(head)?;
        state.finalized = Some(VerifiedJointParent::checked(
            &state.binding,
            head,
            state.current.slot(),
            decision.semantic_id(),
            control,
        ));
        state.last_context = Some(state.current.clone());
        state.history.insert(
            next.slot(),
            Historical {
                context: next.id(),
                parent: head,
            },
        );
        state.current = next;
        Ok(())
    }
}
impl State {
    fn new(
        binding: JointBinding,
        journal: DurableJournal,
        charge: FileCharge,
        verifier: JointVerifier,
    ) -> Self {
        let current = binding.initial_context().clone();
        let mut history = BTreeMap::new();
        history.insert(
            1,
            Historical {
                context: current.id(),
                parent: journal.journal().genesis_head(),
            },
        );
        Self {
            binding,
            journal,
            charge,
            verifier,
            history,
            current,
            last_context: None,
            finalized: None,
            handoff: Arc::new(DriveHandoff::default()),
            #[cfg(test)]
            completed_application_checks: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn verify(&self, context: &Context, value: &[u8]) -> Result<(HeadRef, Control)> {
        if context.slot() > u64::from(self.binding.journal_genesis().profile.max_headers) {
            return Err(Error::ResourceLimit);
        }
        let d = JointCandidate::decode(value)?;
        let h = self.history.get(&context.slot()).ok_or(Error::Context)?;
        if context.id() != h.context {
            return Err(Error::Context);
        }
        let body = self
            .journal
            .journal()
            .body(d.header.id())
            .ok_or(crate::Error::MissingCandidate)?;
        let control = verify_candidate(
            &self.binding,
            self.journal.journal(),
            &self.verifier,
            context,
            h.parent,
            &d,
            body,
        )?;
        let head = HeadRef {
            genesis: d.header.genesis,
            database: self.binding.journal_genesis().database,
            block: d.header.id(),
            height: d.header.height,
            state_root: d.header.state_root,
        };
        self.journal.journal().validated_shards(head)?;
        #[cfg(test)]
        self.completed_application_checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok((head, control))
    }
    fn preflight<'state, 'decision>(
        &'state mut self,
        decision: &'decision Decision,
    ) -> Result<PreparedFinalization<'state, 'decision>> {
        if decision.context_id() != self.current.id() {
            return Err(Error::Context);
        }
        let (head, control) = self.verify(&self.current, decision.value())?;
        self.prepare_finalization(decision, head, control)
    }
    fn preflight_checked<'state, 'decision>(
        &'state mut self,
        decision: &'decision Decision,
        checked: CheckedForFloor<'_>,
    ) -> Result<PreparedFinalization<'state, 'decision>> {
        let CheckedForFloor {
            channel,
            frame,
            application: checked,
        } = checked;
        let registered = self.handoff.active.lock().map_err(|_| Error::Poisoned)?;
        if !registered
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, frame))
            || !std::ptr::eq(self.handoff.as_ref(), channel)
            || frame.context != self.current.id()
            || checked.binding != self.binding.id()
            || checked.context != self.current.id()
            || decision.context_id() != self.current.id()
            || decision.value() != checked.candidate.as_slice()
            || checked.floor != self.journal.journal().ancestry_floor()
        {
            return Err(Error::Context);
        }
        drop(registered);
        let d = JointCandidate::decode(decision.value())?;
        let historical = self
            .history
            .get(&self.current.slot())
            .ok_or(Error::Context)?;
        if historical.context != self.current.id() || historical.parent != checked.parent {
            return Err(Error::Context);
        }
        require_candidate_context(&self.binding, &self.current, checked.parent, &d)?;
        let journal = self.journal.journal();
        if journal.header(checked.head.block) != Some(&d.header)
            || checked.head
                != (HeadRef {
                    genesis: d.header.genesis,
                    database: self.binding.journal_genesis().database,
                    block: d.header.id(),
                    height: d.header.height,
                    state_root: d.header.state_root,
                })
        {
            return Err(Error::Context);
        }
        let body = journal
            .body(checked.head.block)
            .ok_or(crate::Error::MissingCandidate)?;
        if body.len() > journal.profile().max_body_bytes as usize
            || version_journal::hash(body) != d.header.body_hash
        {
            return Err(Error::Context);
        }
        if let version_journal::Body::Transition(transition) =
            version_journal::Body::decode(body, journal.profile())?
        {
            transition.check_authorization(&journal.genesis().owner, journal.genesis_id())?;
        }
        let old = parent_heads(&self.binding, journal, checked.parent)?;
        if candidate_control(&self.binding, old, body)? != checked.control {
            return Err(Error::Context);
        }
        journal.validated_shards(checked.head)?;
        self.prepare_finalization(decision, checked.head, checked.control)
    }
    fn prepare_finalization<'state, 'decision>(
        &'state mut self,
        decision: &'decision Decision,
        head: HeadRef,
        control: Control,
    ) -> Result<PreparedFinalization<'state, 'decision>> {
        let next = self.current.after_decision(decision)?;
        // Initial slot plus each successor is retained for actual WAL replay.
        // len == max_headers is the LAST admissible decision, not exhaustion.
        if self.history.len() > self.binding.journal_genesis().profile.max_headers as usize {
            return Err(Error::ResourceLimit);
        }
        Ok(PreparedFinalization {
            state: self,
            decision,
            head,
            control,
            next,
        })
    }
    fn install(&mut self, decision: &Decision) -> Result<()> {
        // Recovery has no same-call prepared result: perform the complete
        // application/quorum/successor preflight for every actual floor record.
        self.preflight(decision)?.install()
    }
}

fn install_current_decision(
    state: &mut State,
    floor: &mut FloorLog,
    decision: &Decision,
) -> Result<()> {
    // Keep the complete actual application/QC/cap preflight and the same
    // exclusive State borrow through the floor's successful fsync and install.
    let prepared = state.preflight(decision)?;
    floor.append(decision)?;
    prepared.install()
}

#[derive(Clone)]
struct ClosedJointApplication(Arc<Mutex<State>>);
impl ApplicationVerifier for ClosedJointApplication {
    fn verify(
        &self,
        context: &ApplicationContext<'_>,
        value: &[u8],
    ) -> core::result::Result<(), ApplicationError> {
        self.check(context.consensus(), value)
            .map_err(|_| ApplicationError)
    }
}
impl ClosedJointApplication {
    fn check(&self, context: &Context, value: &[u8]) -> Result<()> {
        let state = self.0.lock().map_err(|_| Error::Poisoned)?;
        // Never look up a prior result. The fixed verifier runs in full before
        // depositing metadata for this drive's possible floor finalization.
        let (head, control) = state.verify(context, value)?;
        let candidate = JointCandidate::decode(value)?;
        let parent = state
            .history
            .get(&context.slot())
            .ok_or(Error::Context)?
            .parent;
        state.handoff.record(CheckedApplication {
            binding: state.binding.id(),
            context: context.id(),
            candidate: candidate.encode(),
            parent,
            floor: state.journal.journal().ancestry_floor(),
            head,
            control,
        })
    }
}

/// Owns the actual Journal, floor and signer. Metadata is historical, never a
/// current SQL grant. No-quorum decisions cannot advance a lock or an End.
/// The host prefetches outside locks, then holds its ONE existing ProofGate for
/// construction/replay/import/voting. Local I/O only; no network callback.
/// ```compile_fail
/// fn key(x: &registry200_finality::joint::DurableJointFinality) { let _ = &x.voter.key; }
/// ```
/// ```compile_fail
/// fn copy(x: &registry200_finality::joint::DurableJointFinality) {
///     let _: registry200_finality::joint::DurableJointFinality = x.clone();
/// }
/// ```
pub struct DurableJointFinality {
    state: Arc<Mutex<State>>,
    floor: FloorLog,
    voter: DurableVoter<ClosedJointApplication>,
    poisoned: bool,
    _metadata: FileCharge,
    ingress: JointEvidenceIngress,
    #[cfg(test)]
    poison_before_advance: bool,
}
impl DurableJointFinality {
    /// NEW-only participant installation. Setup and every future proof premise
    /// use the participant's one concrete typed depot and shared ledger.
    pub fn create_participant(
        quota: &ParticipantQuota,
        binding: JointBinding,
        key: SigningKey,
    ) -> Result<Self> {
        binding.require_durable()?;
        let signer = key.verifying_key().to_bytes();
        let paths = Paths::participant(quota, Pins::Joint(&binding), signer);
        let budget = quota.control_budget();
        let marker = paths.metadata.as_ref().ok_or(Error::Binding)?;
        // Check existing marker BEFORE touching any signer file; publish LAST.
        let metadata_permit = budget
            .preflight_file(marker, participant::META_BYTES as u64)
            .map_err(crate::Error::from)?;
        let depot = JointDepot::open(quota.depot_budget())?;
        let ingress = depot.ingress();
        let verifier = JointVerifier::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
            binding.setup_claim(),
            depot,
        )?;
        let initial = 76u64
            .checked_add(binding.journal_genesis().encode()?.len() as u64)
            .ok_or(Error::ResourceLimit)?;
        let mut permit = budget
            .preflight_file(&paths.journal, initial)
            .map_err(crate::Error::from)?;
        let journal = DurableJournal::create(
            permit.path(),
            binding.journal_genesis().clone(),
            binding.namespace(),
        )?;
        let charge = permit.register_file().map_err(crate::Error::from)?;
        let floor = FloorLog::create(&paths.floor, Pins::Joint(&binding), &budget)?;
        let context = binding.initial_context().clone();
        let state = Arc::new(Mutex::new(State::new(
            binding.clone(),
            journal,
            charge,
            verifier,
        )));
        let voter = DurableVoter::create_new(
            &paths.wal,
            context,
            ClosedJointApplication(state.clone()),
            key,
            &budget,
        )?;
        let metadata = participant::install(metadata_permit, Pins::Joint(&binding), signer)?;
        Ok(Self {
            state,
            floor,
            voter,
            poisoned: false,
            _metadata: metadata,
            ingress,
            #[cfg(test)]
            poison_before_advance: false,
        })
    }
    /// Existing-only recovery. Full quota inventory precedes this call. No
    /// missing/corrupt file repair, signer recreation or trusted QC-only replay.
    pub fn open_participant(
        quota: &ParticipantQuota,
        binding: JointBinding,
        key: SigningKey,
    ) -> Result<Self> {
        binding.require_durable()?;
        let paths =
            Paths::participant(quota, Pins::Joint(&binding), key.verifying_key().to_bytes());
        let budget = quota.control_budget();
        let metadata = participant::open(
            paths.metadata.as_ref().ok_or(Error::Binding)?,
            Pins::Joint(&binding),
            key.verifying_key().to_bytes(),
            &budget,
        )?;
        let depot = JointDepot::open(quota.depot_budget())?;
        let ingress = depot.ingress();
        // Independently pinned full setup hashes/anchor are checked before SDK.
        let verifier = JointVerifier::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
            binding.setup_claim(),
            depot,
        )?;
        budget
            .check_existing_file(&paths.journal)
            .map_err(crate::Error::from)?;
        let charge = budget
            .register_file(&paths.journal)
            .map_err(crate::Error::from)?;
        let journal = DurableJournal::open(
            &paths.journal,
            binding.journal_genesis().clone(),
            binding.namespace(),
            crate::adapter::now()?,
            &verifier,
        )
        .map_err(|e| {
            charge.mark_io_failed();
            Error::from(e)
        })?;
        let mut floor = FloorLog::open(&paths.floor, Pins::Joint(&binding), &budget)?;
        let initial = binding.initial_context().clone();
        let mut state = State::new(binding, journal, charge, verifier);
        while let Some(record) = floor.next()? {
            let decision =
                state
                    .current
                    .verify_commit(&record.value, record.round, &record.certificate)?;
            state.install(&decision)?;
        }
        let state = Arc::new(Mutex::new(state));
        let voter = DurableVoter::open_existing(
            &paths.wal,
            initial,
            ClosedJointApplication(state.clone()),
            key,
            &budget,
        )?;
        let mut owner = Self {
            state,
            floor,
            voter,
            poisoned: false,
            _metadata: metadata,
            ingress,
            #[cfg(test)]
            poison_before_advance: false,
        };
        owner.synchronize()?;
        Ok(owner)
    }
    pub fn context(&self) -> Result<&Context> {
        self.live()?;
        Ok(self.voter.context())
    }
    pub fn binding(&self) -> Result<JointBinding> {
        self.live()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .binding
            .clone())
    }
    /// Same concrete store/ledger, public bounded bytes only. No proof grant or
    /// mutable store/Journal guard is returned. RPC must finish before retain.
    pub fn evidence_ingress(&self) -> Result<JointEvidenceIngress> {
        self.live()?;
        Ok(self.ingress.clone())
    }
    pub fn finalized_parent(&self) -> Result<Option<VerifiedJointParent>> {
        self.live()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .finalized
            .clone())
    }
    /// Bounded untrusted DTO export; not a proof-validation receipt.
    pub fn candidate_block(&self, id: Hash) -> Result<CandidateBlock> {
        self.live()?;
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let journal = state.journal.journal();
        Ok(CandidateBlock::new(
            journal
                .header(id)
                .ok_or(crate::Error::MissingCandidate)?
                .clone(),
            journal
                .body(id)
                .ok_or(crate::Error::MissingCandidate)?
                .to_vec(),
        )?)
    }
    /// Availability only. Cached presence never replaces actual proof checking.
    pub fn has_candidate(&self, id: Hash) -> Result<bool> {
        self.live()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .journal
            .journal()
            .body(id)
            .is_some())
    }
    pub fn import_candidate(&mut self, header: Header, body: &[u8]) -> Result<JointCandidate> {
        self.live()?;
        let terminal = {
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            state.current.slot() > u64::from(state.binding.journal_genesis().profile.max_headers)
        };
        if terminal {
            self.poisoned = true;
            return Err(Error::ResourceLimit);
        }
        let mut uncertain = false;
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let parent = state
                .history
                .get(&state.current.slot())
                .ok_or(Error::Context)?
                .parent;
            let d = JointCandidate::for_context(&state.binding, &state.current, header.clone())?;
            let State {
                binding,
                journal,
                charge,
                verifier,
                current,
                ..
            } = &mut *state;
            require_candidate_context(binding, current, parent, &d)?;
            let old = parent_heads(binding, journal.journal(), parent)?;
            let before_disk = journal.disk_bytes();
            // Fresh even for a known candidate. The SAME State MutexGuard and
            // exclusive Journal borrow span proof checking, semantics, charge
            // and the argument-free commit; no second verifier call is needed.
            let pending = journal.prepare_append(header, body, crate::adapter::now()?, verifier)?;
            candidate_control(binding, old, body)?;
            let next = pending.next_disk_bytes();
            if next > before_disk {
                charge.grow(next).map_err(crate::Error::from)?;
                uncertain = true;
            }
            pending.commit()?;
            Ok(d)
        })();
        if result.is_err() && uncertain {
            self.poisoned = true;
            if let Ok(state) = self.state.lock() {
                state.charge.mark_io_failed();
            }
        }
        result
    }
    pub fn propose(&mut self, candidate: &JointCandidate) -> Result<Vec<Action>> {
        self.drive(Input::Propose(candidate.encode().to_vec()))
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.live()?;
        let input = Input::decode(self.voter.context(), bytes)?;
        self.drive(input)
    }
    pub fn receive_checkpoint(&mut self, checkpoint: &JointCheckpoint) -> Result<Vec<Action>> {
        self.live()?;
        if checkpoint.candidate().slot() != self.voter.context().slot() {
            // Only the last semantic decision is an idempotent retry. Reverify
            // actual proofs and the alternate QC even though nothing is appended.
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let context = state.last_context.as_ref().ok_or(Error::Context)?;
            let decision = context.verify_commit(
                &checkpoint.candidate().encode(),
                checkpoint.round(),
                checkpoint.certificate(),
            )?;
            let parent = state.finalized.as_ref().ok_or(Error::Context)?;
            let (head, control) = state.verify(context, decision.value())?;
            if decision.semantic_id() != parent.decision_id()
                || head != parent.head()
                || control != parent.control()
                || context.after_decision(&decision)?.id() != state.current.id()
            {
                return Err(Error::Context);
            }
            return Ok(Vec::new());
        }
        let decision = self.voter.context().verify_commit(
            &checkpoint.candidate().encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )?;
        self.drive(Input::Certificate {
            value: decision.value().to_vec(),
            certificate: decision.certificate().clone(),
        })
    }
    pub fn checkpoint_after(&mut self, slot: u64) -> Result<Option<JointCheckpoint>> {
        self.live()?;
        let latest = self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .current
            .slot()
            - 1;
        if slot >= latest {
            return Ok(None);
        }
        let result = self
            .floor
            .export(slot.checked_add(1).ok_or(Error::ResourceLimit)?)
            .map_err(Error::from)
            .and_then(|r| {
                JointCheckpoint::new(JointCandidate::decode(&r.value)?, r.round, r.certificate)
            });
        match result {
            Ok(record) => Ok(Some(record)),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }
    pub fn timeout(&self) -> Result<Timeout> {
        self.live()?;
        Ok(self.voter.timeout()?)
    }
    pub fn outbound(&self) -> Result<Vec<Action>> {
        self.live()?;
        Ok(self.voter.outbound()?)
    }
    pub fn on_timeout(&mut self, timeout: Timeout) -> Result<Vec<Action>> {
        self.drive(Input::Timeout(timeout))
    }
    fn drive(&mut self, input: Input) -> Result<Vec<Action>> {
        self.live()?;
        // &mut self excludes every other owner mutation. State and its Arc are
        // private; ingress can only add immutable depot blobs. Do not hold the
        // State mutex here: the actual application verifier locks it itself.
        let handoff = self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .handoff
            .clone();
        let capture = handoff.begin(self.voter.context().id())?;
        let finished = match self.voter.handle_for_finalization(input) {
            Ok((actions, Some(fresh))) => {
                match Self::synchronize_fresh(
                    &self.state,
                    &mut self.floor,
                    fresh,
                    &capture,
                    #[cfg(test)]
                    &mut self.poison_before_advance,
                ) {
                    Ok(()) => Ok(actions),
                    Err(error) => {
                        self.poisoned = true;
                        Err(error)
                    }
                }
            }
            Ok((actions, None)) => Ok(actions),
            Err(error) => Err(error.into()),
        };
        let actions = match finished {
            Ok(actions) => actions,
            Err(e) => {
                if self.voter.is_poisoned() {
                    self.poisoned = true;
                }
                return Err(e);
            }
        };
        drop(capture);
        if let Err(e) = self.synchronize() {
            self.poisoned = true;
            return Err(e);
        }
        Ok(actions)
    }
    fn synchronize_fresh(
        state: &Arc<Mutex<State>>,
        floor: &mut FloorLog,
        fresh: FreshDecision<'_, ClosedJointApplication>,
        capture: &DriveCapture<'_>,
        #[cfg(test)] poison_before_advance: &mut bool,
    ) -> Result<()> {
        let mut guard = state.lock().map_err(|_| Error::Poisoned)?;
        if guard.current.id() != fresh.context().id() {
            return Err(crate::Error::CorruptFloor.into());
        }
        // The capability came only from THIS owner's private voter and its
        // captured ClosedJointApplication. It is not accepted as an argument
        // from a client, checkpoint DTO, different owner or recovery path.
        let prepared = guard.preflight_checked(fresh.decision(), capture.take()?)?;
        floor.append(fresh.decision())?;
        prepared.install()?;
        drop(guard);
        #[cfg(test)]
        Self::inject_advance_refusal(state, poison_before_advance)?;
        // The floor was actually fsynced and installed above. Only this same
        // command's redundant signer application traversal is omitted.
        fresh.advance()?;
        Ok(())
    }
    #[cfg(test)]
    fn inject_advance_refusal(state: &Arc<Mutex<State>>, refuse: &mut bool) -> Result<()> {
        if std::mem::take(refuse) {
            state
                .lock()
                .map_err(|_| Error::Poisoned)?
                .charge
                .mark_io_failed();
        }
        Ok(())
    }
    fn synchronize(&mut self) -> Result<()> {
        if let Some(decision) = self.voter.decision() {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            if state.current.id() == self.voter.context().id() {
                install_current_decision(&mut state, &mut self.floor, decision)?;
            } else {
                let installed = state.finalized.as_ref().ok_or(crate::Error::CorruptFloor)?;
                if installed.slot() != self.voter.context().slot()
                    || installed.decision_id() != decision.semantic_id()
                    || state.current.id() != self.voter.context().after_decision(decision)?.id()
                {
                    return Err(crate::Error::CorruptFloor.into());
                }
                state.verify(self.voter.context(), decision.value())?;
            }
            drop(state); // advance invokes the SAME actual app, which locks State.
            #[cfg(test)]
            Self::inject_advance_refusal(&self.state, &mut self.poison_before_advance)?;
            self.voter.advance()?;
        }
        if self.state.lock().map_err(|_| Error::Poisoned)?.current.id() != self.voter.context().id()
        {
            return Err(crate::Error::CorruptFloor.into());
        }
        Ok(())
    }
    fn live(&self) -> Result<()> {
        if self.poisoned || self.voter.is_poisoned() {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
}
