//! One private durable engine for three closed proof applications.
//! All State/Arc and floor capabilities stay private to this synchronous owner.
use crate::joint::{Error, Hash, Result};
use crate::public_timings::{Family, Kind, Scope, Section, Stage};
use crate::{
    CandidateBlock,
    participant::{self, Paths},
    pins::Pins,
    store::FloorLog,
};
use ed25519_dalek::SigningKey;
use protocol_storage::{FileCharge, ParticipantQuota};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use version_journal::{DurableJournal, HeadRef, Header};
use work_finality::consensus::{
    Action, ApplicationContext, ApplicationError, ApplicationVerifier, Context, Decision,
    DurableVoter, FreshDecision, Input, Timeout,
};
mod application;
use application::InstalledApplication;
pub(crate) use application::{Ingress, Installation};
/// Distinct mathematical state families. No old control is reinterpreted as Word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApplicationControl {
    Registry(registry200_journal::Control),
    Word(registry200_joint::word::Control),
}
impl ApplicationControl {
    pub(crate) fn registry(self) -> Result<registry200_journal::Control> {
        match self {
            Self::Registry(v) => Ok(v),
            Self::Word(_) => Err(Error::Binding),
        }
    }
    pub(crate) fn word(self) -> Result<registry200_joint::word::Control> {
        match self {
            Self::Word(v) => Ok(v),
            Self::Registry(_) => Err(Error::Binding),
        }
    }
}
const _: [(); crate::DESCRIPTOR_BYTES] = [(); crate::joint::CANDIDATE_BYTES];
const _: [(); crate::DESCRIPTOR_BYTES] = [(); crate::progress::CANDIDATE_BYTES];
const _: [(); crate::DESCRIPTOR_BYTES] = [(); crate::word::CANDIDATE_BYTES];

#[cfg(test)]
#[path = "joint/durable_tests.rs"]
mod tests;
#[cfg(test)]
use crate::joint::{
    DurableJointFinality, JointBinding, JointCandidate, JointCheckpoint, durable_profile_digest,
};
#[cfg(test)]
use registry200_joint::JointDepot;
#[cfg(test)]
#[path = "progress/durable_tests.rs"]
mod progress_tests;

// Bounded untrusted floor export, never application/QC authority.
pub(crate) struct ExportedCheckpoint {
    pub(crate) value: [u8; crate::DESCRIPTOR_BYTES],
    pub(crate) round: u64,
    pub(crate) certificate: Vec<u8>,
}
#[derive(Clone, Copy)]
pub(crate) struct Finalized {
    head: HeadRef,
    slot: u64,
    decision: Hash,
    control: ApplicationControl,
}
impl Finalized {
    pub(crate) fn head(&self) -> HeadRef {
        self.head
    }
    pub(crate) fn slot(&self) -> u64 {
        self.slot
    }
    pub(crate) fn decision_id(&self) -> Hash {
        self.decision
    }
    pub(crate) fn control(&self) -> ApplicationControl {
        self.control
    }
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
    candidate: [u8; crate::DESCRIPTOR_BYTES],
    parent: HeadRef,
    floor: HeadRef,
    head: HeadRef,
    control: ApplicationControl,
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
    application: InstalledApplication,
    journal: DurableJournal,
    charge: FileCharge,
    history: BTreeMap<u64, Historical>,
    current: Context,
    last_context: Option<Context>,
    finalized: Option<Finalized>,
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
    control: ApplicationControl,
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
        state.finalized = Some(Finalized {
            head,
            slot: state.current.slot(),
            decision: decision.semantic_id(),
            control,
        });
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
// Fixed observational wrapper: exactly one unchanged genuine delegate. It is
// private and receives only this closed engine's already-installed application.
struct TimedImport<'a>(&'a InstalledApplication);
impl version_journal::TransitionVerifier for TimedImport<'_> {
    fn verify(
        &self,
        statement: version_journal::TransitionStatement<'_>,
    ) -> version_journal::Result<()> {
        let _timing = Section::new(Stage::Application);
        version_journal::TransitionVerifier::verify(self.0, statement)
    }
}
impl State {
    fn new(application: InstalledApplication, journal: DurableJournal, charge: FileCharge) -> Self {
        let current = application.binding().initial_context().clone();
        let mut history = BTreeMap::new();
        history.insert(
            1,
            Historical {
                context: current.id(),
                parent: journal.journal().genesis_head(),
            },
        );
        Self {
            application,
            journal,
            charge,
            history,
            current,
            last_context: None,
            finalized: None,
            handoff: Arc::new(DriveHandoff::default()),
            #[cfg(test)]
            completed_application_checks: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn verify(&self, context: &Context, value: &[u8]) -> Result<(HeadRef, ApplicationControl)> {
        if context.slot()
            > u64::from(
                self.application
                    .binding()
                    .journal_genesis()
                    .profile
                    .max_headers,
            )
        {
            return Err(Error::ResourceLimit);
        }
        let d = self.application.binding().decode(value)?;
        let h = self.history.get(&context.slot()).ok_or(Error::Context)?;
        if context.id() != h.context {
            return Err(Error::Context);
        }
        let body = self
            .journal
            .journal()
            .body(d.header.id())
            .ok_or(crate::Error::MissingCandidate)?;
        let control = {
            let _timing = Section::new(Stage::Application);
            self.application.verify_candidate(
                self.journal.journal(),
                context,
                h.parent,
                &d,
                body,
            )?
        };
        let head = HeadRef {
            genesis: d.header.genesis,
            database: self.application.binding().journal_genesis().database,
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
            || checked.binding != self.application.binding().id()
            || checked.context != self.current.id()
            || decision.context_id() != self.current.id()
            || decision.value() != checked.candidate.as_slice()
            || checked.floor != self.journal.journal().ancestry_floor()
        {
            return Err(Error::Context);
        }
        drop(registered);
        let d = self.application.binding().decode(decision.value())?;
        let historical = self
            .history
            .get(&self.current.slot())
            .ok_or(Error::Context)?;
        if historical.context != self.current.id() || historical.parent != checked.parent {
            return Err(Error::Context);
        }
        self.application
            .binding()
            .require_context(&self.current, checked.parent, &d)?;
        let journal = self.journal.journal();
        if journal.header(checked.head.block) != Some(&d.header)
            || checked.head
                != (HeadRef {
                    genesis: d.header.genesis,
                    database: self.application.binding().journal_genesis().database,
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
        let old = self
            .application
            .binding()
            .parent_heads(journal, checked.parent)?;
        if self.application.binding().candidate_control(old, body)? != checked.control {
            return Err(Error::Context);
        }
        journal.validated_shards(checked.head)?;
        self.prepare_finalization(decision, checked.head, checked.control)
    }
    fn prepare_finalization<'state, 'decision>(
        &'state mut self,
        decision: &'decision Decision,
        head: HeadRef,
        control: ApplicationControl,
    ) -> Result<PreparedFinalization<'state, 'decision>> {
        let next = self.current.after_decision(decision)?;
        // Initial slot plus each successor is retained for actual WAL replay.
        // len == max_headers is the LAST admissible decision, not exhaustion.
        if self.history.len()
            > self
                .application
                .binding()
                .journal_genesis()
                .profile
                .max_headers as usize
        {
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
    let prepared = {
        let _timing = Section::new(Stage::Preflight);
        state.preflight(decision)?
    };
    {
        let _timing = Section::new(Stage::FloorAppend);
        floor.append(decision)?;
    }
    let _timing = Section::new(Stage::Install);
    prepared.install()
}

#[derive(Clone)]
struct ClosedApplication(Arc<Mutex<State>>);
impl ApplicationVerifier for ClosedApplication {
    fn verify(
        &self,
        context: &ApplicationContext<'_>,
        value: &[u8],
    ) -> core::result::Result<(), ApplicationError> {
        self.check(context.consensus(), value)
            .map_err(|_| ApplicationError)
    }
}
impl ClosedApplication {
    fn check(&self, context: &Context, value: &[u8]) -> Result<()> {
        let state = {
            let _timing = Section::new(Stage::StateWait);
            self.0.lock().map_err(|_| Error::Poisoned)?
        };
        // Never look up a prior result. The fixed verifier runs in full before
        // depositing metadata for this drive's possible floor finalization.
        let (head, control) = state.verify(context, value)?;
        let candidate = state.application.binding().decode(value)?;
        let parent = state
            .history
            .get(&context.slot())
            .ok_or(Error::Context)?
            .parent;
        state.handoff.record(CheckedApplication {
            binding: state.application.binding().id(),
            context: context.id(),
            candidate: candidate.encode(),
            parent,
            floor: state.journal.journal().ancestry_floor(),
            head,
            control,
        })
    }
}

pub(crate) struct DurableEngine {
    state: Arc<Mutex<State>>,
    floor: FloorLog,
    voter: DurableVoter<ClosedApplication>,
    poisoned: bool,
    _metadata: FileCharge,
    pub(crate) ingress: Ingress,
    #[cfg(test)]
    poison_before_advance: bool,
}
impl DurableEngine {
    #[cfg(test)]
    pub(crate) fn inject_floor_fault_for_test(&mut self, fault: crate::store::Fault) {
        self.floor.inject(fault);
    }
    /// NEW-only participant installation. Setup and every future proof premise
    /// use the participant's one concrete typed depot and shared ledger.
    pub(crate) fn create_participant(
        quota: &ParticipantQuota,
        installation: Installation,
        key: SigningKey,
    ) -> Result<Self> {
        let binding = installation.binding();
        binding.require_durable()?;
        let signer = key.verifying_key().to_bytes();
        let paths = Paths::participant(quota, binding.pins(), signer);
        let budget = quota.control_budget();
        let marker = paths.metadata.as_ref().ok_or(Error::Binding)?;
        // Check existing marker BEFORE touching any signer file; publish LAST.
        let metadata_permit = budget
            .preflight_file(marker, participant::META_BYTES as u64)
            .map_err(crate::Error::from)?;
        let (application, ingress) = installation.open(quota)?;
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
        let floor = FloorLog::create(&paths.floor, binding.pins(), &budget)?;
        let context = binding.initial_context().clone();
        let state = Arc::new(Mutex::new(State::new(application, journal, charge)));
        let voter = DurableVoter::create_new(
            &paths.wal,
            context,
            ClosedApplication(state.clone()),
            key,
            &budget,
        )?;
        let metadata = participant::install(metadata_permit, binding.pins(), signer)?;
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
    pub(crate) fn open_participant(
        quota: &ParticipantQuota,
        installation: Installation,
        key: SigningKey,
    ) -> Result<Self> {
        let binding = installation.binding();
        binding.require_durable()?;
        let paths = Paths::participant(quota, binding.pins(), key.verifying_key().to_bytes());
        let budget = quota.control_budget();
        let metadata = participant::open(
            paths.metadata.as_ref().ok_or(Error::Binding)?,
            binding.pins(),
            key.verifying_key().to_bytes(),
            &budget,
        )?;
        let (application, ingress) = installation.open(quota)?;
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
            &application,
        )
        .map_err(|e| {
            charge.mark_io_failed();
            Error::from(e)
        })?;
        let mut floor = FloorLog::open(&paths.floor, binding.pins(), &budget)?;
        let initial = binding.initial_context().clone();
        let mut state = State::new(application, journal, charge);
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
            ClosedApplication(state.clone()),
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
    pub(crate) fn context(&self) -> Result<&Context> {
        self.live()?;
        Ok(self.voter.context())
    }
    pub(crate) fn binding_id(&self) -> Result<Hash> {
        self.live()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .application
            .binding()
            .id())
    }
    pub(crate) fn finalized_parent(&self) -> Result<Option<Finalized>> {
        self.live()?;
        Ok(self.state.lock().map_err(|_| Error::Poisoned)?.finalized)
    }
    /// Bounded untrusted DTO export; not a proof-validation receipt.
    pub(crate) fn candidate_block(&self, id: Hash) -> Result<CandidateBlock> {
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
    pub(crate) fn has_candidate(&self, id: Hash) -> Result<bool> {
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
    pub(crate) fn restore_word_transport(
        &self,
        header: Header,
        compact: Vec<u8>,
    ) -> Result<CandidateBlock> {
        self.live()?;
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let parent = state
            .history
            .get(&state.current.slot())
            .ok_or(Error::Context)?
            .parent;
        let binding = state.application.binding();
        let candidate = binding.candidate(&state.current, header.clone())?;
        binding.require_context(&state.current, parent, &candidate)?;
        // No I/O, native proof, signer, durable write or retained result here.
        state.application.restore_word_transport(header, compact)
    }
    pub(crate) fn import_candidate(
        &mut self,
        header: Header,
        body: &[u8],
    ) -> Result<[u8; crate::DESCRIPTOR_BYTES]> {
        self.live()?;
        let _timing = Scope::new(
            match &self.ingress {
                Ingress::Progress(_) => Some(Family::Progress),
                Ingress::Word => Some(Family::Word),
                Ingress::Joint(_) => None,
            },
            Kind::Import,
            self.voter.context().slot(),
        );
        let terminal = {
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            state.current.slot()
                > u64::from(
                    state
                        .application
                        .binding()
                        .journal_genesis()
                        .profile
                        .max_headers,
                )
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
            let d = state
                .application
                .binding()
                .candidate(&state.current, header.clone())?;
            let State {
                application,
                journal,
                charge,
                current,
                ..
            } = &mut *state;
            let binding = application.binding();
            binding.require_context(current, parent, &d)?;
            let old = binding.parent_heads(journal.journal(), parent)?;
            let before_disk = journal.disk_bytes();
            // Fresh even for a known candidate. The SAME State MutexGuard and
            // exclusive Journal borrow span proof checking, semantics, charge
            // and the argument-free commit; no second verifier call is needed.
            let pending = {
                let _timing = Section::new(Stage::ImportPrepare);
                journal.prepare_append(
                    header,
                    body,
                    crate::adapter::now()?,
                    &TimedImport(&*application),
                )?
            };
            binding.candidate_control(old, body)?;
            let next = pending.next_disk_bytes();
            if next > before_disk {
                {
                    let _timing = Section::new(Stage::ImportCharge);
                    charge.grow(next).map_err(crate::Error::from)?;
                }
                uncertain = true;
            }
            {
                let _timing = Section::new(Stage::ImportCommit);
                pending.commit()?;
            }
            Ok(d.encode())
        })();
        if result.is_err() && uncertain {
            self.poisoned = true;
            if let Ok(state) = self.state.lock() {
                state.charge.mark_io_failed();
            }
        }
        result
    }
    pub(crate) fn propose(&mut self, value: &[u8]) -> Result<Vec<Action>> {
        self.drive(Input::Propose(value.to_vec()))
    }
    pub(crate) fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.live()?;
        let input = Input::decode(self.voter.context(), bytes)?;
        self.drive(input)
    }
    pub(crate) fn receive_checkpoint(
        &mut self,
        value: &[u8],
        round: u64,
        certificate: &[u8],
    ) -> Result<Vec<Action>> {
        self.live()?;
        let candidate = self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .application
            .binding()
            .decode(value)?;
        let _timing = Scope::new(
            match &self.ingress {
                Ingress::Progress(_) => Some(Family::Progress),
                Ingress::Word => Some(Family::Word),
                Ingress::Joint(_) => None,
            },
            Kind::Checkpoint,
            candidate.slot,
        );
        if candidate.slot != self.voter.context().slot() {
            // Only the last semantic decision is an idempotent retry. Reverify
            // actual proofs and the alternate QC even though nothing is appended.
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let context = state.last_context.as_ref().ok_or(Error::Context)?;
            let decision = context.verify_commit(value, round, certificate)?;
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
        let decision = self
            .voter
            .context()
            .verify_commit(value, round, certificate)?;
        self.drive(Input::Certificate {
            value: decision.value().to_vec(),
            certificate: decision.certificate().clone(),
        })
    }
    pub(crate) fn checkpoint_after(&mut self, slot: u64) -> Result<Option<ExportedCheckpoint>> {
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
                self.state
                    .lock()
                    .map_err(|_| Error::Poisoned)?
                    .application
                    .binding()
                    .decode(&r.value)?;
                Ok(ExportedCheckpoint {
                    value: r.value,
                    round: r.round,
                    certificate: r.certificate,
                })
            });
        match result {
            Ok(record) => Ok(Some(record)),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }
    pub(crate) fn timeout(&self) -> Result<Timeout> {
        self.live()?;
        Ok(self.voter.timeout()?)
    }
    pub(crate) fn outbound(&self) -> Result<Vec<Action>> {
        self.live()?;
        Ok(self.voter.outbound()?)
    }
    pub(crate) fn on_timeout(&mut self, timeout: Timeout) -> Result<Vec<Action>> {
        self.drive(Input::Timeout(timeout))
    }
    fn drive(&mut self, input: Input) -> Result<Vec<Action>> {
        self.live()?;
        let kind = match &input {
            Input::Propose(_) => Kind::Propose,
            Input::Proposal(_) => Kind::Proposal,
            Input::Vote(_) => Kind::Vote,
            Input::Certificate { .. } => Kind::Certificate,
            Input::Timeout(_) => Kind::Timeout,
        };
        let _timing = Scope::new(
            match &self.ingress {
                Ingress::Progress(_) => Some(Family::Progress),
                Ingress::Word => Some(Family::Word),
                Ingress::Joint(_) => None,
            },
            kind,
            self.voter.context().slot(),
        );
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
        let handled = {
            let _timing = Section::new(Stage::HandleWal);
            self.voter.handle_for_finalization(input)
        };
        let finished = match handled {
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
        let synchronized = {
            let _timing = Section::new(Stage::Synchronize);
            self.synchronize()
        };
        if let Err(e) = synchronized {
            self.poisoned = true;
            return Err(e);
        }
        Ok(actions)
    }
    fn synchronize_fresh(
        state: &Arc<Mutex<State>>,
        floor: &mut FloorLog,
        fresh: FreshDecision<'_, ClosedApplication>,
        capture: &DriveCapture<'_>,
        #[cfg(test)] poison_before_advance: &mut bool,
    ) -> Result<()> {
        let mut guard = {
            let _timing = Section::new(Stage::StateWait);
            state.lock().map_err(|_| Error::Poisoned)?
        };
        if guard.current.id() != fresh.context().id() {
            return Err(crate::Error::CorruptFloor.into());
        }
        // The capability came only from THIS owner's private voter and its
        // captured ClosedApplication. It is not accepted as an argument
        // from a client, checkpoint DTO, different owner or recovery path.
        let prepared = {
            let _timing = Section::new(Stage::Preflight);
            guard.preflight_checked(fresh.decision(), capture.take()?)?
        };
        {
            let _timing = Section::new(Stage::FloorAppend);
            floor.append(fresh.decision())?;
        }
        {
            let _timing = Section::new(Stage::Install);
            prepared.install()?;
        }
        drop(guard);
        #[cfg(test)]
        Self::inject_advance_refusal(state, poison_before_advance)?;
        // The floor was actually fsynced and installed above. Only this same
        // command's redundant signer application traversal is omitted.
        {
            let _timing = Section::new(Stage::Advance);
            fresh.advance()?;
        }
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
            {
                let _timing = Section::new(Stage::Advance);
                self.voter.advance()?;
            }
        }
        if self.state.lock().map_err(|_| Error::Poisoned)?.current.id() != self.voter.context().id()
        {
            return Err(crate::Error::CorruptFloor.into());
        }
        Ok(())
    }
    pub(crate) fn live(&self) -> Result<()> {
        if self.poisoned || self.voter.is_poisoned() {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
}
