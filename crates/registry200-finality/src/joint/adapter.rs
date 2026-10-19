//! Concrete durable Joint owner. No supplied verifier, journal, key getter or
//! successor exists. All evidence must already be local in the SAME depot.
use super::history::verify_candidate;
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
    DurableVoter, Input, Timeout,
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
struct State {
    binding: JointBinding,
    journal: DurableJournal,
    charge: FileCharge,
    verifier: JointVerifier,
    history: BTreeMap<u64, Historical>,
    current: Context,
    last_context: Option<Context>,
    finalized: Option<VerifiedJointParent>,
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
        Ok((head, control))
    }
    fn preflight(&self, decision: &Decision) -> Result<(HeadRef, Control, Context)> {
        if decision.context_id() != self.current.id() {
            return Err(Error::Context);
        }
        let (head, control) = self.verify(&self.current, decision.value())?;
        let next = self.current.after_decision(decision)?;
        // Initial slot plus each successor is retained for actual WAL replay.
        // len == max_headers is the LAST admissible decision, not exhaustion.
        if self.history.len() > self.binding.journal_genesis().profile.max_headers as usize {
            return Err(Error::ResourceLimit);
        }
        Ok((head, control, next))
    }
    fn install(&mut self, decision: &Decision) -> Result<()> {
        let (head, control, next) = self.preflight(decision)?;
        self.journal.restrict_ancestry_floor(head)?;
        self.finalized = Some(VerifiedJointParent::checked(
            &self.binding,
            head,
            self.current.slot(),
            decision.semantic_id(),
            control,
        ));
        self.last_context = Some(self.current.clone());
        self.history.insert(
            next.slot(),
            Historical {
                context: next.id(),
                parent: head,
            },
        );
        self.current = next;
        Ok(())
    }
}

#[derive(Clone)]
struct ClosedJointApplication(Arc<Mutex<State>>);
impl ApplicationVerifier for ClosedJointApplication {
    fn verify(
        &self,
        context: &ApplicationContext<'_>,
        value: &[u8],
    ) -> core::result::Result<(), ApplicationError> {
        self.0
            .lock()
            .map_err(|_| ApplicationError)?
            .verify(context.consensus(), value)
            .map(|_| ())
            .map_err(|_| ApplicationError)
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
            verify_candidate(
                &state.binding,
                state.journal.journal(),
                &state.verifier,
                &state.current,
                parent,
                &d,
                body,
            )?;
            if state.journal.journal().body(header.id()).is_none() {
                let next = state
                    .journal
                    .disk_bytes()
                    .checked_add((4 + version_journal::HEADER_BYTES + 32) as u64)
                    .and_then(|n| n.checked_add(body.len() as u64))
                    .ok_or(Error::ResourceLimit)?;
                state.charge.grow(next).map_err(crate::Error::from)?;
                uncertain = true;
            }
            let State {
                journal, verifier, ..
            } = &mut *state;
            journal.append_block(header, body, crate::adapter::now()?, verifier)?;
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
        let actions = match self.voter.handle(input) {
            Ok(actions) => actions,
            Err(e) => {
                if self.voter.is_poisoned() {
                    self.poisoned = true;
                }
                return Err(e.into());
            }
        };
        if let Err(e) = self.synchronize() {
            self.poisoned = true;
            return Err(e);
        }
        Ok(actions)
    }
    fn synchronize(&mut self) -> Result<()> {
        if let Some(decision) = self.voter.decision() {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            if state.current.id() == self.voter.context().id() {
                // All fallible protocol/cap checks BEFORE durable floor append.
                state.preflight(decision)?;
                self.floor.append(decision)?;
                state.install(decision)?;
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
            if std::mem::take(&mut self.poison_before_advance) {
                self.state
                    .lock()
                    .map_err(|_| Error::Poisoned)?
                    .charge
                    .mark_io_failed();
            }
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
