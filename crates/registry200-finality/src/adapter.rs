use crate::{Binding, Descriptor, Error, Hash, Result, store::FloorLog};
use ed25519_dalek::SigningKey;
use protocol_storage::{ByteBudget, FileCharge};
use registry200_journal::RegistryVerifier;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use version_journal::{DurableJournal, HeadRef, Header};
use work_finality::consensus::{
    Action, ApplicationContext, ApplicationError, ApplicationVerifier, Context, Decision,
    DurableVoter, Input, Timeout,
};

#[cfg(test)]
mod tests;

/// Constructed only after actual application/QC checking and durable floor
/// installation. Copying this metadata does not itself prove current freshness.
/// No value exists before the first committed checkpoint; Genesis is separately
/// independently pinned. This is not a SQL/row-lock grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedHead {
    binding: Hash,
    slot: u64,
    decision: Hash,
    head: HeadRef,
}
impl FinalizedHead {
    pub fn binding_id(self) -> Hash {
        self.binding
    }
    pub fn slot(self) -> u64 {
        self.slot
    }
    pub fn decision_id(self) -> Hash {
        self.decision
    }
    pub fn head(self) -> HeadRef {
        self.head
    }
}

struct Historical {
    context: Hash,
    parent: HeadRef,
}
struct State {
    binding: Binding,
    journal: DurableJournal,
    journal_charge: FileCharge,
    verifier: RegistryVerifier,
    history: BTreeMap<u64, Historical>,
    current: Context,
    finalized: Option<FinalizedHead>,
}
impl State {
    fn new(binding: Binding, journal: DurableJournal, journal_charge: FileCharge) -> Result<Self> {
        let verifier = RegistryVerifier::new(binding.application()?, binding.journal_genesis())?;
        let current = binding.initial_context().clone();
        let mut history = BTreeMap::new();
        history.insert(
            1,
            Historical {
                context: current.id(),
                parent: journal.journal().genesis_head(),
            },
        );
        Ok(Self {
            binding,
            journal,
            journal_charge,
            verifier,
            history,
            current,
            finalized: None,
        })
    }
    fn verify(&self, context: &Context, value: &[u8]) -> Result<HeadRef> {
        let d = Descriptor::decode(value)?;
        let h = self
            .history
            .get(&context.slot())
            .ok_or(Error::WrongContext)?;
        if context.id() != h.context {
            return Err(Error::WrongContext);
        }
        // No serialized receipt, cached validation bit, owner signature alone or
        // generic callback can replace the original concrete proof verifier.
        let body = self
            .journal
            .journal()
            .body(d.header.id())
            .ok_or(Error::MissingCandidate)?;
        let head = verify_candidate(
            &self.binding,
            self.journal.journal(),
            &self.verifier,
            context,
            h.parent,
            &d,
            body,
        )?;
        self.journal.journal().validated_shards(head)?;
        Ok(head)
    }
    fn install(&mut self, decision: &Decision) -> Result<()> {
        if decision.context_id() != self.current.id() {
            return Err(Error::WrongContext);
        }
        let head = self.verify(&self.current, decision.value())?;
        let next = self.current.after_decision(decision)?;
        if self.history.len() > self.binding.journal_genesis().profile.max_headers as usize {
            return Err(Error::ResourceLimit);
        }
        self.journal.restrict_ancestry_floor(head)?;
        self.finalized = Some(FinalizedHead {
            binding: self.binding.id(),
            slot: self.current.slot(),
            decision: decision.semantic_id(),
            head,
        });
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
struct ClosedApplication(Arc<Mutex<State>>);
impl ApplicationVerifier for ClosedApplication {
    fn verify(
        &self,
        ctx: &ApplicationContext<'_>,
        value: &[u8],
    ) -> std::result::Result<(), ApplicationError> {
        let state = self.0.lock().map_err(|_| ApplicationError)?;
        state
            .verify(ctx.consensus(), value)
            .map(|_| ())
            .map_err(|_| ApplicationError)
    }
}

/// Exclusive local owner of real journal, floor log and signer. Every public
/// installation path is closed to the original RegistryVerifier. There is no
/// generic verifier constructor, mutable journal/key getter or supplied NextContext.
///
/// ```compile_fail
/// fn key(x: &registry200_finality::RegistryFinality) { let _ = &x.voter.key; }
/// ```
/// ```compile_fail
/// fn copy(x: &registry200_finality::RegistryFinality) { let _: registry200_finality::RegistryFinality = x.clone(); }
/// ```
/// ```compile_fail
/// fn debug(x: &registry200_finality::RegistryFinality) { let _ = format!("{x:?}"); }
/// ```
pub struct RegistryFinality {
    state: Arc<Mutex<State>>,
    floor: FloorLog,
    voter: DurableVoter<ClosedApplication>,
    poisoned: bool,
}
impl RegistryFinality {
    /// Explicit NEW installation in an existing caller-owned directory. Partial
    /// initialization is left intact on failure; never use this to recover.
    pub fn create_new(
        directory: &Path,
        binding: Binding,
        key: SigningKey,
        budget: &ByteBudget,
    ) -> Result<Self> {
        let directory = directory.canonicalize()?;
        let journal_path = directory.join("registry-finality-journal-v1");
        let floor_path = directory.join("registry-finality-floor-v1");
        let voter_path = directory.join("registry-finality-signer-v1");
        // Initial Journal writes occur under a real transient reservation; its
        // persistent exact file charge replaces this before signer creation.
        let initial_bytes = 76u64
            .checked_add(binding.journal_genesis().encode()?.len() as u64)
            .ok_or(Error::ResourceLimit)?;
        let mut initial = budget.reserve(initial_bytes)?;
        let journal = match DurableJournal::create(
            &journal_path,
            binding.journal_genesis().clone(),
            binding.namespace(),
        ) {
            Ok(journal) => journal,
            Err(error) => {
                initial.retain_conservatively();
                return Err(error.into());
            }
        };
        let journal_charge = match initial.retain_file(&journal_path) {
            Ok(charge) => charge,
            Err(error) => {
                initial.retain_conservatively();
                return Err(error.into());
            }
        };
        let floor = FloorLog::create(&floor_path, &binding, budget)?;
        let context = binding.initial_context().clone();
        let state = Arc::new(Mutex::new(State::new(binding, journal, journal_charge)?));
        let voter = DurableVoter::create_new(
            voter_path,
            context,
            ClosedApplication(state.clone()),
            key,
            budget,
        )?;
        Ok(Self {
            state,
            floor,
            voter,
            poisoned: false,
        })
    }
    /// Open ONLY existing files, with independent pins and a new complete shared
    /// budget on process restart. Journal and floor certificates are fully
    /// reverified before the signer WAL replays. No missing/corrupt-file fallback.
    pub fn open_existing(
        directory: &Path,
        binding: Binding,
        key: SigningKey,
        budget: &ByteBudget,
    ) -> Result<Self> {
        let directory = directory.canonicalize()?;
        let journal_path = directory.join("registry-finality-journal-v1");
        let verifier = RegistryVerifier::new(binding.application()?, binding.journal_genesis())?;
        let journal = DurableJournal::open(
            &journal_path,
            binding.journal_genesis().clone(),
            binding.namespace(),
            now()?,
            &verifier,
        )?;
        let journal_charge = budget.register_file(&journal_path)?;
        let mut floor = FloorLog::open(
            &directory.join("registry-finality-floor-v1"),
            &binding,
            budget,
        )?;
        let initial = binding.initial_context().clone();
        let mut state = State::new(binding, journal, journal_charge)?;
        while let Some(record) = floor.next()? {
            let decision =
                state
                    .current
                    .verify_commit(&record.value, record.round, &record.certificate)?;
            state.install(&decision)?;
        }
        let state = Arc::new(Mutex::new(state));
        let voter = DurableVoter::open_existing(
            directory.join("registry-finality-signer-v1"),
            initial,
            ClosedApplication(state.clone()),
            key,
            budget,
        )?;
        let mut owned = Self {
            state,
            floor,
            voter,
            poisoned: false,
        };
        owned.synchronize()?;
        Ok(owned)
    }
    pub fn context(&self) -> &Context {
        self.voter.context()
    }
    pub fn binding(&self) -> Result<Binding> {
        self.live()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .binding
            .clone())
    }
    /// One original retained block. This public DTO carries no verification bit.
    pub fn candidate_block(&self, id: Hash) -> Result<crate::CandidateBlock> {
        self.live()?;
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let journal = state.journal.journal();
        let header = journal.header(id).ok_or(Error::MissingCandidate)?.clone();
        let body = journal.body(id).ok_or(Error::MissingCandidate)?.to_vec();
        crate::CandidateBlock::new(header, body)
    }
    /// Availability only; neither cached presence nor this boolean authorizes a
    /// vote. Every proposal/commit still invokes the original proof verifier.
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
    /// Sequential remote catch-up, through the same durable signer/application
    /// path. The caller cannot supply a next context or finalized-head marker.
    pub fn receive_checkpoint(&mut self, checkpoint: &crate::Checkpoint) -> Result<Vec<Action>> {
        self.live()?;
        let decision = self.context().verify_commit(
            &checkpoint.descriptor().encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )?;
        self.drive(Input::Certificate {
            value: decision.value().to_vec(),
            certificate: decision.certificate().clone(),
        })
    }
    /// Exactly one persisted commit for sequential catch-up. Export rechecks the
    /// actual chained file bytes; the recipient still verifies application + QC.
    pub fn checkpoint_after(&mut self, slot: u64) -> Result<Option<crate::Checkpoint>> {
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
            .and_then(|r| {
                crate::Checkpoint::new(Descriptor::decode(&r.value)?, r.round, r.certificate)
            });
        match result {
            Ok(record) => Ok(Some(record)),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    pub fn finalized_head(&self) -> Result<Option<FinalizedHead>> {
        self.live()?;
        Ok(self.state.lock().map_err(|_| Error::Poisoned)?.finalized)
    }
    pub fn timeout(&self) -> Result<Timeout> {
        self.live()?;
        Ok(self.voter.timeout()?)
    }
    pub fn outbound(&self) -> Result<Vec<Action>> {
        self.live()?;
        Ok(self.voter.outbound()?)
    }

    /// Bounded actual body/header import, always including repeat authentication
    /// and genuine Source/Lifecycle proof verification before a descriptor exists.
    /// Storage is public ciphertext/proof material, never private openings.
    pub fn import_candidate(&mut self, header: Header, body: &[u8]) -> Result<Descriptor> {
        self.live()?;
        let mut uncertain_extent = false;
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let parent = state
                .history
                .get(&state.current.slot())
                .ok_or(Error::WrongContext)?
                .parent;
            if header.parent != parent.block {
                return Err(Error::WrongContext);
            }
            state
                .journal
                .journal()
                .reverify_block(&header, body, now()?, &state.verifier)?;
            if state.journal.journal().body(header.id()).is_none() {
                let added = (4 + version_journal::HEADER_BYTES + 32) as u64;
                let next = state
                    .journal
                    .disk_bytes()
                    .checked_add(added)
                    .and_then(|n| n.checked_add(body.len() as u64))
                    .ok_or(Error::ResourceLimit)?;
                state.journal_charge.grow(next)?;
                uncertain_extent = true;
            }
            let State {
                journal, verifier, ..
            } = &mut *state;
            journal.append_block(header.clone(), body, now()?, verifier)?;
            Ok(Descriptor::for_context(
                &state.binding,
                &state.current,
                header,
            ))
        })();
        // Invalid remote mathematics/context makes no local signing mutation.
        // A conservative precharge followed by a failed append is different:
        // physical extent may be uncertain, so close and require strict reopen.
        if result.is_err() && uncertain_extent {
            self.poisoned = true;
        }
        result
    }
    pub fn propose(&mut self, descriptor: &Descriptor) -> Result<Vec<Action>> {
        self.drive(Input::Propose(descriptor.encode().to_vec()))
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.live()?;
        let input = Input::decode(self.voter.context(), bytes)?;
        self.drive(input)
    }
    /// Only the clock owner may supply its actual elapsed active timer. Timeout
    /// remains a local control; remote Input decoding cannot deliver one.
    pub fn on_timeout(&mut self, timeout: Timeout) -> Result<Vec<Action>> {
        self.drive(Input::Timeout(timeout))
    }
    fn drive(&mut self, input: Input) -> Result<Vec<Action>> {
        self.live()?;
        let actions = match self.voter.handle(input) {
            Ok(actions) => actions,
            Err(error) => {
                if self.voter.is_poisoned() {
                    self.poisoned = true;
                }
                return Err(error.into());
            }
        };
        if let Err(error) = self.synchronize() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(actions)
    }
    fn synchronize(&mut self) -> Result<()> {
        if let Some(decision) = self.voter.decision() {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            if state.current.id() == self.voter.context().id() {
                // WAL decision is durable already. Recheck actual application and
                // certificate, then fsync floor BEFORE branch adoption/next slot.
                state.verify(self.voter.context(), decision.value())?;
                self.voter.context().after_decision(decision)?;
                self.floor.append(decision)?;
                state.install(decision)?;
            } else {
                let installed = state.finalized.ok_or(Error::CorruptFloor)?;
                if installed.slot != self.voter.context().slot()
                    || installed.decision != decision.semantic_id()
                    || state.current.id() != self.voter.context().after_decision(decision)?.id()
                {
                    return Err(Error::CorruptFloor);
                }
                state.verify(self.voter.context(), decision.value())?;
            }
            drop(state); // Application verification in advance acquires this lock.
            self.voter.advance()?;
        }
        if self.state.lock().map_err(|_| Error::Poisoned)?.current.id() != self.voter.context().id()
        {
            return Err(Error::CorruptFloor);
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
pub(crate) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::WrongContext)
}

// Shared concrete application relation, not a callback or an externally minted
// accepting token. Signer and keyless follower use identical actual checks.
pub(crate) fn verify_candidate(
    binding: &Binding,
    journal: &version_journal::Journal,
    verifier: &RegistryVerifier,
    context: &Context,
    parent: HeadRef,
    d: &Descriptor,
    body: &[u8],
) -> Result<HeadRef> {
    if d.binding != binding.id()
        || d.slot != context.slot()
        || d.previous != context.previous_decision()
        || d.header.parent != parent.block
        || d.header.genesis != parent.genesis
        || d.header.height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
    {
        return Err(Error::WrongContext);
    }
    journal.reverify_block(&d.header, body, now()?, verifier)?;
    Ok(HeadRef {
        genesis: d.header.genesis,
        database: binding.journal_genesis().database,
        block: d.header.id(),
        height: d.header.height,
        state_root: d.header.state_root,
    })
}
