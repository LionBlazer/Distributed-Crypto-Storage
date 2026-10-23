//! Word participant with no mutable Journal, accepting callback or signer export.
use super::{Binding, Candidate, Checkpoint, Error, Hash, Result};
use crate::{
    closed::{DurableEngine, Installation},
    digest, participant,
};
use ed25519_dalek::SigningKey;
use protocol_storage::ParticipantQuota;
use registry200_joint::word::Control;
use version_journal::{HeadRef, Header};
use work_finality::consensus::{Action, Context, Timeout};
pub fn participant_storage_profile_digest() -> Hash {
    digest(
        b"dcs/registry200-finality/word-participant-storage/v1",
        &[
            &super::profile_digest(),
            &protocol_storage::participant_profile_digest(),
            b"new-four-files/metadata-last/binding-source-signer/full-Word-replay/no-adoption",
            &(participant::META_BYTES as u64).to_le_bytes(),
        ],
    )
}
/// Historical fully checked Word/QC metadata. This is not a current SQL lock lease.
/// ```compile_fail
/// fn cast(x:registry200_finality::progress::VerifiedParent)->registry200_finality::word::VerifiedParent { x.into() }
/// ```
#[derive(Clone)]
pub struct VerifiedParent {
    binding: Hash,
    head: HeadRef,
    slot: u64,
    decision: Hash,
    control: Control,
}
impl VerifiedParent {
    pub(super) fn checked(
        binding: Hash,
        head: HeadRef,
        slot: u64,
        decision: Hash,
        control: Control,
    ) -> Self {
        Self {
            binding,
            head,
            slot,
            decision,
            control,
        }
    }
    pub fn binding_id(&self) -> Hash {
        self.binding
    }
    pub fn head(&self) -> HeadRef {
        self.head
    }
    pub fn slot(&self) -> u64 {
        self.slot
    }
    pub fn decision_id(&self) -> Hash {
        self.decision
    }
    pub fn control(&self) -> Control {
        self.control
    }
}
/// Fixed actual Word, owner, quorum, durable WAL and floor owner.
/// ```compile_fail
/// fn forge(){let _=registry200_finality::word::DurableFinality { engine:todo!(),binding:todo!() };}
/// ```
/// ```compile_fail
/// fn clone(x:&registry200_finality::word::DurableFinality)->registry200_finality::word::DurableFinality {x.clone()}
/// ```
pub struct DurableFinality {
    pub(crate) engine: DurableEngine,
    binding: Binding,
}
impl DurableFinality {
    pub fn create_participant(
        q: &ParticipantQuota,
        binding: Binding,
        key: SigningKey,
    ) -> Result<Self> {
        let engine =
            DurableEngine::create_participant(q, Installation::Word(binding.clone()), key)?;
        Ok(Self { engine, binding })
    }
    pub fn open_participant(
        q: &ParticipantQuota,
        binding: Binding,
        key: SigningKey,
    ) -> Result<Self> {
        let engine = DurableEngine::open_participant(q, Installation::Word(binding.clone()), key)?;
        Ok(Self { engine, binding })
    }
    pub fn binding(&self) -> Result<Binding> {
        if self.engine.binding_id()? != self.binding.id() {
            return Err(Error::Binding);
        }
        Ok(self.binding.clone())
    }
    pub fn context(&self) -> Result<&Context> {
        self.engine.context()
    }
    pub fn finalized_parent(&self) -> Result<Option<VerifiedParent>> {
        self.engine
            .finalized_parent()?
            .map(|p| {
                Ok(VerifiedParent::checked(
                    self.binding.id(),
                    p.head(),
                    p.slot(),
                    p.decision_id(),
                    p.control().word()?,
                ))
            })
            .transpose()
    }
    pub fn candidate_block(&self, id: Hash) -> Result<crate::CandidateBlock> {
        self.engine.candidate_block(id)
    }
    pub fn has_candidate(&self, id: Hash) -> Result<bool> {
        self.engine.has_candidate(id)
    }
    /// TLS-only restoration against this participant's actual immutable cache.
    /// Returns unverified FULL bytes; performs no native check, signer action,
    /// import or mutation. Normal full Body authorization and import are required.
    pub fn restore_transport_body(
        &self,
        header: Header,
        compact: Vec<u8>,
    ) -> Result<crate::CandidateBlock> {
        self.engine.restore_word_transport(header, compact)
    }
    pub fn import_candidate(&mut self, header: Header, body: &[u8]) -> Result<Candidate> {
        Candidate::decode(&self.engine.import_candidate(header, body)?)
    }
    pub fn propose(&mut self, c: &Candidate) -> Result<Vec<Action>> {
        self.engine.propose(&c.encode())
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.engine.receive(bytes)
    }
    pub fn receive_checkpoint(&mut self, c: &Checkpoint) -> Result<Vec<Action>> {
        self.engine
            .receive_checkpoint(&c.candidate().encode(), c.round(), c.certificate())
    }
    pub fn checkpoint_after(&mut self, slot: u64) -> Result<Option<Checkpoint>> {
        self.engine
            .checkpoint_after(slot)?
            .map(|c| Checkpoint::new(Candidate::decode(&c.value)?, c.round, c.certificate))
            .transpose()
    }
    pub fn timeout(&self) -> Result<Timeout> {
        self.engine.timeout()
    }
    pub fn on_timeout(&mut self, t: Timeout) -> Result<Vec<Action>> {
        self.engine.on_timeout(t)
    }
    pub fn outbound(&self) -> Result<Vec<Action>> {
        self.engine.outbound()
    }
}
