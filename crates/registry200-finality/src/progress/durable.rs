//! Typed owner over the one private durable engine. No mutable Journal,
//! arbitrary verifier, secret getter or unchecked successor is exposed.
use super::{
    Binding, Candidate, Checkpoint, Error, Hash, Result, VerifiedParent, durable_profile_digest,
};
use crate::{
    CandidateBlock,
    closed::{DurableEngine, Ingress, Installation},
    digest, participant,
};
use ed25519_dalek::SigningKey;
use protocol_storage::ParticipantQuota;
use registry200_joint::progress::ProgressEvidenceIngress;
use version_journal::Header;
use work_finality::consensus::{Action, Context, Timeout};

pub fn participant_storage_profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/progress-participant-storage/v2", &[
        &durable_profile_digest(), &protocol_storage::participant_profile_digest(),
        b"typed-four-control-files/binding+signer-id/metadata-last/new-only/existing-only/no-adoption",
        b"journal76+G/floor168/wal144/all-writes-precharged/owned-IO-poisons-global-ledger",
        &(participant::META_BYTES as u64).to_le_bytes(),
    ])
}

/// Durable Registry208 participant, not a SQL grant. The host holds its one
/// actual ProofGate around construction/replay/import/voting, never across RPC.
/// ```compile_fail
/// fn forge(){let _=registry200_finality::progress::DurableFinality{engine:todo!()};}
/// ```
/// ```compile_fail
/// fn foreign(q:&protocol_storage::ParticipantQuota,b:registry200_finality::joint::JointBinding,k:ed25519_dalek::SigningKey){
///     let _=registry200_finality::progress::DurableFinality::create_participant(q,b,k);
/// }
/// ```
pub struct DurableFinality {
    pub(crate) engine: DurableEngine,
    binding: Binding,
}
impl DurableFinality {
    pub fn create_participant(
        quota: &ParticipantQuota,
        binding: Binding,
        key: SigningKey,
    ) -> Result<Self> {
        let engine =
            DurableEngine::create_participant(quota, Installation::Progress(binding.clone()), key)?;
        Ok(Self { engine, binding })
    }
    pub fn open_participant(
        quota: &ParticipantQuota,
        binding: Binding,
        key: SigningKey,
    ) -> Result<Self> {
        let engine =
            DurableEngine::open_participant(quota, Installation::Progress(binding.clone()), key)?;
        Ok(Self { engine, binding })
    }
    pub fn context(&self) -> Result<&Context> {
        self.engine.context()
    }
    pub fn binding(&self) -> Result<Binding> {
        if self.engine.binding_id()? != self.binding.id() {
            return Err(Error::Binding);
        }
        Ok(self.binding.clone())
    }
    /// Same store/ledger. This capability retains bounded untrusted public bytes.
    pub fn evidence_ingress(&self) -> Result<ProgressEvidenceIngress> {
        self.engine.live()?;
        match &self.engine.ingress {
            Ingress::Progress(i) => Ok(i.clone()),
            _ => Err(Error::Binding),
        }
    }
    pub fn finalized_parent(&self) -> Result<Option<VerifiedParent>> {
        self.engine
            .finalized_parent()?
            .map(|p| {
                Ok(VerifiedParent::checked(
                    &self.binding,
                    p.head(),
                    p.slot(),
                    p.decision_id(),
                    p.control().registry()?,
                ))
            })
            .transpose()
    }
    pub fn candidate_block(&self, id: Hash) -> Result<CandidateBlock> {
        self.engine.candidate_block(id)
    }
    pub fn has_candidate(&self, id: Hash) -> Result<bool> {
        self.engine.has_candidate(id)
    }
    pub fn import_candidate(&mut self, header: Header, body: &[u8]) -> Result<Candidate> {
        Candidate::decode(&self.engine.import_candidate(header, body)?)
    }
    pub fn propose(&mut self, candidate: &Candidate) -> Result<Vec<Action>> {
        self.engine.propose(&candidate.encode())
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.engine.receive(bytes)
    }
    pub fn receive_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<Vec<Action>> {
        self.engine.receive_checkpoint(
            &checkpoint.candidate().encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )
    }
    pub fn checkpoint_after(&mut self, slot: u64) -> Result<Option<Checkpoint>> {
        self.engine
            .checkpoint_after(slot)?
            .map(|record| {
                Checkpoint::new(
                    Candidate::decode(&record.value)?,
                    record.round,
                    record.certificate,
                )
            })
            .transpose()
    }
    pub fn timeout(&self) -> Result<Timeout> {
        self.engine.timeout()
    }
    pub fn outbound(&self) -> Result<Vec<Action>> {
        self.engine.outbound()
    }
    pub fn on_timeout(&mut self, timeout: Timeout) -> Result<Vec<Action>> {
        self.engine.on_timeout(timeout)
    }
}
