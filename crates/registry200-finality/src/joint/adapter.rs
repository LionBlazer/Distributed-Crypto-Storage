//! Typed owner over the one private durable engine. No mutable Journal,
//! arbitrary verifier, secret getter or unchecked successor is exposed.
use super::{
    Error, Hash, JointBinding, JointCandidate, JointCheckpoint, Result, VerifiedJointParent,
    durable_profile_digest,
};
use crate::{
    CandidateBlock,
    closed::{DurableEngine, Ingress, Installation},
    digest, participant,
};
use ed25519_dalek::SigningKey;
use protocol_storage::ParticipantQuota;
use registry200_joint::JointEvidenceIngress;
use version_journal::Header;
use work_finality::consensus::{Action, Context, Timeout};

pub fn participant_storage_profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/joint-participant-storage/v1", &[
        &durable_profile_digest(), &protocol_storage::participant_profile_digest(),
        b"typed-four-control-files/binding+signer-id/metadata-last/new-only/existing-only/no-adoption",
        b"journal76+G/floor168/wal144/all-writes-precharged/owned-IO-poisons-global-ledger",
        &(participant::META_BYTES as u64).to_le_bytes(),
    ])
}

/// Owns the actual Journal, floor and signer. Metadata is historical, never a
/// current SQL grant. No-quorum decisions cannot advance a lock or an End.
/// The host prefetches outside locks, then holds its ONE existing ProofGate for
/// construction/replay/import/voting. Local I/O only; no network callback.
/// ```compile_fail
/// fn key(x: &registry200_finality::joint::DurableJointFinality) { let _ = &x.engine; }
/// ```
/// ```compile_fail
/// fn copy(x: &registry200_finality::joint::DurableJointFinality) {
///     let _: registry200_finality::joint::DurableJointFinality = x.clone();
/// }
/// ```
pub struct DurableJointFinality {
    pub(crate) engine: DurableEngine,
    binding: JointBinding,
}
impl DurableJointFinality {
    pub fn create_participant(
        quota: &ParticipantQuota,
        binding: JointBinding,
        key: SigningKey,
    ) -> Result<Self> {
        let engine =
            DurableEngine::create_participant(quota, Installation::Joint(binding.clone()), key)?;
        Ok(Self { engine, binding })
    }
    pub fn open_participant(
        quota: &ParticipantQuota,
        binding: JointBinding,
        key: SigningKey,
    ) -> Result<Self> {
        let engine =
            DurableEngine::open_participant(quota, Installation::Joint(binding.clone()), key)?;
        Ok(Self { engine, binding })
    }
    pub fn context(&self) -> Result<&Context> {
        self.engine.context()
    }
    pub fn binding(&self) -> Result<JointBinding> {
        if self.engine.binding_id()? != self.binding.id() {
            return Err(Error::Binding);
        }
        Ok(self.binding.clone())
    }
    /// Same store/ledger. This capability retains bounded untrusted public bytes.
    pub fn evidence_ingress(&self) -> Result<JointEvidenceIngress> {
        self.engine.live()?;
        match &self.engine.ingress {
            Ingress::Joint(i) => Ok(i.clone()),
            _ => Err(Error::Binding),
        }
    }
    pub fn finalized_parent(&self) -> Result<Option<VerifiedJointParent>> {
        self.engine
            .finalized_parent()?
            .map(|p| {
                Ok(VerifiedJointParent::checked(
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
    pub fn import_candidate(&mut self, header: Header, body: &[u8]) -> Result<JointCandidate> {
        JointCandidate::decode(&self.engine.import_candidate(header, body)?)
    }
    pub fn propose(&mut self, candidate: &JointCandidate) -> Result<Vec<Action>> {
        self.engine.propose(&candidate.encode())
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.engine.receive(bytes)
    }
    pub fn receive_checkpoint(&mut self, checkpoint: &JointCheckpoint) -> Result<Vec<Action>> {
        self.engine.receive_checkpoint(
            &checkpoint.candidate().encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )
    }
    pub fn checkpoint_after(&mut self, slot: u64) -> Result<Option<JointCheckpoint>> {
        self.engine
            .checkpoint_after(slot)?
            .map(|record| {
                JointCheckpoint::new(
                    JointCandidate::decode(&record.value)?,
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
