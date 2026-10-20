//! A client's exact own Acquire, linearized by actual application proofs and QC.
//! No signer, generic current lock, persistent lease or SQL capability is exposed.
use super::{
    CandidateBlock, Error, Hash, JointBinding, JointCheckpoint, Result, VerifiedJointParent,
};
use registry200_joint::{AcquireExpected, CheckedAcquire, Lane, Request};
use registry200_journal::Control;
use version_journal::{HeadRef, Header};
use work_finality::consensus::Context;

/// Independent owner-produced public pins. This is not a receipt. The selected
/// current context must be authenticated by the caller's closed Joint history.
pub struct AcquireExpectation {
    binding: Hash,
    context: Hash,
    parent: HeadRef,
    slot: u64,
    previous: Hash,
    inputs: AcquireExpected,
}
impl AcquireExpectation {
    pub fn new(
        binding: &JointBinding,
        parent: &VerifiedJointParent,
        current: &Context,
        inputs: AcquireExpected,
    ) -> Result<Self> {
        let request = Request::decode(inputs.request_bytes())?;
        let Control::Active { enrollment, .. } = parent.control() else {
            return Err(Error::Context);
        };
        if parent.binding_id() != binding.id()
            || parent.application_descriptor().encode() != binding.application_descriptor().encode()
            || inputs.application_id() != binding.application_descriptor().id()
            || current.rules().id() != binding.rules().id()
            || current.network_id() != binding.work_genesis().id()
            || current.journal_genesis() != binding.journal_genesis().id()?
            || current.slot() != parent.slot().checked_add(1).ok_or(Error::ResourceLimit)?
            || current.previous_decision() != parent.decision_id()
            || request.lane() != Lane::Acquire
            || request.inner().parent != parent.head().block
            || request.inner().genesis != parent.head().genesis
            || request.inner().enrollment != enrollment
        {
            return Err(Error::Context);
        }
        Ok(Self {
            binding: binding.id(),
            context: current.id(),
            parent: parent.head(),
            slot: current.slot(),
            previous: current.previous_decision(),
            inputs,
        })
    }
    pub fn binding_id(&self) -> Hash {
        self.binding
    }
    pub fn context_id(&self) -> Hash {
        self.context
    }
    pub fn parent(&self) -> HeadRef {
        self.parent
    }
    pub fn inputs(&self) -> &AcquireExpected {
        &self.inputs
    }
    pub(super) fn require_context(
        &self,
        binding: &JointBinding,
        context: &Context,
        parent: HeadRef,
    ) -> Result<()> {
        if self.binding != binding.id()
            || self.context != context.id()
            || self.parent != parent
            || self.slot != context.slot()
            || self.previous != context.previous_decision()
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

/// One exact operation, not a reusable authorization/current-head token. Its
/// response comes from this call's fresh all-input16/output118/Life/Link replay.
/// Later End/reacquire decisions do not make this a generic current lock.
///
/// ```compile_fail
/// fn forge() { let _ = registry200_finality::joint::VerifiedJointAcquire { slot: 1 }; }
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {} fn forbidden() {
///     clone::<registry200_finality::joint::VerifiedJointAcquire>();
/// }
/// ```
pub struct VerifiedJointAcquire {
    before: HeadRef,
    context: Hash,
    next_context: Hash,
    previous: Hash,
    checked_parent: VerifiedJointParent,
    header: Header,
    body: Vec<u8>,
    checkpoint: Vec<u8>,
    acquired: CheckedAcquire,
}
impl VerifiedJointAcquire {
    pub(super) fn checked(
        expected: &AcquireExpectation,
        next_context: Hash,
        checked_parent: VerifiedJointParent,
        block: &CandidateBlock,
        checkpoint: &JointCheckpoint,
        acquired: CheckedAcquire,
    ) -> Self {
        Self {
            before: expected.parent,
            context: expected.context,
            previous: expected.previous,
            next_context,
            checked_parent,
            header: block.header().clone(),
            body: block.body().to_vec(),
            checkpoint: checkpoint.encode(),
            acquired,
        }
    }
    pub fn binding_id(&self) -> Hash {
        self.checked_parent.binding_id()
    }
    pub fn parent(&self) -> HeadRef {
        self.before
    }
    pub fn head(&self) -> HeadRef {
        self.checked_parent.head()
    }
    pub fn slot(&self) -> u64 {
        self.checked_parent.slot()
    }
    pub fn decision_id(&self) -> Hash {
        self.checked_parent.decision_id()
    }
    pub fn context_id(&self) -> Hash {
        self.context
    }
    pub fn previous_decision_id(&self) -> Hash {
        self.previous
    }
    pub fn next_context_id(&self) -> Hash {
        self.next_context
    }
    pub fn control(&self) -> Control {
        self.checked_parent.control()
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
    pub fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint
    }
    pub fn acquired(&self) -> &CheckedAcquire {
        &self.acquired
    }
    /// Historical sealed post-operation metadata, never a permanent lock lease.
    pub fn checked_parent(&self) -> &VerifiedJointParent {
        &self.checked_parent
    }
}
