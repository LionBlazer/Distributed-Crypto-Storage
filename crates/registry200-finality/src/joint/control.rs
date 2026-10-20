//! Exact own BEGIN/End association. No SQL data commit or current lock token.
use super::{
    CandidateBlock, Error, Hash, JointBinding, JointCheckpoint, Result, VerifiedJointParent,
};
use registry200_joint::{Lane, Manifest, Request};
use registry200_journal::Control;
use registry200_proof::{
    admission, lifecycle::statement::Statement, source::statement::encode_digest,
};
use version_journal::{Body, HeadRef, Header};
use work_finality::consensus::Context;

/// Independently retained public intent, never a verification receipt. Only the
/// existing Control lane is allowed; Registry Bootstrap is a separate protocol.
pub struct ControlExpectation {
    binding: Hash,
    before: VerifiedJointParent,
    context: Hash,
    request: Vec<u8>,
    statement: Statement,
    manifest: Manifest,
}
impl ControlExpectation {
    pub fn new(
        binding: &JointBinding,
        parent: &VerifiedJointParent,
        current: &Context,
        request: &Request,
        statement: &Statement,
        manifest: Manifest,
    ) -> Result<Self> {
        let Control::Active {
            enrollment,
            registry,
        } = parent.control()
        else {
            return Err(Error::Context);
        };
        let app = binding.application()?;
        let canonical = Request::new(&app, Lane::Control, request.inner().clone())?;
        if parent.binding_id() != binding.id()
            || parent.application_descriptor().encode() != binding.application_descriptor().encode()
            || current.rules().id() != binding.rules().id()
            || current.network_id() != binding.work_genesis().id()
            || current.journal_genesis() != binding.journal_genesis().id()?
            || current.slot() != parent.slot().checked_add(1).ok_or(Error::ResourceLimit)?
            || current.previous_decision() != parent.decision_id()
            || request.lane() != Lane::Control
            || canonical.encode()? != request.encode()?
            || request.inner().parent != parent.head().block
            || request.inner().genesis != parent.head().genesis
            || request.inner().enrollment != enrollment
            || manifest.lane() != Lane::Control
            || manifest.next_root() != encode_digest(statement.next)
            || manifest.result_root() != encode_digest(statement.result)
        {
            return Err(Error::Context);
        }
        let source = request.inner().source(app.source_spec())?;
        if source.values() != statement.expected.source.values()
            || source.heads != statement.expected.source.heads
            || source.packets != statement.expected.source.packets
        {
            return Err(Error::Context);
        }
        let source =
            admission::CanonicalSource::checked_claim(&source).map_err(|_| Error::Context)?;
        let expected = admission::Expected::transition(
            &source,
            app.genesis(),
            parent.head().block,
            enrollment,
            registry,
            request.inner().command,
        )
        .map_err(|_| Error::Context)?;
        statement
            .require_expected(expected.claim())
            .map_err(|_| Error::Context)?;
        Ok(Self {
            binding: binding.id(),
            before: parent.clone(),
            context: current.id(),
            request: request.encode()?,
            statement: statement.clone(),
            manifest,
        })
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn parent(&self) -> &VerifiedJointParent {
        &self.before
    }
    pub(super) fn require_context(
        &self,
        binding: &JointBinding,
        current: &Context,
        parent: HeadRef,
    ) -> Result<()> {
        if self.binding != binding.id()
            || self.context != current.id()
            || self.before.head() != parent
            || current.slot()
                != self
                    .before
                    .slot()
                    .checked_add(1)
                    .ok_or(Error::ResourceLimit)?
            || current.previous_decision() != self.before.decision_id()
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub(super) fn require_block(
        &self,
        binding: &JointBinding,
        block: &CandidateBlock,
    ) -> Result<()> {
        let app = binding.application()?;
        let Body::Transition(body) =
            Body::decode(block.body(), &binding.journal_genesis().profile)?
        else {
            return Err(Error::Context);
        };
        let next = Control::Active {
            enrollment: encode_digest(self.statement.expected.enrollment),
            registry: self.manifest.next_root(),
        };
        if body.parent != self.before.head().block
            || body.request != self.request
            || body.proof != self.manifest.encode()
            || body.updates.len() != 1
            || body.updates[0].id != app.source_spec().control_id
            || body.updates[0].old != self.before.control().heads(app.source_spec())
            || body.updates[0].new != next.heads(app.source_spec())
            || block.header().body_hash != version_journal::hash(block.body())
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

/// This call's actual Source/Life/ControlKind replay and exact weighted QC.
/// Historical operation only; it releases no encrypted SQL overlay or lease.
/// ```compile_fail
/// fn forge(){let _ = registry200_finality::joint::VerifiedJointControl { context:[0;32] };}
/// ```
/// ```compile_fail
/// fn clone<T:Clone>(){} fn forbidden(){clone::<registry200_finality::joint::VerifiedJointControl>();}
/// ```
pub struct VerifiedJointControl {
    before: VerifiedJointParent,
    context: Hash,
    request: Vec<u8>,
    statement: Statement,
    manifest: Vec<u8>,
    parent: VerifiedJointParent,
    next_context: Hash,
    header: Header,
    body: Vec<u8>,
    checkpoint: Vec<u8>,
}
impl VerifiedJointControl {
    pub(super) fn checked(
        expected: &ControlExpectation,
        parent: VerifiedJointParent,
        next_context: Hash,
        block: &CandidateBlock,
        checkpoint: &JointCheckpoint,
    ) -> Self {
        Self {
            before: expected.before.clone(),
            context: expected.context,
            request: expected.request.clone(),
            statement: expected.statement.clone(),
            manifest: expected.manifest.encode(),
            parent,
            next_context,
            header: block.header().clone(),
            body: block.body().to_vec(),
            checkpoint: checkpoint.encode(),
        }
    }
    pub fn checked_parent(&self) -> &VerifiedJointParent {
        &self.parent
    }
    pub fn before(&self) -> &VerifiedJointParent {
        &self.before
    }
    pub fn context_id(&self) -> Hash {
        self.context
    }
    pub fn next_context_id(&self) -> Hash {
        self.next_context
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
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
}
