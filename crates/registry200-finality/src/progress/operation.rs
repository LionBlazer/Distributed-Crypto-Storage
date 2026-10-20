//! Exact own-operation binding and a move-only genuine finality result.
use super::{
    Binding, BootstrapParent, CandidateBlock, Checkpoint, Error, Hash, Result, VerifiedParent,
};
use registry200_joint::progress::{Lane, Manifest, OperationId, Request};
use registry200_journal::{Control, Operation};
use version_journal::{Body, HeadRef, Header};
use work_finality::consensus::Context;

/// Independent owner-retained intent, not evidence of validity or freshness.
pub struct OperationExpectation {
    binding: Hash,
    context: Hash,
    parent: HeadRef,
    slot: u64,
    previous: Hash,
    request: Vec<u8>,
    manifest: Manifest,
    body: Vec<u8>,
    operation: OperationId,
}
impl OperationExpectation {
    pub fn bootstrap(
        b: &Binding,
        p: &BootstrapParent,
        request: &Request,
        manifest: Manifest,
        body: &Body,
    ) -> Result<Self> {
        p.require_binding(b)?;
        if request.lane() != Lane::Bootstrap {
            return Err(Error::Context);
        }
        Self::new(
            b,
            p.context(),
            p.head(),
            Control::Pending,
            request,
            manifest,
            body,
        )
    }
    pub fn transition(
        b: &Binding,
        p: &VerifiedParent,
        current: &Context,
        request: &Request,
        manifest: Manifest,
        body: &Body,
    ) -> Result<Self> {
        if p.binding_id() != b.id()
            || p.application_descriptor().encode() != b.application_descriptor().encode()
            || current.slot() != p.slot().checked_add(1).ok_or(Error::ResourceLimit)?
            || current.previous_decision() != p.decision_id()
            || p.control() == Control::Pending
            || request.lane() == Lane::Bootstrap
        {
            return Err(Error::Context);
        }
        Self::new(b, current, p.head(), p.control(), request, manifest, body)
    }
    fn new(
        b: &Binding,
        c: &Context,
        parent: HeadRef,
        old: Control,
        r: &Request,
        m: Manifest,
        body: &Body,
    ) -> Result<Self> {
        super::history::require_context_binding(b, c)?;
        let app = b.application()?;
        let canonical = Request::new(&app, r.lane(), r.inner().clone())?;
        let inner = r.inner();
        let old_enrollment = match old {
            Control::Pending => inner.enrollment,
            Control::Active { enrollment, .. } => enrollment,
        };
        if canonical.encode()? != r.encode()?
            || m.lane() != r.lane()
            || inner.genesis != parent.genesis
            || inner.parent != parent.block
            || inner.enrollment != old_enrollment
            || (r.lane() == Lane::Bootstrap
                && (inner.operation != Operation::Bootstrap || inner.command != [0; 32]))
            || (r.lane() != Lane::Bootstrap && inner.operation != Operation::Transition)
        {
            return Err(Error::Context);
        }
        let Body::Transition(t) = body else {
            return Err(Error::Context);
        };
        let next = Control::Active {
            enrollment: inner.enrollment,
            registry: m.next_root(),
        };
        if t.parent != parent.block
            || t.request != r.encode()?
            || t.proof != m.encode()
            || t.updates.len() != 1
            || t.updates[0].id != app.source_spec().control_id
            || t.updates[0].old != old.heads(app.source_spec())
            || t.updates[0].new != next.heads(app.source_spec())
        {
            return Err(Error::Context);
        }
        t.check_authorization(&b.journal_genesis().owner, parent.genesis)?;
        let body = body.encode(&b.journal_genesis().profile)?;
        Ok(Self {
            binding: b.id(),
            context: c.id(),
            parent,
            slot: c.slot(),
            previous: c.previous_decision(),
            request: r.encode()?,
            operation: OperationId::new(&app, r, &m)?,
            manifest: m,
            body,
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
    pub fn operation_id(&self) -> OperationId {
        self.operation
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
    pub(super) fn require(
        &self,
        b: &Binding,
        c: &Context,
        parent: HeadRef,
        block: &CandidateBlock,
    ) -> Result<()> {
        if self.binding != b.id()
            || self.context != c.id()
            || self.parent != parent
            || self.slot != c.slot()
            || self.previous != c.previous_decision()
            || block.body() != self.body
            || block.header().genesis != parent.genesis
            || block.header().parent != parent.block
            || block.header().height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
            || block.header().body_hash != version_journal::hash(&self.body)
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}
/// One exact operation, linearized by actual application replay and QC. No
/// constructor accepts a kernel math result, boolean or generic parent.
/// ```compile_fail
/// fn private(x:&registry200_finality::progress::VerifiedOperation){let _=&x.operation;}
/// ```
/// ```compile_fail
/// fn copy<T:Clone>(){} fn forbidden(){copy::<registry200_finality::progress::VerifiedOperation>();}
/// ```
pub struct VerifiedOperation {
    before: HeadRef,
    context: Hash,
    next_context: Hash,
    previous: Hash,
    checked_parent: VerifiedParent,
    header: Header,
    body: Vec<u8>,
    checkpoint: Vec<u8>,
    operation: registry200_joint::progress::VerifiedOperation,
}
impl VerifiedOperation {
    pub(super) fn checked(
        e: &OperationExpectation,
        parent: VerifiedParent,
        next_context: Hash,
        b: &CandidateBlock,
        q: &Checkpoint,
        operation: registry200_joint::progress::VerifiedOperation,
    ) -> Self {
        Self {
            before: e.parent,
            context: e.context,
            next_context,
            previous: e.previous,
            checked_parent: parent,
            header: b.header().clone(),
            body: b.body().to_vec(),
            checkpoint: q.encode(),
            operation,
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
    pub fn operation(&self) -> &registry200_joint::progress::VerifiedOperation {
        &self.operation
    }
    pub fn checked_parent(&self) -> &VerifiedParent {
        &self.checked_parent
    }
}
