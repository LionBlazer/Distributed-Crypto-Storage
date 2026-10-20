//! Exact owner Bootstrap association over a closed historical Pending lineage.
use super::{
    CandidateBlock, Error, Hash, JointBinding, JointCheckpoint, Result, VerifiedJointParent,
};
use registry200_joint::{Descriptor, Lane, Manifest, Request};
use registry200_journal::{Control, Operation};
use registry200_proof::{
    admission,
    lifecycle::statement::{Phase, Statement},
    source::statement::encode_digest,
};
use version_journal::{Body, HeadRef, Header};
use work_finality::consensus::Context;

/// Historical Pending parent selected only by the live closed JointHistory.
/// Genesis and an actually checked EmptyPending lineage are both valid. This is
/// not an Active parent, a current network head, a signer floor or a SQL grant.
/// ```compile_fail
/// fn forge(head:version_journal::HeadRef){let _:registry200_finality::joint::JointBootstrapParent=head.into();}
/// ```
/// ```compile_fail
/// fn forge(){let _=registry200_finality::joint::JointBootstrapParent{head:todo!()};}
/// ```
#[derive(Clone)]
pub struct JointBootstrapParent {
    binding: JointBinding,
    head: HeadRef,
    context: Context,
}
impl JointBootstrapParent {
    pub(super) fn checked(binding: &JointBinding, head: HeadRef, context: &Context) -> Self {
        Self {
            binding: binding.clone(),
            head,
            context: context.clone(),
        }
    }
    pub fn binding_id(&self) -> Hash {
        self.binding.id()
    }
    pub fn application_descriptor(&self) -> &Descriptor {
        self.binding.application_descriptor()
    }
    pub fn head(&self) -> HeadRef {
        self.head
    }
    /// The slot in which this exact Bootstrap may be proposed.
    pub fn slot(&self) -> u64 {
        self.context.slot()
    }
    pub fn context_id(&self) -> Hash {
        self.context.id()
    }
    pub fn previous_decision(&self) -> Hash {
        self.context.previous_decision()
    }
    fn require_binding(&self, binding: &JointBinding) -> Result<()> {
        if self.binding.id() != binding.id()
            || self.binding.application_descriptor().encode()
                != binding.application_descriptor().encode()
            || self.head.genesis != binding.journal_genesis().id()?
            || self.head.database != binding.journal_genesis().database
            || self.context.rules().id() != binding.rules().id()
            || self.context.network_id() != binding.work_genesis().id()
            || self.context.journal_genesis() != self.head.genesis
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

/// Independently retained own public intent. Construction verifies no proof/QC.
pub struct BootstrapExpectation {
    before: JointBootstrapParent,
    request: Vec<u8>,
    statement: Statement,
    manifest: Manifest,
}
impl BootstrapExpectation {
    pub fn new(
        binding: &JointBinding,
        parent: &JointBootstrapParent,
        request: &Request,
        statement: &Statement,
        manifest: Manifest,
    ) -> Result<Self> {
        parent.require_binding(binding)?;
        let app = binding.application()?;
        let canonical = Request::new(&app, Lane::Bootstrap, request.inner().clone())?;
        if request.lane() != Lane::Bootstrap
            || canonical.encode()? != request.encode()?
            || request.inner().operation != Operation::Bootstrap
            || request.inner().parent != parent.head.block
            || request.inner().genesis != parent.head.genesis
            || request.inner().command != [0; 32]
            || !matches!(statement.expected.phase, Phase::Bootstrap)
            || encode_digest(statement.result) != [0; 32]
            || manifest.lane() != Lane::Bootstrap
            || manifest.result_root() != [0; 32]
            || manifest.next_root() != encode_digest(statement.next)
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
        let expected = admission::Expected::bootstrap(
            &source,
            app.genesis(),
            parent.head.block,
            request.inner().enrollment,
        )
        .map_err(|_| Error::Context)?;
        statement
            .require_expected(expected.claim())
            .map_err(|_| Error::Context)?;
        Ok(Self {
            before: parent.clone(),
            request: request.encode()?,
            statement: statement.clone(),
            manifest,
        })
    }
    pub fn parent(&self) -> &JointBootstrapParent {
        &self.before
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
    pub(super) fn require_context(
        &self,
        binding: &JointBinding,
        current: &Context,
        parent: HeadRef,
    ) -> Result<()> {
        self.before.require_binding(binding)?;
        if self.before.head != parent || self.before.context != *current {
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
        if body.parent != self.before.head.block
            || body.request != self.request
            || body.proof != self.manifest.encode()
            || body.updates.len() != 1
            || body.updates[0].id != app.source_spec().control_id
            || body.updates[0].old != Control::Pending.heads(app.source_spec())
            || body.updates[0].new != next.heads(app.source_spec())
            || block.header().genesis != self.before.head.genesis
            || block.header().parent != self.before.head.block
            || block.header().height
                != self
                    .before
                    .head
                    .height
                    .checked_add(1)
                    .ok_or(Error::ResourceLimit)?
            || block.header().body_hash != version_journal::hash(block.body())
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

/// This call's actual Source/Lifecycle replay, exact owner Body and weighted QC.
/// It attests one historical Bootstrap operation, not a current lock or install.
/// ```compile_fail
/// fn forge(){let _=registry200_finality::joint::VerifiedJointBootstrap{request:vec![]};}
/// ```
/// ```compile_fail
/// fn clone<T:Clone>(){} fn forbidden(){clone::<registry200_finality::joint::VerifiedJointBootstrap>();}
/// ```
pub struct VerifiedJointBootstrap {
    before: JointBootstrapParent,
    request: Vec<u8>,
    statement: Statement,
    manifest: Vec<u8>,
    parent: VerifiedJointParent,
    next_context: Hash,
    header: Header,
    body: Vec<u8>,
    checkpoint: Vec<u8>,
}
impl VerifiedJointBootstrap {
    pub(super) fn checked(
        expected: &BootstrapExpectation,
        parent: VerifiedJointParent,
        next_context: Hash,
        block: &CandidateBlock,
        checkpoint: &JointCheckpoint,
    ) -> Self {
        Self {
            before: expected.before.clone(),
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
    pub fn before(&self) -> &JointBootstrapParent {
        &self.before
    }
    pub fn context_id(&self) -> Hash {
        self.before.context_id()
    }
    pub fn checked_parent(&self) -> &VerifiedJointParent {
        &self.parent
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
