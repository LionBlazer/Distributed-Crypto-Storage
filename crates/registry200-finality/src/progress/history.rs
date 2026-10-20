//! Closed historical lineage. No generic Journal or raw head can mint a parent.
use super::{
    Binding, Candidate, CandidateBlock, Checkpoint, Error, Hash, OperationExpectation, Result,
    VerifiedOperation,
};
use registry200_joint::progress::{Descriptor, ProgressDepot, ProgressVerifier};
use registry200_journal::Control;
use version_journal::{Body, HeadPair, HeadRef, Header, Journal};
use work_finality::consensus::Context;

/// Historical full-proof/QC metadata, never a current lock lease.
/// ```compile_fail
/// fn forge(head:version_journal::HeadRef){let _:registry200_finality::progress::VerifiedParent=head.into();}
/// ```
#[derive(Clone)]
pub struct VerifiedParent {
    binding: Hash,
    descriptor: Descriptor,
    head: HeadRef,
    slot: u64,
    decision: Hash,
    control: Control,
}
impl VerifiedParent {
    pub(super) fn checked(
        binding: &Binding,
        head: HeadRef,
        slot: u64,
        decision: Hash,
        control: Control,
    ) -> Self {
        Self {
            binding: binding.id(),
            descriptor: binding.application_descriptor().clone(),
            head,
            slot,
            decision,
            control,
        }
    }
    pub fn binding_id(&self) -> Hash {
        self.binding
    }
    pub fn application_id(&self) -> Hash {
        self.descriptor.id()
    }
    pub fn application_descriptor(&self) -> &Descriptor {
        &self.descriptor
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
/// Pending parent selected only from this live closed History. It may be the
/// original genesis or an actually finalized EmptyPending successor.
/// ```compile_fail
/// fn forge(){let _=registry200_finality::progress::BootstrapParent{head:todo!()};}
/// ```
#[derive(Clone)]
pub struct BootstrapParent {
    binding: Binding,
    head: HeadRef,
    context: Context,
}
impl BootstrapParent {
    pub fn binding_id(&self) -> Hash {
        self.binding.id()
    }
    pub fn application_descriptor(&self) -> &Descriptor {
        self.binding.application_descriptor()
    }
    pub fn head(&self) -> HeadRef {
        self.head
    }
    pub fn slot(&self) -> u64 {
        self.context.slot()
    }
    pub fn context_id(&self) -> Hash {
        self.context.id()
    }
    pub fn previous_decision(&self) -> Hash {
        self.context.previous_decision()
    }
    pub(super) fn context(&self) -> &Context {
        &self.context
    }
    pub(super) fn require_binding(&self, b: &Binding) -> Result<()> {
        if self.binding.id() != b.id()
            || self.binding.application_descriptor().encode() != b.application_descriptor().encode()
            || self.head.genesis != b.journal_genesis().id()?
            || self.head.database != b.journal_genesis().database
        {
            return Err(Error::Context);
        }
        require_context_binding(b, &self.context)
    }
}
struct Last {
    context: Context,
    before: HeadRef,
    checked: VerifiedParent,
}
pub struct History {
    binding: Binding,
    verifier: ProgressVerifier,
    journal: Journal,
    context: Context,
    last: Option<Last>,
    poisoned: bool,
}
impl History {
    pub fn new(binding: Binding, depot: ProgressDepot) -> Result<Self> {
        let verifier = ProgressVerifier::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
            binding.setup_claim(),
            depot,
        )?;
        let journal = Journal::new(binding.journal_genesis().clone())?;
        let context = binding.initial_context().clone();
        Ok(Self {
            binding,
            verifier,
            journal,
            context,
            last: None,
            poisoned: false,
        })
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn context(&self) -> Result<&Context> {
        self.live()?;
        Ok(&self.context)
    }
    pub fn checked_parent(&self) -> Result<Option<&VerifiedParent>> {
        self.live()?;
        Ok(self.last.as_ref().map(|l| &l.checked))
    }
    pub fn bootstrap_parent(&self) -> Result<BootstrapParent> {
        self.live()?;
        let head = self.journal.ancestry_floor();
        let app = self.binding.application()?;
        let control = Control::decode(
            app.source_spec(),
            app.source_spec()
                .control(self.journal.validated_shards(head)?)?,
        )?;
        if control != Control::Pending {
            return Err(Error::Context);
        }
        match &self.last {
            None if head == self.journal.genesis_head()
                && self.context == *self.binding.initial_context() => {}
            Some(last)
                if last.checked.head() == head
                    && last.checked.control() == Control::Pending
                    && self.context.slot()
                        == last
                            .checked
                            .slot()
                            .checked_add(1)
                            .ok_or(Error::ResourceLimit)?
                    && self.context.previous_decision() == last.checked.decision_id() => {}
            _ => return Err(Error::Context),
        }
        Ok(BootstrapParent {
            binding: self.binding.clone(),
            head,
            context: self.context.clone(),
        })
    }
    /// Mining metadata from the SAME owned floor and real target rules. This
    /// does not verify an application, publish, or assert network freshness.
    pub fn candidate_header(&self, body: &Body, timestamp: u64, now: u64) -> Result<Header> {
        self.live()?;
        if let Body::Transition(t) = body {
            t.check_authorization(
                &self.binding.journal_genesis().owner,
                self.journal.genesis_id(),
            )?;
        }
        let header =
            self.journal
                .candidate(self.journal.ancestry_floor().block, body, timestamp)?;
        self.journal.validate_mining_candidate(&header, now)?;
        Ok(header)
    }
    pub fn apply(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
    ) -> Result<VerifiedParent> {
        Ok(self.apply_owned(checkpoint, block, None)?.parent)
    }
    /// Own association, fixed full proof replay, QC and floor all precede this
    /// one-shot receipt. A latest retry remains historical and read-only.
    pub fn apply_operation(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
        expected: &OperationExpectation,
    ) -> Result<VerifiedOperation> {
        let applied = self.apply_owned(checkpoint, block, Some(expected))?;
        let Applied {
            parent,
            next_context,
            operation,
        } = applied;
        let operation =
            operation.expect("own fixed mode required a genuine result before publication");
        Ok(VerifiedOperation::checked(
            expected,
            parent,
            next_context,
            block,
            checkpoint,
            operation,
        ))
    }
    fn apply_owned(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
        own: Option<&OperationExpectation>,
    ) -> Result<Applied> {
        self.live()?;
        let candidate = checkpoint.candidate();
        if candidate.header() != block.header() {
            return Err(Error::Context);
        }
        let duplicate = candidate.slot() != self.context.slot();
        let (context, parent) = if duplicate {
            let last = self.last.as_ref().ok_or(Error::Context)?;
            if last.context.slot() != candidate.slot() {
                return Err(Error::Context);
            }
            (&last.context, last.before)
        } else {
            (&self.context, self.journal.ancestry_floor())
        };
        // ALL own context/body checks are before QC/native/I/O/publication.
        if let Some(expected) = own {
            expected.require(&self.binding, context, parent, block)?;
        }
        require_candidate_context(&self.binding, context, parent, candidate)?;
        let decision = context.verify_commit(
            &candidate.encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )?;
        let next = context.after_decision(&decision)?;
        let head = HeadRef {
            genesis: candidate.header.genesis,
            database: self.binding.journal_genesis().database,
            block: candidate.header.id(),
            height: candidate.header.height,
            state_root: candidate.header.state_root,
        };
        if duplicate {
            let last = self.last.as_ref().ok_or(Error::Context)?;
            if decision.semantic_id() != last.checked.decision_id()
                || next.id() != self.context.id()
            {
                return Err(Error::Context);
            }
            let old = parent_heads(&self.binding, &self.journal, parent)?;
            let operation = if let Some(expected) = own {
                Some(self.verifier.check_block(
                    &self.journal,
                    &candidate.header,
                    block.body(),
                    crate::adapter::now()?,
                    expected.operation_id(),
                )?)
            } else {
                self.journal.reverify_block(
                    &candidate.header,
                    block.body(),
                    crate::adapter::now()?,
                    &self.verifier,
                )?;
                None
            };
            let control = candidate_control(&self.binding, old, block.body())?;
            require_result(own, operation.as_ref())?;
            if head != last.checked.head() || control != last.checked.control() {
                return Err(Error::Context);
            }
            return Ok(Applied {
                parent: last.checked.clone(),
                next_context: next.id(),
                operation,
            });
        }
        let old = parent_heads(&self.binding, &self.journal, parent)?;
        let before_context = context.clone();
        let now = crate::adapter::now()?;
        let (pending, operation) = if let Some(expected) = own {
            let (pending, checked) = self.verifier.prepare_import(
                &mut self.journal,
                candidate.header.clone(),
                block.body(),
                now,
                expected.operation_id(),
            )?;
            (pending, Some(checked))
        } else {
            // Empty is authenticated by the real Journal, but never produces an
            // operation receipt. Transition still invokes the actual verifier.
            (
                self.journal.prepare_import(
                    candidate.header.clone(),
                    block.body(),
                    now,
                    &self.verifier,
                )?,
                None,
            )
        };
        let control = candidate_control(&self.binding, old, block.body())?;
        require_result(own, operation.as_ref())?;
        let checked = VerifiedParent::checked(
            &self.binding,
            head,
            context.slot(),
            decision.semantic_id(),
            control,
        );
        pending.commit();
        if let Err(e) = self.journal.restrict_ancestry_floor(head) {
            self.poisoned = true;
            return Err(e.into());
        }
        self.last = Some(Last {
            context: before_context,
            before: parent,
            checked: checked.clone(),
        });
        self.context = next;
        Ok(Applied {
            parent: checked,
            next_context: self.context.id(),
            operation,
        })
    }
    fn live(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
}
struct Applied {
    parent: VerifiedParent,
    next_context: Hash,
    operation: Option<registry200_joint::progress::VerifiedOperation>,
}
fn require_result(
    expected: Option<&OperationExpectation>,
    actual: Option<&registry200_joint::progress::VerifiedOperation>,
) -> Result<()> {
    match (expected, actual) {
        (None, None) => Ok(()),
        (Some(e), Some(a))
            if a.operation_id() == e.operation_id()
                && a.request() == e.request_bytes()
                && a.manifest().encode() == e.manifest().encode() =>
        {
            Ok(())
        }
        _ => Err(Error::Context),
    }
}
pub(super) fn require_context_binding(b: &Binding, c: &Context) -> Result<()> {
    if c.rules().id() != b.rules().id()
        || c.network_id() != b.work_genesis().id()
        || c.journal_genesis() != b.journal_genesis().id()?
    {
        Err(Error::Context)
    } else {
        Ok(())
    }
}
pub(crate) fn require_candidate_context(
    b: &Binding,
    c: &Context,
    parent: HeadRef,
    d: &Candidate,
) -> Result<()> {
    require_context_binding(b, c)?;
    if d.binding != b.id()
        || d.slot != c.slot()
        || d.previous != c.previous_decision()
        || d.header.parent != parent.block
        || d.header.genesis != parent.genesis
        || d.header.height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
    {
        Err(Error::Context)
    } else {
        Ok(())
    }
}
pub(crate) fn parent_heads(b: &Binding, j: &Journal, parent: HeadRef) -> Result<HeadPair> {
    let a = b.application()?;
    Ok(a.source_spec().control(j.validated_shards(parent)?)?)
}
pub(crate) fn candidate_control(b: &Binding, old: HeadPair, body: &[u8]) -> Result<Control> {
    let a = b.application()?;
    let next = match Body::decode(body, &b.journal_genesis().profile)? {
        Body::Empty => old,
        Body::Transition(t) => {
            if t.updates.len() != 1 || t.updates[0].id != a.source_spec().control_id {
                return Err(Error::Context);
            }
            t.updates[0].new
        }
    };
    Ok(Control::decode(a.source_spec(), next)?)
}
pub(crate) fn verify_candidate(
    b: &Binding,
    j: &Journal,
    v: &ProgressVerifier,
    c: &Context,
    parent: HeadRef,
    d: &Candidate,
    body: &[u8],
) -> Result<Control> {
    require_candidate_context(b, c, parent, d)?;
    let old = parent_heads(b, j, parent)?;
    j.reverify_block(&d.header, body, crate::adapter::now()?, v)?;
    candidate_control(b, old, body)
}

// Test-only observables of the SAME owned Journal; no production reader or
// authority escapes. This detects even an unpublished premature import.
#[cfg(test)]
impl History {
    pub(super) fn journal_state_for_test(
        &self,
        candidate: Hash,
    ) -> (usize, u64, HeadRef, HeadRef, bool) {
        (
            self.journal.header_count(),
            self.journal.accounted_bytes(),
            self.journal.best_validated(),
            self.journal.ancestry_floor(),
            self.journal.body(candidate).is_some(),
        )
    }
}
