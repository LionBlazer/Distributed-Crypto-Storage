//! Closed keyless history. Only actual Joint mathematics plus weighted QC advance it.
use super::{
    AcquireExpectation, BootstrapExpectation, CandidateBlock, ControlExpectation, Error, Hash,
    JointBinding, JointBootstrapParent, JointCandidate, JointCheckpoint, Result,
    VerifiedJointAcquire, VerifiedJointBootstrap, VerifiedJointControl,
};
use registry200_joint::{AcquireExpected, CheckedAcquire, Descriptor, JointDepot, JointVerifier};
use registry200_journal::Control;
use version_journal::{Body, HeadPair, HeadRef, Journal};
use work_finality::consensus::Context;

#[path = "acquire_candidate.rs"]
mod acquire_candidate;
#[path = "control_candidate.rs"]
mod control_candidate;

/// Historical proof+QC metadata, never a current fresh SQL lock or signer floor.
/// It cannot be nominated using a generic Journal, shards, or an untrusted HeadRef.
/// ```compile_fail
/// fn forge() { let _ = registry200_finality::joint::VerifiedJointParent { binding: [0;32] }; }
/// ```
/// ```compile_fail
/// fn forge(head: version_journal::HeadRef) {
///     let _: registry200_finality::joint::VerifiedJointParent = head.into();
/// }
/// ```
#[derive(Clone)]
pub struct VerifiedJointParent {
    binding: Hash,
    descriptor: Descriptor,
    head: HeadRef,
    slot: u64,
    decision: Hash,
    control: Control,
}
impl VerifiedJointParent {
    pub(super) fn checked(
        binding: &JointBinding,
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
struct Last {
    context: Context,
    before: HeadRef,
    checked: VerifiedJointParent,
}

// Closed own-operation selection. No external verifier or accepting callback
// can enter this dispatch, and contradictory optional expectations cannot exist.
enum OwnMode<'a> {
    Generic,
    Acquire(&'a AcquireExpectation),
    Control(&'a ControlExpectation),
    Bootstrap(&'a BootstrapExpectation),
}
impl<'a> OwnMode<'a> {
    fn require(
        &self,
        binding: &JointBinding,
        context: &Context,
        parent: HeadRef,
        block: &CandidateBlock,
    ) -> Result<()> {
        match self {
            Self::Generic => Ok(()),
            Self::Acquire(expected) => expected.require_context(binding, context, parent),
            Self::Control(expected) => {
                expected.require_context(binding, context, parent)?;
                expected.require_block(binding, block)
            }
            Self::Bootstrap(expected) => {
                expected.require_context(binding, context, parent)?;
                expected.require_block(binding, block)
            }
        }
    }
    fn acquire_inputs(&self) -> Option<&AcquireExpected> {
        match self {
            Self::Acquire(expected) => Some(expected.inputs()),
            _ => None,
        }
    }
    // Called only after this call's actual verification. Reject a missing or
    // unexpected Acquire result BEFORE publication, not in a public wrapper.
    fn prepare_receipt(self, acquired: Option<CheckedAcquire>) -> Result<PreparedReceipt<'a>> {
        match (self, acquired) {
            (Self::Generic, None) => Ok(PreparedReceipt::Generic),
            (Self::Acquire(expected), Some(acquired)) => Ok(PreparedReceipt::Acquire {
                expected,
                acquired: Box::new(acquired),
            }),
            (Self::Control(expected), None) => Ok(PreparedReceipt::Control(expected)),
            (Self::Bootstrap(expected), None) => Ok(PreparedReceipt::Bootstrap(expected)),
            _ => Err(Error::Context),
        }
    }
}
// Move-only, per-call result. The Box moves the actual Acquire payload without
// cloning it or sizing every other mode for it. Neither enum is stored in History
// or exposed as a reusable verification token.
enum PreparedReceipt<'a> {
    Generic,
    Acquire {
        expected: &'a AcquireExpectation,
        acquired: Box<CheckedAcquire>,
    },
    Control(&'a ControlExpectation),
    Bootstrap(&'a BootstrapExpectation),
}
struct AppliedReceipt<'a> {
    parent: VerifiedJointParent,
    next_context: Hash,
    receipt: PreparedReceipt<'a>,
}

/// Owns its real Journal, fixed JointVerifier and deterministic Work lineage.
/// Callers must prefetch all public evidence locally through the SAME depot
/// ingress, outside application locks, and hold their one native ProofGate.
/// No network or supplied verifier/callback is invoked here.
pub struct JointHistory {
    binding: JointBinding,
    verifier: JointVerifier,
    journal: Journal,
    context: Context,
    last: Option<Last>,
    poisoned: bool,
}
impl JointHistory {
    pub fn new(binding: JointBinding, depot: JointDepot) -> Result<Self> {
        let verifier = JointVerifier::new(
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
    pub fn context(&self) -> Result<&Context> {
        self.live()?;
        Ok(&self.context)
    }
    pub fn binding(&self) -> &JointBinding {
        &self.binding
    }
    pub fn checked_parent(&self) -> Result<Option<&VerifiedJointParent>> {
        self.live()?;
        Ok(self.last.as_ref().map(|last| &last.checked))
    }
    /// Snapshot only this live closed Pending lineage. An authentic old snapshot
    /// remains historical and cannot authorize a later/current network state.
    pub fn bootstrap_parent(&self) -> Result<JointBootstrapParent> {
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
            None => {
                if head != self.journal.genesis_head()
                    || self.context != *self.binding.initial_context()
                {
                    return Err(Error::Context);
                }
            }
            Some(last) => {
                if last.checked.head() != head
                    || last.checked.control() != Control::Pending
                    || self.context.slot()
                        != last
                            .checked
                            .slot()
                            .checked_add(1)
                            .ok_or(Error::ResourceLimit)?
                    || self.context.previous_decision() != last.checked.decision_id()
                {
                    return Err(Error::Context);
                }
            }
        }
        Ok(JointBootstrapParent::checked(
            &self.binding,
            head,
            &self.context,
        ))
    }
    pub fn apply(
        &mut self,
        checkpoint: &JointCheckpoint,
        block: &CandidateBlock,
    ) -> Result<VerifiedJointParent> {
        Ok(self
            .apply_owned(checkpoint, block, OwnMode::Generic)?
            .parent)
    }
    /// Apply the exact independently pinned own Acquire in the next slot, or
    /// genuinely recheck the latest identical semantic decision. No signer is
    /// needed and no generic historical Parent can construct the returned value.
    pub fn apply_acquire(
        &mut self,
        checkpoint: &JointCheckpoint,
        block: &CandidateBlock,
        expected: &AcquireExpectation,
    ) -> Result<VerifiedJointAcquire> {
        let AppliedReceipt {
            parent,
            next_context,
            receipt,
        } = self.apply_owned(checkpoint, block, OwnMode::Acquire(expected))?;
        let PreparedReceipt::Acquire { expected, acquired } = receipt else {
            unreachable!("closed Acquire mode retains its actual prepared result")
        };
        Ok(VerifiedJointAcquire::checked(
            expected,
            next_context,
            parent,
            block,
            checkpoint,
            *acquired,
        ))
    }
    /// Recheck the exact own non-Acquire operation through the same concrete
    /// application verifier and weighted QC. No supplied verifier is accepted.
    pub fn apply_control(
        &mut self,
        checkpoint: &JointCheckpoint,
        block: &CandidateBlock,
        expected: &ControlExpectation,
    ) -> Result<VerifiedJointControl> {
        let AppliedReceipt {
            parent,
            next_context,
            receipt,
        } = self.apply_owned(checkpoint, block, OwnMode::Control(expected))?;
        let PreparedReceipt::Control(expected) = receipt else {
            unreachable!("closed Control mode retains its prepared expectation")
        };
        Ok(VerifiedJointControl::checked(
            expected,
            parent,
            next_context,
            block,
            checkpoint,
        ))
    }
    /// Apply the exact own Bootstrap, or fully recheck its latest semantic retry.
    /// The expectation precedes Journal import and no supplied verifier is accepted.
    pub fn apply_bootstrap(
        &mut self,
        checkpoint: &JointCheckpoint,
        block: &CandidateBlock,
        expected: &BootstrapExpectation,
    ) -> Result<VerifiedJointBootstrap> {
        let AppliedReceipt {
            parent,
            next_context,
            receipt,
        } = self.apply_owned(checkpoint, block, OwnMode::Bootstrap(expected))?;
        let PreparedReceipt::Bootstrap(expected) = receipt else {
            unreachable!("closed Bootstrap mode retains its prepared expectation")
        };
        Ok(VerifiedJointBootstrap::checked(
            expected,
            parent,
            next_context,
            block,
            checkpoint,
        ))
    }
    fn apply_owned<'own>(
        &mut self,
        checkpoint: &JointCheckpoint,
        block: &CandidateBlock,
        own: OwnMode<'own>,
    ) -> Result<AppliedReceipt<'own>> {
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
        own.require(&self.binding, context, parent, block)?;
        let decision = context.verify_commit(
            &candidate.encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )?;
        let next = context.after_decision(&decision)?; // every fallible lineage check before publication
        if duplicate {
            let last = self.last.as_ref().ok_or(Error::Context)?;
            if decision.semantic_id() != last.checked.decision || next.id() != self.context.id() {
                return Err(Error::Context);
            }
        }
        let head = HeadRef {
            genesis: candidate.header.genesis,
            database: self.binding.journal_genesis().database,
            block: candidate.header.id(),
            height: candidate.header.height,
            state_root: candidate.header.state_root,
        };
        if duplicate {
            // The latest selected block's parent is below the current ancestry
            // floor. Keep actual fresh READ-ONLY verification under its real
            // historical context; a pending new import is not this operation.
            let (control, acquired) = verify_candidate_owned(
                &self.binding,
                &self.journal,
                &self.verifier,
                context,
                parent,
                candidate,
                CandidateBody {
                    wire: block.body(),
                    own: own.acquire_inputs(),
                },
            )?;
            let last = self.last.as_ref().ok_or(Error::Context)?;
            if head != last.checked.head || control != last.checked.control {
                return Err(Error::Context);
            }
            let receipt = own.prepare_receipt(acquired)?;
            return Ok(AppliedReceipt {
                parent: last.checked.clone(),
                next_context: next.id(),
                receipt,
            }); // full actual read-only revalidation above; no new import below the floor
        }
        require_candidate_context(&self.binding, context, parent, candidate)?;
        let old = parent_heads(&self.binding, &self.journal, parent)?;
        let old_context = context.clone();
        let now = crate::adapter::now()?;
        let (pending, acquired) = if let Some(inputs) = own.acquire_inputs() {
            let (pending, acquired) = self.verifier.prepare_acquire_import(
                &mut self.journal,
                candidate.header.clone(),
                block.body(),
                now,
                inputs,
            )?;
            (pending, Some(acquired))
        } else {
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
        // Derive the same complete Control only after the fresh owner/header/
        // application check, using copied parent heads and exact borrowed Body.
        // Every fallible own/context/QC/successor/Control check precedes commit.
        let control = candidate_control(&self.binding, old, block.body())?;
        let receipt = own.prepare_receipt(acquired)?;
        let checked = VerifiedJointParent {
            binding: self.binding.id(),
            descriptor: self.binding.application_descriptor().clone(),
            head,
            slot: context.slot(),
            decision: decision.semantic_id(),
            control,
        };
        // Consume this exact freshly verified import. No cached success is
        // supplied and no header/body/verifier can be substituted at commit.
        pending.commit();
        if let Err(error) = self.journal.restrict_ancestry_floor(head) {
            // An unexpected post-import invariant failure is terminal; no new
            // parent/context escapes and no subsequent operation can use history.
            self.poisoned = true;
            return Err(error.into());
        }
        self.last = Some(Last {
            context: old_context,
            before: parent,
            checked: checked.clone(),
        });
        self.context = next;
        Ok(AppliedReceipt {
            parent: checked,
            next_context: self.context.id(),
            receipt,
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

pub(super) fn verify_candidate(
    binding: &JointBinding,
    journal: &Journal,
    verifier: &JointVerifier,
    context: &Context,
    parent: HeadRef,
    d: &JointCandidate,
    body: &[u8],
) -> Result<Control> {
    verify_candidate_owned(
        binding,
        journal,
        verifier,
        context,
        parent,
        d,
        CandidateBody {
            wire: body,
            own: None,
        },
    )
    .map(|(control, _)| control)
}
struct CandidateBody<'a> {
    wire: &'a [u8],
    own: Option<&'a AcquireExpected>,
}
fn verify_candidate_owned(
    binding: &JointBinding,
    journal: &Journal,
    verifier: &JointVerifier,
    context: &Context,
    parent: HeadRef,
    d: &JointCandidate,
    body: CandidateBody<'_>,
) -> Result<(Control, Option<CheckedAcquire>)> {
    require_candidate_context(binding, context, parent, d)?;
    let now = crate::adapter::now()?;
    let acquired = if let Some(own) = body.own {
        Some(verifier.check_acquire_block(journal, &d.header, body.wire, now, own)?)
    } else {
        journal.reverify_block(&d.header, body.wire, now, verifier)?;
        None
    };
    let old = parent_heads(binding, journal, parent)?;
    Ok((candidate_control(binding, old, body.wire)?, acquired))
}
pub(super) fn require_candidate_context(
    binding: &JointBinding,
    context: &Context,
    parent: HeadRef,
    d: &JointCandidate,
) -> Result<()> {
    if d.binding != binding.id()
        || d.slot != context.slot()
        || d.previous != context.previous_decision()
        || d.header.parent != parent.block
        || d.header.genesis != parent.genesis
        || d.header.height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
    {
        return Err(Error::Context);
    }
    Ok(())
}
pub(super) fn parent_heads(
    binding: &JointBinding,
    journal: &Journal,
    parent: HeadRef,
) -> Result<HeadPair> {
    // Read-only candidate metadata. It cannot authorize publication; callers
    // must still perform the actual fresh Journal/application proof check.
    let application = binding.application()?;
    let spec = application.source_spec();
    Ok(spec.control(journal.validated_shards(parent)?)?)
}
pub(super) fn candidate_control(
    binding: &JointBinding,
    old: HeadPair,
    body: &[u8],
) -> Result<Control> {
    let application = binding.application()?;
    let spec = application.source_spec();
    let next = match Body::decode(body, &binding.journal_genesis().profile)? {
        Body::Empty => old,
        Body::Transition(body) => {
            if body.updates.len() != 1 || body.updates[0].id != spec.control_id {
                return Err(Error::Context);
            }
            body.updates[0].new
        }
    };
    Ok(Control::decode(spec, next)?)
}

#[cfg(test)]
#[path = "tests.rs"]
pub(super) mod tests;
