//! Closed keyless history. Only actual Joint mathematics plus weighted QC advance it.
use super::{CandidateBlock, Error, Hash, JointBinding, JointCandidate, JointCheckpoint, Result};
use registry200_joint::{Descriptor, JointDepot, JointVerifier};
use registry200_journal::Control;
use version_journal::{Body, HeadRef, Journal};
use work_finality::consensus::Context;

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
    pub fn apply(
        &mut self,
        checkpoint: &JointCheckpoint,
        block: &CandidateBlock,
    ) -> Result<VerifiedJointParent> {
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
        let control = verify_candidate(
            &self.binding,
            &self.journal,
            &self.verifier,
            context,
            parent,
            candidate,
            block.body(),
        )?;
        let head = HeadRef {
            genesis: candidate.header.genesis,
            database: self.binding.journal_genesis().database,
            block: candidate.header.id(),
            height: candidate.header.height,
            state_root: candidate.header.state_root,
        };
        if duplicate {
            let last = self.last.as_ref().ok_or(Error::Context)?;
            if head != last.checked.head || control != last.checked.control {
                return Err(Error::Context);
            }
            return Ok(last.checked.clone()); // full actual revalidation above, even for duplicate QC
        }
        let checked = VerifiedJointParent {
            binding: self.binding.id(),
            descriptor: self.binding.application_descriptor().clone(),
            head,
            slot: context.slot(),
            decision: decision.semantic_id(),
            control,
        };
        let old_context = self.context.clone();
        // import_block is atomic on invalid data/resource errors. It uses only
        // this concrete JointVerifier, never a caller-selected generic verifier.
        self.journal.import_block(
            candidate.header.clone(),
            block.body(),
            crate::adapter::now().map_err(|_| Error::Context)?,
            &self.verifier,
        )?;
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
        Ok(checked)
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
    if d.binding != binding.id()
        || d.slot != context.slot()
        || d.previous != context.previous_decision()
        || d.header.parent != parent.block
        || d.header.genesis != parent.genesis
        || d.header.height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
    {
        return Err(Error::Context);
    }
    journal.reverify_block(&d.header, body, crate::adapter::now()?, verifier)?;
    // Snapshot only after the actual owner/header/application proof checks.
    // SourceSpec derives from immutable independently pinned NEW application.
    let application = binding.application()?;
    let spec = application.source_spec();
    let old = spec.control(journal.validated_shards(parent)?)?;
    let next = match Body::decode(body, journal.profile())? {
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
