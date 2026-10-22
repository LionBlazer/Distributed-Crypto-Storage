//! Keyless Word lineage with fixed native verification and independent intent.
use super::{
    Binding, CandidateBlock, Checkpoint, Error, Result, VerifiedParent,
    verification::{candidate_control, parent_heads, require_candidate_context},
};
use registry200_joint::word::{OperationId, Verifier};
use version_journal::{Body, HeadRef, Header, Journal};
use work_finality::consensus::Context;

struct Last {
    context: Context,
    before: HeadRef,
    checked: VerifiedParent,
}
/// In-memory historical proof/QC receiver. No signer, freshness or SQL authority.
/// The complete immutable Source is verified at installation; each received
/// operation still runs the original native Word verifier and weighted QC check.
/// ```compile_fail
/// fn forge(){ let _=registry200_finality::word::History { binding:todo!(), verifier:todo!(), journal:todo!(), context:todo!(), last:todo!(), poisoned:false }; }
/// ```
pub struct History {
    binding: Binding,
    verifier: Verifier,
    journal: Journal,
    context: Context,
    last: Option<Last>,
    poisoned: bool,
}
impl History {
    pub fn new(binding: Binding) -> Result<Self> {
        let verifier = Verifier::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
            binding.source_bytes(),
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
        Ok(self.last.as_ref().map(|last| &last.checked))
    }
    /// Author mining metadata from this exact checked floor and actual target
    /// history. This grants no proof, currentness, publication or SQL authority.
    pub fn candidate_header(&self, body: &Body, timestamp: u64, now: u64) -> Result<Header> {
        self.live()?;
        if let Body::Transition(transition) = body {
            transition.check_authorization(
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
    /// Follow another historical operation with full native/owner/QC checks.
    /// This supplies no receipt asserting that it was the caller's own request.
    pub fn apply(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
    ) -> Result<VerifiedParent> {
        Ok(self.apply_owned(checkpoint, block, None)?.parent)
    }
    /// Independently retain expected from the ORIGINAL request/evidence before
    /// sending it. Deriving that pin from a responder cannot establish intent.
    /// Only the exact operation and its genuine proofs/QC can produce a receipt.
    pub fn apply_operation(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
        expected: OperationId,
    ) -> Result<VerifiedOperation> {
        let applied = self.apply_owned(checkpoint, block, Some(expected))?;
        Ok(VerifiedOperation {
            parent: applied.parent,
            operation: applied
                .operation
                .expect("closed own-operation mode requires native receipt"),
        })
    }
    fn apply_owned(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
        expected: Option<OperationId>,
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
        require_candidate_context(&self.binding, context, parent, candidate)?;
        let decision = context.verify_commit(
            &candidate.encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )?;
        // Every fallible successor/intent/control/native check precedes commit.
        let next = context.after_decision(&decision)?;
        let head = HeadRef {
            genesis: candidate.header.genesis,
            database: self.binding.journal_genesis().database,
            block: candidate.header.id(),
            height: candidate.header.height,
            state_root: candidate.header.state_root,
        };
        let old = parent_heads(&self.binding, &self.journal, parent)?;
        let now = crate::adapter::now()?;
        if duplicate {
            let last = self.last.as_ref().ok_or(Error::Context)?;
            if decision.semantic_id() != last.checked.decision_id()
                || next.id() != self.context.id()
                || head != last.checked.head()
            {
                return Err(Error::Context);
            }
            // The latest selected block is below the current ancestry floor.
            // Recheck it read-only under its retained REAL prior context.
            let operation = match expected {
                Some(id) => Some(self.verifier.check_block(
                    &self.journal,
                    &candidate.header,
                    block.body(),
                    now,
                    id,
                )?),
                None => {
                    self.journal.reverify_block(
                        &candidate.header,
                        block.body(),
                        now,
                        &self.verifier,
                    )?;
                    None
                }
            };
            if candidate_control(&self.binding, old, block.body())? != last.checked.control() {
                return Err(Error::Context);
            }
            return Ok(Applied {
                parent: last.checked.clone(),
                operation,
            });
        }
        let previous = context.clone();
        let (pending, operation) = match expected {
            Some(id) => {
                let (pending, checked) = self.verifier.prepare_import(
                    &mut self.journal,
                    candidate.header.clone(),
                    block.body(),
                    now,
                    id,
                )?;
                (pending, Some(checked))
            }
            None => (
                self.journal.prepare_import(
                    candidate.header.clone(),
                    block.body(),
                    now,
                    &self.verifier,
                )?,
                None,
            ),
        };
        let control = candidate_control(&self.binding, old, block.body())?;
        let checked = VerifiedParent::checked(
            self.binding.id(),
            head,
            context.slot(),
            decision.semantic_id(),
            control,
        );
        // This exact unpublished import has already passed the fixed verifier;
        // argument-free commit accepts no replacement Body/verifier/receipt.
        pending.commit();
        if let Err(error) = self.journal.restrict_ancestry_floor(head) {
            self.poisoned = true;
            return Err(error.into());
        }
        self.last = Some(Last {
            context: previous,
            before: parent,
            checked: checked.clone(),
        });
        self.context = next;
        Ok(Applied {
            parent: checked,
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
    operation: Option<registry200_joint::word::VerifiedOperation>,
}
/// Exact own historical operation with fresh native verification and weighted QC.
/// No current head, row-lock lease, SQL acceptance or serialized verdict is stored.
/// ```compile_fail
/// fn clone(x:&registry200_finality::word::VerifiedOperation)->registry200_finality::word::VerifiedOperation { x.clone() }
/// ```
/// ```compile_fail
/// fn forge(){ let _=registry200_finality::word::VerifiedOperation { parent:todo!(), operation:todo!() }; }
/// ```
pub struct VerifiedOperation {
    parent: VerifiedParent,
    operation: registry200_joint::word::VerifiedOperation,
}
impl VerifiedOperation {
    pub fn parent(&self) -> &VerifiedParent {
        &self.parent
    }
    pub fn operation(&self) -> &registry200_joint::word::VerifiedOperation {
        &self.operation
    }
}

#[cfg(test)]
impl History {
    pub(super) fn journal_state_for_test(
        &self,
        candidate: super::Hash,
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
