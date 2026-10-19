//! Signer-free independent actual application/QC verification. No callback.
use crate::{
    Binding, CandidateBlock, Checkpoint, Error, Hash, Result,
    adapter::{now, verify_candidate},
};
use registry200_journal::RegistryVerifier;
use version_journal::{HeadRef, Journal};
use work_finality::consensus::Context;

/// Independently checked quorum + original application proof under fixed pins.
/// In-memory client state, not a durable signer floor, network freshness barrier
/// or SQL grant. The original peer's status/metadata cannot construct this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    binding: Hash,
    head: HeadRef,
    slot: u64,
    decision: Hash,
}
impl VerifiedCheckpoint {
    pub fn binding_id(self) -> Hash {
        self.binding
    }
    pub fn head(self) -> HeadRef {
        self.head
    }
    pub fn slot(self) -> u64 {
        self.slot
    }
    pub fn decision_id(self) -> Hash {
        self.decision
    }
}
pub struct Follower {
    binding: Binding,
    verifier: RegistryVerifier,
    journal: Journal,
    context: Context,
    last: Option<(Context, VerifiedCheckpoint)>,
}
impl Follower {
    pub fn new(binding: Binding) -> Result<Self> {
        let verifier = RegistryVerifier::new(binding.application()?, binding.journal_genesis())?;
        let journal = Journal::new(binding.journal_genesis().clone())?;
        let context = binding.initial_context().clone();
        Ok(Self {
            binding,
            verifier,
            journal,
            context,
            last: None,
        })
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn checked_head(&self) -> Option<VerifiedCheckpoint> {
        self.last.as_ref().map(|(_, h)| *h)
    }
    pub fn apply(
        &mut self,
        checkpoint: &Checkpoint,
        block: &CandidateBlock,
    ) -> Result<VerifiedCheckpoint> {
        let d = checkpoint.descriptor();
        if d.header() != block.header() {
            return Err(Error::WrongContext);
        }
        let duplicate = d.slot() != self.context.slot();
        let context = if duplicate {
            let (old, _) = self.last.as_ref().ok_or(Error::WrongContext)?;
            if old.slot() != d.slot() {
                return Err(Error::WrongContext);
            }
            old
        } else {
            &self.context
        };
        let decision =
            context.verify_commit(&d.encode(), checkpoint.round(), checkpoint.certificate())?;
        let parent = if duplicate {
            let header = self.journal.header(block.header().parent);
            match header {
                Some(h) => HeadRef {
                    genesis: h.genesis,
                    database: self.binding.journal_genesis().database,
                    block: h.id(),
                    height: h.height,
                    state_root: h.state_root,
                },
                None if block.header().parent == self.journal.genesis_id() => {
                    self.journal.genesis_head()
                }
                None => return Err(Error::WrongContext),
            }
        } else {
            self.journal.ancestry_floor()
        };
        let head = verify_candidate(
            &self.binding,
            &self.journal,
            &self.verifier,
            context,
            parent,
            d,
            block.body(),
        )?;
        let next = context.after_decision(&decision)?;
        if duplicate {
            let (_, previous) = self.last.as_ref().ok_or(Error::WrongContext)?;
            if previous.decision != decision.semantic_id() || next.id() != self.context.id() {
                return Err(Error::WrongContext);
            }
            return Ok(*previous);
        }
        self.journal
            .import_block(block.header().clone(), block.body(), now()?, &self.verifier)?;
        self.journal.restrict_ancestry_floor(head)?;
        let checked = VerifiedCheckpoint {
            binding: self.binding.id(),
            head,
            slot: context.slot(),
            decision: decision.semantic_id(),
        };
        self.last = Some((context.clone(), checked));
        self.context = next;
        Ok(checked)
    }
}
