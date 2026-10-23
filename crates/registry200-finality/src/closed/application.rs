//! The only installed application choices. Each binding stays paired with its
//! actual fixed verifier; no caller-selected verifier or success flag exists.
use super::*;
use crate::{joint, progress, word};
use registry200_joint::progress::{ProgressDepot, ProgressEvidenceIngress, ProgressVerifier};
use registry200_joint::{JointDepot, JointEvidenceIngress, JointVerifier};
use version_journal::{Genesis, Journal, TransitionStatement, TransitionVerifier};
use work_finality::{Genesis as WorkGenesis, consensus::Rules};

pub(crate) enum Installation {
    Joint(joint::JointBinding),
    Progress(progress::Binding),
    Word(word::Binding),
}
#[derive(Clone, Copy)]
pub(super) enum BindingRef<'a> {
    Joint(&'a joint::JointBinding),
    Progress(&'a progress::Binding),
    Word(&'a word::Binding),
}
pub(super) enum InstalledApplication {
    Joint {
        binding: joint::JointBinding,
        verifier: Box<JointVerifier>,
    },
    Progress {
        binding: progress::Binding,
        verifier: Box<ProgressVerifier>,
    },
    Word {
        binding: word::Binding,
        verifier: Box<registry200_joint::word::Verifier>,
    },
}
pub(crate) enum Ingress {
    Joint(JointEvidenceIngress),
    Progress(ProgressEvidenceIngress),
    Word,
}
impl Installation {
    pub(super) fn binding(&self) -> BindingRef<'_> {
        match self {
            Self::Joint(b) => BindingRef::Joint(b),
            Self::Progress(b) => BindingRef::Progress(b),
            Self::Word(b) => BindingRef::Word(b),
        }
    }
    pub(super) fn open(&self, quota: &ParticipantQuota) -> Result<(InstalledApplication, Ingress)> {
        match self {
            Self::Word(binding) => {
                let verifier = registry200_joint::word::Verifier::new(
                    binding.application_descriptor().clone(),
                    binding.journal_genesis(),
                    binding.source_bytes(),
                )?;
                Ok((
                    InstalledApplication::Word {
                        binding: binding.clone(),
                        verifier: Box::new(verifier),
                    },
                    Ingress::Word,
                ))
            }
            Self::Joint(binding) => {
                let depot = JointDepot::open(quota.depot_budget())?;
                let ingress = depot.ingress();
                let verifier = JointVerifier::new(
                    binding.application_descriptor().clone(),
                    binding.journal_genesis(),
                    binding.setup_claim(),
                    depot,
                )?;
                Ok((
                    InstalledApplication::Joint {
                        binding: binding.clone(),
                        verifier: Box::new(verifier),
                    },
                    Ingress::Joint(ingress),
                ))
            }
            Self::Progress(binding) => {
                let depot =
                    ProgressDepot::open(quota.depot_budget(), binding.application_descriptor())?;
                let ingress = depot.ingress();
                let verifier = ProgressVerifier::new(
                    binding.application_descriptor().clone(),
                    binding.journal_genesis(),
                    binding.setup_claim(),
                    depot,
                )?;
                Ok((
                    InstalledApplication::Progress {
                        binding: binding.clone(),
                        verifier: Box::new(verifier),
                    },
                    Ingress::Progress(ingress),
                ))
            }
        }
    }
}
impl<'a> BindingRef<'a> {
    pub(super) fn id(self) -> Hash {
        match self {
            Self::Joint(b) => b.id(),
            Self::Progress(b) => b.id(),
            Self::Word(b) => b.id(),
        }
    }
    pub(super) fn rules(self) -> &'a Rules {
        match self {
            Self::Joint(b) => b.rules(),
            Self::Progress(b) => b.rules(),
            Self::Word(b) => b.rules(),
        }
    }
    pub(super) fn work_genesis(self) -> &'a WorkGenesis {
        match self {
            Self::Joint(b) => b.work_genesis(),
            Self::Progress(b) => b.work_genesis(),
            Self::Word(b) => b.work_genesis(),
        }
    }
    pub(super) fn journal_genesis(self) -> &'a Genesis {
        match self {
            Self::Joint(b) => b.journal_genesis(),
            Self::Progress(b) => b.journal_genesis(),
            Self::Word(b) => b.journal_genesis(),
        }
    }
    pub(super) fn initial_context(self) -> &'a Context {
        match self {
            Self::Joint(b) => b.initial_context(),
            Self::Progress(b) => b.initial_context(),
            Self::Word(b) => b.initial_context(),
        }
    }
    pub(super) fn namespace(self) -> Hash {
        match self {
            Self::Joint(b) => b.namespace(),
            Self::Progress(b) => b.namespace(),
            Self::Word(b) => b.namespace(),
        }
    }
    pub(super) fn require_durable(self) -> Result<()> {
        match self {
            Self::Joint(b) => b.require_durable(),
            Self::Progress(b) => b.require_durable(),
            Self::Word(b) => b.require_durable(),
        }
    }
    pub(super) fn pins(self) -> Pins<'a> {
        match self {
            Self::Joint(b) => Pins::Joint(b),
            Self::Progress(b) => Pins::Progress(b),
            Self::Word(b) => Pins::Word(b),
        }
    }
    pub(super) fn decode(self, bytes: &[u8]) -> Result<Value> {
        match self {
            Self::Word(_) => {
                let c = word::Candidate::decode(bytes)?;
                Ok(Value {
                    binding: c.binding,
                    slot: c.slot,
                    previous: c.previous,
                    header: c.header,
                    magic: *b"DCSWCV01",
                })
            }
            Self::Joint(_) => {
                let c = joint::JointCandidate::decode(bytes)?;
                Ok(Value {
                    binding: c.binding,
                    slot: c.slot,
                    previous: c.previous,
                    header: c.header,
                    magic: *b"DCSJCV01",
                })
            }
            Self::Progress(_) => {
                let c = progress::Candidate::decode(bytes)?;
                Ok(Value {
                    binding: c.binding,
                    slot: c.slot,
                    previous: c.previous,
                    header: c.header,
                    magic: *b"DCSPCV02",
                })
            }
        }
    }
    pub(super) fn candidate(self, context: &Context, header: Header) -> Result<Value> {
        let encoded = match self {
            Self::Joint(b) => joint::JointCandidate::for_context(b, context, header)?.encode(),
            Self::Progress(b) => progress::Candidate::for_context(b, context, header)?.encode(),
            Self::Word(b) => word::Candidate::for_context(b, context, header)?.encode(),
        };
        self.decode(&encoded)
    }
    pub(super) fn require_context(
        self,
        context: &Context,
        parent: HeadRef,
        c: &Value,
    ) -> Result<()> {
        if context.rules().id() != self.rules().id()
            || context.network_id() != self.work_genesis().id()
            || context.journal_genesis() != self.journal_genesis().id()?
            || c.binding != self.id()
            || c.slot != context.slot()
            || c.previous != context.previous_decision()
            || c.header.genesis != parent.genesis
            || c.header.parent != parent.block
            || c.header.height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub(super) fn parent_heads(
        self,
        journal: &Journal,
        parent: HeadRef,
    ) -> Result<version_journal::HeadPair> {
        match self {
            Self::Joint(b) => joint::history::parent_heads(b, journal, parent),
            Self::Progress(b) => progress::history::parent_heads(b, journal, parent),
            Self::Word(b) => word::verification::parent_heads(b, journal, parent),
        }
    }
    pub(super) fn candidate_control(
        self,
        old: version_journal::HeadPair,
        body: &[u8],
    ) -> Result<ApplicationControl> {
        match self {
            Self::Joint(b) => {
                joint::history::candidate_control(b, old, body).map(ApplicationControl::Registry)
            }
            Self::Progress(b) => {
                progress::history::candidate_control(b, old, body).map(ApplicationControl::Registry)
            }
            Self::Word(b) => {
                word::verification::candidate_control(b, old, body).map(ApplicationControl::Word)
            }
        }
    }
}
impl InstalledApplication {
    pub(super) fn restore_word_transport(
        &self,
        header: Header,
        compact: Vec<u8>,
    ) -> Result<CandidateBlock> {
        match self {
            Self::Word { binding, verifier } => {
                word::transport::restore_body(binding, verifier, header, compact)
            }
            Self::Joint { .. } | Self::Progress { .. } => Err(Error::Binding),
        }
    }
    pub(super) fn binding(&self) -> BindingRef<'_> {
        match self {
            Self::Joint { binding, .. } => BindingRef::Joint(binding),
            Self::Progress { binding, .. } => BindingRef::Progress(binding),
            Self::Word { binding, .. } => BindingRef::Word(binding),
        }
    }
    pub(super) fn verify_candidate(
        &self,
        journal: &Journal,
        context: &Context,
        parent: HeadRef,
        c: &Value,
        body: &[u8],
    ) -> Result<ApplicationControl> {
        match self {
            Self::Joint { binding, verifier } => {
                let candidate = joint::JointCandidate::decode(&c.encode())?;
                joint::history::verify_candidate(
                    binding, journal, verifier, context, parent, &candidate, body,
                )
                .map(ApplicationControl::Registry)
            }
            Self::Progress { binding, verifier } => {
                let candidate = progress::Candidate::decode(&c.encode())?;
                progress::history::verify_candidate(
                    binding, journal, verifier, context, parent, &candidate, body,
                )
                .map(ApplicationControl::Registry)
            }
            Self::Word { binding, verifier } => {
                let candidate = word::Candidate::decode(&c.encode())?;
                word::verification::verify_candidate(
                    binding, journal, verifier, context, parent, &candidate, body,
                )
                .map(ApplicationControl::Word)
            }
        }
    }
}
impl TransitionVerifier for InstalledApplication {
    fn verify(&self, s: TransitionStatement<'_>) -> version_journal::Result<()> {
        match self {
            Self::Joint { verifier, .. } => verifier.verify(s),
            Self::Progress { verifier, .. } => verifier.verify(s),
            Self::Word { verifier, .. } => verifier.verify(s),
        }
    }
}
// Neutral private metadata only. It can never be decoded or supplied publicly.
pub(super) struct Value {
    pub(super) binding: Hash,
    pub(super) slot: u64,
    pub(super) previous: Hash,
    pub(super) header: Header,
    magic: [u8; 8],
}
impl Value {
    pub(super) fn encode(&self) -> [u8; crate::DESCRIPTOR_BYTES] {
        let mut b = [0; crate::DESCRIPTOR_BYTES];
        b[..8].copy_from_slice(&self.magic);
        b[8..40].copy_from_slice(&self.binding);
        b[40..48].copy_from_slice(&self.slot.to_le_bytes());
        b[48..80].copy_from_slice(&self.previous);
        b[80..].copy_from_slice(&self.header.encode());
        b
    }
}
