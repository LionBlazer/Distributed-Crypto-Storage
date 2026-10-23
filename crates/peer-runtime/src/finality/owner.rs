//! Closed dispatch over the four real durable application owners.
use super::*;
use registry200_finality::{
    Checkpoint, Descriptor, RegistryFinality,
    joint::{DurableJointFinality, JointCandidate, JointCheckpoint},
    progress::{Candidate as ProgressCandidate, Checkpoint as ProgressCheckpoint, DurableFinality},
    word::{Candidate as WordCandidate, Checkpoint as WordCheckpoint},
};
use work_finality::consensus::{Action, Context, Timeout};

pub(super) enum Owner {
    Original(Box<RegistryFinality>),
    Joint(Box<DurableJointFinality>),
    Progress(Box<DurableFinality>),
    Word(Box<registry200_finality::word::DurableFinality>),
}
#[derive(Clone)]
pub(super) enum Pins {
    Original([u8; 32]),
    Joint([u8; 32]),
    Progress([u8; 32]),
    Word([u8; 32]),
}
#[derive(Clone)]
pub(super) enum Candidate {
    Original(Descriptor),
    Joint(JointCandidate),
    Progress(ProgressCandidate),
    Word(WordCandidate),
}
pub(super) enum Certificate {
    Original(Checkpoint),
    Joint(JointCheckpoint),
    Progress(ProgressCheckpoint),
    Word(WordCheckpoint),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub slot: u64,
    pub context: [u8; 32],
    pub parent: [u8; 32],
}
/// Public availability metadata only. It never supplies a verification receipt.
#[derive(Clone, Copy)]
pub(super) struct PendingSnapshot {
    pub current: Snapshot,
    pub candidate: Option<[u8; 32]>,
}
impl PendingSnapshot {
    pub fn candidate_at(self, current: Snapshot) -> Option<[u8; 32]> {
        (self.current == current)
            .then_some(self.candidate)
            .flatten()
    }
}
impl Pins {
    pub fn id(&self) -> [u8; 32] {
        match self {
            Self::Original(id) | Self::Joint(id) | Self::Progress(id) | Self::Word(id) => *id,
        }
    }
    pub fn candidate(&self, b: &[u8]) -> io::Result<Candidate> {
        match self {
            Self::Original(_) => Descriptor::decode(b)
                .map(Candidate::Original)
                .map_err(error),
            Self::Joint(_) => JointCandidate::decode(b)
                .map(Candidate::Joint)
                .map_err(error),
            Self::Progress(_) => ProgressCandidate::decode(b)
                .map(Candidate::Progress)
                .map_err(error),
            Self::Word(_) => WordCandidate::decode(b).map(Candidate::Word).map_err(error),
        }
    }
}
impl Candidate {
    pub fn slot(&self) -> u64 {
        match self {
            Self::Original(d) => d.slot(),
            Self::Joint(d) => d.slot(),
            Self::Progress(d) => d.slot(),
            Self::Word(d) => d.slot(),
        }
    }
    pub fn header(&self) -> &version_journal::Header {
        match self {
            Self::Original(d) => d.header(),
            Self::Joint(d) => d.header(),
            Self::Progress(d) => d.header(),
            Self::Word(d) => d.header(),
        }
    }
}
impl Certificate {
    pub fn candidate(&self) -> Candidate {
        match self {
            Self::Original(c) => Candidate::Original(c.descriptor().clone()),
            Self::Joint(c) => Candidate::Joint(c.candidate().clone()),
            Self::Progress(c) => Candidate::Progress(c.candidate().clone()),
            Self::Word(c) => Candidate::Word(c.candidate().clone()),
        }
    }
}
impl Owner {
    pub fn pins(&self) -> io::Result<Pins> {
        match self {
            Self::Original(o) => o.binding().map(|b| Pins::Original(b.id())).map_err(error),
            Self::Joint(o) => o.binding().map(|b| Pins::Joint(b.id())).map_err(error),
            Self::Progress(o) => o.binding().map(|b| Pins::Progress(b.id())).map_err(error),
            Self::Word(o) => o.binding().map(|b| Pins::Word(b.id())).map_err(error),
        }
    }
    pub fn context(&self) -> io::Result<&Context> {
        match self {
            Self::Original(o) => Ok(o.context()),
            Self::Joint(o) => o.context().map_err(error),
            Self::Progress(o) => o.context().map_err(error),
            Self::Word(o) => o.context().map_err(error),
        }
    }
    pub fn snapshot(&self) -> io::Result<Snapshot> {
        let context = self.context()?;
        let parent = match self {
            Self::Original(o) => o.finalized_head().map_err(error)?.map(|h| h.head().block),
            Self::Joint(o) => o.finalized_parent().map_err(error)?.map(|h| h.head().block),
            Self::Progress(o) => o.finalized_parent().map_err(error)?.map(|h| h.head().block),
            Self::Word(o) => o.finalized_parent().map_err(error)?.map(|h| h.head().block),
        }
        .unwrap_or(context.journal_genesis());
        Ok(Snapshot {
            slot: context.slot(),
            context: context.id(),
            parent,
        })
    }
    pub fn active_timer(&self) -> io::Result<Option<Timeout>> {
        match self {
            Self::Original(o) => match o.timeout() {
                Ok(t) => Ok(Some(t)),
                Err(registry200_finality::Error::Consensus(
                    work_finality::consensus::Error::Stale,
                )) => Ok(None),
                Err(e) => Err(error(e)),
            },
            Self::Joint(o) => match o.timeout() {
                Ok(t) => Ok(Some(t)),
                Err(registry200_finality::joint::Error::Consensus(
                    work_finality::consensus::Error::Stale,
                )) => Ok(None),
                Err(e) => Err(error(e)),
            },
            Self::Progress(o) => match o.timeout() {
                Ok(t) => Ok(Some(t)),
                Err(registry200_finality::progress::Error::Consensus(
                    work_finality::consensus::Error::Stale,
                )) => Ok(None),
                Err(e) => Err(error(e)),
            },
            Self::Word(o) => match o.timeout() {
                Ok(t) => Ok(Some(t)),
                Err(registry200_finality::word::Error::Consensus(
                    work_finality::consensus::Error::Stale,
                )) => Ok(None),
                Err(e) => Err(error(e)),
            },
        }
    }
    pub fn outbound(&self) -> io::Result<Vec<Action>> {
        match self {
            Self::Original(o) => o.outbound().map_err(error),
            Self::Joint(o) => o.outbound().map_err(error),
            Self::Progress(o) => o.outbound().map_err(error),
            Self::Word(o) => o.outbound().map_err(error),
        }
    }
    pub fn block(&self, id: [u8; 32]) -> io::Result<CandidateBlock> {
        match self {
            Self::Original(o) => o.candidate_block(id).map_err(error),
            Self::Joint(o) => o.candidate_block(id).map_err(error),
            Self::Progress(o) => o.candidate_block(id).map_err(error),
            Self::Word(o) => o.candidate_block(id).map_err(error),
        }
    }
    pub fn has(&self, id: [u8; 32]) -> io::Result<bool> {
        match self {
            Self::Original(o) => o.has_candidate(id).map_err(error),
            Self::Joint(o) => o.has_candidate(id).map_err(error),
            Self::Progress(o) => o.has_candidate(id).map_err(error),
            Self::Word(o) => o.has_candidate(id).map_err(error),
        }
    }
    pub fn checkpoint(&mut self, slot: u64) -> io::Result<Option<Certificate>> {
        match self {
            Self::Original(o) => o
                .checkpoint_after(slot)
                .map(|c| c.map(Certificate::Original))
                .map_err(error),
            Self::Joint(o) => o
                .checkpoint_after(slot)
                .map(|c| c.map(Certificate::Joint))
                .map_err(error),
            Self::Progress(o) => o
                .checkpoint_after(slot)
                .map(|c| c.map(Certificate::Progress))
                .map_err(error),
            Self::Word(o) => o
                .checkpoint_after(slot)
                .map(|c| c.map(Certificate::Word))
                .map_err(error),
        }
    }
    pub fn restore_word_transport(
        &self,
        header: version_journal::Header,
        body: Vec<u8>,
    ) -> io::Result<CandidateBlock> {
        match self {
            Self::Word(owner) => owner.restore_transport_body(header, body).map_err(error),
            _ => Err(invalid()),
        }
    }
    pub fn import(&mut self, b: &CandidateBlock) -> io::Result<Candidate> {
        match self {
            Self::Original(o) => o
                .import_candidate(b.header().clone(), b.body())
                .map(Candidate::Original)
                .map_err(error),
            Self::Joint(o) => o
                .import_candidate(b.header().clone(), b.body())
                .map(Candidate::Joint)
                .map_err(error),
            Self::Progress(o) => o
                .import_candidate(b.header().clone(), b.body())
                .map(Candidate::Progress)
                .map_err(error),
            Self::Word(o) => o
                .import_candidate(b.header().clone(), b.body())
                .map(Candidate::Word)
                .map_err(error),
        }
    }
    pub fn propose(&mut self, c: &Candidate) -> io::Result<()> {
        match (self, c) {
            (Self::Original(o), Candidate::Original(c)) => match o.propose(c) {
                Ok(_)
                | Err(registry200_finality::Error::Consensus(
                    work_finality::consensus::Error::WrongProposer
                    | work_finality::consensus::Error::Stale,
                )) => Ok(()),
                Err(e) => Err(error(e)),
            },
            (Self::Joint(o), Candidate::Joint(c)) => match o.propose(c) {
                Ok(_)
                | Err(registry200_finality::joint::Error::Consensus(
                    work_finality::consensus::Error::WrongProposer
                    | work_finality::consensus::Error::Stale,
                )) => Ok(()),
                Err(e) => Err(error(e)),
            },
            (Self::Progress(o), Candidate::Progress(c)) => match o.propose(c) {
                Ok(_)
                | Err(registry200_finality::progress::Error::Consensus(
                    work_finality::consensus::Error::WrongProposer
                    | work_finality::consensus::Error::Stale,
                )) => Ok(()),
                Err(e) => Err(error(e)),
            },
            (Self::Word(o), Candidate::Word(c)) => match o.propose(c) {
                Ok(_)
                | Err(registry200_finality::word::Error::Consensus(
                    work_finality::consensus::Error::WrongProposer
                    | work_finality::consensus::Error::Stale,
                )) => Ok(()),
                Err(e) => Err(error(e)),
            },
            _ => Err(invalid()),
        }
    }
    pub fn receive(&mut self, b: &[u8]) -> io::Result<()> {
        match self {
            Self::Original(o) => o.receive(b).map(|_| ()).map_err(error),
            Self::Joint(o) => o.receive(b).map(|_| ()).map_err(error),
            Self::Progress(o) => o.receive(b).map(|_| ()).map_err(error),
            Self::Word(o) => o.receive(b).map(|_| ()).map_err(error),
        }
    }
    pub fn commit(&mut self, c: &Certificate) -> io::Result<()> {
        match (self, c) {
            (Self::Original(o), Certificate::Original(c)) => {
                o.receive_checkpoint(c).map(|_| ()).map_err(error)
            }
            (Self::Joint(o), Certificate::Joint(c)) => {
                o.receive_checkpoint(c).map(|_| ()).map_err(error)
            }
            (Self::Progress(o), Certificate::Progress(c)) => {
                o.receive_checkpoint(c).map(|_| ()).map_err(error)
            }
            (Self::Word(o), Certificate::Word(c)) => {
                o.receive_checkpoint(c).map(|_| ()).map_err(error)
            }
            _ => Err(invalid()),
        }
    }
    pub fn timeout(&mut self, t: Timeout) -> io::Result<()> {
        match self {
            Self::Original(o) => o.on_timeout(t).map(|_| ()).map_err(error),
            Self::Joint(o) => o.on_timeout(t).map(|_| ()).map_err(error),
            Self::Progress(o) => o.on_timeout(t).map(|_| ()).map_err(error),
            Self::Word(o) => o.on_timeout(t).map(|_| ()).map_err(error),
        }
    }
}

impl Candidate {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Original(c) => c.encode().to_vec(),
            Self::Joint(c) => c.encode().to_vec(),
            Self::Progress(c) => c.encode().to_vec(),
            Self::Word(c) => c.encode().to_vec(),
        }
    }
}
impl Certificate {
    pub fn round(&self) -> u64 {
        match self {
            Self::Original(c) => c.round(),
            Self::Joint(c) => c.round(),
            Self::Progress(c) => c.round(),
            Self::Word(c) => c.round(),
        }
    }
    pub fn certificate(&self) -> &[u8] {
        match self {
            Self::Original(c) => c.certificate(),
            Self::Joint(c) => c.certificate(),
            Self::Progress(c) => c.certificate(),
            Self::Word(c) => c.certificate(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Original(c) => c.encode(),
            Self::Joint(c) => c.encode(),
            Self::Progress(c) => c.encode(),
            Self::Word(c) => c.encode(),
        }
    }
    pub fn decode(kind: super::proof_application::Kind, b: &[u8]) -> io::Result<Self> {
        match kind {
            super::proof_application::Kind::Joint => {
                JointCheckpoint::decode(b).map(Self::Joint).map_err(error)
            }
            super::proof_application::Kind::Progress => ProgressCheckpoint::decode(b)
                .map(Self::Progress)
                .map_err(error),
            super::proof_application::Kind::Word => {
                WordCheckpoint::decode(b).map(Self::Word).map_err(error)
            }
        }
    }
}
