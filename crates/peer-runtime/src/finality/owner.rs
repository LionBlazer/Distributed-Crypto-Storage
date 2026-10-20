//! Closed dispatch over the two real durable application owners.
use super::*;
use registry200_finality::{
    Checkpoint, Descriptor, RegistryFinality,
    joint::{DurableJointFinality, JointCandidate, JointCheckpoint},
};
use work_finality::consensus::{Action, Context, Timeout};

pub(super) enum Owner {
    Original(Box<RegistryFinality>),
    Joint(Box<DurableJointFinality>),
}
#[derive(Clone)]
pub(super) enum Pins {
    Original([u8; 32]),
    Joint([u8; 32]),
}
#[derive(Clone)]
pub(super) enum Candidate {
    Original(Descriptor),
    Joint(JointCandidate),
}
pub(super) enum Certificate {
    Original(Checkpoint),
    Joint(JointCheckpoint),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub slot: u64,
    pub context: [u8; 32],
    pub parent: [u8; 32],
}
impl Pins {
    pub fn id(&self) -> [u8; 32] {
        match self {
            Self::Original(id) | Self::Joint(id) => *id,
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
        }
    }
}
impl Candidate {
    pub fn slot(&self) -> u64 {
        match self {
            Self::Original(d) => d.slot(),
            Self::Joint(d) => d.slot(),
        }
    }
    pub fn header(&self) -> &version_journal::Header {
        match self {
            Self::Original(d) => d.header(),
            Self::Joint(d) => d.header(),
        }
    }
}
impl Certificate {
    pub fn candidate(&self) -> Candidate {
        match self {
            Self::Original(c) => Candidate::Original(c.descriptor().clone()),
            Self::Joint(c) => Candidate::Joint(c.candidate().clone()),
        }
    }
}
impl Owner {
    pub fn pins(&self) -> io::Result<Pins> {
        match self {
            Self::Original(o) => o.binding().map(|b| Pins::Original(b.id())).map_err(error),
            Self::Joint(o) => o.binding().map(|b| Pins::Joint(b.id())).map_err(error),
        }
    }
    pub fn context(&self) -> io::Result<&Context> {
        match self {
            Self::Original(o) => Ok(o.context()),
            Self::Joint(o) => o.context().map_err(error),
        }
    }
    pub fn snapshot(&self) -> io::Result<Snapshot> {
        let context = self.context()?;
        let parent = match self {
            Self::Original(o) => o.finalized_head().map_err(error)?.map(|h| h.head().block),
            Self::Joint(o) => o.finalized_parent().map_err(error)?.map(|h| h.head().block),
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
        }
    }
    pub fn outbound(&self) -> io::Result<Vec<Action>> {
        match self {
            Self::Original(o) => o.outbound().map_err(error),
            Self::Joint(o) => o.outbound().map_err(error),
        }
    }
    pub fn block(&self, id: [u8; 32]) -> io::Result<CandidateBlock> {
        match self {
            Self::Original(o) => o.candidate_block(id).map_err(error),
            Self::Joint(o) => o.candidate_block(id).map_err(error),
        }
    }
    pub fn has(&self, id: [u8; 32]) -> io::Result<bool> {
        match self {
            Self::Original(o) => o.has_candidate(id).map_err(error),
            Self::Joint(o) => o.has_candidate(id).map_err(error),
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
            _ => Err(invalid()),
        }
    }
    pub fn receive(&mut self, b: &[u8]) -> io::Result<()> {
        match self {
            Self::Original(o) => o.receive(b).map(|_| ()).map_err(error),
            Self::Joint(o) => o.receive(b).map(|_| ()).map_err(error),
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
            _ => Err(invalid()),
        }
    }
    pub fn timeout(&mut self, t: Timeout) -> io::Result<()> {
        match self {
            Self::Original(o) => o.on_timeout(t).map(|_| ()).map_err(error),
            Self::Joint(o) => o.on_timeout(t).map(|_| ()).map_err(error),
        }
    }
}
