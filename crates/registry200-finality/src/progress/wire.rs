//! Bounded untrusted metadata. Decoding supplies no application/QC authority.
use super::{Binding, Error, Hash, Result};
use crate::codec::Reader;
use version_journal::Header;
use work_finality::consensus::Context;

pub const CANDIDATE_BYTES: usize = 8 + 32 + 8 + 32 + version_journal::HEADER_BYTES;
pub const MAX_CHECKPOINT_BYTES: usize =
    8 + CANDIDATE_BYTES + 8 + 4 + work_finality::MAX_CERTIFICATE_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub(crate) binding: Hash,
    pub(crate) slot: u64,
    pub(crate) previous: Hash,
    pub(crate) header: Header,
}
impl Candidate {
    /// A proposed value only. The context, header, owner and proofs are all
    /// independently checked again by History::apply.
    pub fn for_context(binding: &Binding, context: &Context, header: Header) -> Result<Self> {
        if context.rules().id() != binding.rules().id()
            || context.network_id() != binding.work_genesis().id()
            || context.journal_genesis() != binding.journal_genesis().id()?
        {
            return Err(Error::Context);
        }
        Ok(Self {
            binding: binding.id(),
            slot: context.slot(),
            previous: context.previous_decision(),
            header,
        })
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn slot(&self) -> u64 {
        self.slot
    }
    pub fn encode(&self) -> [u8; CANDIDATE_BYTES] {
        let mut b = [0; CANDIDATE_BYTES];
        b[..8].copy_from_slice(b"DCSPCV02");
        b[8..40].copy_from_slice(&self.binding);
        b[40..48].copy_from_slice(&self.slot.to_le_bytes());
        b[48..80].copy_from_slice(&self.previous);
        b[80..].copy_from_slice(&self.header.encode());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != CANDIDATE_BYTES || &b[..8] != b"DCSPCV02" {
            return Err(Error::Encoding);
        }
        let x = Self {
            binding: b[8..40].try_into().unwrap(),
            slot: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            previous: b[48..80].try_into().unwrap(),
            header: Header::decode(&b[80..])?,
        };
        if x.slot == 0 || x.encode() != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
}
pub struct Checkpoint {
    candidate: Candidate,
    round: u64,
    certificate: Vec<u8>,
}
impl Checkpoint {
    pub fn new(candidate: Candidate, round: u64, certificate: Vec<u8>) -> Result<Self> {
        if certificate.is_empty()
            || certificate.len() > work_finality::MAX_CERTIFICATE_BYTES
            || round > work_finality::consensus::MAX_ROUND
        {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            candidate,
            round,
            certificate,
        })
    }
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }
    pub fn round(&self) -> u64 {
        self.round
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + CANDIDATE_BYTES + 12 + self.certificate.len());
        b.extend_from_slice(b"DCSPCQ02");
        b.extend_from_slice(&self.candidate.encode());
        b.extend_from_slice(&self.round.to_le_bytes());
        b.extend_from_slice(&(self.certificate.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.certificate);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut r = Reader::new(b);
        if r.array::<8>()? != *b"DCSPCQ02" {
            return Err(Error::Encoding);
        }
        let candidate = Candidate::decode(r.take(CANDIDATE_BYTES)?)?;
        let round = r.u64()?;
        let n = r.u32()? as usize;
        if n == 0
            || n > work_finality::MAX_CERTIFICATE_BYTES
            || 8 + CANDIDATE_BYTES + 12 + n != b.len()
        {
            return Err(Error::Encoding);
        }
        let certificate = r.take(n)?.to_vec();
        r.end()?;
        Self::new(candidate, round, certificate)
    }
}
