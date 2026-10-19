//! Untrusted bounded public exports. Decoding is never finality/proof authority.
use crate::{DESCRIPTOR_BYTES, Descriptor, Error, Hash, Result, codec::Reader, digest};
use version_journal::{HEADER_BYTES, Header, MAX_BODY_BYTES};

pub const MAX_BLOCK_BYTES: usize = 8 + HEADER_BYTES + 4 + MAX_BODY_BYTES;
pub const MAX_CHECKPOINT_BYTES: usize =
    8 + DESCRIPTOR_BYTES + 8 + 4 + work_finality::MAX_CERTIFICATE_BYTES;

pub fn export_profile_digest() -> Hash {
    digest(
        b"dcs/registry200-finality/exports/v1",
        &[
            &crate::profile_digest(),
            b"DCSRFB01/header192/body-u32le/exact-EOF/DCSRFC01/descriptor272/round64/QC-u32le",
            &(MAX_BLOCK_BYTES as u64).to_le_bytes(),
            &(MAX_CHECKPOINT_BYTES as u64).to_le_bytes(),
        ],
    )
}

/// Complete original candidate bytes; anyone can construct this untrusted DTO.
pub struct CandidateBlock {
    header: Header,
    body: Vec<u8>,
}
impl CandidateBlock {
    pub fn new(header: Header, body: Vec<u8>) -> Result<Self> {
        if body.is_empty() || body.len() > MAX_BODY_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(Self { header, body })
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + HEADER_BYTES + 4 + self.body.len());
        b.extend_from_slice(b"DCSRFB01");
        b.extend_from_slice(&self.header.encode());
        b.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.body);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_BLOCK_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut r = Reader::new(b);
        if r.array::<8>()? != *b"DCSRFB01" {
            return Err(Error::InvalidEncoding);
        }
        let header = Header::decode(r.take(HEADER_BYTES)?)?;
        let n = r.u32()? as usize;
        if n == 0 || n > MAX_BODY_BYTES || 8 + HEADER_BYTES + 4 + n != b.len() {
            return Err(Error::InvalidEncoding);
        }
        let body = r.take(n)?.to_vec();
        r.end()?;
        Self::new(header, body)
    }
}

/// Actual exported certificate and descriptor, still untrusted until a closed
/// follower/signer checks BOTH the actual application Body and this quorum.
pub struct Checkpoint {
    pub(crate) descriptor: Descriptor,
    pub(crate) round: u64,
    pub(crate) certificate: Vec<u8>,
}
impl Checkpoint {
    pub fn new(descriptor: Descriptor, round: u64, certificate: Vec<u8>) -> Result<Self> {
        if certificate.is_empty() || certificate.len() > work_finality::MAX_CERTIFICATE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            descriptor,
            round,
            certificate,
        })
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn round(&self) -> u64 {
        self.round
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + DESCRIPTOR_BYTES + 12 + self.certificate.len());
        b.extend_from_slice(b"DCSRFC01");
        b.extend_from_slice(&self.descriptor.encode());
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
        if r.array::<8>()? != *b"DCSRFC01" {
            return Err(Error::InvalidEncoding);
        }
        let descriptor = Descriptor::decode(r.take(DESCRIPTOR_BYTES)?)?;
        let round = r.u64()?;
        let n = r.u32()? as usize;
        if n == 0
            || n > work_finality::MAX_CERTIFICATE_BYTES
            || 8 + DESCRIPTOR_BYTES + 12 + n != b.len()
        {
            return Err(Error::InvalidEncoding);
        }
        let certificate = r.take(n)?.to_vec();
        r.end()?;
        Self::new(descriptor, round, certificate)
    }
}
