//! Bounded canonical detached native evidence. No serialized checked flag exists.
use super::{Error, Lane, Result};
use registry200_proof::{registry_progress::word, source::version};
pub const MAX_EVIDENCE_BYTES: usize = version_journal::MAX_BODY_BYTES;
pub struct Evidence {
    bytes: Vec<u8>,
}
impl Evidence {
    pub fn bootstrap(source: &[u8], child: &[u8]) -> Result<Self> {
        Self::new(Lane::Bootstrap, source, child)
    }
    pub fn control(child: &[u8]) -> Result<Self> {
        Self::new(Lane::Control, &[], child)
    }
    pub fn predicate(packet: &super::predicate::PredicatePacket) -> Result<Self> {
        Self::new(Lane::Predicate, &[], packet.as_bytes())
    }
    fn new(lane: Lane, source: &[u8], child: &[u8]) -> Result<Self> {
        let n = 24usize
            .checked_add(source.len())
            .and_then(|n| n.checked_add(child.len()))
            .ok_or(Error::ResourceLimit)?;
        if n > MAX_EVIDENCE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Self::require_lengths(lane, source.len(), child.len())?;
        let mut bytes = Vec::with_capacity(n);
        bytes.extend(b"DCSWJE01");
        bytes.push(lane.tag());
        bytes.extend([0; 7]);
        bytes.extend((source.len() as u32).to_le_bytes());
        bytes.extend((child.len() as u32).to_le_bytes());
        bytes.extend(source);
        bytes.extend(child);
        Ok(Self { bytes })
    }
    fn require_lengths(lane: Lane, source: usize, child: usize) -> Result<()> {
        let cap = match lane {
            Lane::Bootstrap => {
                if source == 0 || source > version::MAX_CERTIFICATE_BYTES {
                    return Err(Error::ResourceLimit);
                }
                word::bootstrap::MAX_EVIDENCE_BYTES
            }
            Lane::Control => {
                if source != 0 {
                    return Err(Error::InvalidEncoding);
                }
                word::MAX_EVIDENCE_BYTES
            }
            Lane::Predicate => {
                if source != 0 {
                    return Err(Error::InvalidEncoding);
                }
                super::predicate::MAX_PREDICATE_PACKET_BYTES
            }
        };
        if child == 0 || child > cap {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
    pub(super) fn split(lane: Lane, b: &[u8]) -> Result<(&[u8], &[u8])> {
        if b.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::ResourceLimit);
        }
        if b.len() < 24 || &b[..8] != b"DCSWJE01" || b[8] != lane.tag() || b[9..16] != [0; 7] {
            return Err(Error::InvalidEncoding);
        }
        let s = u32::from_le_bytes(b[16..20].try_into().unwrap()) as usize;
        let c = u32::from_le_bytes(b[20..24].try_into().unwrap()) as usize;
        Self::require_lengths(lane, s, c)?;
        let mid = 24usize.checked_add(s).ok_or(Error::ResourceLimit)?;
        if mid.checked_add(c) != Some(b.len()) {
            return Err(Error::InvalidEncoding);
        }
        Ok((&b[24..mid], &b[mid..]))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
