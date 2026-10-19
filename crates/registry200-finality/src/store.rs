//! Private bounded certificate log. Parsing/checksums never confer authority.
use crate::{
    Binding, DESCRIPTOR_BYTES, Error, Hash, Result, codec::Reader, digest, profile_digest,
};
use protocol_storage::{ByteBudget, FileCharge};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use work_finality::consensus::Decision;

const HEADER_BYTES: usize = 8 + 32 * 5;
const OVERHEAD: usize = 4 + 8 + 32 + 8 + DESCRIPTOR_BYTES + 4 + 32 + 4 + 8;
const MAX_RECORD: usize = OVERHEAD + work_finality::MAX_CERTIFICATE_BYTES;
pub(crate) struct Record {
    pub(crate) value: [u8; DESCRIPTOR_BYTES],
    pub(crate) round: u64,
    pub(crate) certificate: Vec<u8>,
}
pub(crate) struct FloorLog {
    file: File,
    charge: FileCharge,
    length: u64,
    position: u64,
    sequence: u64,
    previous: Hash,
    max_records: u64,
    #[cfg(test)]
    fault: Option<Fault>,
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum Fault {
    Partial(usize),
    AfterSync,
}
impl FloorLog {
    pub(crate) fn create(path: &Path, binding: &Binding, budget: &ByteBudget) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        file.try_lock().map_err(|_| Error::CorruptFloor)?;
        let mut charge = budget.register_file(path)?;
        let header = header(binding);
        charge.grow(header.len() as u64)?;
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Self {
            file,
            charge,
            length: header.len() as u64,
            position: header.len() as u64,
            sequence: 0,
            previous: digest(b"dcs/registry200-finality/floor-header/v1", &[&header]),
            max_records: u64::from(binding.journal_genesis().profile.max_headers),
            #[cfg(test)]
            fault: None,
        })
    }
    pub(crate) fn open(path: &Path, binding: &Binding, budget: &ByteBudget) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock().map_err(|_| Error::CorruptFloor)?;
        let length = file.metadata()?.len();
        if length < HEADER_BYTES as u64 || length > version_journal::MAX_JOURNAL_BYTES {
            return Err(Error::CorruptFloor);
        }
        let charge = budget.register_file(path)?;
        let mut b = [0; HEADER_BYTES];
        file.read_exact(&mut b).map_err(|_| Error::CorruptFloor)?;
        if b.as_slice() != header(binding).as_slice() {
            return Err(Error::InvalidBinding);
        }
        Ok(Self {
            file,
            charge,
            length,
            position: HEADER_BYTES as u64,
            sequence: 0,
            previous: digest(b"dcs/registry200-finality/floor-header/v1", &[&b]),
            max_records: u64::from(binding.journal_genesis().profile.max_headers),
            #[cfg(test)]
            fault: None,
        })
    }
    pub(crate) fn next(&mut self) -> Result<Option<Record>> {
        if self.position == self.length {
            return Ok(None);
        }
        if self.sequence >= self.max_records || self.length - self.position < OVERHEAD as u64 {
            return Err(Error::CorruptFloor);
        }
        let mut word = [0; 4];
        self.file
            .read_exact(&mut word)
            .map_err(|_| Error::CorruptFloor)?;
        let n = u32::from_le_bytes(word) as usize;
        if !(OVERHEAD..=MAX_RECORD).contains(&n) || n as u64 > self.length - self.position {
            return Err(Error::CorruptFloor);
        }
        // File/record/count/exact remaining extents precede allocation.
        let mut b = vec![0; n];
        b[..4].copy_from_slice(&word);
        self.file
            .read_exact(&mut b[4..])
            .map_err(|_| Error::CorruptFloor)?;
        let mut r = Reader::new(&b);
        if r.u32()? as usize != n || r.u64()? != self.sequence + 1 || r.hash()? != self.previous {
            return Err(Error::CorruptFloor);
        }
        let round = r.u64()?;
        let value = r.array()?;
        let cert_len = r.u32()? as usize;
        if cert_len > work_finality::MAX_CERTIFICATE_BYTES
            || OVERHEAD.checked_add(cert_len) != Some(n)
        {
            return Err(Error::CorruptFloor);
        }
        let certificate = r.take(cert_len)?.to_vec();
        let hash = r.hash()?;
        if hash != digest(b"dcs/registry200-finality/floor-record/v1", &[&b[..n - 44]])
            || r.u32()? as usize != n
            || r.array::<8>()? != *b"DCSRFR01"
        {
            return Err(Error::CorruptFloor);
        }
        r.end()?;
        self.sequence += 1;
        self.previous = hash;
        self.position += n as u64;
        Ok(Some(Record {
            value,
            round,
            certificate,
        }))
    }
    pub(crate) fn append(&mut self, decision: &Decision) -> Result<()> {
        if self.position != self.length || self.file.metadata()?.len() != self.length {
            return Err(Error::CorruptFloor);
        }
        if self.sequence >= self.max_records || decision.value().len() != DESCRIPTOR_BYTES {
            return Err(Error::ResourceLimit);
        }
        let certificate = decision
            .certificate()
            .encode()
            .map_err(work_finality::consensus::Error::from)?;
        let n = OVERHEAD
            .checked_add(certificate.len())
            .ok_or(Error::ResourceLimit)?;
        if n > MAX_RECORD {
            return Err(Error::ResourceLimit);
        }
        let next = self
            .length
            .checked_add(n as u64)
            .ok_or(Error::ResourceLimit)?;
        if next > version_journal::MAX_JOURNAL_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut b = Vec::with_capacity(n);
        b.extend_from_slice(&(n as u32).to_le_bytes());
        b.extend_from_slice(&(self.sequence + 1).to_le_bytes());
        b.extend_from_slice(&self.previous);
        b.extend_from_slice(&decision.certificate().context().round().to_le_bytes());
        b.extend_from_slice(decision.value());
        b.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
        b.extend_from_slice(&certificate);
        let hash = digest(b"dcs/registry200-finality/floor-record/v1", &[&b]);
        b.extend_from_slice(&hash);
        b.extend_from_slice(&(n as u32).to_le_bytes());
        b.extend_from_slice(b"DCSRFR01");
        self.charge.grow(next)?;
        self.file.seek(SeekFrom::Start(self.length))?;
        #[cfg(test)]
        if let Some(Fault::Partial(n)) = self.fault {
            self.fault = None;
            self.file.write_all(&b[..n.min(b.len())])?;
            self.file.sync_all()?;
            return Err(std::io::Error::other("PUBLIC fixture partial floor write").into());
        }
        self.file.write_all(&b)?;
        self.file.sync_all()?;
        #[cfg(test)]
        if self.fault.take().is_some() {
            return Err(
                std::io::Error::other("PUBLIC fixture lost floor sync acknowledgement").into(),
            );
        }
        // No truncation/repair on an uncertain write; the owner must poison.
        self.length = next;
        self.position = next;
        self.sequence += 1;
        self.previous = hash;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn inject(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }
}
fn header(binding: &Binding) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_BYTES);
    b.extend_from_slice(b"DCSRFL01");
    b.extend_from_slice(&profile_digest());
    b.extend_from_slice(&binding.id());
    b.extend_from_slice(&binding.initial_context().id());
    b.extend_from_slice(&binding.journal_genesis().id().expect("checked binding"));
    let checksum = digest(b"dcs/registry200-finality/floor-header-check/v1", &[&b]);
    b.extend_from_slice(&checksum);
    b
}
