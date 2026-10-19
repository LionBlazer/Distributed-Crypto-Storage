//! Private bounded certificate log. Parsing/checksums never confer authority.
use crate::{
    DESCRIPTOR_BYTES, Error, Hash, Result,
    codec::Reader,
    digest,
    pins::{Format, Pins},
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
    format: Format,
    file: File,
    charge: FileCharge,
    length: u64,
    position: u64,
    sequence: u64,
    previous: Hash,
    header_hash: Hash,
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
    /// Bounded one-record export. Restore the append/replay cursor on all paths;
    /// no parsed hash is an application/QC authority. The wrapper poisons on an
    /// unreadable/corrupt owned log instead of silently signing past it.
    pub(crate) fn export(&mut self, slot: u64) -> Result<Record> {
        let result = self.export_checked(slot);
        if result.is_err() {
            self.charge.mark_io_failed();
        }
        result
    }
    fn export_checked(&mut self, slot: u64) -> Result<Record> {
        if slot == 0
            || slot > self.sequence
            || self.position != self.length
            || self.file.metadata()?.len() != self.length
        {
            return Err(Error::CorruptFloor);
        }
        let saved = (self.position, self.sequence, self.previous);
        let result = (|| {
            self.file.seek(SeekFrom::Start(0))?;
            let mut header = [0; HEADER_BYTES];
            self.file.read_exact(&mut header)?;
            if digest(self.format.header_hash(), &[&header]) != self.header_hash {
                return Err(Error::CorruptFloor);
            }
            self.position = HEADER_BYTES as u64;
            self.sequence = 0;
            self.previous = digest(self.format.header_hash(), &[&header]);
            for _ in 0..slot {
                let record = self.next()?.ok_or(Error::CorruptFloor)?;
                if self.sequence == slot {
                    return Ok(record);
                }
            }
            Err(Error::CorruptFloor)
        })();
        self.position = saved.0;
        self.sequence = saved.1;
        self.previous = saved.2;
        self.file.seek(SeekFrom::Start(saved.0))?;
        result
    }
    pub(crate) fn create(path: &Path, binding: Pins<'_>, budget: &ByteBudget) -> Result<Self> {
        let header = header(binding);
        let mut permit = budget.preflight_file(path, header.len() as u64)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(permit.path())?;
        file.try_lock().map_err(|_| Error::CorruptFloor)?;
        let charge = permit.register_file()?;
        if let Err(e) = file.write_all(&header).and_then(|()| file.sync_all()) {
            charge.mark_io_failed();
            return Err(e.into());
        }
        Ok(Self {
            format: binding.format(),
            file,
            charge,
            length: header.len() as u64,
            position: header.len() as u64,
            sequence: 0,
            previous: digest(binding.format().header_hash(), &[&header]),
            header_hash: digest(binding.format().header_hash(), &[&header]),
            max_records: u64::from(binding.genesis().profile.max_headers),
            #[cfg(test)]
            fault: None,
        })
    }
    pub(crate) fn open(path: &Path, binding: Pins<'_>, budget: &ByteBudget) -> Result<Self> {
        budget.check_existing_file(path)?;
        let charge = budget.register_file(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                charge.mark_io_failed();
                Error::from(e)
            })?;
        file.try_lock().map_err(|_| Error::CorruptFloor)?;
        let inspected = (|| {
            let length = file.metadata()?.len();
            if length < HEADER_BYTES as u64 || length > version_journal::MAX_JOURNAL_BYTES {
                return Err(Error::CorruptFloor);
            }
            let mut b = [0; HEADER_BYTES];
            file.read_exact(&mut b).map_err(|_| Error::CorruptFloor)?;
            if b.as_slice() != header(binding).as_slice() {
                return Err(Error::InvalidBinding);
            }
            Ok((length, b))
        })();
        if inspected.is_err() {
            charge.mark_io_failed();
        }
        let (length, b) = inspected?;
        Ok(Self {
            format: binding.format(),
            file,
            charge,
            length,
            position: HEADER_BYTES as u64,
            sequence: 0,
            previous: digest(binding.format().header_hash(), &[&b]),
            header_hash: digest(binding.format().header_hash(), &[&b]),
            max_records: u64::from(binding.genesis().profile.max_headers),
            #[cfg(test)]
            fault: None,
        })
    }
    pub(crate) fn next(&mut self) -> Result<Option<Record>> {
        let result = self.next_checked();
        if result.is_err() {
            self.charge.mark_io_failed();
        }
        result
    }
    fn next_checked(&mut self) -> Result<Option<Record>> {
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
        if hash != digest(self.format.record_hash(), &[&b[..n - 44]])
            || r.u32()? as usize != n
            || r.array::<8>()? != *self.format.record_magic()
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
        let result = self.append_checked(decision);
        if matches!(&result, Err(Error::Io(_) | Error::CorruptFloor)) {
            self.charge.mark_io_failed();
        }
        result
    }
    fn append_checked(&mut self, decision: &Decision) -> Result<()> {
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
        let hash = digest(self.format.record_hash(), &[&b]);
        b.extend_from_slice(&hash);
        b.extend_from_slice(&(n as u32).to_le_bytes());
        b.extend_from_slice(self.format.record_magic());
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
fn header(binding: Pins<'_>) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_BYTES);
    b.extend_from_slice(binding.format().floor_magic());
    b.extend_from_slice(&binding.format().profile());
    b.extend_from_slice(&binding.id());
    b.extend_from_slice(&binding.context().id());
    b.extend_from_slice(&binding.genesis().id().expect("checked binding"));
    let checksum = digest(binding.format().header_check(), &[&b]);
    b.extend_from_slice(&checksum);
    b
}
