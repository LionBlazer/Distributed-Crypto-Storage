//! One quota-accounted, locked append-only AEAD log. Every prefix is strict;
//! ambiguous writes poison the live owner. No truncation, repair or success cache.
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use protocol_storage::{ByteBudget, FileCharge, Reservation};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Read, Seek, Write},
    path::Path,
};
const HEADER: usize = 104;
const PREFIX: usize = 72;
const TAG: usize = 16;
pub(super) const OVERHEAD: usize = PREFIX + TAG;
pub(super) struct Wal {
    file: File,
    charge: FileCharge,
    pub budget: ByteBudget,
    authority: Authority,
    header: [u8; HEADER],
    pub length: u64,
    pub sequence: u64,
    pub digest: [u8; 32],
    poisoned: bool,
    #[cfg(test)]
    pub fault: Option<Fault>,
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum Fault {
    BeforeWrite,
    PartialWrite,
    AfterSync,
}
impl Wal {
    pub fn create(
        path: &Path,
        budget: ByteBudget,
        pins: &Pins,
        authority: Authority,
    ) -> Result<Self> {
        Self::create_bound(path, budget, header(pins), authority)
    }
    pub(super) fn create_bound(
        path: &Path,
        budget: ByteBudget,
        header: [u8; HEADER],
        authority: Authority,
    ) -> Result<Self> {
        let mut permit = budget
            .preflight_file(path, HEADER as u64)
            .map_err(storage)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(permit.path())?;
        lock(&file)?;
        let charge = permit.register_file().map_err(storage)?;
        if let Err(e) = file
            .write_all(&header)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent(path))
        {
            charge.mark_io_failed();
            return Err(e.into());
        }
        Ok(Self {
            file,
            charge,
            budget,
            authority,
            header,
            length: HEADER as u64,
            sequence: 0,
            digest: hash(&[b"DCS/Progress-owner/WAL/header/v1", &header]),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }
    pub fn open(
        path: &Path,
        budget: ByteBudget,
        pins: &Pins,
        authority: Authority,
    ) -> Result<(Self, Vec<Zeroizing<Vec<u8>>>)> {
        Self::open_bound(path, budget, header(pins), authority)
    }
    pub(super) fn open_bound(
        path: &Path,
        budget: ByteBudget,
        expected_header: [u8; HEADER],
        authority: Authority,
    ) -> Result<(Self, Vec<Zeroizing<Vec<u8>>>)> {
        budget.check_existing_file(path).map_err(storage)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&file)?;
        let charge = budget.register_file(path).map_err(storage)?;
        let length = file.metadata()?.len();
        if !(HEADER as u64 + 1..=MAX_FILE_BYTES).contains(&length) {
            return Err(Error::Encoding);
        }
        let mut actual = [0; HEADER];
        file.read_exact(&mut actual)?;
        if actual != expected_header {
            return Err(Error::Pins);
        }
        let mut w = Self {
            file,
            charge,
            budget,
            authority,
            header: actual,
            length,
            sequence: 0,
            digest: hash(&[b"DCS/Progress-owner/WAL/header/v1", &actual]),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        let mut records = Vec::new();
        let mut at = HEADER as u64;
        while at < length {
            if records.len() >= MAX_RECORDS {
                return Err(Error::ResourceLimit);
            }
            let mut prefix = [0; PREFIX];
            w.file.read_exact(&mut prefix)?;
            let n = u32::from_le_bytes(prefix[..4].try_into().unwrap()) as usize;
            let payload = u32::from_le_bytes(prefix[68..72].try_into().unwrap()) as usize;
            if !(OVERHEAD..=MAX_RECORD_BYTES).contains(&n)
                || n as u64 > length - at
                || n != payload + OVERHEAD
                || u64::from_le_bytes(prefix[4..12].try_into().unwrap()) != w.sequence + 1
                || prefix[12..44] != w.digest
            {
                return Err(Error::Encoding);
            }
            let mut bytes = Zeroizing::new(vec![0; payload]);
            w.file.read_exact(&mut bytes)?;
            let mut tag = [0; TAG];
            w.file.read_exact(&mut tag)?;
            let digest = hash(&[b"DCS/Progress-owner/WAL/record/v1", &prefix, &bytes, &tag]);
            let mut aad = w.header.to_vec();
            aad.extend(prefix);
            XChaCha20Poly1305::new_from_slice(w.authority.0.as_ref())
                .map_err(crypto)?
                .decrypt_in_place_detached(
                    XNonce::from_slice(&prefix[44..68]),
                    &aad,
                    bytes.as_mut(),
                    Tag::<XChaCha20Poly1305>::from_slice(&tag),
                )
                .map_err(crypto)?;
            records.push(bytes);
            w.sequence += 1;
            w.digest = digest;
            at += n as u64;
        }
        if at != length || w.file.stream_position()? != length || w.file.metadata()?.len() != length
        {
            return Err(Error::Encoding);
        }
        Ok((w, records))
    }
    pub fn live(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        self.budget.require_live().map_err(storage)
    }
    pub fn reserve(&self, records: u64, bytes: u64) -> Result<Reservation> {
        self.live()?;
        if self
            .sequence
            .checked_add(records)
            .is_none_or(|n| n > MAX_RECORDS as u64)
            || self
                .length
                .checked_add(bytes)
                .is_none_or(|n| n > MAX_FILE_BYTES)
        {
            return Err(Error::ResourceLimit);
        }
        self.budget.reserve(bytes).map_err(storage)
    }
    pub fn append(&mut self, payload: &[u8], lease: &mut Reservation) -> Result<()> {
        self.live()?;
        let n = payload
            .len()
            .checked_add(OVERHEAD)
            .ok_or(Error::ResourceLimit)?;
        if n > MAX_RECORD_BYTES || self.sequence >= MAX_RECORDS as u64 {
            return Err(Error::ResourceLimit);
        }
        let next = self
            .length
            .checked_add(n as u64)
            .filter(|n| *n <= MAX_FILE_BYTES)
            .ok_or(Error::ResourceLimit)?;
        let mut bytes = Zeroizing::new(payload.to_vec());
        let mut prefix = [0; PREFIX];
        prefix[..4].copy_from_slice(&(n as u32).to_le_bytes());
        prefix[4..12].copy_from_slice(&(self.sequence + 1).to_le_bytes());
        prefix[12..44].copy_from_slice(&self.digest);
        getrandom::getrandom(&mut prefix[44..68]).map_err(crypto)?;
        prefix[68..72].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        let mut aad = self.header.to_vec();
        aad.extend(prefix);
        let tag = XChaCha20Poly1305::new_from_slice(self.authority.0.as_ref())
            .map_err(crypto)?
            .encrypt_in_place_detached(XNonce::from_slice(&prefix[44..68]), &aad, bytes.as_mut())
            .map_err(crypto)?;
        self.charge.grow_reserved(next, lease).map_err(storage)?;
        let written = (|| -> io::Result<()> {
            if self.file.metadata()?.len() != self.length
                || self.file.stream_position()? != self.length
            {
                return Err(io::Error::other("Progress WAL append position changed"));
            }
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::BeforeWrite)) {
                self.fault = None;
                return Err(io::Error::other("injected before write"));
            }
            self.file.write_all(&prefix)?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::PartialWrite)) {
                self.fault = None;
                self.file.write_all(&bytes[..bytes.len() / 2])?;
                return Err(io::Error::other("injected partial write"));
            }
            self.file.write_all(&bytes)?;
            self.file.write_all(&tag)?;
            self.file.sync_all()?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::AfterSync)) {
                self.fault = None;
                return Err(io::Error::other("injected lost acknowledgement"));
            }
            Ok(())
        })();
        if let Err(e) = written {
            self.poison();
            return Err(e.into());
        }
        self.length = next;
        self.sequence += 1;
        self.digest = hash(&[b"DCS/Progress-owner/WAL/record/v1", &prefix, &bytes, &tag]);
        Ok(())
    }
    pub fn poison(&mut self) {
        self.poisoned = true;
        self.charge.mark_io_failed();
    }
}
fn header(p: &Pins) -> [u8; HEADER] {
    let mut h = [0; HEADER];
    h[..8].copy_from_slice(b"POWAL001");
    h[8..40].copy_from_slice(&profile_digest());
    h[40..72].copy_from_slice(&p.binding.id());
    h[72..104].copy_from_slice(&p.id);
    h
}
fn lock(f: &File) -> Result<()> {
    f.try_lock().map_err(|e| {
        Error::Io(match e {
            TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::WouldBlock, "Progress owner already open")
            }
            TryLockError::Error(e) => e,
        })
    })
}
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("WAL parent absent"))?,
    )?
    .sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
/// Strict bounded private codec shared only by this new owner grammar.
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::ResourceLimit)?;
        let value = self.bytes.get(self.at..end).ok_or(Error::Encoding)?;
        self.at = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn blob(&mut self, cap: usize) -> Result<&'a [u8]> {
        let n = u32::from_le_bytes(self.array()?) as usize;
        if n > cap {
            return Err(Error::ResourceLimit);
        }
        self.take(n)
    }
    pub fn end(self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}
pub(super) fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let n = u32::try_from(bytes.len()).map_err(|_| Error::ResourceLimit)?;
    out.extend(n.to_le_bytes());
    out.extend(bytes);
    Ok(())
}
