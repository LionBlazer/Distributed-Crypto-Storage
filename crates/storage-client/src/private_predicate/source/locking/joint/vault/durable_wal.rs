//! Private append-only authenticated phase log with strict replay.
use super::super::control::{
    JointControlOutcome,
    state::{CONTROL_BYTES, IDLE_BYTES},
};
use super::durable::acquire::{AcquireState, MAX_ACQUIRE_STATE};
use super::durable::host::state::{Bindings, Managed};
use super::durable::{
    BLOCK_CAP, MAX_RECORDS, OWNER_VAULT_MAX_BODY_BYTES, OWNER_VAULT_MAX_FILE_BYTES,
    OWNER_VAULT_MAX_RECORD_BYTES, OwnerVaultAuthority, OwnerVaultError, OwnerVaultPhase,
    OwnerVaultPins, VaultResult, hash,
};
use crate::private_predicate::cryptography;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use protocol_storage::{ByteBudget, FileCharge, Reservation};
use registry200_finality::{
    CandidateBlock,
    joint::{JointCheckpoint, MAX_CHECKPOINT_BYTES},
};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Read, Seek, Write},
    path::Path,
};
use zeroize::Zeroizing;

const FILE_HEADER: usize = 104;
const RECORD_HEADER: usize = 72;
const TAG_BYTES: usize = 16;
const MAGIC: &[u8; 8] = b"DCSOVL02";

pub(super) struct Snapshot {
    pub managed: Option<Managed>,
    pub phase: OwnerVaultPhase,
    pub generation: u64,
    pub pending: [u8; 32],
    pub stamp: [u8; 32],
    pub idle: Zeroizing<[u8; IDLE_BYTES]>,
    pub candidate: Option<Zeroizing<[u8; CONTROL_BYTES]>>,
    pub block: Option<CandidateBlock>,
    pub checkpoint: Option<JointCheckpoint>,
    pub outcome: Option<JointControlOutcome>,
    pub acquire: Option<AcquireState>,
}
impl Snapshot {
    fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        let block = self
            .block
            .as_ref()
            .map(CandidateBlock::encode)
            .unwrap_or_default();
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(JointCheckpoint::encode)
            .unwrap_or_default();
        if block.len() > BLOCK_CAP || checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(OwnerVaultError::ResourceLimit);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            8 + 16 + 64 + IDLE_BYTES + CONTROL_BYTES + 8 + block.len() + checkpoint.len(),
        ));
        bytes.extend_from_slice(if self.managed.is_some() {
            b"DCSOVP03"
        } else {
            b"DCSOVP02"
        });
        bytes.push(match self.phase {
            OwnerVaultPhase::Idle => 0,
            OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown => 1,
            OwnerVaultPhase::Completed => 2,
            OwnerVaultPhase::AcquireComputePrepared => 3,
        });
        bytes.push(match self.outcome {
            None => 0,
            Some(JointControlOutcome::Begun) => 1,
            Some(JointControlOutcome::ClosedRegistry) => 2,
            Some(JointControlOutcome::AbortedRegistry) => 3,
        });
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.pending);
        bytes.extend_from_slice(&self.stamp);
        bytes.extend_from_slice(self.idle.as_ref());
        match &self.candidate {
            Some(value) => bytes.extend_from_slice(value.as_ref()),
            None => bytes.extend_from_slice(&[0; CONTROL_BYTES]),
        }
        let acquire = self
            .acquire
            .as_ref()
            .map(AcquireState::encode)
            .transpose()?;
        let acquire = acquire.as_deref().map(Vec::as_slice).unwrap_or_default();
        bytes.extend_from_slice(&(acquire.len() as u32).to_le_bytes());
        bytes.extend_from_slice(acquire);
        for value in [&block, &checkpoint] {
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value);
        }
        if let Some(managed) = &self.managed {
            bytes.extend_from_slice(managed.encode().as_ref());
        }
        if bytes.len() + RECORD_HEADER + TAG_BYTES > OWNER_VAULT_MAX_RECORD_BYTES {
            return Err(OwnerVaultError::ResourceLimit);
        }
        // Use the decoder as the canonical shape audit before any write.
        let bindings = self
            .managed
            .as_ref()
            .map(|m| Bindings(m.clients.map(|c| c.binding)));
        let _ = Self::decode(&bytes, bindings.as_ref())?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8], bindings: Option<&Bindings>) -> VaultResult<Self> {
        let mut r = Reader::new(bytes);
        if r.take(8)?
            != if bindings.is_some() {
                b"DCSOVP03"
            } else {
                b"DCSOVP02"
            }
        {
            return Err(OwnerVaultError::Encoding);
        }
        let phase = r.take(1)?[0];
        let outcome = r.take(1)?[0];
        if r.take(6)? != [0; 6] {
            return Err(OwnerVaultError::Encoding);
        }
        let generation = r.u64()?;
        let pending = r.array()?;
        let stamp = r.array()?;
        let idle = Zeroizing::new(r.array()?);
        let candidate = Zeroizing::new(r.array::<CONTROL_BYTES>()?);
        let acquire_bytes = r.blob(MAX_ACQUIRE_STATE)?;
        let acquire = if acquire_bytes.is_empty() {
            None
        } else {
            Some(AcquireState::decode(acquire_bytes)?)
        };
        let block_bytes = r.blob(BLOCK_CAP)?;
        let block = if block_bytes.is_empty() {
            None
        } else {
            Some(CandidateBlock::decode(block_bytes).map_err(OwnerVaultError::Finality)?)
        };
        if block
            .as_ref()
            .is_some_and(|value| value.body().len() > OWNER_VAULT_MAX_BODY_BYTES)
        {
            return Err(OwnerVaultError::ResourceLimit);
        }
        let qc = r.blob(MAX_CHECKPOINT_BYTES)?;
        let checkpoint = if qc.is_empty() {
            None
        } else {
            Some(JointCheckpoint::decode(qc).map_err(OwnerVaultError::Joint)?)
        };
        let managed = bindings
            .map(|b| Managed::decode(r.take(256)?, b))
            .transpose()?;
        r.end()?;
        let (phase, candidate, outcome) = match (phase, outcome) {
            (0, 0)
                if pending == [0; 32]
                    && acquire.is_none()
                    && candidate.iter().all(|b| *b == 0)
                    && block.is_none()
                    && checkpoint.is_none() =>
            {
                (OwnerVaultPhase::Idle, None, None)
            }
            (1, 0) if pending != [0; 32] && block.is_some() && checkpoint.is_none() => {
                if acquire.is_some() && candidate.iter().any(|b| *b != 0) {
                    return Err(OwnerVaultError::Encoding);
                }
                (
                    OwnerVaultPhase::SubmittedUnknown,
                    if acquire.is_none() {
                        Some(candidate)
                    } else {
                        None
                    },
                    None,
                )
            }
            (2, 1..=3)
                if pending != [0; 32]
                    && acquire.is_none()
                    && candidate.iter().all(|b| *b == 0)
                    && block.is_some()
                    && checkpoint.is_some() =>
            {
                (
                    OwnerVaultPhase::Completed,
                    None,
                    Some(match outcome {
                        1 => JointControlOutcome::Begun,
                        2 => JointControlOutcome::ClosedRegistry,
                        _ => JointControlOutcome::AbortedRegistry,
                    }),
                )
            }
            (2, 0)
                if pending != [0; 32]
                    && acquire.is_some()
                    && candidate.iter().all(|b| *b == 0)
                    && block.is_some()
                    && checkpoint.is_some() =>
            {
                (OwnerVaultPhase::Completed, None, None)
            }
            (3, 0)
                if pending != [0; 32]
                    && acquire.is_some()
                    && candidate.iter().all(|b| *b == 0)
                    && block.is_none()
                    && checkpoint.is_none() =>
            {
                (OwnerVaultPhase::AcquireComputePrepared, None, None)
            }
            _ => return Err(OwnerVaultError::Encoding),
        };
        if managed
            .as_ref()
            .is_some_and(|m| (phase == OwnerVaultPhase::Idle) != m.call.is_none())
        {
            return Err(OwnerVaultError::Encoding);
        }
        Ok(Self {
            managed,
            phase,
            generation,
            pending,
            stamp,
            idle,
            candidate,
            block,
            checkpoint,
            outcome,
            acquire,
        })
    }
}

pub(super) struct Wal {
    managed: Option<Bindings>,
    file: File,
    charge: FileCharge,
    pub budget: ByteBudget,
    authority: OwnerVaultAuthority,
    header: [u8; FILE_HEADER],
    pub length: u64,
    sequence: u64,
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
    pub fn create_new(
        path: &Path,
        budget: ByteBudget,
        pins: &OwnerVaultPins,
        authority: OwnerVaultAuthority,
    ) -> VaultResult<Self> {
        let header = file_header(pins);
        let mut permit = budget.preflight_file(path, FILE_HEADER as u64)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(permit.path())?;
        lock(&file)?;
        let charge = permit.register_file()?;
        if let Err(error) = file
            .write_all(&header)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent(path))
        {
            charge.mark_io_failed();
            return Err(error.into());
        }
        Ok(Self {
            managed: pins.managed.clone(),
            file,
            charge,
            budget,
            authority,
            header,
            length: FILE_HEADER as u64,
            sequence: 0,
            digest: hash(&[b"DCS/owner-vault/header/v1", &header]),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }
    pub fn open_existing(
        path: &Path,
        budget: ByteBudget,
        pins: &OwnerVaultPins,
        authority: OwnerVaultAuthority,
    ) -> VaultResult<(Self, Vec<Snapshot>)> {
        budget.check_existing_file(path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&file)?;
        let charge = budget.register_file(path)?;
        let length = file
            .metadata()
            .map_err(|error| {
                charge.mark_io_failed();
                OwnerVaultError::Io(error)
            })?
            .len();
        if length <= FILE_HEADER as u64 || length > OWNER_VAULT_MAX_FILE_BYTES {
            return Err(OwnerVaultError::Encoding);
        }
        let mut header = [0; FILE_HEADER];
        file.read_exact(&mut header).map_err(|error| {
            charge.mark_io_failed();
            OwnerVaultError::Io(error)
        })?;
        if header != file_header(pins) {
            return Err(OwnerVaultError::Pins);
        }
        let mut wal = Self {
            managed: pins.managed.clone(),
            file,
            charge,
            budget,
            authority,
            header,
            length,
            sequence: 0,
            digest: hash(&[b"DCS/owner-vault/header/v1", &header]),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        let mut snapshots = Vec::new();
        let mut position = FILE_HEADER as u64;
        while position < length {
            if snapshots.len() >= MAX_RECORDS {
                return Err(OwnerVaultError::ResourceLimit);
            }
            let mut prefix = [0; RECORD_HEADER];
            wal.read(&mut prefix)?;
            let n = u32::from_le_bytes(prefix[..4].try_into().unwrap()) as usize;
            let payload = u32::from_le_bytes(prefix[68..72].try_into().unwrap()) as usize;
            if !(RECORD_HEADER + TAG_BYTES..=OWNER_VAULT_MAX_RECORD_BYTES).contains(&n)
                || n as u64 > length - position
                || payload + RECORD_HEADER + TAG_BYTES != n
                || u64::from_le_bytes(prefix[4..12].try_into().unwrap()) != wal.sequence + 1
                || prefix[12..44] != wal.digest
            {
                return Err(OwnerVaultError::Encoding);
            }
            let mut bytes = Zeroizing::new(vec![0; payload]);
            wal.read(&mut bytes)?;
            let mut tag = [0; TAG_BYTES];
            wal.read(&mut tag)?;
            let digest = hash(&[wal.record_domain(), &prefix, &bytes, &tag]);
            let cipher = XChaCha20Poly1305::new_from_slice(wal.authority.0.as_ref())
                .map_err(|_| OwnerVaultError::Authentication)?;
            let mut aad = wal.header.to_vec();
            aad.extend_from_slice(&prefix);
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(&prefix[44..68]),
                    &aad,
                    bytes.as_mut(),
                    Tag::<XChaCha20Poly1305>::from_slice(&tag),
                )
                .map_err(|_| OwnerVaultError::Authentication)?;
            snapshots.push(Snapshot::decode(&bytes, wal.managed.as_ref())?);
            wal.sequence += 1;
            wal.digest = digest;
            position += n as u64;
        }
        let end = wal.file.stream_position().map_err(|error| {
            wal.charge.mark_io_failed();
            OwnerVaultError::Io(error)
        })?;
        let actual = wal
            .file
            .metadata()
            .map_err(|error| {
                wal.charge.mark_io_failed();
                OwnerVaultError::Io(error)
            })?
            .len();
        if position != length || end != length || actual != length {
            wal.charge.mark_io_failed();
            return Err(OwnerVaultError::Encoding);
        }
        Ok((wal, snapshots))
    }
    pub fn record_bytes(snapshot: &Snapshot) -> VaultResult<u64> {
        Ok((snapshot.encode()?.len() + RECORD_HEADER + TAG_BYTES) as u64)
    }
    pub fn next_sequence(&self) -> VaultResult<u64> {
        self.sequence
            .checked_add(1)
            .filter(|n| *n <= MAX_RECORDS as u64)
            .ok_or(OwnerVaultError::ResourceLimit)
    }
    fn record_domain(&self) -> &'static [u8] {
        if self.managed.is_some() {
            b"DCS/owner-vault/record/v3"
        } else {
            b"DCS/owner-vault/record/v2"
        }
    }
    pub fn require_terminal_capacity(&self, additional: u64) -> VaultResult<()> {
        let slots = if additional == 0 { 1 } else { 2 };
        if self
            .sequence
            .checked_add(slots)
            .is_none_or(|n| n > MAX_RECORDS as u64)
            || self
                .length
                .checked_add(additional)
                .and_then(|n| n.checked_add(OWNER_VAULT_MAX_RECORD_BYTES as u64))
                .is_none_or(|n| n > OWNER_VAULT_MAX_FILE_BYTES)
        {
            return Err(OwnerVaultError::ResourceLimit);
        }
        Ok(())
    }
    pub fn require_capacity(&self, records: u64, bytes: u64) -> VaultResult<()> {
        self.live()?;
        if self
            .sequence
            .checked_add(records)
            .is_none_or(|n| n > MAX_RECORDS as u64)
            || self
                .length
                .checked_add(bytes)
                .is_none_or(|n| n > OWNER_VAULT_MAX_FILE_BYTES)
        {
            return Err(OwnerVaultError::ResourceLimit);
        }
        Ok(())
    }
    pub fn append(
        &mut self,
        snapshot: &Snapshot,
        mut reserved: Reservation,
    ) -> VaultResult<Reservation> {
        match self.append_reserved(snapshot, &mut reserved) {
            Ok(()) => Ok(reserved),
            Err(error) => {
                if self.poisoned {
                    reserved.retain_conservatively();
                }
                Err(error)
            }
        }
    }
    // SAME writer, borrowed lease. An Acquire keeps its prepromised terminal
    // bytes even when an error occurs before the actual append begins.
    pub fn append_reserved(
        &mut self,
        snapshot: &Snapshot,
        reserved: &mut Reservation,
    ) -> VaultResult<()> {
        self.live()?;
        if snapshot
            .managed
            .as_ref()
            .map(|m| Bindings(m.clients.map(|c| c.binding)))
            != self.managed
        {
            return Err(OwnerVaultError::Pins);
        }
        if self.sequence as usize >= MAX_RECORDS {
            return Err(OwnerVaultError::ResourceLimit);
        }
        let mut bytes = snapshot.encode()?;
        let n = bytes.len() + RECORD_HEADER + TAG_BYTES;
        let next = self
            .length
            .checked_add(n as u64)
            .filter(|next| *next <= OWNER_VAULT_MAX_FILE_BYTES)
            .ok_or(OwnerVaultError::ResourceLimit)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(OwnerVaultError::ResourceLimit)?;
        let mut prefix = [0; RECORD_HEADER];
        prefix[..4].copy_from_slice(&(n as u32).to_le_bytes());
        prefix[4..12].copy_from_slice(&sequence.to_le_bytes());
        prefix[12..44].copy_from_slice(&self.digest);
        getrandom::getrandom(&mut prefix[44..68])
            .map_err(|error| OwnerVaultError::Owner(cryptography(error)))?;
        prefix[68..72].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(self.authority.0.as_ref())
            .map_err(|_| OwnerVaultError::Authentication)?;
        let mut aad = self.header.to_vec();
        aad.extend_from_slice(&prefix);
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&prefix[44..68]), &aad, bytes.as_mut())
            .map_err(|_| OwnerVaultError::Authentication)?;
        self.charge.grow_reserved(next, reserved)?;
        let write = (|| -> std::io::Result<()> {
            // Check AFTER precharge, before any append, just like the signer WAL.
            if self.file.metadata()?.len() != self.length
                || self.file.stream_position()? != self.length
            {
                return Err(std::io::Error::other("owner Vault append position changed"));
            }
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::BeforeWrite)) {
                self.fault = None;
                return Err(std::io::Error::other("injected before write"));
            }
            self.file.write_all(&prefix)?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::PartialWrite)) {
                self.fault = None;
                self.file.write_all(&bytes[..bytes.len() / 2])?;
                return Err(std::io::Error::other("injected partial write"));
            }
            self.file.write_all(&bytes)?;
            self.file.write_all(&tag)?;
            self.file.sync_all()?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::AfterSync)) {
                self.fault = None;
                return Err(std::io::Error::other("injected lost sync acknowledgement"));
            }
            Ok(())
        })();
        if let Err(error) = write {
            self.poisoned = true;
            self.charge.mark_io_failed();
            return Err(error.into());
        }
        self.length = next;
        self.sequence = sequence;
        self.digest = hash(&[self.record_domain(), &prefix, &bytes, &tag]);
        Ok(())
    }
    pub fn live(&self) -> VaultResult<()> {
        if self.poisoned {
            return Err(OwnerVaultError::Poisoned);
        }
        // This must not acquire another reservation slot: the pending owner
        // already owns its complete terminal lease, even when other slots fill.
        self.budget.require_live()?;
        Ok(())
    }
    pub fn poison(&mut self) {
        self.poisoned = true;
        self.charge.mark_io_failed();
    }
    fn read(&mut self, bytes: &mut [u8]) -> VaultResult<()> {
        self.file.read_exact(bytes).map_err(|error| {
            self.charge.mark_io_failed();
            OwnerVaultError::Io(error)
        })
    }
}
fn file_header(pins: &OwnerVaultPins) -> [u8; FILE_HEADER] {
    let mut out = [0; FILE_HEADER];
    out[..8].copy_from_slice(if pins.managed.is_some() {
        b"DCSOVL03"
    } else {
        MAGIC
    });
    out[8..40].copy_from_slice(&pins.file_profile());
    out[40..72].copy_from_slice(&pins.binding.id());
    out[72..104].copy_from_slice(&pins.identity.0);
    out
}
fn lock(file: &File) -> VaultResult<()> {
    file.try_lock().map_err(|error| {
        OwnerVaultError::Io(match error {
            TryLockError::WouldBlock => {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "owner Vault already open")
            }
            TryLockError::Error(error) => error,
        })
    })
}
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("Vault parent absent"))?,
    )?
    .sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(super) fn take(&mut self, n: usize) -> VaultResult<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(OwnerVaultError::ResourceLimit)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(OwnerVaultError::Encoding)?;
        self.at = end;
        Ok(value)
    }
    pub(super) fn array<const N: usize>(&mut self) -> VaultResult<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub(super) fn u64(&mut self) -> VaultResult<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(super) fn blob(&mut self, cap: usize) -> VaultResult<&'a [u8]> {
        let n = u32::from_le_bytes(self.array()?) as usize;
        if n > cap {
            return Err(OwnerVaultError::ResourceLimit);
        }
        self.take(n)
    }
    pub(super) fn end(self) -> VaultResult<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(OwnerVaultError::Encoding)
        }
    }
}
