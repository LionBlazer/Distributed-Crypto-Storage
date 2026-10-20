use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::chain::PreparedBlock;
use crate::{
    Error, Genesis, HEADER_BYTES, Header, ImportOutcome, Journal, Result, TransitionVerifier, hash,
};

/// Append-only checked journal, holding an OS exclusive file lock until dropped.
/// Each block is fully verified before writing, flushed before publication in
/// memory, and reverified on reopen. An incomplete crash tail is rejected, never
/// silently treated as agreement or an instruction to roll back accepted writes.
pub struct DurableJournal {
    journal: Journal,
    file: File,
    length: u64,
}

/// Exact fresh append preparation under one exclusive DurableJournal borrow.
/// Drop performs no file write or in-memory publication. No success receipt,
/// second header/body argument, storage-budget callback or authority flag exists.
/// The exact input bytes remain immutably borrowed until commit or Drop:
///
/// ```compile_fail
/// use version_journal::{DurableJournal, Header, RejectUnprovedTransitions, Result};
/// fn change_body(j: &mut DurableJournal, h: Header, b: &mut Vec<u8>) -> Result<()> {
///     let pending = j.prepare_append(h, b, 2000, &RejectUnprovedTransitions)?;
///     b.clear();
///     pending.commit()?;
///     Ok(())
/// }
/// ```
#[must_use = "dropping a pending append writes and publishes nothing"]
pub struct PendingAppend<'journal> {
    journal: &'journal mut DurableJournal,
    header: Header,
    body: &'journal [u8],
    prepared: PreparedBlock,
    next_length: u64,
}
impl PendingAppend<'_> {
    /// Checked absolute journal-file length after this exact append. For a
    /// known complete block it is unchanged. This is accounting metadata only;
    /// the application must precharge its own file quota before commit.
    pub fn next_disk_bytes(&self) -> u64 {
        self.next_length
    }
    /// After all owner checks and external file precharge, append/fsync and only
    /// then publish this exact state. Position/IO errors retain the original
    /// failure ordering: the enclosing owner must conservatively charge/poison
    /// uncertain writes. This crate does not own that independent storage quota.
    pub fn commit(self) -> Result<ImportOutcome> {
        let Self {
            journal,
            header,
            body,
            prepared,
            next_length,
        } = self;
        journal.append_prepared(header, body, prepared, next_length)
    }
}

impl DurableJournal {
    pub fn create(path: impl AsRef<Path>, genesis: Genesis, namespace: [u8; 32]) -> Result<Self> {
        let journal = Journal::new(genesis)?;
        let genesis_wire = journal.genesis().encode()?;
        let mut initial = b"DCSJL002".to_vec();
        initial.extend_from_slice(&namespace);
        initial.extend_from_slice(&(genesis_wire.len() as u32).to_le_bytes());
        initial.extend_from_slice(&genesis_wire);
        initial.extend_from_slice(&hash(&genesis_wire));
        if initial.len() as u64 > journal.profile().max_journal_bytes {
            return Err(Error::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::ExistingPath
                } else {
                    e.into()
                }
            })?;
        lock(&file)?;
        file.write_all(&initial)?;
        file.sync_all()?;
        Ok(Self {
            journal,
            file,
            length: initial.len() as u64,
        })
    }
    /// The independent pinned genesis is mandatory; a journal cannot nominate its
    /// own authorization key or easier target profile on restart.
    pub fn open<V: TransitionVerifier + ?Sized>(
        path: impl AsRef<Path>,
        pinned_genesis: Genesis,
        namespace: [u8; 32],
        now: u64,
        verifier: &V,
    ) -> Result<Self> {
        let mut journal = Journal::new(pinned_genesis)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&file)?;
        let length = file.metadata()?.len();
        if length > journal.profile().max_journal_bytes {
            return Err(Error::ResourceLimit);
        }
        let mut magic = [0; 8];
        file.read_exact(&mut magic)
            .map_err(|_| Error::CorruptJournal)?;
        if &magic != b"DCSJL002" {
            return Err(Error::CorruptJournal);
        }
        let mut received_namespace = [0; 32];
        file.read_exact(&mut received_namespace)
            .map_err(|_| Error::CorruptJournal)?;
        if received_namespace != namespace {
            return Err(Error::WrongDomain);
        }
        let mut number = [0; 4];
        file.read_exact(&mut number)
            .map_err(|_| Error::CorruptJournal)?;
        let genesis_len = u32::from_le_bytes(number) as usize;
        let expected_genesis = journal.genesis().encode()?;
        if genesis_len != expected_genesis.len() {
            return Err(Error::WrongDomain);
        }
        let mut genesis_wire = vec![0; genesis_len];
        file.read_exact(&mut genesis_wire)
            .map_err(|_| Error::CorruptJournal)?;
        let mut checksum = [0; 32];
        file.read_exact(&mut checksum)
            .map_err(|_| Error::CorruptJournal)?;
        if genesis_wire != expected_genesis || hash(&genesis_wire) != checksum {
            return Err(Error::WrongDomain);
        }
        loop {
            if file.stream_position()? == length {
                break;
            }
            file.read_exact(&mut number)
                .map_err(|_| Error::CorruptJournal)?;
            let frame_len = u32::from_le_bytes(number) as usize;
            if frame_len < HEADER_BYTES + 9
                || frame_len > HEADER_BYTES + journal.profile().max_body_bytes as usize
            {
                return Err(Error::CorruptJournal);
            }
            let remaining = length.saturating_sub(file.stream_position()?);
            if remaining < frame_len as u64 + 32 {
                return Err(Error::CorruptJournal);
            }
            let mut frame = vec![0; frame_len];
            file.read_exact(&mut frame)
                .map_err(|_| Error::CorruptJournal)?;
            file.read_exact(&mut checksum)
                .map_err(|_| Error::CorruptJournal)?;
            if hash(&frame) != checksum {
                return Err(Error::CorruptJournal);
            }
            let header = Header::decode(&frame[..HEADER_BYTES])?;
            journal.import_block(header, &frame[HEADER_BYTES..], now, verifier)?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            journal,
            file,
            length,
        })
    }
    /// Read-only bounded namespace preflight, before application state mutation.
    /// Does not validate genesis, blocks, authorization or physical custody.
    pub fn check_namespace(path: impl AsRef<Path>, namespace: [u8; 32]) -> Result<()> {
        let mut file = File::open(path)?;
        let mut header = [0; 40];
        file.read_exact(&mut header)
            .map_err(|_| Error::CorruptJournal)?;
        if &header[..8] != b"DCSJL002" || header[8..] != namespace {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub fn journal(&self) -> &Journal {
        &self.journal
    }
    pub fn disk_bytes(&self) -> u64 {
        self.length
    }
    /// In-memory mechanical restriction, not persisted certificate authority.
    /// The closed finality owner persists/reverifies its decision log first and
    /// reinstalls this restriction on every reopen before exposing any head.
    pub fn restrict_ancestry_floor(&mut self, head: crate::HeadRef) -> Result<()> {
        self.journal.restrict_ancestry_floor(head)
    }
    pub fn append_block<V: TransitionVerifier + ?Sized>(
        &mut self,
        header: Header,
        body: &[u8],
        now: u64,
        verifier: &V,
    ) -> Result<ImportOutcome> {
        let prepared = self
            .journal
            .prepare_block(header.clone(), body, now, verifier)?;
        self.pending_append(header, body, prepared)?.commit()
    }
    /// Run the complete fresh block verification, even for a known block,
    /// without writing/publishing. The returned borrow must stay local to this
    /// operation while the owner checks its remaining semantics and precharges
    /// next_disk_bytes. Cached append_block behavior is deliberately unchanged.
    pub fn prepare_append<'journal, V: TransitionVerifier + ?Sized>(
        &'journal mut self,
        header: Header,
        body: &'journal [u8],
        now: u64,
        verifier: &V,
    ) -> Result<PendingAppend<'journal>> {
        let prepared = self
            .journal
            .prepare_block_fresh(header.clone(), body, now, verifier)?;
        self.pending_append(header, body, prepared)
    }
    fn pending_append<'journal>(
        &'journal mut self,
        header: Header,
        body: &'journal [u8],
        prepared: PreparedBlock,
    ) -> Result<PendingAppend<'journal>> {
        let next_length = if self.journal.body(prepared.id).is_some() {
            self.length
        } else {
            let frame_len = HEADER_BYTES
                .checked_add(body.len())
                .ok_or(Error::ResourceLimit)?;
            let added = (frame_len as u64)
                .checked_add(4 + 32)
                .ok_or(Error::ResourceLimit)?;
            let next = self.length.checked_add(added).ok_or(Error::ResourceLimit)?;
            if next > self.journal.profile().max_journal_bytes {
                return Err(Error::ResourceLimit);
            }
            next
        };
        Ok(PendingAppend {
            journal: self,
            header,
            body,
            prepared,
            next_length,
        })
    }
    fn append_prepared(
        &mut self,
        header: Header,
        body: &[u8],
        prepared: PreparedBlock,
        next_length: u64,
    ) -> Result<ImportOutcome> {
        if self.journal.body(prepared.id).is_some() {
            return Ok(self.journal.publish(prepared));
        }
        let frame_len = HEADER_BYTES + body.len();
        // Recheck the owned append position; another writer is an application error.
        if self.file.metadata()?.len() != self.length {
            return Err(Error::CorruptJournal);
        }
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(body);
        let result = (|| -> std::io::Result<()> {
            self.file.write_all(&(frame_len as u32).to_le_bytes())?;
            self.file.write_all(&frame)?;
            self.file.write_all(&hash(&frame))?;
            self.file.sync_all()
        })();
        if let Err(error) = result {
            // No in-memory publication occurs on failure. A failed repair leaves a
            // corrupt tail that reopening rejects rather than hiding lost state.
            let _ = self.file.set_len(self.length);
            let _ = self.file.seek(SeekFrom::Start(self.length));
            let _ = self.file.sync_all();
            return Err(error.into());
        }
        self.length = next_length;
        Ok(self.journal.publish(prepared))
    }
}

fn lock(file: &File) -> Result<()> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => Error::JournalLocked,
        TryLockError::Error(error) => error.into(),
    })
}

#[cfg(test)]
mod pending_tests {
    use super::*;
    use crate::{
        RejectUnprovedTransitions,
        chain::pending_tests::{PublicFile, empty, genesis},
    };

    #[test]
    fn pending_append_checks_actual_position_at_commit_without_publishing_or_repairing_it() {
        let path = PublicFile::new();
        let pinned = genesis();
        let mut durable = DurableJournal::create(path.path(), pinned.clone(), [71; 32]).unwrap();
        let root = durable.journal().genesis_head();
        let before_disk = durable.disk_bytes();
        let before_ram = durable.journal().accounted_bytes();
        let (header, body) = empty(durable.journal(), root.block, 1001);
        // Actual extent mismatch through the owning test's private file handle.
        // Preparation must not silently relocate the existing post-precharge IO
        // failure into an earlier harmless application/semantic rejection.
        durable.file.write_all(&[0x7f]).unwrap();
        durable.file.sync_all().unwrap();
        let pending = durable
            .prepare_append(header, &body, 2000, &RejectUnprovedTransitions)
            .unwrap();
        assert!(pending.next_disk_bytes() > before_disk);
        assert_eq!(pending.commit(), Err(Error::CorruptJournal));
        assert_eq!(durable.disk_bytes(), before_disk);
        assert_eq!(durable.journal().best_validated(), root);
        assert_eq!(durable.journal().accounted_bytes(), before_ram);
        assert_eq!(durable.file.metadata().unwrap().len(), before_disk + 1);
        drop(durable);
        assert!(matches!(
            DurableJournal::open(
                path.path(),
                pinned,
                [71; 32],
                2000,
                &RejectUnprovedTransitions
            ),
            Err(Error::CorruptJournal)
        ));
    }

    #[test]
    fn pending_append_actual_write_failure_publishes_nothing_and_valid_prefix_reopens() {
        let path = PublicFile::new();
        let pinned = genesis();
        let durable = DurableJournal::create(path.path(), pinned.clone(), [71; 32]).unwrap();
        let DurableJournal {
            journal,
            file,
            length,
        } = durable;
        drop(file); // release the old exclusive OS lock before changing file mode
        let file = File::open(path.path()).unwrap();
        lock(&file).unwrap();
        let mut durable = DurableJournal {
            journal,
            file,
            length,
        };
        let root = durable.journal().genesis_head();
        let before_ram = durable.journal().accounted_bytes();
        let (header, body) = empty(durable.journal(), root.block, 1001);
        let pending = durable
            .prepare_append(header, &body, 2000, &RejectUnprovedTransitions)
            .unwrap();
        assert!(pending.next_disk_bytes() > length);
        // Genuine OS write failure on this read-only handle, not a fake proof or
        // synthetic success counter. No frame or accepted state may escape.
        assert!(matches!(pending.commit(), Err(Error::Io(_))));
        assert_eq!(durable.disk_bytes(), length);
        assert_eq!(durable.file.metadata().unwrap().len(), length);
        assert_eq!(durable.journal().best_validated(), root);
        assert_eq!(durable.journal().accounted_bytes(), before_ram);
        drop(durable);
        let reopened = DurableJournal::open(
            path.path(),
            pinned,
            [71; 32],
            2000,
            &RejectUnprovedTransitions,
        )
        .unwrap();
        assert_eq!(reopened.disk_bytes(), length);
        assert_eq!(reopened.journal().best_validated(), root);
    }
}
