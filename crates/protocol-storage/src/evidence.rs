use crate::budget::{Budget, Class, regular_file};
use crate::{
    ByteBudget, DepotBudget, Error, FileCharge, MAX_BLOB_BYTES, MAX_TRACKED_FILES, Result,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const LOCK: &str = ".evidence-lock";
const CHUNK: usize = 64 * 1024;

/// Expected SHA-256 of the COMPLETE original public bytes and their exact length.
/// Anyone can construct this identity. It certifies no proof, authorization,
/// agreed head, availability after restart, or SQL/lock permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlobId {
    digest: [u8; 32],
    bytes: u64,
}
impl BlobId {
    pub fn new(digest: [u8; 32], bytes: u64) -> Result<Self> {
        if bytes == 0 || bytes > MAX_BLOB_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(Self { digest, bytes })
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    fn stem(&self) -> String {
        format!("{}-{:016x}", hex(&self.digest), self.bytes)
    }
    fn filename(&self) -> String {
        format!("{}.blob", self.stem())
    }
}

/// Lowerable local storage bounds. Proof roles/topologies and protocol messages
/// retain their separate existing bounds; this is not a new proof wire format.
#[derive(Clone, Copy)]
pub struct StoreLimits {
    blob_bytes: u64,
    blobs: usize,
}
impl StoreLimits {
    pub fn new(blob_bytes: u64, blobs: usize) -> Result<Self> {
        // Leave room for the lock and one staged path in the global file bound.
        if blob_bytes == 0
            || blob_bytes > MAX_BLOB_BYTES
            || blobs == 0
            || blobs > MAX_TRACKED_FILES - 2
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self { blob_bytes, blobs })
    }
    pub fn max_blob_bytes(&self) -> u64 {
        self.blob_bytes
    }
    pub fn max_blobs(&self) -> usize {
        self.blobs
    }
}

/// Exclusive owner of one evidence directory. All files are public bytes.
/// Existing blobs are actually rehashed on open; no verified-proof receipt is
/// persisted. The caller must reconstruct other retained Journal/WAL/floor
/// charges in the SAME budget before resuming its protocol.
pub struct EvidenceStore {
    directory: PathBuf,
    budget: Budget,
    limits: StoreLimits,
    _lock: File,
    _lock_charge: FileCharge,
    sequence: u64,
}
impl EvidenceStore {
    /// Open an independently owned EXISTING directory. Unknown entries, symlinks,
    /// corrupt identities and unavailable cleanup are errors, not eviction hints.
    pub fn open(
        directory: impl AsRef<Path>,
        budget: ByteBudget,
        limits: StoreLimits,
    ) -> Result<Self> {
        if budget.inner.owner.is_some() {
            return Err(Error::InvalidConfig);
        }
        Self::open_with_budget(directory.as_ref(), budget.inner, limits)
    }
    /// Open the NEW participant's fixed depot, after complete participant-wide
    /// inventory. It shares the same bounded CAS implementation and blob caps.
    pub fn open_depot(budget: DepotBudget, limits: StoreLimits) -> Result<Self> {
        let owner = budget.inner.owner.as_ref().ok_or(Error::InvalidConfig)?;
        let directory = owner.directory(Class::Depot);
        Self::open_with_budget(&directory, budget.inner, limits)
    }
    fn open_with_budget(directory: &Path, budget: Budget, limits: StoreLimits) -> Result<Self> {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.file_type().is_dir() {
            return Err(Error::CorruptFile);
        }
        let directory = directory.canonicalize()?;
        let lock_path = directory.join(LOCK);
        let exists = match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if !metadata.file_type().is_file() => return Err(Error::CorruptFile),
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let mut permit = if exists {
            budget.check_existing_file(&lock_path)?;
            None
        } else {
            Some(budget.preflight_file(&lock_path, 0)?)
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!exists)
            .open(&lock_path)?;
        lock.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => Error::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "evidence directory already owned",
            )),
            TryLockError::Error(error) => error.into(),
        })?;
        if lock.metadata()?.len() != 0 {
            return Err(Error::CorruptFile);
        }
        let lock_charge = match &mut permit {
            Some(permit) => permit.register_file()?,
            None => budget.register_file(&lock_path)?,
        };
        let mut store = Self {
            directory,
            budget,
            limits,
            _lock: lock,
            _lock_charge: lock_charge,
            sequence: 0,
        };
        store.restore()?;
        Ok(store)
    }
    fn restore(&mut self) -> Result<()> {
        let mut entries = 0usize;
        let mut blobs = Vec::new();
        let mut stages = Vec::new();
        // Preflight all bounded names, regular-file types and extents before
        // deleting anything. Invalid metadata is never a cleanup hint.
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            entries = entries.checked_add(1).ok_or(Error::ResourceLimit)?;
            if entries > MAX_TRACKED_FILES {
                return Err(Error::ResourceLimit);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Encoding)?;
            let (path, actual_bytes) = regular_file(&entry.path())?;
            match classify_name(&name)? {
                DepotName::Lock => {
                    if actual_bytes != 0 {
                        return Err(Error::CorruptFile);
                    }
                }
                DepotName::Blob(id) => {
                    self.require_id(id)?;
                    if actual_bytes != id.bytes {
                        return Err(Error::CorruptFile);
                    }
                    if blobs.len() >= self.limits.blobs {
                        return Err(Error::ResourceLimit);
                    }
                    blobs.push((path, id));
                }
                DepotName::Stage(id, sequence) => {
                    self.require_id(id)?;
                    self.sequence = self
                        .sequence
                        .max(sequence.checked_add(1).ok_or(Error::ResourceLimit)?);
                    if actual_bytes > id.bytes {
                        return Err(Error::CorruptFile);
                    }
                    stages.push(path);
                }
            }
        }
        // A crash can leave .part + .blob hard links to ONE physical file. Remove
        // recognized abandoned stages under exclusive ownership BEFORE charging
        // retained blobs, independent of read_dir order and exact-quota limits.
        for path in stages {
            if let Err(error) = fs::remove_file(&path) {
                // Existing conservative charges survive. Try to register an
                // uncharged surviving file too; failed open is never a complete
                // reconstructed inventory and must not resume admission.
                let _ = self.budget.register_file(&path);
                return Err(error.into());
            }
            self.budget.release_removed_path(&path)?;
            sync_directory(&self.directory)?;
        }
        for (path, id) in blobs {
            self.budget.register_file(&path)?;
            require_contents(&mut File::open(path)?, id)?;
        }
        Ok(())
    }
    fn require_id(&self, id: BlobId) -> Result<()> {
        if id.bytes > self.limits.blob_bytes {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
    fn blob_count(&self) -> Result<usize> {
        let mut count = 0usize;
        let mut entries = 0usize;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            entries += 1;
            if entries > MAX_TRACKED_FILES {
                return Err(Error::ResourceLimit);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Encoding)?;
            if name == LOCK {
                continue;
            }
            let stem = name.strip_suffix(".blob").ok_or(Error::Encoding)?;
            self.require_id(parse_stem(stem)?)?;
            count += 1;
            if count > self.limits.blobs {
                return Err(Error::ResourceLimit);
            }
        }
        Ok(count)
    }
    /// One staged writer at a time, enforced by the mutable store borrow. The
    /// entire expected length is charged before the first payload write.
    pub fn stage(&mut self, id: BlobId) -> Result<StagedBlob<'_>> {
        self.require_id(id)?;
        let final_path = self.directory.join(id.filename());
        if self.blob_count()? >= self.limits.blobs && !final_path.exists() {
            return Err(Error::ResourceLimit);
        }
        let sequence = self.sequence;
        self.sequence = sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
        let path = self
            .directory
            .join(format!("{}-{sequence:016x}.part", id.stem()));
        let mut permit = self.budget.preflight_file(&path, id.bytes)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(permit.path())?;
        let charge = match permit.register_file() {
            Ok(charge) => charge,
            Err(error) => {
                // The newly created file is empty; no uncharged payload exists.
                drop(file);
                if fs::remove_file(&path).is_ok() {
                    let _ = self.budget.release_removed_path(&path);
                }
                return Err(error);
            }
        };
        let stage = StagedBlob {
            store: self,
            id,
            path,
            file: Some(file),
            charge: Some(charge),
            written: 0,
            hash: Sha256::new(),
            published: false,
            cleaned: false,
            failed: false,
            #[cfg(test)]
            fault: None,
        };
        Ok(stage)
    }
    /// A bounded sequential reader, not proof verification. Call finish after
    /// consuming ALL original bytes; actual proof and fresh-head checks follow.
    pub fn reader(&mut self, id: BlobId) -> Result<BlobReader<'_>> {
        self.require_id(id)?;
        let path = self.directory.join(id.filename());
        self.budget.check_existing_file(&path)?;
        self.budget.register_file(&path)?;
        let file = File::open(path)?;
        if file.metadata()?.len() != id.bytes {
            return Err(Error::CorruptFile);
        }
        Ok(BlobReader {
            _store: self,
            file,
            id,
            remaining: id.bytes,
            hash: Sha256::new(),
        })
    }
}

/// A bounded upload of public evidence. An I/O failure is terminal for this
/// stage. Explicit cancellation reports cleanup errors; Drop is best effort and
/// never releases charge for a file whose removal failed.
pub struct StagedBlob<'a> {
    store: &'a mut EvidenceStore,
    id: BlobId,
    path: PathBuf,
    file: Option<File>,
    charge: Option<FileCharge>,
    written: u64,
    hash: Sha256,
    published: bool,
    cleaned: bool,
    failed: bool,
    #[cfg(test)]
    fault: Option<TestFault>,
}
impl StagedBlob<'_> {
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed || self.cleaned {
            return Err(Error::Poisoned);
        }
        self.store.budget.check_live()?;
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or(Error::ResourceLimit)?;
        if next > self.id.bytes {
            return Err(Error::ResourceLimit);
        }
        if let Err(error) = self.file.as_mut().ok_or(Error::Poisoned)?.write_all(bytes) {
            self.failed = true;
            self.store.budget.poison_after_io();
            return Err(error.into());
        }
        self.hash.update(bytes);
        self.written = next;
        Ok(())
    }
    pub fn finish(mut self) -> Result<BlobId> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        self.store.budget.check_live()?;
        if self.written != self.id.bytes {
            return Err(Error::Encoding);
        }
        if <[u8; 32]>::from(self.hash.clone().finalize()) != self.id.digest {
            return Err(Error::Identity);
        }
        #[cfg(test)]
        if self.fault == Some(TestFault::Sync) {
            self.store.budget.poison_after_io();
            return Err(std::io::Error::other("PUBLIC test: stage sync failure").into());
        }
        if let Err(error) = self.file.as_ref().ok_or(Error::Poisoned)?.sync_all() {
            self.store.budget.poison_after_io();
            return Err(error.into());
        }
        let target = self.store.directory.join(self.id.filename());
        self.store.budget.publication_target(&target)?;
        match fs::hard_link(&self.path, &target) {
            Ok(()) => {
                // From here a committed name may survive even if cleanup/sync
                // fails. Never release its charge or delete it as cancellation.
                self.published = true;
                if let Err(error) = self
                    .charge
                    .as_mut()
                    .ok_or(Error::Poisoned)?
                    .retarget(&target)
                {
                    self.store.budget.poison_after_io();
                    return Err(error);
                }
                #[cfg(test)]
                if self.fault == Some(TestFault::AfterLink) {
                    return Err(std::io::Error::other(
                        "PUBLIC test: lost response after immutable publication",
                    )
                    .into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.store.budget.check_existing_file(&target)?;
                self.store.budget.register_file(&target)?;
                require_contents(&mut File::open(&target)?, self.id)?;
            }
            Err(error) => {
                self.store.budget.poison_after_io();
                return Err(error.into());
            } // no overwrite/copy fallback
        }
        self.cleanup()?;
        if let Err(error) = sync_directory(&self.store.directory) {
            self.store.budget.poison_after_io();
            return Err(error);
        }
        Ok(self.id)
    }
    pub fn cancel(mut self) -> Result<()> {
        self.cleanup()
    }
    #[cfg(test)]
    pub(crate) fn fail_cleanup_for_test(&mut self) {
        self.fault = Some(TestFault::Cleanup);
    }
    #[cfg(test)]
    pub(crate) fn fail_sync_for_test(&mut self) {
        self.fault = Some(TestFault::Sync);
    }
    #[cfg(test)]
    pub(crate) fn fail_after_link_for_test(&mut self) {
        self.fault = Some(TestFault::AfterLink);
    }
    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        drop(self.file.take());
        #[cfg(test)]
        if self.fault == Some(TestFault::Cleanup) {
            self.store.budget.poison_after_io();
            return Err(std::io::Error::other("PUBLIC test: failed stage removal").into());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                self.store.budget.poison_after_io();
                return Err(error.into());
            }
        }
        if !self.published {
            self.charge.as_mut().ok_or(Error::Poisoned)?.removed()?;
            self.charge = None;
        }
        self.cleaned = true;
        let synced = sync_directory(&self.store.directory);
        if synced.is_err() {
            self.store.budget.poison_after_io();
        }
        synced
    }
}
impl Drop for StagedBlob<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestFault {
    Cleanup,
    Sync,
    AfterLink,
}

/// Read-only public bytes. No cached identity or cryptographic success token.
/// It borrows the owning store so publication/cleanup cannot run concurrently.
pub struct BlobReader<'a> {
    _store: &'a mut EvidenceStore,
    file: File,
    id: BlobId,
    remaining: u64,
    hash: Sha256,
}
impl BlobReader<'_> {
    pub fn id(&self) -> BlobId {
        self.id
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn finish(mut self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::Encoding);
        }
        let mut extra = [0];
        if self.file.read(&mut extra)? != 0 || self.file.metadata()?.len() != self.id.bytes {
            return Err(Error::CorruptFile);
        }
        if <[u8; 32]>::from(self.hash.finalize()) != self.id.digest {
            return Err(Error::Identity);
        }
        Ok(())
    }
}
impl Read for BlobReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let n = out.len().min(self.remaining as usize);
        let read = self.file.read(&mut out[..n])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated evidence",
            ));
        }
        self.hash.update(&out[..read]);
        self.remaining -= read as u64;
        Ok(read)
    }
}

pub(crate) fn require_contents(file: &mut File, id: BlobId) -> Result<()> {
    if file.metadata()?.len() != id.bytes {
        return Err(Error::CorruptFile);
    }
    let mut remaining = id.bytes;
    let mut hash = Sha256::new();
    let mut buffer = [0; CHUNK];
    while remaining != 0 {
        let n = buffer.len().min(remaining as usize);
        file.read_exact(&mut buffer[..n])
            .map_err(|_| Error::CorruptFile)?;
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    let mut extra = [0];
    if file.read(&mut extra)? != 0 || file.metadata()?.len() != id.bytes {
        return Err(Error::CorruptFile);
    }
    if <[u8; 32]>::from(hash.finalize()) != id.digest {
        return Err(Error::Identity);
    }
    Ok(())
}
pub(crate) enum DepotName {
    Lock,
    Blob(BlobId),
    Stage(BlobId, u64),
}
pub(crate) fn classify_name(name: &str) -> Result<DepotName> {
    if name == LOCK {
        return Ok(DepotName::Lock);
    }
    if let Some(stem) = name.strip_suffix(".blob") {
        return Ok(DepotName::Blob(parse_stem(stem)?));
    }
    if let Some(stem) = name.strip_suffix(".part") {
        let (identity, sequence_text) = stem.rsplit_once('-').ok_or(Error::Encoding)?;
        let id = parse_stem(identity)?;
        if sequence_text.len() != 16 {
            return Err(Error::Encoding);
        }
        let sequence = u64::from_str_radix(sequence_text, 16).map_err(|_| Error::Encoding)?;
        if format!("{sequence:016x}") != sequence_text {
            return Err(Error::Encoding);
        }
        sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
        return Ok(DepotName::Stage(id, sequence));
    }
    Err(Error::Encoding)
}
fn parse_stem(stem: &str) -> Result<BlobId> {
    if stem.len() != 81 || !stem.is_ascii() || stem.as_bytes()[64] != b'-' {
        return Err(Error::Encoding);
    }
    let mut digest = [0; 32];
    for (i, value) in digest.iter_mut().enumerate() {
        *value = u8::from_str_radix(&stem[2 * i..2 * i + 2], 16).map_err(|_| Error::Encoding)?;
    }
    let bytes = u64::from_str_radix(&stem[65..], 16).map_err(|_| Error::Encoding)?;
    let id = BlobId::new(digest, bytes)?;
    if id.stem() != stem {
        return Err(Error::Encoding);
    }
    Ok(id)
}
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(text, "{byte:02x}");
    }
    text
}
pub(crate) fn sync_directory(directory: &Path) -> Result<()> {
    // std provides directory fsync on Unix. Windows file sync/hard-link success
    // does NOT promise durable directory entries; missing entries stop reopen.
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}
