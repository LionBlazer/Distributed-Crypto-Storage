use crate::{Error, MAX_SHARED_BYTES, MAX_TRACKED_FILES, Result};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// One actual byte budget for retained Journal, signer, floor and public proof
/// files. The participant's separate disk quota remains an additional check.
#[derive(Clone)]
pub struct ByteBudget {
    state: Arc<Mutex<State>>,
}
struct State {
    used: u64,
    limit: u64,
    files: BTreeMap<PathBuf, u64>,
}

/// A transient pre-write reservation. The owner must keep it for as long as its
/// bytes exist, transfer it with retain_file, or explicitly retain an ambiguous
/// failure charge. Dropping a live artifact's only reservation is misuse.
pub struct Reservation {
    budget: ByteBudget,
    bytes: u64,
}

/// Persistent charge for an actual canonical regular file. It survives Drop.
/// The caller separately owns/locks the file; this handle grants no write right.
pub struct FileCharge {
    budget: ByteBudget,
    path: PathBuf,
}

impl ByteBudget {
    pub fn new(limit: u64) -> Result<Self> {
        if limit == 0 || limit > MAX_SHARED_BYTES {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                used: 0,
                limit,
                files: BTreeMap::new(),
            })),
        })
    }
    pub fn used(&self) -> Result<u64> {
        Ok(self.state.lock().map_err(|_| Error::Poisoned)?.used)
    }
    pub fn reserve(&self, bytes: u64) -> Result<Reservation> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let next = state.used.checked_add(bytes).ok_or(Error::ResourceLimit)?;
        if next > state.limit {
            return Err(Error::ResourceLimit);
        }
        state.used = next;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }
    /// Register only actual existing bytes, after the caller acquires its file
    /// ownership/lock. Reopening the same canonical file reuses an exact charge.
    /// Reconstruct all retained files in a new budget before resuming admission.
    pub fn register_file(&self, path: impl AsRef<Path>) -> Result<FileCharge> {
        let (path, bytes) = regular_file(path.as_ref())?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(old) = state.files.get(&path) {
            if *old != bytes {
                return Err(Error::CorruptFile);
            }
        } else {
            if state.files.len() >= MAX_TRACKED_FILES {
                return Err(Error::ResourceLimit);
            }
            let next = state.used.checked_add(bytes).ok_or(Error::ResourceLimit)?;
            if next > state.limit {
                return Err(Error::ResourceLimit);
            }
            state.used = next;
            state.files.insert(path.clone(), bytes);
        }
        Ok(FileCharge {
            budget: self.clone(),
            path,
        })
    }
    // Recovery can remove a recognized abandoned stage before it registers the
    // retained inventory. Release only an existing charge, after actual unlink;
    // an unregistered removed file needs no temporary/double charge.
    pub(crate) fn release_removed_path(&self, path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(Error::CorruptFile),
            Err(error) => return Err(error.into()),
        }
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(bytes) = state.files.get(path).copied() {
            let used = state.used.checked_sub(bytes).ok_or(Error::Poisoned)?;
            state.files.remove(path);
            state.used = used;
        }
        Ok(())
    }
}
impl FileCharge {
    pub fn bytes(&self) -> Result<u64> {
        self.budget
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .files
            .get(&self.path)
            .copied()
            .ok_or(Error::Poisoned)
    }
    /// Reserve the absolute next extent BEFORE writing. An ambiguous I/O failure
    /// keeps this conservative extent; the writer must stop/poison, not shrink it.
    pub fn grow(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        let old = *state.files.get(&self.path).ok_or(Error::Poisoned)?;
        if bytes < old {
            return Err(Error::CorruptFile);
        }
        let next = state
            .used
            .checked_add(bytes - old)
            .ok_or(Error::ResourceLimit)?;
        if next > state.limit {
            return Err(Error::ResourceLimit);
        }
        state.used = next;
        state.files.insert(self.path.clone(), bytes);
        Ok(())
    }
    // Only the evidence lifecycle invokes these after its own successful OS
    // operations. No public release/retarget operation exists for signer files.
    pub(crate) fn retarget(&mut self, path: &Path) -> Result<()> {
        let (path, bytes) = regular_file(path)?;
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        let old = *state.files.get(&self.path).ok_or(Error::Poisoned)?;
        if bytes != old || state.files.contains_key(&path) {
            return Err(Error::CorruptFile);
        }
        state.files.remove(&self.path);
        state.files.insert(path.clone(), bytes);
        self.path = path;
        Ok(())
    }
    pub(crate) fn removed(&mut self) -> Result<()> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(Error::CorruptFile),
            Err(error) => return Err(error.into()),
        }
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        let bytes = *state.files.get(&self.path).ok_or(Error::Poisoned)?;
        let used = state.used.checked_sub(bytes).ok_or(Error::Poisoned)?;
        state.files.remove(&self.path);
        state.used = used;
        Ok(())
    }
}
impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Shrinking follows actual removal. Reserve growth before associated writes.
    pub fn resize(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        let base = state.used.checked_sub(self.bytes).ok_or(Error::Poisoned)?;
        let next = base.checked_add(bytes).ok_or(Error::ResourceLimit)?;
        if next > state.limit {
            return Err(Error::ResourceLimit);
        }
        state.used = next;
        self.bytes = bytes;
        Ok(())
    }
    /// Atomically transfer an exact, already charged lease to a newly retained
    /// actual file. Failure leaves the lease unchanged. Do not use `?` across
    /// creation/transfer if it could drop the last charge for a surviving file.
    pub fn retain_file(&mut self, path: impl AsRef<Path>) -> Result<FileCharge> {
        let (path, bytes) = regular_file(path.as_ref())?;
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        if bytes != self.bytes || state.files.contains_key(&path) {
            return Err(Error::CorruptFile);
        }
        if state.files.len() >= MAX_TRACKED_FILES {
            return Err(Error::ResourceLimit);
        }
        state.files.insert(path.clone(), bytes);
        self.bytes = 0;
        Ok(FileCharge {
            budget: self.budget.clone(),
            path,
        })
    }
    /// ERROR/POISON PATH ONLY: keep this conservative charge after ambiguous I/O
    /// or failed cleanup. It cannot be released in this budget. Stop the owner;
    /// only a new accounting owner may reconstruct actual disk at full restart.
    pub fn retain_conservatively(mut self) {
        self.bytes = 0;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.budget.state.lock()
            && let Some(used) = state.used.checked_sub(self.bytes)
        {
            state.used = used;
        }
    }
}

pub(crate) fn regular_file(path: &Path) -> Result<(PathBuf, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(Error::CorruptFile);
    }
    let canonical = path.canonicalize()?;
    let actual = fs::metadata(&canonical)?;
    if !actual.is_file() || actual.len() != metadata.len() {
        return Err(Error::CorruptFile);
    }
    Ok((canonical, actual.len()))
}
