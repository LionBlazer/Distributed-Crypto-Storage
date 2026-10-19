use super::{Error, MAX_SHARED_BYTES, Result};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// One actual byte budget shared by the WAL and other retained artifacts.
/// Integrations must reserve existing journal/proof files before opening a voter,
/// and reserve growth before writing those artifacts. No caller `remaining` flag.
#[derive(Clone)]
pub struct ByteBudget {
    state: Arc<Mutex<State>>,
}
struct State {
    used: u64,
    limit: u64,
    files: BTreeMap<PathBuf, u64>,
}
pub struct Reservation {
    budget: ByteBudget,
    bytes: u64,
}
pub(crate) struct FileCharge {
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
    pub fn used(&self) -> Result<u64> {
        Ok(self.state.lock().map_err(|_| Error::Poisoned)?.used)
    }
    pub(crate) fn file(&self, path: PathBuf, bytes: u64) -> Result<FileCharge> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(old) = state.files.get(&path) {
            if *old != bytes {
                return Err(Error::CorruptWal);
            }
        } else {
            if state.files.len() >= super::MAX_TRACKED_FILES {
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
}
impl FileCharge {
    pub(crate) fn grow(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        let old = *state.files.get(&self.path).ok_or(Error::Poisoned)?;
        if bytes < old {
            return Err(Error::CorruptWal);
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
}
// A WAL charge deliberately survives handle Drop: the actual file still exists.
// Reopening the same canonical file in this budget reuses its exact charge.
impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Reserve BEFORE the associated artifact grows. Shrinking is explicit and
    /// must follow actual removal; dropping a live artifact's lease is misuse.
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
}
impl Drop for Reservation {
    fn drop(&mut self) {
        // On a poisoned accounting lock, do not invent a smaller used total.
        if let Ok(mut state) = self.budget.state.lock()
            && let Some(used) = state.used.checked_sub(self.bytes)
        {
            state.used = used;
        }
    }
}
