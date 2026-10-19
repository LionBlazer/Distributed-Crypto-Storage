use crate::{Error, MAX_SHARED_BYTES, MAX_TRACKED_FILES, Result, participant::Owner};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Control,
    Depot,
    Custody,
}
impl Class {
    fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Depot => 1,
            Self::Custody => 2,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Retained,
    Pending(u64),
}
struct Record {
    bytes: u64,
    class: Class,
    status: Status,
}
pub(crate) struct State {
    used: u64,
    limit: u64,
    classes: [u64; 3],
    files: BTreeMap<PathBuf, Record>,
    reservations: usize,
    next_permit: u64,
    poisoned: bool,
}
impl State {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            used: 0,
            limit,
            classes: [0; 3],
            files: BTreeMap::new(),
            reservations: 0,
            next_permit: 0,
            poisoned: false,
        }
    }
    fn live(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn charge(&mut self, class: Class, bytes: u64) -> Result<()> {
        self.live()?;
        let used = self.used.checked_add(bytes).ok_or(Error::ResourceLimit)?;
        let class_used = self.classes[class.index()]
            .checked_add(bytes)
            .ok_or(Error::ResourceLimit)?;
        if used > self.limit || (class == Class::Control && class_used > MAX_SHARED_BYTES) {
            return Err(Error::ResourceLimit);
        }
        self.used = used;
        self.classes[class.index()] = class_used;
        Ok(())
    }
    fn release(&mut self, class: Class, bytes: u64) -> Result<()> {
        let used = self.used.checked_sub(bytes).ok_or(Error::Poisoned)?;
        let class_used = self.classes[class.index()]
            .checked_sub(bytes)
            .ok_or(Error::Poisoned)?;
        self.used = used;
        self.classes[class.index()] = class_used;
        Ok(())
    }
    fn end_reservation(&mut self) {
        if let Some(n) = self.reservations.checked_sub(1) {
            self.reservations = n;
        } else {
            self.poisoned = true;
        }
    }
    pub(crate) fn usage(&self) -> (u64, [u64; 3], usize) {
        (self.used, self.classes, self.files.len())
    }
    pub(crate) fn inventory_file(&mut self, path: PathBuf, bytes: u64, class: Class) -> Result<()> {
        if self.files.contains_key(&path) {
            return Err(Error::CorruptFile);
        }
        if self.files.len() >= MAX_TRACKED_FILES {
            return Err(Error::ResourceLimit);
        }
        self.charge(class, bytes)?;
        self.files.insert(
            path,
            Record {
                bytes,
                class,
                status: Status::Retained,
            },
        );
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct Budget {
    pub(crate) state: Arc<Mutex<State>>,
    pub(crate) owner: Option<Arc<Owner>>,
    pub(crate) class: Class,
}
impl Budget {
    pub(crate) fn check_live(&self) -> Result<()> {
        self.state.lock().map_err(|_| Error::Poisoned)?.live()
    }
    fn existing(&self, path: &Path) -> Result<(PathBuf, u64)> {
        let scoped = if let Some(owner) = &self.owner {
            Some(owner.path(self.class, path)?)
        } else {
            None
        };
        let inspected = regular_file(path);
        if inspected.is_err()
            && let Some(scoped) = scoped
            && let Ok(mut state) = self.state.lock()
            && state
                .files
                .get(&scoped)
                .is_some_and(|record| record.status == Status::Retained)
        {
            state.poisoned = true;
        }
        inspected
    }
    pub(crate) fn check_existing_file(&self, path: &Path) -> Result<()> {
        if self.owner.is_none() {
            return Ok(());
        }
        let (path, bytes) = self.existing(path)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        if !state.files.get(&path).is_some_and(|record| {
            record.class == self.class && record.bytes == bytes && record.status == Status::Retained
        }) {
            state.poisoned = true;
            return Err(Error::CorruptFile);
        }
        Ok(())
    }
    fn used(&self) -> Result<u64> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(if self.owner.is_some() {
            state.classes[self.class.index()]
        } else {
            state.used
        })
    }
    fn reserve(&self, bytes: u64) -> Result<Reservation> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if self.owner.is_some() && state.reservations >= MAX_TRACKED_FILES {
            return Err(Error::ResourceLimit);
        }
        state.charge(self.class, bytes)?;
        if self.owner.is_some() {
            state.reservations += 1;
        }
        Ok(Reservation {
            budget: self.clone(),
            bytes,
            active: true,
        })
    }
    pub(crate) fn register_file(&self, path: &Path) -> Result<FileCharge> {
        let (path, bytes) = self.existing(path)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        if let Some(old) = state.files.get(&path) {
            if old.bytes != bytes || old.class != self.class || old.status != Status::Retained {
                if self.owner.is_some() {
                    state.poisoned = true;
                }
                return Err(Error::CorruptFile);
            }
        } else {
            // Ready participant handles cannot adopt an unpermitted new path.
            // Complete startup inventory uses a separate private entry point.
            if self.owner.is_some() {
                state.poisoned = true;
                return Err(Error::CorruptFile);
            }
            state.inventory_file(path.clone(), bytes, self.class)?;
        }
        Ok(FileCharge {
            budget: self.clone(),
            path,
        })
    }
    pub(crate) fn preflight_file(&self, path: &Path, initial: u64) -> Result<FilePermit> {
        let Some(owner) = &self.owner else {
            return Ok(FilePermit {
                budget: self.clone(),
                path: path.to_owned(),
                initial,
                token: None,
                promoted: false,
            });
        };
        let path = owner.path(self.class, path)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata) if !metadata.file_type().is_file() => return Err(Error::CorruptFile),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "participant file already exists",
                )
                .into());
            }
            Err(error) => return Err(error.into()),
        }
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        if state.files.contains_key(&path) {
            return Err(Error::CorruptFile);
        }
        if state.files.len() >= MAX_TRACKED_FILES {
            return Err(Error::ResourceLimit);
        }
        let token = state.next_permit;
        let next = token.checked_add(1).ok_or(Error::ResourceLimit)?;
        state.charge(self.class, initial)?;
        state.next_permit = next;
        state.files.insert(
            path.clone(),
            Record {
                bytes: initial,
                class: self.class,
                status: Status::Pending(token),
            },
        );
        Ok(FilePermit {
            budget: self.clone(),
            path,
            initial,
            token: Some(token),
            promoted: false,
        })
    }
    pub(crate) fn publication_target(&self, path: &Path) -> Result<()> {
        if let Some(owner) = &self.owner {
            owner.path(self.class, path)?;
        }
        self.check_live()
    }
    pub(crate) fn poison_after_io(&self) {
        if self.owner.is_some()
            && let Ok(mut state) = self.state.lock()
        {
            state.poisoned = true;
        }
    }
    pub(crate) fn release_removed_path(&self, path: &Path) -> Result<()> {
        if let Some(owner) = &self.owner {
            owner.path(self.class, path)?;
        }
        require_absent(path)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(record) = state.files.get(path) {
            if record.class != self.class {
                return Err(Error::CorruptFile);
            }
            let bytes = record.bytes;
            state.release(self.class, bytes)?;
            state.files.remove(path);
        }
        Ok(())
    }
}

/// Legacy unscoped budget, or the participant's fixed CONTROL class. The public
/// constructor still accepts only an explicit limit at most 256 MiB.
#[derive(Clone)]
pub struct ByteBudget {
    pub(crate) inner: Budget,
}
/// Participant depot class. Only ParticipantQuota can construct it.
#[derive(Clone)]
pub struct DepotBudget {
    pub(crate) inner: Budget,
}
/// Participant custody class. No conversion into another class is provided.
#[derive(Clone)]
pub struct CustodyBudget {
    pub(crate) inner: Budget,
}

macro_rules! quota_methods {
    () => {
        pub fn used(&self) -> Result<u64> {
            self.inner.used()
        }
        pub fn reserve(&self, bytes: u64) -> Result<Reservation> {
            self.inner.reserve(bytes)
        }
        pub fn register_file(&self, path: impl AsRef<Path>) -> Result<FileCharge> {
            self.inner.register_file(path.as_ref())
        }
        /// New participant paths reserve a file slot and initial extent before
        /// creation. Legacy unscoped budgets preserve late registration.
        pub fn preflight_file(
            &self,
            path: impl AsRef<Path>,
            initial_extent: u64,
        ) -> Result<FilePermit> {
            self.inner.preflight_file(path.as_ref(), initial_extent)
        }
        /// Check an existing scoped/tracked file BEFORE opening it for I/O.
        /// Legacy unscoped budgets preserve the caller's previous behavior.
        pub fn check_existing_file(&self, path: impl AsRef<Path>) -> Result<()> {
            self.inner.check_existing_file(path.as_ref())
        }
    };
}
impl ByteBudget {
    pub fn new(limit: u64) -> Result<Self> {
        if limit == 0 || limit > MAX_SHARED_BYTES {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            inner: Budget {
                state: Arc::new(Mutex::new(State::new(limit))),
                owner: None,
                class: Class::Control,
            },
        })
    }
    quota_methods!();
}
impl DepotBudget {
    quota_methods!();
}
impl CustodyBudget {
    quota_methods!();
}

/// Pre-create permission for ONE fixed path. In the NEW profile this owns a
/// pending slot and initial extent, not a proof or authorization token.
/// Drop releases only a proven absent file; a surviving or unknown file keeps
/// the pending charge and poisons the namespace. Every handle keeps root-lock
/// ownership alive until all descendant handles have been dropped.
pub struct FilePermit {
    budget: Budget,
    path: PathBuf,
    initial: u64,
    token: Option<u64>,
    promoted: bool,
}
impl FilePermit {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn register_file(&mut self) -> Result<FileCharge> {
        if self.promoted {
            return Err(Error::CorruptFile);
        }
        if let Some(token) = self.token {
            let (path, actual) = self.budget.existing(&self.path)?;
            let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
            state.live()?;
            let record = state.files.get_mut(&path).ok_or(Error::CorruptFile)?;
            if actual > self.initial
                || record.bytes != self.initial
                || record.class != self.budget.class
                || record.status != Status::Pending(token)
            {
                return Err(Error::CorruptFile);
            }
            record.status = Status::Retained;
            self.promoted = true;
            Ok(FileCharge {
                budget: self.budget.clone(),
                path,
            })
        } else {
            let mut charge = self.budget.register_file(&self.path)?;
            charge.grow(self.initial)?;
            self.promoted = true;
            Ok(charge)
        }
    }
}
impl Drop for FilePermit {
    fn drop(&mut self) {
        let Some(token) = self.token else {
            return;
        };
        if self.promoted {
            return;
        }
        let absent = fs::symlink_metadata(&self.path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        if let Ok(mut state) = self.budget.state.lock() {
            if let Some(record) = state.files.get(&self.path)
                && record.status == Status::Retained
            {
                return;
            } // retain_file promoted zero extent
            if !state
                .files
                .get(&self.path)
                .is_some_and(|record| record.status == Status::Pending(token))
            {
                state.poisoned = true;
                return;
            }
            if absent {
                if state.release(self.budget.class, self.initial).is_ok() {
                    state.files.remove(&self.path);
                } else {
                    state.poisoned = true;
                }
            } else {
                state.poisoned = true;
            }
        }
    }
}

pub struct Reservation {
    budget: Budget,
    bytes: u64,
    active: bool,
}
pub struct FileCharge {
    budget: Budget,
    path: PathBuf,
}
impl FileCharge {
    pub fn bytes(&self) -> Result<u64> {
        self.budget
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .files
            .get(&self.path)
            .map(|r| r.bytes)
            .ok_or(Error::Poisoned)
    }
    pub fn grow(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        let record = state.files.get(&self.path).ok_or(Error::Poisoned)?;
        if record.class != self.budget.class
            || record.status != Status::Retained
            || bytes < record.bytes
        {
            return Err(Error::CorruptFile);
        }
        let extra = bytes - record.bytes;
        state.charge(self.budget.class, extra)?;
        state
            .files
            .get_mut(&self.path)
            .ok_or(Error::Poisoned)?
            .bytes = bytes;
        Ok(())
    }
    /// Error-only ownership after a precharged file write or sync becomes
    /// uncertain. Persistent bytes stay charged; a NEW namespace is poisoned.
    /// Legacy budgets retain their previous conservative accounting behavior.
    pub fn mark_io_failed(&self) {
        self.budget.poison_after_io();
    }
    pub(crate) fn retarget(&mut self, path: &Path) -> Result<()> {
        let (path, bytes) = self.budget.existing(path)?;
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        let old = state.files.get(&self.path).ok_or(Error::Poisoned)?;
        if bytes != old.bytes
            || old.class != self.budget.class
            || old.status != Status::Retained
            || state.files.contains_key(&path)
        {
            return Err(Error::CorruptFile);
        }
        state.files.remove(&self.path);
        state.files.insert(
            path.clone(),
            Record {
                bytes,
                class: self.budget.class,
                status: Status::Retained,
            },
        );
        self.path = path;
        Ok(())
    }
    pub(crate) fn removed(&mut self) -> Result<()> {
        require_absent(&self.path)?;
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        let record = state.files.get(&self.path).ok_or(Error::Poisoned)?;
        if record.class != self.budget.class {
            return Err(Error::CorruptFile);
        }
        let bytes = record.bytes;
        state.release(self.budget.class, bytes)?;
        state.files.remove(&self.path);
        Ok(())
    }
}
impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn resize(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        if self.budget.owner.is_some() && !self.active && state.reservations >= MAX_TRACKED_FILES {
            return Err(Error::ResourceLimit);
        }
        if bytes >= self.bytes {
            state.charge(self.budget.class, bytes - self.bytes)?;
        } else {
            state.release(self.budget.class, self.bytes - bytes)?;
        }
        if self.budget.owner.is_some() && !self.active {
            state.reservations += 1;
        }
        self.active = true;
        self.bytes = bytes;
        Ok(())
    }
    pub fn retain_file(&mut self, path: impl AsRef<Path>) -> Result<FileCharge> {
        let (path, bytes) = self.budget.existing(path.as_ref())?;
        let mut state = self.budget.state.lock().map_err(|_| Error::Poisoned)?;
        state.live()?;
        if bytes != self.bytes {
            return Err(Error::CorruptFile);
        }
        if self.budget.owner.is_some() {
            let record = state.files.get_mut(&path).ok_or(Error::CorruptFile)?;
            if record.class != self.budget.class
                || record.bytes != 0
                || !matches!(record.status, Status::Pending(_))
            {
                return Err(Error::CorruptFile);
            }
            record.bytes = bytes;
            record.status = Status::Retained;
            if self.active {
                state.end_reservation();
            }
        } else {
            if state.files.contains_key(&path) {
                return Err(Error::CorruptFile);
            }
            if state.files.len() >= MAX_TRACKED_FILES {
                return Err(Error::ResourceLimit);
            }
            state.files.insert(
                path.clone(),
                Record {
                    bytes,
                    class: self.budget.class,
                    status: Status::Retained,
                },
            );
        }
        self.bytes = 0;
        self.active = false;
        Ok(FileCharge {
            budget: self.budget.clone(),
            path,
        })
    }
    /// Explicit error-only ownership. New participant namespaces are poisoned;
    /// legacy budgets retain their existing conservative-charge semantics.
    pub fn retain_conservatively(mut self) {
        if self.budget.owner.is_some()
            && let Ok(mut state) = self.budget.state.lock()
        {
            state.poisoned = true;
            if self.active {
                state.end_reservation();
            }
        }
        self.bytes = 0;
        self.active = false;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.budget.state.lock() {
            if state.release(self.budget.class, self.bytes).is_err() {
                state.poisoned = true;
            }
            if self.budget.owner.is_some() && self.active {
                state.end_reservation();
            }
        }
    }
}
fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Error::CorruptFile),
        Err(error) => Err(error.into()),
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
