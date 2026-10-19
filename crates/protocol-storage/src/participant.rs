//! Explicit NEW local logical-file quota profile. No legacy workspace import.
use crate::{
    ByteBudget, CustodyBudget, DepotBudget, Error, MAX_BLOB_BYTES, MAX_SHARED_BYTES,
    MAX_TRACKED_FILES, Result,
    budget::{Budget, Class, State, regular_file},
    evidence::{DepotName, classify_name, require_contents, sync_directory},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const MAX_PARTICIPANT_BYTES: u64 = 30_000_000_000;
const HEADER: &str = "participant-v1.profile";
const LOCK: &str = "participant.lock";
const HEADER_BYTES: usize = 136;
const MAGIC: &[u8; 8] = b"DCSPSQ01";
// ONE exclusive depot writer can leave one extra .part hard-link name after
// publication, without creating a second logical payload/ledger entry.
const MAX_INVENTORY_NAMES: usize = MAX_TRACKED_FILES + 1;

pub fn participant_profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/participant-logical-file-quota/v1/new-namespace/no-migration");
    hash.update(
        b"root:participant-v1.profile+participant.lock+control+depot+custody/flat-lowercase-names",
    );
    hash.update(
        b"control:hex32.wal|journal|floor|meta;custody:hex32.object2|meta;depot:canonical-CAS",
    );
    hash.update(
        b"ONE-ledger/global+class/precreate-pending-slot+extent/retain-on-error/poison/no-reset",
    );
    hash.update(b"temporary-CAS-hardlink-alias-one-charge;directory-and-FS-overhead-excluded;not-physical-quota");
    for value in [
        MAX_PARTICIPANT_BYTES,
        MAX_SHARED_BYTES,
        MAX_BLOB_BYTES,
        MAX_TRACKED_FILES as u64,
        MAX_INVENTORY_NAMES as u64,
        HEADER_BYTES as u64,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}

#[derive(Clone, Copy)]
pub enum ControlFile {
    Wal,
    Journal,
    Floor,
    Metadata,
}
impl ControlFile {
    fn suffix(self) -> &'static str {
        match self {
            Self::Wal => ".wal",
            Self::Journal => ".journal",
            Self::Floor => ".floor",
            Self::Metadata => ".meta",
        }
    }
}
#[derive(Clone, Copy)]
pub enum CustodyFile {
    Object,
    Metadata,
}
impl CustodyFile {
    fn suffix(self) -> &'static str {
        match self {
            Self::Object => ".object2",
            Self::Metadata => ".meta",
        }
    }
}

/// A read-only observation. This carries no allocation or application authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParticipantUsage {
    total: u64,
    classes: [u64; 3],
    files: usize,
}
impl ParticipantUsage {
    pub fn total_bytes(self) -> u64 {
        self.total
    }
    pub fn control_bytes(self) -> u64 {
        self.classes[0]
    }
    pub fn depot_bytes(self) -> u64 {
        self.classes[1]
    }
    pub fn custody_bytes(self) -> u64 {
        self.classes[2]
    }
    pub fn tracked_files(self) -> usize {
        self.files
    }
}

pub(crate) struct Owner {
    root: PathBuf,
    _lock: File,
}
impl Owner {
    pub(crate) fn directory(&self, class: Class) -> PathBuf {
        self.root.join(match class {
            Class::Control => "control",
            Class::Depot => "depot",
            Class::Custody => "custody",
        })
    }
    pub(crate) fn path(&self, class: Class, path: &Path) -> Result<PathBuf> {
        let directory = self.directory(class);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            || path.parent() != Some(directory.as_path())
        {
            return Err(Error::CorruptFile);
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.file_type().is_dir() || directory.canonicalize()? != directory {
            return Err(Error::CorruptFile);
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Encoding)?;
        match class {
            Class::Control if !control_name(name) => return Err(Error::Encoding),
            Class::Custody if !custody_name(name) => return Err(Error::Encoding),
            Class::Depot => {
                classify_name(name)?;
            }
            _ => {}
        }
        Ok(directory.join(name))
    }
}

/// Exclusive NEW namespace. Child budgets, reservations, file permits and file
/// charges all retain its root lock and ONE ledger; clones grant no new allowance.
pub struct ParticipantQuota {
    state: Arc<Mutex<State>>,
    owner: Arc<Owner>,
}
impl ParticipantQuota {
    /// Explicit decimal capacity, at most 30 GB. 10/20/30 GB are local policy
    /// choices; smaller positive limits are useful for constrained deployments
    /// and owning tests. This capacity is deliberately not consensus RulesId.
    pub fn create_new(
        root: impl AsRef<Path>,
        namespace: [u8; 32],
        total_limit: u64,
    ) -> Result<Self> {
        validate_limit(total_limit)?;
        if total_limit < HEADER_BYTES as u64 {
            return Err(Error::ResourceLimit);
        }
        fs::create_dir(root.as_ref())?; // no fallback from an existing namespace
        let root = root.as_ref().canonicalize()?;
        for name in ["control", "depot", "custody"] {
            fs::create_dir(root.join(name))?;
        }
        let mut state = State::new(total_limit);
        // Metadata and both file slots are charged BEFORE either file is written.
        state.inventory_file(root.join(HEADER), HEADER_BYTES as u64, Class::Control)?;
        state.inventory_file(root.join(LOCK), 0, Class::Control)?;
        let lock = File::create_new(root.join(LOCK))?;
        exclusive(&lock)?;
        let mut header = File::create_new(root.join(HEADER))?;
        header.write_all(&header_bytes(namespace, total_limit))?;
        header.sync_all()?;
        lock.sync_all()?;
        sync_directory(&root)?;
        sync_directory(root.parent().ok_or(Error::InvalidConfig)?)?;
        let quota = Self {
            state: Arc::new(Mutex::new(state)),
            owner: Arc::new(Owner { root, _lock: lock }),
        };
        quota.inventory()?;
        Ok(quota)
    }
    /// Existing-only reopen with independent namespace and capacity pins. Every
    /// class is inventoried before any admission-capable child handle escapes.
    pub fn open_existing(
        root: impl AsRef<Path>,
        namespace: [u8; 32],
        total_limit: u64,
    ) -> Result<Self> {
        validate_limit(total_limit)?;
        let metadata = fs::symlink_metadata(root.as_ref())?;
        if !metadata.file_type().is_dir() {
            return Err(Error::CorruptFile);
        }
        let root = root.as_ref().canonicalize()?;
        let (_, lock_bytes) = regular_file(&root.join(LOCK))?;
        if lock_bytes != 0 {
            return Err(Error::CorruptFile);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(LOCK))?;
        exclusive(&lock)?;
        if lock.metadata()?.len() != 0 {
            return Err(Error::CorruptFile);
        }
        let (header_path, bytes) = regular_file(&root.join(HEADER))?;
        if bytes != HEADER_BYTES as u64 {
            return Err(Error::CorruptFile);
        }
        let mut received = [0; HEADER_BYTES];
        let mut header = File::open(&header_path)?;
        header.read_exact(&mut received)?;
        let mut extra = [0];
        if header.read(&mut extra)? != 0 || header.metadata()?.len() != HEADER_BYTES as u64 {
            return Err(Error::CorruptFile);
        }
        if received != header_bytes(namespace, total_limit) {
            return Err(Error::Identity);
        }
        let mut state = State::new(total_limit);
        state.inventory_file(header_path, bytes, Class::Control)?;
        state.inventory_file(root.join(LOCK), 0, Class::Control)?;
        let quota = Self {
            state: Arc::new(Mutex::new(state)),
            owner: Arc::new(Owner { root, _lock: lock }),
        };
        quota.inventory()?;
        Ok(quota)
    }
    fn budget(&self, class: Class) -> Budget {
        Budget {
            state: self.state.clone(),
            owner: Some(self.owner.clone()),
            class,
        }
    }
    pub fn control_budget(&self) -> ByteBudget {
        ByteBudget {
            inner: self.budget(Class::Control),
        }
    }
    pub fn depot_budget(&self) -> DepotBudget {
        DepotBudget {
            inner: self.budget(Class::Depot),
        }
    }
    pub fn custody_budget(&self) -> CustodyBudget {
        CustodyBudget {
            inner: self.budget(Class::Custody),
        }
    }
    pub fn control_file(&self, id: [u8; 32], kind: ControlFile) -> PathBuf {
        self.owner
            .directory(Class::Control)
            .join(format!("{}{}", hex(&id), kind.suffix()))
    }
    pub fn custody_file(&self, id: [u8; 32], kind: CustodyFile) -> PathBuf {
        self.owner
            .directory(Class::Custody)
            .join(format!("{}{}", hex(&id), kind.suffix()))
    }
    pub fn depot_directory(&self) -> PathBuf {
        self.owner.directory(Class::Depot)
    }
    pub fn usage(&self) -> Result<ParticipantUsage> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let (total, classes, files) = state.usage();
        Ok(ParticipantUsage {
            total,
            classes,
            files,
        })
    }
    fn inventory(&self) -> Result<()> {
        let mut roots = 0;
        for entry in fs::read_dir(&self.owner.root)? {
            let entry = entry?;
            roots += 1;
            if roots > 5 {
                return Err(Error::Encoding);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Encoding)?;
            let metadata = fs::symlink_metadata(entry.path())?;
            match name.as_str() {
                HEADER
                    if metadata.file_type().is_file() && metadata.len() == HEADER_BYTES as u64 => {}
                LOCK if metadata.file_type().is_file() && metadata.len() == 0 => {}
                "control" | "depot" | "custody" if metadata.file_type().is_dir() => {}
                _ => return Err(Error::Encoding),
            }
        }
        if roots != 5 {
            return Err(Error::CorruptFile);
        }
        let mut files = Vec::new();
        let mut stages = Vec::new();
        let mut entries = 2usize;
        // ALL classes pass metadata/name preflight before any stage is removed.
        for class in [Class::Control, Class::Depot, Class::Custody] {
            let directory = self.owner.directory(class);
            let metadata = fs::symlink_metadata(&directory)?;
            if !metadata.file_type().is_dir() {
                return Err(Error::CorruptFile);
            }
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                entries += 1;
                if entries > MAX_INVENTORY_NAMES {
                    return Err(Error::ResourceLimit);
                }
                let scoped = self.owner.path(class, &entry.path())?;
                let (path, bytes) = regular_file(&scoped)?;
                let mut blob = None;
                if class == Class::Depot {
                    let name = entry
                        .file_name()
                        .into_string()
                        .map_err(|_| Error::Encoding)?;
                    match classify_name(&name)? {
                        DepotName::Lock if bytes != 0 => return Err(Error::CorruptFile),
                        DepotName::Lock => {}
                        DepotName::Blob(id) => {
                            if bytes != id.bytes() {
                                return Err(Error::CorruptFile);
                            }
                            blob = Some(id);
                        }
                        DepotName::Stage(id, _) => {
                            if bytes > id.bytes() {
                                return Err(Error::CorruptFile);
                            }
                            stages.push((path, bytes));
                            continue;
                        }
                    }
                }
                files.push((path, bytes, class, blob));
            }
        }
        for (path, bytes) in stages {
            if let Err(error) = fs::remove_file(&path) {
                let _ = self
                    .state
                    .lock()
                    .map_err(|_| Error::Poisoned)?
                    .inventory_file(path, bytes, Class::Depot);
                return Err(error.into());
            }
            sync_directory(&self.owner.directory(Class::Depot))?;
        }
        for (path, bytes, class, blob) in files {
            self.state
                .lock()
                .map_err(|_| Error::Poisoned)?
                .inventory_file(path.clone(), bytes, class)?;
            if let Some(id) = blob {
                require_contents(&mut File::open(path)?, id)?;
            }
        }
        Ok(())
    }
}

fn validate_limit(limit: u64) -> Result<()> {
    if limit == 0 || limit > MAX_PARTICIPANT_BYTES {
        Err(Error::InvalidConfig)
    } else {
        Ok(())
    }
}
fn header_bytes(namespace: [u8; 32], limit: u64) -> [u8; HEADER_BYTES] {
    let mut out = [0; HEADER_BYTES];
    out[..8].copy_from_slice(MAGIC);
    out[8..40].copy_from_slice(&participant_profile_digest());
    out[40..72].copy_from_slice(&namespace);
    out[72..80].copy_from_slice(&limit.to_le_bytes());
    out[80..88].copy_from_slice(&MAX_SHARED_BYTES.to_le_bytes());
    out[88..96].copy_from_slice(&(MAX_TRACKED_FILES as u64).to_le_bytes());
    out[96..104].copy_from_slice(&MAX_BLOB_BYTES.to_le_bytes());
    let mut hash = Sha256::new();
    hash.update(b"dcs/participant-logical-file-header/v1");
    hash.update(&out[..104]);
    out[104..].copy_from_slice(&hash.finalize());
    out
}
fn canonical_name(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix).is_some_and(|stem| {
        stem.len() == 64
            && stem
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn control_name(name: &str) -> bool {
    [".wal", ".journal", ".floor", ".meta"]
        .into_iter()
        .any(|suffix| canonical_name(name, suffix))
}
fn custody_name(name: &str) -> bool {
    [".object2", ".meta"]
        .into_iter()
        .any(|suffix| canonical_name(name, suffix))
}
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(text, "{byte:02x}");
    }
    text
}
fn exclusive(file: &File) -> Result<()> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => Error::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "participant namespace already owned",
        )),
        TryLockError::Error(error) => error.into(),
    })
}
