use crate::wire::*;
use compact_store::{Commitment, EncryptedSnapshot, Limits};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub(crate) struct Store {
    directory: PathBuf,
    _lock: File,
    quota: u64,
    objects: BTreeMap<[u8; 32], ObjectInfo>,
    invalid: BTreeSet<[u8; 32]>,
}
fn error(e: impl std::fmt::Display) -> RemoteError {
    RemoteError::Io(e.to_string())
}
fn filename(id: &[u8; 32]) -> String {
    id.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        + ".bundle"
}
fn validate(bundle: &Bundle, stored: u64) -> Result<ObjectInfo, RemoteError> {
    let data = Commitment::decode(&bundle.data_head, Limits::default())
        .map_err(|_| RemoteError::Integrity)?;
    Commitment::decode(&bundle.index_head, Limits::default())
        .map_err(|_| RemoteError::Integrity)?;
    EncryptedSnapshot::decode_for_head(&bundle.data, &data, Limits::default())
        .map_err(|_| RemoteError::Integrity)?;
    if bundle.index.len() > Limits::default().max_image_bytes {
        return Err(RemoteError::ResourceLimit);
    }
    Ok(ObjectInfo {
        available: true,
        id: bundle.id(),
        stored_bytes: stored,
        data_bytes: bundle.data.len() as u64,
        index_bytes: bundle.index.len() as u64,
        logical_bytes: data
            .layout()
            .logical_bytes()
            .map_err(|_| RemoteError::Integrity)? as u64,
        rows: data.layout().row_count,
    })
}
impl Store {
    pub(crate) fn open(directory: &Path, quota: u64) -> io::Result<Self> {
        if quota == 0 {
            return Err(io::Error::other("Storage quota must be positive"));
        }
        fs::create_dir_all(directory)?;
        let directory = directory.canonicalize()?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("peer.lock"))?;
        lock.try_lock().map_err(io::Error::other)?;
        let pending = directory.join("write.pending");
        if pending.exists() {
            fs::remove_file(pending)?;
        }
        let mut store = Self {
            directory,
            _lock: lock,
            quota,
            objects: BTreeMap::new(),
            invalid: BTreeSet::new(),
        };
        for entry in fs::read_dir(&store.directory)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("bundle") {
                continue;
            }
            if store.objects.len() >= 1024 {
                return Err(io::Error::other("Too many stored objects"));
            }
            let bytes = read_bounded(&path)?;
            let bundle: Bundle = decode(&bytes)?;
            let info = validate(&bundle, bytes.len() as u64).map_err(io::Error::other)?;
            if path.file_name().and_then(|n| n.to_str()) != Some(filename(&info.id).as_str()) {
                return Err(io::Error::other("Object filename/hash mismatch"));
            }
            store.objects.insert(info.id, info);
        }
        if store.used() > quota {
            return Err(io::Error::other("Stored data exceeds the configured quota"));
        }
        Ok(store)
    }
    fn used(&self) -> u64 {
        self.objects
            .keys()
            .filter_map(|id| fs::metadata(self.directory.join(filename(id))).ok())
            .map(|metadata| metadata.len())
            .sum()
    }
    pub(crate) fn quota(&self) -> u64 {
        self.quota
    }
    pub(crate) fn configure(&mut self, quota: u64) -> Result<(), RemoteError> {
        if quota == 0 || quota < self.used() {
            return Err(RemoteError::ResourceLimit);
        }
        self.quota = quota;
        Ok(())
    }
    pub(crate) fn objects(&self) -> Vec<ObjectInfo> {
        self.objects
            .values()
            .map(|info| {
                let mut observed = info.clone();
                let metadata = fs::metadata(self.directory.join(filename(&info.id))).ok();
                observed.stored_bytes = metadata.as_ref().map_or(0, |m| m.len());
                observed.available = !self.invalid.contains(&info.id)
                    && metadata.is_some_and(|m| m.is_file() && m.len() == info.stored_bytes);
                if !observed.available {
                    observed.data_bytes = 0;
                    observed.index_bytes = 0;
                    observed.logical_bytes = 0;
                    observed.rows = 0;
                }
                observed
            })
            .collect()
    }
    pub(crate) fn put(&mut self, bundle: Bundle) -> Result<ObjectInfo, RemoteError> {
        let bytes = encode(&bundle).map_err(error)?;
        let info = validate(&bundle, bytes.len() as u64)?;
        if let Some(existing) = self.objects.get(&info.id).cloned() {
            self.get(&info.id)?;
            return Ok(existing);
        }
        if self.objects.len() >= 1024
            || self
                .used()
                .checked_add(info.stored_bytes)
                .is_none_or(|n| n > self.quota)
        {
            return Err(RemoteError::ResourceLimit);
        }
        let pending = self.directory.join("write.pending");
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&pending)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&pending, self.directory.join(filename(&info.id)))
        })()
        .map_err(error);
        if result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        result?;
        self.objects.insert(info.id, info.clone());
        Ok(info)
    }
    pub(crate) fn get(&mut self, id: &[u8; 32]) -> Result<Bundle, RemoteError> {
        if !self.objects.contains_key(id) {
            return Err(RemoteError::NotFound);
        }
        let result = (|| {
            let bytes = read_bounded(&self.directory.join(filename(id))).map_err(error)?;
            let bundle: Bundle = decode(&bytes).map_err(error)?;
            if &bundle.id() != id {
                return Err(RemoteError::Integrity);
            }
            validate(&bundle, bytes.len() as u64)?;
            Ok(bundle)
        })();
        if result.is_err() {
            self.invalid.insert(*id);
        } else {
            self.invalid.remove(id);
        }
        result
    }
}
fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > peer_transport::MAX_FRAME_BYTES as u64 {
        return Err(io::Error::other("Object file exceeds frame limit"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(peer_transport::MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > peer_transport::MAX_FRAME_BYTES {
        return Err(io::Error::other("Object file grew beyond limit"));
    }
    Ok(bytes)
}
