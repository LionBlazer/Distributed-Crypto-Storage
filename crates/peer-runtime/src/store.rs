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
    heads: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    invalid: BTreeSet<[u8; 32]>,
    journals: BTreeSet<[u8; 32]>,
    reserved: u64,
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
            heads: BTreeMap::new(),
            invalid: BTreeSet::new(),
            journals: BTreeSet::new(),
            reserved: 0,
        };
        for entry in fs::read_dir(&store.directory)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("journal") {
                if store.journals.len() >= 8 {
                    return Err(io::Error::other("Too many journals"));
                }
                let stem = path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| io::Error::other("Invalid journal filename"))?;
                if stem.len() != 64
                    || !stem
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(io::Error::other("Invalid journal filename"));
                }
                let mut id = [0; 32];
                for (index, byte) in id.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&stem[index * 2..index * 2 + 2], 16)
                        .map_err(io::Error::other)?;
                }
                if !path.is_file()
                    || fs::metadata(&path)?.len() > version_journal::MAX_JOURNAL_BYTES
                {
                    return Err(io::Error::other("Invalid journal file"));
                }
                store.journals.insert(id);
                continue;
            }
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
            store
                .heads
                .entry(head_pair_id(&bundle.data_head, &bundle.index_head))
                .or_default()
                .insert(info.id);
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
            .sum::<u64>()
            + self.journal_bytes()
            + self.reserved
    }
    pub(crate) fn journal_bytes(&self) -> u64 {
        self.journals
            .iter()
            .filter_map(|id| fs::metadata(self.journal_path(id)).ok())
            .map(|m| m.len())
            .sum()
    }
    pub(crate) fn journal_path(&self, id: &[u8; 32]) -> PathBuf {
        self.directory
            .join(filename(id).trim_end_matches(".bundle").to_owned() + ".journal")
    }
    pub(crate) fn has_unloaded_journal(&self, active: &BTreeSet<[u8; 32]>) -> bool {
        self.journals
            .iter()
            .any(|id| !active.contains(id) && self.journal_path(id).exists())
    }
    pub(crate) fn reserve(&mut self, bytes: u64) -> Result<(), RemoteError> {
        if self
            .used()
            .checked_add(bytes)
            .is_none_or(|n| n > self.quota)
        {
            return Err(RemoteError::ResourceLimit);
        }
        self.reserved = self
            .reserved
            .checked_add(bytes)
            .ok_or(RemoteError::ResourceLimit)?;
        Ok(())
    }
    pub(crate) fn release(&mut self, bytes: u64) {
        self.reserved = self.reserved.saturating_sub(bytes);
    }
    pub(crate) fn register_journal(&mut self, id: [u8; 32]) -> Result<(), RemoteError> {
        if !self.journals.contains(&id) && self.journals.len() >= 8 {
            return Err(RemoteError::ResourceLimit);
        }
        self.journals.insert(id);
        Ok(())
    }
    /// Removes only objects that were committed in this journal's validated
    /// history and are absent from all currently retained network states.
    pub(crate) fn prune_journal_objects(
        &mut self,
        history: &BTreeSet<[u8; 32]>,
        retained: &BTreeSet<[u8; 32]>,
    ) -> Result<(), RemoteError> {
        let ids: Vec<_> = self.objects.keys().copied().collect();
        for id in ids {
            let bundle = self.get(&id)?;
            let pair = head_pair_id(&bundle.data_head, &bundle.index_head);
            if history.contains(&pair) && !retained.contains(&pair) {
                fs::remove_file(self.directory.join(filename(&id))).map_err(error)?;
                self.objects.remove(&id);
                self.invalid.remove(&id);
                if let Some(objects) = self.heads.get_mut(&pair) {
                    objects.remove(&id);
                }
                if self.heads.get(&pair).is_some_and(BTreeSet::is_empty) {
                    self.heads.remove(&pair);
                }
            }
        }
        Ok(())
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
        self.heads
            .entry(head_pair_id(&bundle.data_head, &bundle.index_head))
            .or_default()
            .insert(info.id);
        self.objects.insert(info.id, info.clone());
        Ok(info)
    }
    pub(crate) fn get_version(
        &mut self,
        data_head: &[u8],
        index_head: &[u8],
    ) -> Result<Bundle, RemoteError> {
        if data_head.len() != 112 || index_head.len() != 112 {
            return Err(RemoteError::InvalidRequest);
        }
        let pair = head_pair_id(data_head, index_head);
        let ids = self
            .heads
            .get(&pair)
            .cloned()
            .ok_or(RemoteError::NotFound)?;
        for id in ids {
            if let Ok(bundle) = self.get(&id)
                && bundle.data_head == data_head
                && bundle.index_head == index_head
            {
                return Ok(bundle);
            }
        }
        Err(RemoteError::NotFound)
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
pub(crate) fn head_pair_id(data: &[u8], index: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"dcs/peer-runtime/head-pair/v1");
    digest.update((data.len() as u64).to_le_bytes());
    digest.update(data);
    digest.update((index.len() as u64).to_le_bytes());
    digest.update(index);
    digest.finalize().into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "dcs-runtime-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn bundle() -> Bundle {
        let owner = compact_store::Owner::generate([1; 16]).unwrap();
        let snapshot = owner
            .seal(
                compact_store::Layout {
                    schema: [2; 16],
                    row_width: 3,
                    rows_per_page: 8,
                    row_count: 1,
                },
                &[18, 10, 0],
                Limits::default(),
            )
            .unwrap();
        Bundle {
            data_head: snapshot.commitment().encode().to_vec(),
            index_head: snapshot.commitment().encode().to_vec(),
            data: snapshot.encode(),
            index: snapshot.encode(),
        }
    }
    #[test]
    fn journal_bytes_and_inflight_reservations_share_the_bundle_disk_quota() {
        let directory = Directory::new();
        let mut store = Store::open(&directory.0, 4096).unwrap();
        let id = [3; 32];
        store.register_journal(id).unwrap();
        fs::write(store.journal_path(&id), vec![0; 1024]).unwrap();
        assert_eq!(store.journal_bytes(), 1024);
        store.reserve(2048).unwrap();
        assert!(store.configure(2048).is_err());
        assert!(store.reserve(1025).is_err());
        store.release(2048);
        assert!(store.configure(2048).is_ok());
    }
    #[test]
    fn exact_head_fetch_checks_physical_data_and_collection_preserves_staging() {
        let directory = Directory::new();
        let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
        let committed = bundle();
        let staged = bundle();
        store.put(committed.clone()).unwrap();
        store.put(staged.clone()).unwrap();
        assert_eq!(
            store
                .get_version(&committed.data_head, &committed.index_head)
                .unwrap()
                .id(),
            committed.id()
        );
        let history = BTreeSet::from([head_pair_id(&committed.data_head, &committed.index_head)]);
        let retained = BTreeSet::from([head_pair_id(&committed.data_head, &committed.index_head)]);
        store.prune_journal_objects(&history, &retained).unwrap();
        assert_eq!(store.objects.len(), 2);
        store
            .prune_journal_objects(&history, &BTreeSet::new())
            .unwrap();
        assert_eq!(store.objects.len(), 1);
        assert_eq!(store.heads.len(), 1);
        assert!(store.get(&staged.id()).is_ok());
        assert!(
            store
                .get_version(&committed.data_head, &committed.index_head)
                .is_err()
        );
        fs::write(store.directory.join(filename(&staged.id())), b"damaged").unwrap();
        assert!(
            store
                .get_version(&staged.data_head, &staged.index_head)
                .is_err()
        );
    }
}
