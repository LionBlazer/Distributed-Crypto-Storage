use crate::wire::*;
use crate::{CheckedObject, RawBundle, objects};
use compact_store::{Commitment, Limits};
mod workspace;
pub(crate) const PROFILE_BYTES: usize = 40;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

mod candidate;
use candidate::Candidate;

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
pub(super) fn error(e: impl std::fmt::Display) -> RemoteError {
    RemoteError::Io(e.to_string())
}
fn filename(id: &[u8; 32]) -> String {
    id.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        + ".object2"
}
/// Custody is bounded by authenticated image size rather than a SQL row model.
/// A typed relation can use row_width=1, where row_count counts encoded bytes.
/// Every row occupies at least one byte; the unchanged image/page/frame/quota
/// bounds therefore also bound this geometry before any page allocation.
pub(crate) fn custody_limits() -> Limits {
    let limits = Limits::default();
    Limits {
        max_rows: limits.max_image_bytes as u64,
        ..limits
    }
}
fn object_info(
    bundle: &RawBundle,
    stored: u64,
    object: [u8; 32],
    data: &Commitment,
) -> Result<ObjectInfo, RemoteError> {
    Ok(ObjectInfo {
        available: true,
        id: object,
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
        if quota < PROFILE_BYTES as u64 {
            return Err(io::Error::other(
                "Storage quota cannot fit the custody profile",
            ));
        }
        let fresh = workspace::preflight(directory, false)?;
        fs::create_dir_all(directory)?;
        let directory = directory.canonicalize()?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("peer.lock"))?;
        lock.try_lock().map_err(io::Error::other)?;
        workspace::preflight(&directory, fresh)?;
        if fresh {
            workspace::initialize(&directory)?;
        }
        workspace::preflight(&directory, false)?;
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
            if path.extension().and_then(|e| e.to_str()) == Some("journal2") {
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
            if path.extension().and_then(|e| e.to_str()) != Some("object2") {
                continue;
            }
            if store.objects.len() >= 1024 {
                return Err(io::Error::other("Too many stored objects"));
            }
            let bytes = read_bounded(&path)?;
            let checked =
                CheckedObject::audit(objects::decode_disk(&bytes)?).map_err(io::Error::other)?;
            let object = *checked.version().object();
            let (version, bundle) = checked.into_raw_with_version();
            let info = object_info(&bundle, bytes.len() as u64, object, version.data_head())
                .map_err(io::Error::other)?;
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
        let pending = store.directory.join(workspace::PENDING);
        if pending.exists() {
            fs::remove_file(pending)?;
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
            + PROFILE_BYTES as u64
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
            .join(filename(id).trim_end_matches(".object2").to_owned() + ".journal2")
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
    /// The head index establishes deletion eligibility, never physical custody.
    pub(crate) fn prune_journal_objects(
        &mut self,
        history: &BTreeSet<[u8; 32]>,
        retained: &BTreeSet<[u8; 32]>,
    ) -> Result<(), RemoteError> {
        // put/open populate this index only after validating the complete images
        // and canonical object hash. Collection needs those immutable identities,
        // not a second audit of retained or unrelated ciphertext. Actual reads
        // and proving still validate every physical byte.
        let protected: BTreeSet<_> = retained
            .iter()
            .filter_map(|pair| self.heads.get(pair))
            .flat_map(|objects| objects.iter().copied())
            .collect();
        let candidates: Vec<_> = history
            .difference(retained)
            .filter_map(|pair| self.heads.get(pair).map(|objects| (pair, objects)))
            .flat_map(|(pair, objects)| objects.iter().map(move |id| (*pair, *id)))
            .filter(|(_, id)| !protected.contains(id))
            .collect();
        for (pair, id) in candidates {
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
    pub(crate) fn put_delta(
        &mut self,
        request: crate::StoreDeltaRequest,
    ) -> Result<ObjectInfo, RemoteError> {
        let verified = request.verify_pages().map_err(|_| RemoteError::Integrity)?;
        let object = *request.object();
        if let Some(existing) = self.objects.get(&object).cloned() {
            // An acknowledgement lost after durable storage may be retried even
            // after the old base is collected. Metadata is never enough: audit
            // every physical byte of the already stored target before replying.
            let bundle = self.get(&object)?;
            let (data, index) = request.new_heads();
            if bundle.data_head != data.encode() || bundle.index_head != index.encode() {
                return Err(RemoteError::Integrity);
            }
            return Ok(existing);
        }
        let base = self.read_verified(request.base_object())?;
        let reconstructed = request
            .reconstruct(base, verified)
            .map_err(|_| RemoteError::Integrity)?;
        self.persist(Candidate::from_reconstructed(reconstructed)?)
    }

    pub(crate) fn put(&mut self, bundle: RawBundle) -> Result<ObjectInfo, RemoteError> {
        self.persist(Candidate::full(bundle)?)
    }

    pub(crate) fn put_checked(
        &mut self,
        checked: CheckedObject,
    ) -> Result<ObjectInfo, RemoteError> {
        self.persist(Candidate::checked(checked)?)
    }

    // The only durable admission route consumes an immutable fully checked
    // candidate. No RawBundle, advisory metadata or revalidation flag is accepted.
    fn persist(&mut self, candidate: Candidate) -> Result<ObjectInfo, RemoteError> {
        let info = candidate.info();
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
        let pending = self.directory.join(workspace::PENDING);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&pending)?;
            {
                // Coalesce scalar/header writes without allocating another full
                // disk image. Complete flushing precedes file sync and rename.
                let mut output = io::BufWriter::with_capacity(16 * 1024, &mut file);
                candidate.write_to(&mut output)?;
                output.flush()?;
            }
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
            .entry(head_pair_id(candidate.heads().0, candidate.heads().1))
            .or_default()
            .insert(info.id);
        self.objects.insert(info.id, info.clone());
        Ok(info.clone())
    }
    pub(crate) fn get_version(
        &mut self,
        data_head: &[u8],
        index_head: &[u8],
    ) -> Result<RawBundle, RemoteError> {
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
    pub(crate) fn get(&mut self, id: &[u8; 32]) -> Result<RawBundle, RemoteError> {
        self.read_verified(id).map(CheckedObject::into_raw)
    }
    pub(crate) fn get_pages(
        &mut self,
        request: crate::PageBatchRequest,
    ) -> Result<crate::PageBatch, RemoteError> {
        let id = *request.object();
        self.read_audited(&id, |bytes| {
            let checked = objects::audit_disk_images(&bytes)?;
            if checked.version().object() != &id {
                return Err(RemoteError::Integrity);
            }
            let (_, data, index) = checked.into_images();
            // Outer success records physical custody even if the independently
            // supplied request heads fail while constructing the owned reply.
            Ok(crate::PageBatch::from_images(request, &data, &index)
                .map_err(|_| RemoteError::Integrity))
        })?
    }
    pub(crate) fn get_read_image(
        &mut self,
        request: crate::ReadImageRequest,
    ) -> Result<crate::ReadImage, RemoteError> {
        let id = *request.object();
        self.read_audited(&id, |bytes| {
            let checked = objects::audit_disk_images(&bytes)?;
            if checked.version().object() != &id {
                return Err(RemoteError::Integrity);
            }
            let (version, data, index) = checked.into_images();
            Ok(
                crate::ReadImage::from_images(request, version.nonce(), data, &index)
                    .map_err(|_| RemoteError::Integrity),
            )
        })?
    }
    // Every route audits the complete physical bundle, including unrequested
    // bytes in both images. Cached names/status never establish custody.
    fn read_verified(&mut self, id: &[u8; 32]) -> Result<CheckedObject, RemoteError> {
        self.read_audited(id, |bytes| {
            let checked = CheckedObject::audit(objects::decode_disk(&bytes).map_err(error)?)?;
            if checked.version().object() != id {
                return Err(RemoteError::Integrity);
            }
            Ok(checked)
        })
    }
    pub(crate) fn audit_version(
        &mut self,
        id: &[u8; 32],
    ) -> Result<crate::TargetVersion, RemoteError> {
        self.read_audited(id, |bytes| {
            let version = objects::audit_disk_version(&bytes)?;
            if version.object() != id {
                return Err(RemoteError::Integrity);
            }
            Ok(version)
        })
    }
    // Callers complete both image audits and check the object ID. Their outer
    // Result describes physical custody only: reply-binding/lookup errors stay
    // inside an Ok so successful physical repair clears an old invalid marker.
    // Unknown names stay NotFound; failed known physical reads mark unavailable.
    fn read_audited<T>(
        &mut self,
        id: &[u8; 32],
        audit: impl FnOnce(Vec<u8>) -> Result<T, RemoteError>,
    ) -> Result<T, RemoteError> {
        if !self.objects.contains_key(id) {
            return Err(RemoteError::NotFound);
        }
        let result = read_bounded(&self.directory.join(filename(id)))
            .map_err(error)
            .and_then(audit);
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
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::test_support::Directory;
    use super::*;
    use compact_store::EncryptedSnapshot;
    fn bundle() -> RawBundle {
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
        RawBundle {
            version: 2,
            nonce: [31; 32],
            data_head: snapshot.commitment().encode().to_vec(),
            index_head: snapshot.commitment().encode().to_vec(),
            data: snapshot.encode(),
            index: snapshot.encode(),
        }
    }
    #[test]
    fn full_upload_quota_rejection_leaves_no_pending_or_published_object() {
        let directory = Directory::new();
        let original = bundle();
        let bytes = objects::encode_disk(&original).unwrap();
        let quota = PROFILE_BYTES as u64 + bytes.len() as u64 - 1;
        let mut store = Store::open(&directory.0, quota).unwrap();

        assert!(matches!(
            store.put(original),
            Err(RemoteError::ResourceLimit)
        ));

        assert!(store.objects.is_empty());
        assert!(!directory.0.join(workspace::PENDING).exists());
        assert_eq!(store.used(), PROFILE_BYTES as u64);
    }
    #[test]
    fn failed_atomic_rename_removes_the_streamed_pending_and_allows_a_retry() {
        let directory = Directory::new();
        let original = bundle();
        let object = *original.target_version().unwrap().object();
        let expected = objects::encode_disk(&original).unwrap();
        let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
        let target = directory.0.join(filename(&object));
        fs::create_dir(&target).unwrap();

        assert!(matches!(
            store.put(original.clone()),
            Err(RemoteError::Io(_))
        ));

        assert!(store.objects.is_empty());
        assert_eq!(store.used(), PROFILE_BYTES as u64);
        assert!(!directory.0.join(workspace::PENDING).exists());
        assert!(target.is_dir());
        fs::remove_dir(&target).unwrap();
        let stored = store.put(original.clone()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert_eq!(stored.stored_bytes, expected.len() as u64);
        drop(store);
        let mut reopened = Store::open(&directory.0, 1024 * 1024).unwrap();
        assert_eq!(reopened.get(&object).unwrap(), original);
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
                .target_version()
                .unwrap()
                .object()
                .to_owned(),
            *committed.target_version().unwrap().object()
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
        assert!(store.get(staged.target_version().unwrap().object()).is_ok());
        assert!(
            store
                .get_version(&committed.data_head, &committed.index_head)
                .is_err()
        );
        fs::write(
            store
                .directory
                .join(filename(staged.target_version().unwrap().object())),
            b"damaged",
        )
        .unwrap();
        assert!(
            store
                .get_version(&staged.data_head, &staged.index_head)
                .is_err()
        );
    }
    #[test]
    fn collection_preserves_corrupt_retained_and_staged_images_but_removes_stale_membership() {
        let directory = Directory::new();
        let stale = bundle();
        let retained = bundle();
        let other_network = bundle();
        let staged = bundle();
        let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
        for image in [&stale, &retained, &other_network, &staged] {
            store.put(image.clone()).unwrap();
        }
        drop(store);
        // Restart must rebuild deletion membership from fully verified disk images.
        let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
        let mut preserved = Vec::new();
        for image in [&stale, &retained, &other_network, &staged] {
            let path = store
                .directory
                .join(filename(image.target_version().unwrap().object()));
            let mut damaged = fs::read(&path).unwrap();
            *damaged.last_mut().unwrap() ^= 1;
            fs::write(&path, &damaged).unwrap();
            if *image.target_version().unwrap().object()
                != *stale.target_version().unwrap().object()
            {
                assert!(matches!(
                    store.get(image.target_version().unwrap().object()),
                    Err(RemoteError::Integrity)
                ));
                preserved.push((*image.target_version().unwrap().object(), path, damaged));
            }
        }
        let pair = |image: &RawBundle| head_pair_id(&image.data_head, &image.index_head);
        let history = BTreeSet::from([pair(&stale), pair(&retained), pair(&other_network)]);
        let keep = BTreeSet::from([pair(&retained), pair(&other_network)]);

        store.prune_journal_objects(&history, &keep).unwrap();

        assert!(
            !store
                .directory
                .join(filename(stale.target_version().unwrap().object()))
                .exists()
        );
        assert_eq!(store.objects.len(), 3);
        assert_eq!(store.heads.len(), 3);
        for (id, path, damaged) in preserved {
            assert_eq!(fs::read(path).unwrap(), damaged);
            assert!(store.invalid.contains(&id));
            assert!(
                !store
                    .objects()
                    .into_iter()
                    .find(|info| info.id == id)
                    .unwrap()
                    .available
            );
            assert!(matches!(store.get(&id), Err(RemoteError::Integrity)));
        }
        // Collection cannot bless corrupted bytes for the next process startup.
        drop(store);
        assert!(Store::open(&directory.0, 1024 * 1024).is_err());
    }

    #[test]
    fn failed_collection_unlink_retains_membership_for_a_later_retry() {
        let directory = Directory::new();
        let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
        let stale = bundle();
        let retained = bundle();
        for image in [&stale, &retained] {
            store.put(image.clone()).unwrap();
        }
        let path = store
            .directory
            .join(filename(stale.target_version().unwrap().object()));
        let original = fs::read(&path).unwrap();
        let retained_path = store
            .directory
            .join(filename(retained.target_version().unwrap().object()));
        let retained_bytes = fs::read(&retained_path).unwrap();
        let pair = head_pair_id(&stale.data_head, &stale.index_head);
        let history = BTreeSet::from([pair]);
        // A directory at the canonical filename makes unlink fail on every host.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        assert!(
            store
                .prune_journal_objects(&history, &BTreeSet::new())
                .is_err()
        );

        assert_eq!(store.objects.len(), 2);
        assert!(store.heads[&pair].contains(stale.target_version().unwrap().object()));
        assert_eq!(fs::read(&retained_path).unwrap(), retained_bytes);
        fs::remove_dir(&path).unwrap();
        fs::write(&path, original).unwrap();
        store
            .prune_journal_objects(&history, &BTreeSet::new())
            .unwrap();
        assert!(!path.exists());
        assert!(!store.heads.contains_key(&pair));
        assert_eq!(store.objects.len(), 1);
        assert_eq!(
            store
                .get(retained.target_version().unwrap().object())
                .unwrap(),
            retained
        );
    }
    #[test]
    fn custody_rejects_a_corrupt_index_or_an_index_from_another_committed_object() {
        let directory = Directory::new();
        let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
        let original = bundle();
        let mut corrupt = original.clone();
        *corrupt.index.last_mut().unwrap() ^= 1;
        assert!(matches!(store.put(corrupt), Err(RemoteError::Integrity)));
        let mut replaced = original.clone();
        replaced.index = bundle().index;
        assert!(matches!(store.put(replaced), Err(RemoteError::Integrity)));
        assert!(store.objects.is_empty());
        store.put(original).unwrap();
    }
    #[test]
    fn byte_addressed_images_above_one_million_bytes_remain_bounded_and_survive_reopen() {
        let directory = Directory::new();
        let owner = compact_store::Owner::generate([7; 16]).unwrap();
        let original = vec![42; 2 * 1024 * 1024];
        let snapshot = owner
            .seal(
                compact_store::Layout {
                    schema: [8; 16],
                    row_width: 1,
                    rows_per_page: 16 * 1024,
                    row_count: original.len() as u64,
                },
                &original,
                custody_limits(),
            )
            .unwrap();
        let bundle = RawBundle {
            version: 2,
            nonce: [31; 32],
            data_head: snapshot.commitment().encode().to_vec(),
            index_head: snapshot.commitment().encode().to_vec(),
            data: snapshot.encode(),
            index: snapshot.encode(),
        };
        let mut store = Store::open(&directory.0, 8 * 1024 * 1024).unwrap();

        let stored = store.put(bundle.clone()).unwrap();

        assert_eq!(stored.logical_bytes, original.len() as u64);
        assert_eq!(store.get(&stored.id).unwrap(), bundle);
        assert!(matches!(
            store.configure(1024),
            Err(RemoteError::ResourceLimit)
        ));
        drop(store);
        let mut reopened = Store::open(&directory.0, 8 * 1024 * 1024).unwrap();
        assert_eq!(reopened.get(&stored.id).unwrap(), bundle);
        let mut hostile = snapshot.commitment().layout();
        hostile.row_count = custody_limits().max_rows + 1;
        assert!(hostile.validate(custody_limits()).is_err());
        assert_eq!(
            custody_limits().max_image_bytes,
            Limits::default().max_image_bytes
        );
        assert_eq!(
            custody_limits().max_page_plaintext_bytes,
            Limits::default().max_page_plaintext_bytes
        );
    }

    fn delta_fixture() -> (RawBundle, RawBundle, crate::StoreDeltaRequest) {
        let owner = compact_store::Owner::generate([81; 16]).unwrap();
        let layout = compact_store::Layout {
            schema: [1; 16],
            row_width: 1,
            rows_per_page: 4096,
            row_count: 300 * 4096,
        };
        let original_data = owner
            .seal(
                layout,
                &vec![1; layout.row_count as usize],
                custody_limits(),
            )
            .unwrap();
        let original_index = owner
            .seal(
                compact_store::Layout {
                    schema: [2; 16],
                    ..layout
                },
                &vec![2; layout.row_count as usize],
                custody_limits(),
            )
            .unwrap();
        let as_bundle = |data: &EncryptedSnapshot, index: &EncryptedSnapshot| RawBundle {
            version: 2,
            nonce: [31; 32],
            data_head: data.commitment().encode().to_vec(),
            index_head: index.commitment().encode().to_vec(),
            data: data.encode(),
            index: index.encode(),
        };
        let base = as_bundle(&original_data, &original_index);
        let mut data = original_data.clone();
        let mut index = original_index.clone();
        owner
            .replace_page(
                &mut data,
                original_data.commitment(),
                0,
                &[3; 4096],
                custody_limits(),
            )
            .unwrap();
        owner
            .replace_page(
                &mut index,
                original_index.commitment(),
                0,
                &[4; 4096],
                custody_limits(),
            )
            .unwrap();
        let target = as_bundle(&data, &index);
        let pages = [
            (
                crate::PageAddress {
                    image: crate::PageImage::Data,
                    index: 0,
                },
                data.lookup(0, custody_limits()).unwrap(),
            ),
            (
                crate::PageAddress {
                    image: crate::PageImage::Index,
                    index: 0,
                },
                index.lookup(0, custody_limits()).unwrap(),
            ),
        ];
        let delta = crate::StoreDeltaRequest::new(
            *base.target_version().unwrap().object(),
            original_data.commitment(),
            original_index.commitment(),
            &(target).target_version().unwrap(),
            &pages,
        )
        .unwrap();
        (base, target, delta)
    }
    #[test]
    fn padded_delta_stores_the_exact_full_target_and_replays_after_restart_and_base_collection() {
        let directory = Directory::new();
        let (base, target, delta) = delta_fixture();
        let mut store = Store::open(&directory.0, 8 * 1024 * 1024).unwrap();
        assert!(matches!(
            store.put_delta(delta.clone()),
            Err(RemoteError::NotFound)
        ));
        assert!(store.objects.is_empty());
        assert!(
            !directory
                .0
                .join(filename(target.target_version().unwrap().object()))
                .exists()
        );
        store.put(base.clone()).unwrap();

        let stored = store.put_delta(delta.clone()).unwrap();

        assert_eq!(stored.id, *target.target_version().unwrap().object());
        assert_eq!(store.get(&stored.id).unwrap(), target);
        assert_eq!(
            store.get(base.target_version().unwrap().object()).unwrap(),
            base
        );
        assert_eq!(store.objects.len(), 2);
        drop(store);
        let mut store = Store::open(&directory.0, 8 * 1024 * 1024).unwrap();
        assert_eq!(store.put_delta(delta.clone()).unwrap().id, stored.id);
        store
            .prune_journal_objects(
                &BTreeSet::from([head_pair_id(&base.data_head, &base.index_head)]),
                &BTreeSet::from([head_pair_id(&target.data_head, &target.index_head)]),
            )
            .unwrap();
        assert_eq!(store.objects.len(), 1);
        assert_eq!(store.put_delta(delta).unwrap().id, stored.id);
        assert_eq!(store.get(&stored.id).unwrap(), target);
        assert!(!directory.0.join(workspace::PENDING).exists());
    }
    #[test]
    fn unrequested_base_corruption_or_a_valid_overwrite_cannot_create_a_delta_target() {
        for corruption in 0..3 {
            let directory = Directory::new();
            let (base, target, delta) = delta_fixture();
            let mut store = Store::open(&directory.0, 8 * 1024 * 1024).unwrap();
            store.put(base.clone()).unwrap();
            let mut altered = base.clone();
            match corruption {
                0 => *altered.data.last_mut().unwrap() ^= 1,
                1 => *altered.index.last_mut().unwrap() ^= 1,
                _ => altered = delta_fixture().0,
            }
            let corrupt_bytes = objects::encode_disk(&altered).unwrap();
            let base_path = directory
                .0
                .join(filename(base.target_version().unwrap().object()));
            fs::write(&base_path, &corrupt_bytes).unwrap();

            assert!(matches!(
                store.put_delta(delta),
                Err(RemoteError::Integrity)
            ));

            assert_eq!(fs::read(base_path).unwrap(), corrupt_bytes);
            assert_eq!(store.objects.len(), 1);
            assert!(
                !directory
                    .0
                    .join(filename(target.target_version().unwrap().object()))
                    .exists()
            );
            assert!(!directory.0.join(workspace::PENDING).exists());
        }
    }
    #[test]
    fn quota_failure_and_a_wrong_old_head_leave_the_existing_full_base_unchanged() {
        let directory = Directory::new();
        let (base, target, delta) = delta_fixture();
        let quota = objects::encode_disk(&base).unwrap().len() as u64 + PROFILE_BYTES as u64;
        let mut store = Store::open(&directory.0, quota).unwrap();
        store.put(base.clone()).unwrap();
        assert!(matches!(
            store.put_delta(delta.clone()),
            Err(RemoteError::ResourceLimit)
        ));
        assert_eq!(
            store.get(base.target_version().unwrap().object()).unwrap(),
            base
        );
        store.configure(8 * 1024 * 1024).unwrap();
        let mut wire = encode(&crate::wire::WireRequest {
            version: 2,
            id: 1,
            request: Request::StoreDelta(delta),
        })
        .unwrap();
        // Whole WireRequest envelope22 + body old data head74 + root80.
        wire[22 + 74 + 80] ^= 1;
        let request: crate::wire::WireRequest = decode(&wire).unwrap();
        let Request::StoreDelta(wrong) = request.request else {
            panic!("delta")
        };
        assert!(matches!(
            store.put_delta(wrong),
            Err(RemoteError::Integrity)
        ));
        assert_eq!(
            store.get(base.target_version().unwrap().object()).unwrap(),
            base
        );
        assert_eq!(store.objects.len(), 1);
        assert!(
            !directory
                .0
                .join(filename(target.target_version().unwrap().object()))
                .exists()
        );
        assert!(!directory.0.join(workspace::PENDING).exists());
    }
    #[test]
    fn duplicate_delta_acknowledgement_audits_every_byte_of_the_already_stored_target() {
        let directory = Directory::new();
        let (base, target, delta) = delta_fixture();
        let mut store = Store::open(&directory.0, 8 * 1024 * 1024).unwrap();
        store.put(base.clone()).unwrap();
        store.put_delta(delta.clone()).unwrap();
        let mut altered = target.clone();
        *altered.index.last_mut().unwrap() ^= 1;
        fs::write(
            directory
                .0
                .join(filename(target.target_version().unwrap().object())),
            objects::encode_disk(&altered).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            store.put_delta(delta),
            Err(RemoteError::Integrity)
        ));

        assert_eq!(
            store.get(base.target_version().unwrap().object()).unwrap(),
            base
        );
        assert_eq!(store.objects.len(), 2);
        assert!(!directory.0.join(workspace::PENDING).exists());
    }
    #[test]
    fn raw_full_store_cannot_bypass_either_image_audit_through_candidate_admission() {
        let (_, original, _) = delta_fixture();
        for corruption in 0..6 {
            let directory = Directory::new();
            let mut store = Store::open(&directory.0, 16 * 1024 * 1024).unwrap();
            let mut hostile = original.clone();
            match corruption {
                0 => *hostile.data.last_mut().unwrap() ^= 1,
                1 => *hostile.index.last_mut().unwrap() ^= 1,
                2 => {
                    hostile.data_head.pop();
                }
                3 => {
                    hostile.index_head.pop();
                }
                4 => hostile.data.push(0),
                _ => {
                    // The first page revision cannot exceed its exact image head.
                    hostile.index[compact_store::MANIFEST_BYTES..compact_store::MANIFEST_BYTES + 8]
                        .copy_from_slice(&u64::MAX.to_le_bytes());
                }
            }

            assert!(
                matches!(store.put(hostile), Err(RemoteError::Integrity)),
                "corruption {corruption}"
            );

            assert!(store.objects.is_empty());
            assert!(!directory.0.join(workspace::PENDING).exists());
            assert!(!fs::read_dir(&directory.0).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "bundle")
            }));
        }
    }
}

/// Read-only compatibility preflight. Does not claim custody or lock ownership.
pub(crate) fn preflight_directory(directory: &Path) -> io::Result<()> {
    workspace::preflight(directory, false).map(|_| ())
}

#[cfg(test)]
mod profile_tests;

#[cfg(test)]
mod audit_tests;

#[cfg(test)]
mod reply_tests;
