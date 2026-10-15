//! Capacity-one disk table ownership. Catalog entries never hold snapshots or NTT caches.
use crate::*;
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const MEMORY_LIMIT: usize = 2_000_000_000;
const RESERVE: usize = 80 * 1024 * 1024;
const MAX_SINGLE_IMAGE: usize = 8 * 1024 * 1024;
pub(crate) struct CatalogEntry {
    pub id: usize,
    pub owner: Owner,
    pub data_path: PathBuf,
    pub index_path: PathBuf,
    pub data_head: Commitment,
    pub index_head: Commitment,
    pub data_len: usize,
    pub index_len: usize,
    pub cached: CachedHeader,
}
impl CatalogEntry {
    pub fn record(&self) -> serde_json::Value {
        self.record_at_heads(&self.data_head, &self.index_head)
    }
    pub fn record_at_heads(&self, data: &Commitment, index: &Commitment) -> serde_json::Value {
        json!({
         "table_id":self.id,"data_file":self.data_path.file_name().unwrap().to_string_lossy(),
         "index_file":self.index_path.file_name().unwrap().to_string_lossy(),
         "data_bytes":self.data_len,"index_bytes":self.index_len,
         "data_head_hex":hex(&data.encode()),"index_head_hex":hex(&index.encode()),
         "owner_secret_key_count":32,"trusted_head_bytes":224,
         "owner_cached_header_bytes":self.cached.payload_bytes(),
        })
    }
}
fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        text.push(ALPHABET[(b >> 4) as usize] as char);
        text.push(ALPHABET[(b & 15) as usize] as char);
    }
    text
}
const CATALOG_BUFFER_BYTES: usize = 64 * 1024;
struct CatalogProjection<'a> {
    id: usize,
    data: &'a Commitment,
    index: &'a Commitment,
}
fn write_catalog<W: Write>(
    writer: &mut W,
    catalog: &[CatalogEntry],
    projection: Option<&CatalogProjection<'_>>,
) -> ProbeResult<()> {
    for entry in catalog {
        let record = match projection.filter(|p| p.id == entry.id) {
            Some(p) => entry.record_at_heads(p.data, p.index),
            None => entry.record(),
        };
        serde_json::to_writer(&mut *writer, &record)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?; // Drop cannot report buffered-tail or inner flush errors.
    Ok(())
}
#[cfg(test)]
pub(crate) fn persist_catalog(directory: &Path, catalog: &[CatalogEntry]) -> ProbeResult<()> {
    let file = File::create(directory.join("catalog.jsonl"))?;
    let mut writer = BufWriter::with_capacity(CATALOG_BUFFER_BYTES, file);
    write_catalog(&mut writer, catalog, None)
}
pub(crate) fn persist_catalog_at_heads(
    directory: &Path,
    catalog: &[CatalogEntry],
    id: usize,
    data: &Commitment,
    index: &Commitment,
) -> ProbeResult<()> {
    if catalog.iter().filter(|entry| entry.id == id).count() != 1 {
        return Err("Staged catalog projection must identify exactly one existing table".into());
    }
    let file = File::create(directory.join("catalog.jsonl"))?;
    let mut writer = BufWriter::with_capacity(CATALOG_BUFFER_BYTES, file);
    write_catalog(
        &mut writer,
        catalog,
        Some(&CatalogProjection { id, data, index }),
    )
}
pub(crate) fn write_replacement(path: &Path, bytes: &[u8]) -> ProbeResult<()> {
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?; // No fsync or crash-atomic commit is claimed.
    Ok(())
}
pub(crate) struct LoadedTable {
    pub id: usize,
    pub data: EncryptedSnapshot,
    pub index: EncryptedSnapshot,
    pub ntt: Option<native::CachePair>,
}
#[derive(Default, Serialize)]
pub(crate) struct LoadStages {
    pub event: &'static str,
    pub evicted: Option<usize>,
    pub eviction_drop_ms: f64,
    pub admission_ms: f64,
    pub data_file_read_ms: f64,
    pub index_file_read_ms: f64,
    pub snapshot_decode_auth_ms: f64,
    pub file_bytes_read: usize,
    pub native_prepare: Option<native::PrepStages>,
    pub total_ms: f64,
}
#[derive(Default, Serialize)]
pub(crate) struct CacheCounters {
    pub table_hits: usize,
    pub table_misses: usize,
    pub native_upgrades: usize,
    pub evictions: usize,
    pub invalidations: usize,
}
pub(crate) struct Loader {
    pub current: Option<LoadedTable>,
    pub counters: CacheCounters,
}
pub(crate) struct DiskRead {
    pub query: ReadResult,
    pub load: LoadStages,
    pub whole_ms: f64,
}
impl Loader {
    pub fn new(capacity: usize) -> ProbeResult<Self> {
        if capacity != 1 {
            return Err("This measured loader supports exactly capacity1".into());
        }
        Ok(Self {
            current: None,
            counters: CacheCounters::default(),
        })
    }
    pub fn invalidate(&mut self, id: usize) {
        if self.current.as_ref().is_some_and(|t| t.id == id) {
            drop(self.current.take());
            self.counters.invalidations += 1;
        }
    }
    pub fn ensure(
        &mut self,
        entry: &CatalogEntry,
        access: Access,
        params: &Params,
    ) -> ProbeResult<LoadStages> {
        let all = Instant::now();
        let mut stages = LoadStages::default();
        if let Some(current) = self.current.as_ref().filter(|t| t.id == entry.id) {
            if current.data.commitment() != &entry.data_head
                || current.index.commitment() != &entry.index_head
            {
                return Err(
                    "Loaded snapshot has stale trusted heads; invalidate before replacement".into(),
                );
            }
            self.counters.table_hits += 1;
            stages.event = "TableHit";
        } else {
            self.counters.table_misses += 1;
            stages.event = "TableMiss";
            let start = Instant::now();
            if let Some(old) = self.current.take() {
                stages.evicted = Some(old.id);
                self.counters.evictions += 1;
                drop(old);
            }
            stages.eviction_drop_ms = ms(start);
            let admission_start = Instant::now();
            admit(
                "before_disk_table_load",
                entry.id,
                if matches!(access, Access::Private) {
                    112 * 1024 * 1024
                } else {
                    16 * 1024 * 1024
                },
            )?;
            stages.admission_ms += ms(admission_start);
            let start = Instant::now();
            let data_bytes = read_exact_image(&entry.data_path, entry.data_len, MAX_SINGLE_IMAGE)?;
            stages.data_file_read_ms = ms(start);
            let start = Instant::now();
            let index_bytes =
                read_exact_image(&entry.index_path, entry.index_len, MAX_SINGLE_IMAGE)?;
            stages.index_file_read_ms = ms(start);
            stages.file_bytes_read = data_bytes.len() + index_bytes.len();
            let start = Instant::now();
            let data = EncryptedSnapshot::decode(&data_bytes, Limits::default())?;
            let index =
                EncryptedSnapshot::decode(&index_bytes, padded_index_codec::index_limits())?;
            if data.commitment() != &entry.data_head || index.commitment() != &entry.index_head {
                return Err(
                    "Disk snapshot disagrees with independently trusted complete head".into(),
                );
            }
            drop(data_bytes);
            drop(index_bytes);
            stages.snapshot_decode_auth_ms = ms(start);
            // Failed reads/decodes/authentication never publish a partial loaded entry.
            self.current = Some(LoadedTable {
                id: entry.id,
                data,
                index,
                ntt: None,
            });
        }
        if matches!(access, Access::Private) && self.current.as_ref().unwrap().ntt.is_none() {
            let admission_start = Instant::now();
            if let Err(error) = admit("before_native_pair", entry.id, 96 * 1024 * 1024) {
                drop(self.current.take());
                return Err(error);
            }
            stages.admission_ms += ms(admission_start);
            let current = self.current.as_mut().unwrap();
            let pair = match native::prepare_pair(&current.data, &current.index, params) {
                Ok(pair) => pair,
                Err(error) => {
                    drop(self.current.take());
                    return Err(error);
                }
            };
            if stages.event == "TableHit" {
                stages.event = "NativeUpgrade";
                self.counters.native_upgrades += 1;
            }
            let native::CachePair {
                data,
                index,
                stages: prep,
            } = pair;
            stages.native_prepare = Some(prep);
            current.ntt = Some(native::CachePair {
                data,
                index,
                stages: native::PrepStages::default(),
            });
        }
        stages.total_ms = ms(all);
        Ok(stages)
    }
    pub fn execute(
        &mut self,
        entry: &CatalogEntry,
        plan: Plan,
        bfv: &BfvOwner,
        evaluator: &PeerEvaluator,
        pir: &Pir<'_>,
        preparations: &Cell<usize>,
    ) -> ProbeResult<DiskRead> {
        let all = Instant::now();
        let load = self.ensure(entry, plan.access, pir.params)?;
        let loaded = self
            .current
            .as_ref()
            .ok_or("No loaded table after successful load")?;
        let data = Store {
            id: 0,
            snapshot: &loaded.data,
            head: &entry.data_head,
            db: loaded.ntt.as_ref().map(|p| &p.data),
            limits: Limits::default(),
        };
        let index = Store {
            id: 1,
            snapshot: &loaded.index,
            head: &entry.index_head,
            db: loaded.ntt.as_ref().map(|p| &p.index),
            limits: padded_index_codec::index_limits(),
        };
        let session = Session {
            owner: &entry.owner,
            bfv,
            evaluator,
            pir,
            data: &data,
            index: &index,
            cached: &entry.cached,
            preparations,
            replacement_wire: None,
        };
        let query = read(plan, &session)?;
        let whole_ms = ms(all);
        Ok(DiskRead {
            query,
            load,
            whole_ms,
        })
    }
    pub fn ledger(&self) -> serde_json::Value {
        let (canonical, hashes, ntt) = self.current.as_ref().map_or((0, 0, 0), |t| {
            (
                t.data.encoded_len() + t.index.encoded_len(),
                t.data.index_hash_bytes() + t.index.index_hash_bytes(),
                t.ntt
                    .as_ref()
                    .map_or(0, |p| (p.data.len() + p.index.len()) * 8),
            )
        });
        json!({"capacity":1,"retained_loaded_tables":usize::from(self.current.is_some()),
   "loaded_table_id":self.current.as_ref().map(|t|t.id),
   "loaded_canonical_snapshot_encoded_bytes":canonical,"loaded_merkle_payload_bytes":hashes,
   "loaded_ntt_overlay_bytes":ntt,"retained_raw_proof_record_bytes":0,
   "unloaded_snapshot_bytes":0,"unloaded_ntt_cache_bytes":0,"counters":self.counters})
    }
}
fn within_memory_budget(s: &resources::MemorySample, additional: usize) -> bool {
    s.working_set_bytes
        .max(s.private_commit_bytes)
        .checked_add(additional)
        .and_then(|v| v.checked_add(RESERVE))
        .is_some_and(|v| v < MEMORY_LIMIT)
        && s.native_peak_working_set_bytes < MEMORY_LIMIT
        && s.native_peak_private_commit_bytes < MEMORY_LIMIT
}
pub(crate) fn admit(stage: &str, id: usize, additional: usize) -> ProbeResult<()> {
    let s = resources::memory_sample();
    let admitted = within_memory_budget(&s, additional);
    println!(
        "{}",
        json!({"experiment":"disk-admission","stage":stage,"table_id":id,
  "expected_additional_bytes":additional,"reserve_bytes":RESERVE,"admitted":admitted,"resources":s})
    );
    if !admitted {
        return Err("Capacity-one loader admission rejected before allocation".into());
    }
    Ok(())
}
pub(crate) fn read_exact_image(
    path: &Path,
    expected: usize,
    maximum: usize,
) -> ProbeResult<Vec<u8>> {
    if expected < compact_store::MANIFEST_BYTES || expected > maximum {
        return Err("Trusted encoded length exceeds fixed loader image bound".into());
    }
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() != expected as u64 {
        return Err("Canonical file length/type mismatch".into());
    }
    let mut bytes = vec![0u8; expected];
    file.read_exact(&mut bytes)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err("Canonical file grew beyond trusted exact length".into());
    }
    Ok(bytes)
}
struct SetupHeaderSource<'a>(&'a EncryptedSnapshot);
impl PageSource for SetupHeaderSource<'_> {
    fn commitment(&self) -> &Commitment {
        self.0.commitment()
    }
    fn lookup_wire(&self, page: u64, limits: Limits) -> IndexResult<Vec<u8>> {
        Ok(self.0.lookup(page, limits)?.encode())
    }
}
pub(crate) fn capture_owner_header(
    owner: &Owner,
    index: &EncryptedSnapshot,
    data: &Commitment,
) -> ProbeResult<CachedHeader> {
    let header = padded_index_codec::check_binding(owner, &SetupHeaderSource(index), data)?;
    Ok(CachedHeader::capture(&header, data, index.commitment()))
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> ProbeResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
pub(crate) fn build_catalog(
    directory: &Path,
    count: usize,
    max_canonical: u64,
) -> ProbeResult<Vec<CatalogEntry>> {
    let upper = count
        .checked_mul(6 * 1024 * 1024)
        .ok_or("Dataset size overflow")?;
    if !(3..=2000).contains(&count) || upper as u64 > max_canonical {
        return Err("Dataset preflight exceeds explicit canonical-byte budget".into());
    }
    let mut catalog = Vec::with_capacity(count);
    let mut bytes_used = 0u64;
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("catalog.jsonl"))?;
    for id in 0..count {
        admit("before_independent_disk_table", id, 24 * 1024 * 1024)?;
        let started = Instant::now();
        let mut database = *b"public-disk-fxt!";
        database[8..].copy_from_slice(&(id as u64).to_le_bytes());
        let owner = Owner::generate(database)?;
        let rows = public_rows(MAX_TABLE_ROWS, id);
        let packed: Vec<u8> = rows
            .iter()
            .flat_map(|r| [r.age, r.amount as u8, (r.amount >> 8) as u8])
            .collect();
        let data = owner.seal(
            Layout {
                schema: SCHEMA,
                row_width: ROW_BYTES,
                rows_per_page: PAGE_ROWS as u32,
                row_count: MAX_TABLE_ROWS as u64,
            },
            &packed,
            Limits::default(),
        )?;
        let index = padded_index_codec::build(&owner, &rows, data.commitment())?;
        drop(packed);
        drop(rows);
        let cached = capture_owner_header(&owner, &index, data.commitment())?;
        let data_image = data.encode();
        let index_image = index.encode();
        bytes_used = bytes_used
            .checked_add((data_image.len() + index_image.len()) as u64)
            .ok_or("Dataset byte overflow")?;
        if bytes_used > max_canonical {
            return Err("Actual canonical images exceed dataset budget before write".into());
        }
        let entry = CatalogEntry {
            id,
            owner,
            data_path: directory.join(format!("table-{id}-data.bin")),
            index_path: directory.join(format!("table-{id}-index.bin")),
            data_head: data.commitment().clone(),
            index_head: index.commitment().clone(),
            data_len: data_image.len(),
            index_len: index_image.len(),
            cached,
        };
        write_new(&entry.data_path, &data_image)?;
        write_new(&entry.index_path, &index_image)?;
        drop(data_image);
        drop(index_image);
        drop(data);
        drop(index);
        if catalog.iter().any(|e: &CatalogEntry| {
            e.data_head.root() == entry.data_head.root()
                || e.index_head.root() == entry.index_head.root()
        }) {
            return Err("Independent table root collision".into());
        }
        let record = entry.record();
        serde_json::to_writer(&mut manifest, &record)?;
        manifest.write_all(b"\n")?;
        println!(
            "{}",
            json!({"experiment":"disk-table-created","entry":record,"table_setup_ms":ms(started),
   "setup_header_owner_authenticated":true,"setup_private_ntt_preparation":false,"retained_setup_snapshots":0})
        );
        catalog.push(entry);
    }
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_keeps_decimal_cap_reserve_native_peaks_and_overflow_fail_closed() {
        let mut state = resources::MemorySample {
            working_set_bytes: 0,
            private_commit_bytes: 0,
            native_peak_working_set_bytes: 0,
            native_peak_private_commit_bytes: 0,
        };
        assert!(within_memory_budget(&state, MEMORY_LIMIT - RESERVE - 1));
        assert!(!within_memory_budget(&state, MEMORY_LIMIT - RESERVE));
        assert!(!within_memory_budget(&state, usize::MAX));
        state.native_peak_working_set_bytes = MEMORY_LIMIT;
        assert!(!within_memory_budget(&state, 0));
        state.native_peak_working_set_bytes = 0;
        state.native_peak_private_commit_bytes = MEMORY_LIMIT;
        assert!(!within_memory_budget(&state, 0));
        state.native_peak_private_commit_bytes = 0;
        state.private_commit_bytes = MEMORY_LIMIT - RESERVE;
        assert!(!within_memory_budget(&state, 0));
    }
    struct TestFile(PathBuf);
    impl TestFile {
        fn new(bytes: &[u8]) -> Self {
            let mut nonce = [0u8; 8];
            getrandom::getrandom(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "private-bfv-disk-{}-{}.bin",
                std::process::id(),
                u64::from_le_bytes(nonce)
            ));
            write_new(&path, bytes).unwrap();
            Self(path)
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    #[test]
    fn exact_file_preflight_rejects_truncation_extra_bytes_and_excessive_trusted_lengths() {
        let file = TestFile::new(&[7; 112]);
        assert_eq!(read_exact_image(&file.0, 112, 1024).unwrap(), vec![7; 112]);
        assert!(read_exact_image(&file.0, 113, 1024).is_err());
        assert!(read_exact_image(&file.0, 111, 1024).is_err());
        assert!(read_exact_image(&file.0, 4096, 1024).is_err());
    }
    fn entry() -> (CatalogEntry, TestFile, TestFile) {
        let owner = Owner::generate([77; 16]).unwrap();
        let data = owner
            .seal(
                Layout {
                    schema: SCHEMA,
                    row_width: 3,
                    rows_per_page: 2048,
                    row_count: 1,
                },
                &[250, 100, 0],
                Limits::default(),
            )
            .unwrap();
        let index = padded_index_codec::build(
            &owner,
            &[PlainRow {
                age: 250,
                amount: 100,
            }],
            data.commitment(),
        )
        .unwrap();
        let cached = capture_owner_header(&owner, &index, data.commitment()).unwrap();
        let data_file = TestFile::new(&data.encode());
        let index_file = TestFile::new(&index.encode());
        let entry = CatalogEntry {
            id: 0,
            owner,
            data_path: data_file.0.clone(),
            index_path: index_file.0.clone(),
            data_head: data.commitment().clone(),
            index_head: index.commitment().clone(),
            data_len: data.encoded_len(),
            index_len: index.encoded_len(),
            cached,
        };
        (entry, data_file, index_file)
    }
    #[test]
    fn visible_hit_and_eviction_hold_exactly_one_actual_decoded_table_without_ntt() {
        let params = spiral_owner_state::profile_params();
        let (first, _d1, _i1) = entry();
        let (mut second, _d2, _i2) = entry();
        second.id = 1;
        let mut loader = Loader::new(1).unwrap();
        assert_eq!(
            loader
                .ensure(&first, Access::Visible, &params)
                .unwrap()
                .event,
            "TableMiss"
        );
        assert!(loader.current.as_ref().unwrap().ntt.is_none());
        assert_eq!(
            loader
                .ensure(&first, Access::Visible, &params)
                .unwrap()
                .event,
            "TableHit"
        );
        assert_eq!(
            loader
                .ensure(&second, Access::Visible, &params)
                .unwrap()
                .evicted,
            Some(0)
        );
        assert_eq!(loader.current.as_ref().unwrap().id, 1);
        assert_eq!(loader.counters.evictions, 1);
        loader.invalidate(1);
        assert!(loader.current.is_none());
        assert!(Loader::new(2).is_err());
    }
    #[test]
    fn tampered_disk_image_and_wrong_table_head_never_publish_an_entry() {
        let params = spiral_owner_state::profile_params();
        let (mut e, _d, _i) = entry();
        let (wrong, _wd, _wi) = entry();
        let mut loader = Loader::new(1).unwrap();
        e.data_head = wrong.data_head;
        assert!(loader.ensure(&e, Access::Visible, &params).is_err());
        assert!(loader.current.is_none());
        let (e, _d, _i) = entry();
        let mut bytes = read_exact_image(&e.data_path, e.data_len, MAX_SINGLE_IMAGE).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 1;
        std::fs::write(&e.data_path, bytes).unwrap();
        assert!(loader.ensure(&e, Access::Visible, &params).is_err());
        assert!(loader.current.is_none());
    }
    #[test]
    fn malformed_private_profile_returns_before_record_allocation_and_clears_failed_load() {
        let (e, _d, _i) = entry();
        let mut params = spiral_owner_state::profile_params();
        params.db_dim_1 = 8;
        let mut loader = Loader::new(1).unwrap();
        assert!(loader.ensure(&e, Access::Private, &params).is_err());
        assert!(loader.current.is_none());
    }
    #[test]
    fn a_loaded_entry_at_an_old_trusted_head_is_rejected_instead_of_silently_reused() {
        let params = spiral_owner_state::profile_params();
        let (mut e, _d, _i) = entry();
        let mut loader = Loader::new(1).unwrap();
        loader.ensure(&e, Access::Visible, &params).unwrap();
        let (other, _od, _oi) = entry();
        e.data_head = other.data_head;
        assert!(loader.ensure(&e, Access::Visible, &params).is_err());
    }
    include!("catalog_io_tests.rs");
}
