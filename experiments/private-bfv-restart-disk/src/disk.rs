//! Capacity-one disk table ownership. Catalog entries never hold snapshots or NTT caches.
use crate::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
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
        json!({
         "table_id":self.id,"data_file":self.data_path.file_name().unwrap().to_string_lossy(),
         "index_file":self.index_path.file_name().unwrap().to_string_lossy(),
         "data_bytes":self.data_len,"index_bytes":self.index_len,
         "data_head_hex":hex(&self.data_head.encode()),"index_head_hex":hex(&self.index_head.encode()),
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
pub(crate) fn persist_catalog(directory: &Path, catalog: &[CatalogEntry]) -> ProbeResult<()> {
    let mut file = File::create(directory.join("catalog.jsonl"))?;
    for entry in catalog {
        serde_json::to_writer(&mut file, &entry.record())?;
        file.write_all(b"\n")?;
    }
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
