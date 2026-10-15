//! Fresh independent canonical files; one DB authority, all trusted heads, no table cache.
use crate::{ProbeResult, fixture, resources, roles};
use compact_query::bfv;
use serde_json::json;
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
pub(crate) const MAX_BUDGET: u64 = 6_500_000_000;
const PER_TABLE_RESERVE: u64 = 6 * 1024 * 1024;
const CATALOG_RESERVE: u64 = 2 * 1024 * 1024;
const FREE_RESERVE: u64 = 64 * 1024 * 1024;
#[derive(Clone)]
pub(crate) struct Entry {
    pub trusted: roles::TrustedTable,
    pub data_path: PathBuf,
    pub index_path: PathBuf,
}
pub(crate) struct Catalog {
    pub entries: Vec<Entry>,
    pub path: PathBuf,
    pub canonical_bytes: u64,
    pub distinct_roots: usize,
}
pub(crate) fn preflight(tables: usize, budget: u64, free: u64) -> ProbeResult<u64> {
    if !(3..=1000).contains(&tables) || budget > MAX_BUDGET {
        return Err("Bounded table-count/canonical budget required".into());
    }
    let planned = (tables as u64)
        .checked_mul(PER_TABLE_RESERVE)
        .and_then(|n| n.checked_add(CATALOG_RESERVE))
        .ok_or("Disk plan overflow")?;
    if planned > budget || planned.checked_add(FREE_RESERVE).is_none_or(|n| n > free) {
        return Err("Actual free disk / declared6.5GB budget rejected before setup".into());
    }
    Ok(planned)
}
#[cfg(windows)]
pub(crate) fn free_bytes(path: &Path) -> ProbeResult<u64> {
    use std::os::windows::ffi::OsStrExt;
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            path: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    let (mut available, mut total, mut free) = (0_u64, 0_u64, 0_u64);
    // SAFETY: NUL-terminated UTF16 path, live writable u64 outputs, Windows API contract.
    if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut free) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(available)
}
#[cfg(not(windows))]
pub(crate) fn free_bytes(_: &Path) -> ProbeResult<u64> {
    Err("This resource-accounted experiment requires Windows".into())
}
impl Catalog {
    pub fn create(
        directory: &Path,
        tables: usize,
        budget: u64,
        authority: &bfv::Owner,
    ) -> ProbeResult<Self> {
        // Caller preflights actual available space before creating the fresh directory/keyset.
        preflight(tables, budget, u64::MAX)?;
        let path = directory.join("catalog.jsonl");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut entries = Vec::with_capacity(tables);
        let mut roots = HashSet::with_capacity(tables * 2);
        let mut canonical_bytes = 0_u64;
        for table in 0..tables {
            resources::guard(96 * 1024 * 1024)?;
            let started = Instant::now();
            let rows = fixture::public_rows_for_table(table);
            let image = authority.seal(&rows, fixture::PAGE_ROWS, roles::data_limits())?;
            drop(rows);
            let trusted = roles::TrustedTable::capture(table as u32, &image)?;
            if trusted.data_len != 3_023_584 || trusted.index_len != 2_041_564 {
                return Err("Per-table canonical format/geometry changed".into());
            }
            if !roots.insert(trusted.data_head.root()) || !roots.insert(trusted.index_head.root()) {
                return Err("Independent canonical root collision".into());
            }
            let data = image.snapshot().encode();
            let index = image.encrypted_index().encode();
            canonical_bytes = canonical_bytes
                .checked_add((data.len() + index.len()) as u64)
                .ok_or("Dataset byte overflow")?;
            if canonical_bytes
                .checked_add(CATALOG_RESERVE)
                .is_none_or(|n| n > budget)
            {
                return Err("Actual canonical bytes exceed declared budget before write".into());
            }
            let data_path = directory.join(format!("table-{table}-data.bin"));
            let index_path = directory.join(format!("table-{table}-index.bin"));
            roles::write_new(&data_path, &data)?;
            roles::write_new(&index_path, &index)?;
            let record = json!({"table_id":table,"data_head":trusted.data_head.encode().as_slice(),"index_head":trusted.index_head.encode().as_slice(),
                "data_len":data.len(),"index_len":index.len(),"data_file":data_path.file_name().ok_or("Data basename")?.to_string_lossy(),
                "index_file":index_path.file_name().ok_or("Index basename")?.to_string_lossy()});
            serde_json::to_writer(&mut file, &record)?;
            file.write_all(b"\n")?;
            drop(data);
            drop(index);
            drop(image);
            entries.push(Entry {
                trusted,
                data_path,
                index_path,
            });
            println!(
                "{}",
                json!({"experiment":"bulk-scale-table-created","table_id":table,"canonical_bytes":5_065_148,"distinct_roots_so_far":roots.len(),
                "table_seal_write_ms":started.elapsed().as_secs_f64()*1000.0,"retained_encrypted_tables":0,"resident_response_cache_bytes":0})
            );
        }
        file.flush()?; // No fsync/crash-durability claim.
        let catalog_bytes = file.metadata()?.len();
        if catalog_bytes > CATALOG_RESERVE
            || canonical_bytes
                .checked_add(catalog_bytes)
                .is_none_or(|n| n > budget)
        {
            return Err("Actual catalog/files exceed declared disk bound".into());
        }
        let distinct_roots = roots.len();
        if distinct_roots != 2 * tables {
            return Err("Incomplete independent-root inventory".into());
        }
        drop(roots);
        Ok(Self {
            entries,
            path,
            canonical_bytes,
            distinct_roots,
        })
    }
    pub fn ledger(&self) -> ProbeResult<serde_json::Value> {
        let directory = self.path.parent().ok_or("Catalog parent")?;
        let mut physical_bytes = 0_u64;
        for entry in &self.entries {
            for (path, len, head) in [
                (
                    &entry.data_path,
                    entry.trusted.data_len,
                    &entry.trusted.data_head,
                ),
                (
                    &entry.index_path,
                    entry.trusted.index_len,
                    &entry.trusted.index_head,
                ),
            ] {
                let mut file = File::open(path)?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.len() != len as u64 {
                    return Err("Physical canonical file length/type mismatch".into());
                }
                let mut actual = [0_u8; 112];
                file.read_exact(&mut actual)?;
                if actual != head.encode() {
                    return Err("Physical112B head differs from independent catalog".into());
                }
                physical_bytes = physical_bytes
                    .checked_add(meta.len())
                    .ok_or("Physical file bytes overflow")?;
            }
        }
        let catalog_bytes = std::fs::metadata(&self.path)?.len();
        let files = std::fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
        if files.len() != self.entries.len() * 2 + 1
            || files
                .iter()
                .any(|v| !v.file_type().is_ok_and(|t| t.is_file()))
            || physical_bytes != self.canonical_bytes
        {
            return Err(
                "Dataset contains unexpected entries or canonical accounting mismatch".into(),
            );
        }
        let path_payload = self
            .entries
            .iter()
            .map(|v| v.data_path.as_os_str().len() + v.index_path.as_os_str().len())
            .sum::<usize>();
        Ok(
            json!({"tables":self.entries.len(),"canonical_file_count":self.entries.len()*2,"all_file_count":files.len(),"all_physical_lengths_and112byte_heads_match":true,
            "distinct_roots":self.distinct_roots,"canonical_bytes":physical_bytes,"catalog_file_bytes":catalog_bytes,"actual_file_bytes":physical_bytes+catalog_bytes,
            "logical_bytes":self.entries.len() as u64*3_000_000,"catalog_live_entry_capacity_bytes":self.entries.capacity()*std::mem::size_of::<Entry>(),
            "catalog_path_os_string_units":path_payload,"trusted_descriptor_serialized_payload_bytes":self.entries.len()*(4+2*112+2*8),
            "descriptor_fields_overlap_live_entry_structs":true,"retained_canonical_snapshot_bytes":0,"resident_ciphertext_response_bytes":0,"owner_response_cache_bytes":0}),
        )
    }
}
pub(crate) struct Dispatched {
    pub whole_ms: f64,
    pub inner: roles::ReadResult,
}
pub(crate) fn execute(
    catalog: &Catalog,
    table: usize,
    owner: &mut roles::OwnerTable,
    evaluator: &bfv::Evaluator,
    case: fixture::Case,
    counters: &roles::Counters,
) -> ProbeResult<Dispatched> {
    let clock = Instant::now();
    let entry = catalog
        .entries
        .get(table)
        .ok_or("Unknown supplied table ID")?;
    if entry.trusted.table_id as usize != table {
        return Err("Catalog table routing mismatch".into());
    }
    // Synchronous descriptor dispatch: no pending request survives changing this trusted pair.
    owner.trusted = entry.trusted.clone();
    let peer = roles::DiskPeer::new(
        evaluator.clone(),
        entry.trusted.clone(),
        entry.data_path.clone(),
        entry.index_path.clone(),
    );
    let inner = owner.execute(&peer, roles::Mode::Disk, case, counters)?;
    if peer.resident_bytes() != 0 {
        return Err("Disk-only peer retained response state".into());
    }
    drop(peer);
    Ok(Dispatched {
        whole_ms: clock.elapsed().as_secs_f64() * 1000.0,
        inner,
    })
}
