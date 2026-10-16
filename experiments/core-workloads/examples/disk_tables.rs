//! Bounded disk-image experiment with supplied table routing and public fixtures.
#[path = "support/key_amortization_memory.rs"]
mod memory;

use compact_query::{
    AgeRange, Aggregate, Operation, Owner, PlainRow, Selection, Table, UnverifiedOutput,
};
use compact_store::{Commitment, Limits};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const HEADER: u64 = 24;
const MAX_IMAGE: u64 = 64 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"CQDISK01";
const ROWS: usize = 1_000_000;
const RESERVE: u64 = 64 * 1024 * 1024;
const MAX_TABLES: usize = 1800;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
fn row(table: usize, ordinal: usize) -> PlainRow {
    if ordinal == (table * 4729 + 17) % ROWS {
        PlainRow {
            age: 250,
            amount: ((table * 997 + 101) % 65536) as u16,
        }
    } else {
        PlainRow {
            age: ((ordinal * 73 + table * 17 + 11) % 200) as u8,
            amount: ((ordinal * 137 + table * 997 + 29) % 65536) as u16,
        }
    }
}
struct Entry {
    path: PathBuf,
    logical_id: compact_query::TableId,
    data: Commitment,
    index: Commitment,
}
struct OwnedRun {
    root: PathBuf,
    paths: Vec<PathBuf>,
}
impl OwnedRun {
    fn create(parent: &Path) -> Result<Self> {
        let parent = parent.canonicalize()?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = parent.join(format!("streamed-{}-{stamp}", std::process::id()));
        fs::create_dir(&root)?;
        Ok(Self {
            root,
            paths: Vec::new(),
        })
    }
    fn path(&self, table: usize) -> PathBuf {
        self.root.join(format!("{table:06}.cq"))
    }
    fn write(&mut self, table: &Table, id: usize) -> Result<u64> {
        let path = self.path(id);
        let data_len = table.canonical_data_bytes() as u64;
        let index_len = table.encrypted_index_bytes() as u64;
        check_lengths(data_len, index_len, HEADER + data_len + index_len)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        self.paths.push(path);
        file.write_all(MAGIC)?;
        file.write_all(&data_len.to_le_bytes())?;
        file.write_all(&index_len.to_le_bytes())?;
        // Only one complete image serialization lives at a time.
        file.write_all(&table.snapshot().encode())?;
        file.write_all(&table.encrypted_index().encode())?;
        file.sync_all()?;
        let actual = file.metadata()?.len();
        if actual != HEADER + data_len + index_len {
            return Err("Disk length mismatch".into());
        }
        Ok(actual)
    }
}
impl Drop for OwnedRun {
    fn drop(&mut self) {
        // Delete only files this run created with create_new, never recursively.
        for path in &self.paths {
            if let Err(error) = fs::remove_file(path) {
                eprintln!("Cleanup {}: {error}", path.display());
            }
        }
        if let Err(error) = fs::remove_dir(&self.root) {
            eprintln!("Cleanup {}: {error}", self.root.display());
        }
    }
}
fn check_lengths(data: u64, index: u64, file: u64) -> Result<()> {
    if !(112..=MAX_IMAGE).contains(&data)
        || !(112..=MAX_IMAGE).contains(&index)
        || data.checked_add(index).and_then(|n| n.checked_add(HEADER)) != Some(file)
    {
        return Err("Bounded disk frame rejected before image allocation".into());
    }
    Ok(())
}
fn load(owner: &Owner, entry: &Entry) -> Result<Table> {
    memory::guard(RESERVE)?;
    let mut file = File::open(&entry.path)?;
    let length = file.metadata()?.len();
    let mut header = [0u8; HEADER as usize];
    file.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err("Wrong disk frame version".into());
    }
    let data_len = u64::from_le_bytes(header[8..16].try_into()?);
    let index_len = u64::from_le_bytes(header[16..24].try_into()?);
    check_lengths(data_len, index_len, length)?;
    let mut data = vec![0u8; data_len as usize];
    let mut index = vec![0u8; index_len as usize];
    file.read_exact(&mut data)?;
    file.read_exact(&mut index)?;
    Ok(owner.restore_table_for_experiment(
        &data,
        &index,
        &entry.logical_id,
        &entry.data,
        &entry.index,
        Limits::default(),
    )?)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("Use disk_tables <existing ignored output directory> <2..1800 tables>".into());
    }
    let count: usize = args[1].parse()?;
    if !(2..=MAX_TABLES).contains(&count) {
        return Err("Table count must be 2..1800".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()?;
    let mut run = OwnedRun::create(Path::new(&args[0]))?;
    memory::guard(256 * 1024 * 1024)?;
    let setup = Instant::now();
    let (owner, evaluator) = Owner::generate(*b"PUBLIC-DISK-TEST")?;
    let evaluator = evaluator.with_row_workers_for_experiment(8)?;
    let eval_bytes = evaluator.encode_evaluation_key_for_experiment()?.len() as u64;
    let owner_key_bytes = owner.secret_key_serialized_bytes()?;
    // Shared Cargo targets can retain an artifact from another local workspace.
    // This experiment is pinned to the measured current classic profile.
    if eval_bytes != 180_610_708 || owner_key_bytes != 31_268 {
        return Err("Unexpected FHE profile: rebuild the current classic library".into());
    }
    let setup_ms = ms(setup);
    let mut entries = Vec::with_capacity(count);
    let mut file_bytes = 0u64;
    let mut hashes_if_all_loaded = 0u64;
    let mut distinct = std::collections::BTreeSet::new();
    let start = Instant::now();
    for table_id in 0..count {
        memory::guard(RESERVE)?;
        let fixture: Vec<_> = (0..ROWS).map(|i| row(table_id, i)).collect();
        let table = owner.seal(&fixture, 2048, Limits::default())?;
        drop(fixture);
        hashes_if_all_loaded += table.rebuildable_hash_bytes() as u64;
        if !distinct.insert(table.commitment().root()) {
            return Err("Duplicate table root".into());
        }
        file_bytes += run.write(&table, table_id)?;
        entries.push(Entry {
            path: run.path(table_id),
            logical_id: *table.table_id(),
            data: table.commitment().clone(),
            index: table.index_commitment().clone(),
        });
        drop(table);
        if table_id == 1 || (table_id + 1).is_multiple_of(100) || table_id + 1 == count {
            println!(
                "{}",
                json!({"kind":"disk_progress","tables_written":table_id+1,
                "actual_image_file_bytes":file_bytes, "elapsed_ms":ms(start),
                "native_memory":memory::guard(0)?})
            );
            std::io::stdout().flush()?;
        }
    }
    let create_sync_ms = ms(start);
    let head_bytes = entries
        .iter()
        .map(|entry| entry.data.encode().len() + entry.index.encode().len())
        .sum::<usize>() as u64;
    // Deterministic u64 table IDs route file names; count that catalog payload too.
    let catalog_bytes = head_bytes + count as u64 * 8;
    let joint = file_bytes + catalog_bytes + eval_bytes + owner_key_bytes + 80;
    let logical = count as u64 * ROWS as u64 * 3;
    println!(
        "{}",
        json!({"kind":"disk_accounting","tables":count,"rows":count as u64*ROWS as u64,
        "logical_bytes":logical,"actual_file_bytes":file_bytes,"disk_container_header_bytes":count as u64*HEADER,
        "trusted_catalog_payload_bytes":catalog_bytes,"public_evaluation_key_wire_bytes":eval_bytes,
        "owner_fhe_key_serialized_bytes":owner_key_bytes,"owner_symmetric_domain_bytes":80,
        "joint_canonical_material_bytes":joint,"joint_expansion":joint as f64/logical as f64,
        "rebuildable_hash_bytes_if_all_loaded":hashes_if_all_loaded,"all_hashes_persisted":false,
        "loaded_tables_during_queries":1,"setup_ms":setup_ms,"create_and_sync_all_ms":create_sync_ms,
        "os_file_cache_bypassed":false,"secret_keys_written":false,"replicas":1,
        "native_memory":memory::guard(0)?})
    );
    let targets = std::collections::BTreeSet::from([0, count / 2, count - 1]);
    for table_id in targets {
        for sample in 0..3 {
            let started = Instant::now();
            let io_started = Instant::now();
            let table = load(&owner, &entries[table_id])?;
            let load_ms = ms(io_started);
            let range = AgeRange::equal(250);
            let mut query = owner.prepare(
                &table,
                Selection::IndexedAgeRange(range),
                range,
                Operation::CountSum,
                256,
                Limits::default(),
            )?;
            let request = query.encode_request()?;
            let mut answer = evaluator.evaluate(table.snapshot(), &request, Limits::default())?;
            let wire = answer.encode()?;
            let peer_stages = answer.stages().clone();
            let owner_stages = query.stages().clone();
            let page_bytes = owner_stages.owner_index_response_bytes
                + owner_stages.owner_data_response_bytes
                + peer_stages.page_response_bytes;
            let decoded = UnverifiedOutput::decode(&wire)?;
            let actual = owner.decrypt_aggregate_for_experiment(&table, &query, &decoded)?;
            let elapsed = ms(started);
            let expected = (0..ROWS)
                .map(|i| row(table_id, i))
                .filter(|row| row.age == 250)
                .fold(Aggregate { count: 0, sum: 0 }, |mut total, row| {
                    total.count += 1;
                    total.sum += u32::from(row.amount);
                    total
                });
            assert_eq!(actual, expected);
            println!(
                "{}",
                json!({"kind":"disk_query","supplied_table_id":table_id,"sample":sample,
                "full_disk_load_auth_fhe_decrypt_ms":elapsed,"file_read_decode_verify_ms":load_ms,
                "count":actual.count,"sum":actual.sum,"exact":true,"request_bytes":request.len(),"output_bytes":wire.len(),
                "separate_authenticated_page_bytes":page_bytes,"total_counted_query_flow_bytes":request.len()+wire.len()+page_bytes,
                "owner_stages":owner_stages,"peer_stages":peer_stages,
                "global_sql_routing_measured":false,"network_measured":false,"computation_proof":false,
                "native_memory":memory::guard(0)?})
            );
            drop(table);
        }
    }
    // Real file-corruption/truncation gates against independently retained heads.
    let original = fs::read(&entries[0].path)?;
    let mut corrupt = original.clone();
    corrupt[HEADER as usize + compact_store::MANIFEST_BYTES + 32] ^= 1;
    fs::write(&entries[0].path, &corrupt)?;
    assert!(load(&owner, &entries[0]).is_err());
    fs::write(&entries[0].path, &original[..original.len() - 1])?;
    assert!(load(&owner, &entries[0]).is_err());
    let mut invalid_length = original.clone();
    invalid_length[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&entries[0].path, invalid_length)?;
    assert!(load(&owner, &entries[0]).is_err());
    fs::write(&entries[0].path, &original)?;
    assert!(load(&owner, &entries[0]).is_ok());
    let wrong_head = Entry {
        path: entries[0].path.clone(),
        logical_id: entries[1].logical_id,
        data: entries[1].data.clone(),
        index: entries[1].index.clone(),
    };
    assert!(load(&owner, &wrong_head).is_err());
    println!(
        "{}",
        json!({"kind":"disk_checks_passed","actual_tables":count,"file_bytes":file_bytes,
        "tamper_rejected":true,"truncation_rejected":true,"hostile_length_rejected_before_allocation":true,
        "wrong_trusted_head_rejected":true,"all_queries_exact":true,"secret_keys_written":false,
        "same_live_owner_keys":true,"durable_key_restore":false,"native_memory":memory::guard(0)?})
    );
    let cleanup_path = run.root.clone();
    drop(run);
    if cleanup_path.exists() {
        return Err("Own generated run directory cleanup failed".into());
    }
    println!(
        "{}",
        json!({"kind":"disk_complete","actual_tables":count,"own_generated_files_removed":true,"all_queries_and_failure_checks_passed":true})
    );
    Ok(())
}
