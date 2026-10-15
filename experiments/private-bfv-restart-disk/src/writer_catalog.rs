use crate::disk::{CatalogEntry, admit, capture_owner_header, write_new};
use crate::*;
use std::{fs::OpenOptions, io::Write, path::Path};
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
