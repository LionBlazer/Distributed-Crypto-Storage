//! Public file/accounting helpers shared by the two owner processes, not by the broker.
use crate::process_protocol::NativeMemory;
use crate::*;
use sealed_owner_bundle::{TableCheckpoint, TableMetadata};
use std::{fs::File, io::Read, path::Path};
pub(crate) fn native_memory() -> NativeMemory {
    let s = resources::memory_sample();
    NativeMemory {
        working_set_bytes: s.working_set_bytes,
        private_commit_bytes: s.private_commit_bytes,
        native_peak_working_set_bytes: s.native_peak_working_set_bytes,
        native_peak_private_commit_bytes: s.native_peak_private_commit_bytes,
    }
}
pub(crate) fn read_bounded(path: &Path, minimum: usize, maximum: usize) -> ProbeResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let length = usize::try_from(metadata.len())?;
    if !metadata.is_file() || length < minimum || length > maximum {
        return Err("Bounded public/ciphertext file length rejected".into());
    }
    let mut wire = vec![0u8; length];
    file.read_exact(&mut wire)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err("File grew during held exact read".into());
    }
    Ok(wire)
}
pub(crate) fn checkpoints(catalog: &[disk::CatalogEntry]) -> Vec<TableCheckpoint<'_>> {
    catalog
        .iter()
        .map(|t| TableCheckpoint {
            metadata: TableMetadata {
                table_id: t.id as u32,
                data_file: t
                    .data_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                index_file: t
                    .index_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                data_bytes: t.data_len as u64,
                index_bytes: t.index_len as u64,
                data_head: t.data_head.clone(),
                index_head: t.index_head.clone(),
            },
            owner: &t.owner,
        })
        .collect()
}
pub(crate) fn public_id() -> ProbeResult<[u8; 32]> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).map_err(|_| "Public binding randomness unavailable")?;
    Ok(id)
}
pub(crate) fn file_ledger(directory: &Path) -> ProbeResult<serde_json::Value> {
    let mut files = Vec::new();
    let mut canonical = 0u64;
    let mut sealed = 0u64;
    let mut public = 0u64;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            return Err("Unexpected dataset subdirectory".into());
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let length = metadata.len();
        let role = if name.starts_with("table-") {
            canonical += length;
            "canonical"
        } else if name.ends_with(".sealed") {
            sealed += length;
            "sealed-owner-checkpoint"
        } else {
            public += length;
            "public-catalog-or-original-setup"
        };
        // Hash ciphertext and public files only. No owner images or keys enter this path.
        let mut file = File::open(entry.path())?;
        let mut hash = sha2::Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        files.push(json!({"name":name,"bytes":length,"role":role,"sha256":format!("{:x}",hash.finalize())}));
    }
    files.sort_by_key(|x| x["name"].as_str().unwrap().to_owned());
    Ok(
        json!({"actual_file_count":files.len(),"canonical_bytes":canonical,"sealed_checkpoint_bytes":sealed,
        "public_files_bytes":public,"all_dataset_file_bytes":canonical+sealed+public,"per_file_name_length_role_hash_manifest_sha256":format!("{:x}",sha2::Sha256::digest(serde_json::to_vec(&files)?)),
        "plaintext_secret_files":0,"fsync_or_crash_durability":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn held_public_reads_reject_truncation_and_oversize_before_allocating_claimed_lengths() {
        let path = std::env::temp_dir().join(format!(
            "restart-bounded-public-{}-{}.bin",
            std::process::id(),
            u64::from_le_bytes(public_id().unwrap()[..8].try_into().unwrap())
        ));
        disk::write_new(&path, b"public").unwrap();
        assert!(read_bounded(&path, 7, 8).is_err());
        assert!(read_bounded(&path, 0, 5).is_err());
        assert_eq!(read_bounded(&path, 6, 6).unwrap(), b"public");
        // Public ephemeral test fixture only; leave generated artifacts in temp.
    }
}
