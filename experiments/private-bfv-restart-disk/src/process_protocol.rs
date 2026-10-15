//! Bounded PUBLIC process protocol plus a raw32-byte secret stdin prefix.
//! Never serialize/log the key; no argv/environment/file key entry point exists.
use compact_bfv_byte_limb_core::Geometry;
use sealed_owner_bundle::{CheckpointAnchor, CheckpointBinding};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;
pub type ProtocolResult<T> = Result<T, Box<dyn std::error::Error>>;
pub const PUBLIC_FRAME_BYTES: usize = 16 * 1024;
pub const PUBLIC_LINE_BYTES: usize = 1024 * 1024;
pub const CHILD_STDOUT_BYTES: usize = 32 * 1024 * 1024;
pub const CHILD_STDERR_BYTES: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub tables: usize,
    pub ids: Vec<usize>,
    pub samples: usize,
    pub threads: usize,
    pub max_canonical_bytes: u64,
    pub directory: PathBuf,
    pub writer_timeout_seconds: u64,
    pub reader_timeout_seconds: u64,
}
impl Config {
    pub fn from_args() -> ProtocolResult<Self> {
        let value = std::env::args()
            .nth(1)
            .ok_or("Public configuration JSON argument required")?;
        if value.len() > PUBLIC_FRAME_BYTES {
            return Err("Public configuration exceeds bound".into());
        }
        let config: Self = serde_json::from_str(&value)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> ProtocolResult<()> {
        if !(3..=1000).contains(&self.tables)
            || self.samples != 1
            || !(1..=8).contains(&self.threads)
            || self.ids.len() != 3
            || self.ids.iter().any(|x| *x >= self.tables)
            || self
                .ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 3
            || self.ids != [0, (self.tables - 1) / 2, self.tables - 1]
            || self.max_canonical_bytes > 6_500_000_000
            || self
                .tables
                .checked_mul(6 * 1024 * 1024)
                .is_none_or(|n| n as u64 > self.max_canonical_bytes)
            || !(10..=300).contains(&self.writer_timeout_seconds)
            || !(30..=600).contains(&self.reader_timeout_seconds)
        {
            return Err("Bounded public process configuration rejected".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMemory {
    pub working_set_bytes: usize,
    pub private_commit_bytes: usize,
    pub native_peak_working_set_bytes: usize,
    pub native_peak_private_commit_bytes: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAnchor {
    pub bundle_id: [u8; 32],
    pub checkpoint_id: [u8; 32],
    pub generation: u64,
    pub catalog_digest: [u8; 32],
    pub bfv_public_digest: [u8; 32],
    pub pir_public_digest: [u8; 32],
    pub geometry_slots: usize,
}
impl PublicAnchor {
    pub fn capture(value: &CheckpointAnchor) -> Self {
        Self {
            bundle_id: value.binding.bundle_id,
            checkpoint_id: value.binding.checkpoint_id,
            generation: value.binding.generation,
            catalog_digest: value.catalog_digest,
            bfv_public_digest: value.bfv_public_digest,
            pir_public_digest: value.pir_public_digest,
            geometry_slots: value.geometry.slots(),
        }
    }
    pub fn restore(&self) -> ProtocolResult<CheckpointAnchor> {
        let geometry = match self.geometry_slots {
            256 => Geometry::Rows256,
            _ => return Err("Rows256 anchor required".into()),
        };
        Ok(CheckpointAnchor {
            binding: CheckpointBinding {
                bundle_id: self.bundle_id,
                checkpoint_id: self.checkpoint_id,
                generation: self.generation,
            },
            catalog_digest: self.catalog_digest,
            bfv_public_digest: self.bfv_public_digest,
            pir_public_digest: self.pir_public_digest,
            geometry,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateReceipt {
    pub table_id: usize,
    pub ordinal: u64,
    pub delta: u16,
    pub original_amount: u16,
    pub updated_amount: u16,
    pub prior_data_head: Vec<u8>,
    pub prior_index_head: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterReceipt {
    pub experiment: String,
    pub protocol_version: u16,
    pub writer_pid: u32,
    pub tables: usize,
    pub previous: PublicAnchor,
    pub current: PublicAnchor,
    pub update: UpdateReceipt,
    pub native: NativeMemory,
    pub setup: serde_json::Value,
    pub file_ledger: serde_json::Value,
    pub original_public_setup_preserved: bool,
}
impl WriterReceipt {
    pub fn validate(&self, config: &Config) -> ProtocolResult<()> {
        if self.experiment != "restart-writer-receipt"
            || self.protocol_version != 1
            || self.tables != config.tables
            || self.update.table_id != config.tables - 1
            || self.previous.generation != 0
            || self.current.generation != 1
            || self.previous.bundle_id != self.current.bundle_id
            || self.previous.checkpoint_id == self.current.checkpoint_id
            || self.previous.bfv_public_digest != self.current.bfv_public_digest
            || self.previous.pir_public_digest != self.current.pir_public_digest
            || self.update.delta != 1
            || self.update.original_amount.checked_add(1) != Some(self.update.updated_amount)
            || self.update.prior_data_head.len() != 112
            || self.update.prior_index_head.len() != 112
            || !self.original_public_setup_preserved
        {
            return Err("Invalid trusted writer receipt".into());
        }
        self.previous.restore()?;
        self.current.restore()?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderStart {
    pub protocol_version: u16,
    pub writer_exited_successfully: bool,
    pub writer: WriterReceipt,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderReceipt {
    pub experiment: String,
    pub protocol_version: u16,
    pub reader_pid: u32,
    pub original_writer_pid: u32,
    pub completed: bool,
    pub correct: bool,
    pub matrix_operations: usize,
    pub reader_key_path: String,
    pub native: NativeMemory,
    pub restore: serde_json::Value,
    pub file_ledger: serde_json::Value,
}
pub fn read_secret_prefix(input: &mut impl Read) -> ProtocolResult<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    input
        .read_exact(key.as_mut())
        .map_err(|_| "Secret stdin prefix truncated")?;
    Ok(key)
}
pub fn read_public_frame<T: serde::de::DeserializeOwned>(
    input: &mut impl Read,
) -> ProtocolResult<T> {
    let mut header = [0u8; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| "Public frame header truncated")?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > PUBLIC_FRAME_BYTES {
        return Err("Public frame length exceeds bound".into());
    }
    let mut wire = vec![0u8; length];
    input
        .read_exact(&mut wire)
        .map_err(|_| "Public frame truncated")?;
    Ok(serde_json::from_slice(&wire)?)
}
pub fn require_eof(input: &mut impl Read) -> ProtocolResult<()> {
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 {
        return Err("Extra stdin frame rejected".into());
    }
    Ok(())
}
pub fn write_public_frame(output: &mut impl Write, value: &impl Serialize) -> ProtocolResult<()> {
    let wire = serde_json::to_vec(value)?;
    if wire.is_empty() || wire.len() > PUBLIC_FRAME_BYTES {
        return Err("Public frame bound".into());
    }
    output.write_all(&(wire.len() as u32).to_le_bytes())?;
    output.write_all(&wire)?;
    Ok(())
}
pub fn write_public_line(value: &impl Serialize) -> ProtocolResult<()> {
    let wire = serde_json::to_vec(value)?;
    if wire.len() > PUBLIC_LINE_BYTES {
        return Err("Public output line bound".into());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&wire)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_frame_is_exactly_bounded_and_truncation_does_not_allocate_claimed_length() {
        let mut wire = Vec::new();
        write_public_frame(&mut wire, &vec![1u32, 2, 3]).unwrap();
        let result: Vec<u32> = read_public_frame(&mut &wire[..]).unwrap();
        assert_eq!(result, [1, 2, 3]);
        let mut over = &u32::MAX.to_le_bytes()[..];
        assert!(read_public_frame::<Vec<u8>>(&mut over).is_err());
        assert!(read_public_frame::<Vec<u8>>(&mut &wire[..wire.len() - 1]).is_err());
    }
    #[test]
    fn secret_prefix_requires_exact32_and_returns_zeroizing_owner_memory_without_a_serializer() {
        assert!(read_secret_prefix(&mut &[0u8; 31][..]).is_err());
        let image = read_secret_prefix(&mut &[17u8; 32][..]).unwrap();
        assert!(image.iter().all(|x| *x == 17));
        assert!(require_eof(&mut &[1u8][..]).is_err());
    }
}
