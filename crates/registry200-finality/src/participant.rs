//! Explicit participant storage profile. No legacy path adoption or recovery create.
use crate::{Binding, Error, Hash, Result, digest};
use protocol_storage::{ByteBudget, ControlFile, FileCharge, FilePermit, ParticipantQuota};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const META_BYTES: usize = 232;
pub fn participant_storage_profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/participant-storage/v1", &[
        &crate::profile_digest(), &protocol_storage::participant_profile_digest(),
        b"typed-four-control-files/binding+signer-id/metadata-last/new-only/existing-only/no-adoption",
        b"journal76+G/floor168/wal144/all-writes-precharged/owned-IO-poisons-global-ledger",
        &(META_BYTES as u64).to_le_bytes(),
    ])
}
pub(crate) struct Paths {
    pub journal: PathBuf,
    pub floor: PathBuf,
    pub wal: PathBuf,
    pub metadata: Option<PathBuf>,
}
impl Paths {
    pub fn legacy(directory: &Path) -> Result<Self> {
        let root = directory.canonicalize()?;
        Ok(Self {
            journal: root.join("registry-finality-journal-v1"),
            floor: root.join("registry-finality-floor-v1"),
            wal: root.join("registry-finality-signer-v1"),
            metadata: None,
        })
    }
    pub fn participant(quota: &ParticipantQuota, binding: &Binding, signer: Hash) -> Self {
        let id = file_id(binding, signer);
        Self {
            journal: quota.control_file(id, ControlFile::Journal),
            floor: quota.control_file(id, ControlFile::Floor),
            wal: quota.control_file(id, ControlFile::Wal),
            metadata: Some(quota.control_file(id, ControlFile::Metadata)),
        }
    }
}
fn file_id(binding: &Binding, signer: Hash) -> Hash {
    digest(
        b"dcs/registry200-finality/participant-file-id/v1",
        &[
            &participant_storage_profile_digest(),
            &binding.id(),
            &signer,
        ],
    )
}
fn metadata(binding: &Binding, signer: Hash) -> [u8; META_BYTES] {
    let mut b = [0; META_BYTES];
    b[..8].copy_from_slice(b"DCSRFM01");
    for (i, h) in [
        participant_storage_profile_digest(),
        protocol_storage::participant_profile_digest(),
        binding.id(),
        signer,
        binding.initial_context().journal_genesis(),
        file_id(binding, signer),
    ]
    .iter()
    .enumerate()
    {
        b[8 + 32 * i..40 + 32 * i].copy_from_slice(h);
    }
    let hash = digest(
        b"dcs/registry200-finality/participant-metadata/v1",
        &[&b[..200]],
    );
    b[200..].copy_from_slice(&hash);
    b
}
pub(crate) fn install(
    mut permit: FilePermit,
    binding: &Binding,
    signer: Hash,
) -> Result<FileCharge> {
    let bytes = metadata(binding, signer);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(permit.path())?;
    file.try_lock().map_err(|_| Error::CorruptFloor)?;
    let charge = permit.register_file()?;
    if let Err(e) = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| sync_parent(permit.path()))
    {
        charge.mark_io_failed();
        return Err(e.into());
    }
    Ok(charge)
}
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(
            path.parent()
                .ok_or_else(|| std::io::Error::other("Missing control parent"))?,
        )?
        .sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    } // File sync does not establish power-loss directory durability on Windows.
    Ok(())
}
pub(crate) fn open(
    path: &Path,
    binding: &Binding,
    signer: Hash,
    budget: &ByteBudget,
) -> Result<FileCharge> {
    budget.check_existing_file(path)?;
    let charge = budget.register_file(path)?;
    let result = (|| {
        let mut file = File::open(path)?;
        if file.metadata()?.len() != META_BYTES as u64 {
            return Err(Error::InvalidBinding);
        }
        let mut bytes = [0; META_BYTES];
        file.read_exact(&mut bytes)?;
        if bytes != metadata(binding, signer) {
            return Err(Error::InvalidBinding);
        }
        Ok(())
    })();
    if result.is_err() {
        charge.mark_io_failed();
    }
    result?;
    Ok(charge)
}
