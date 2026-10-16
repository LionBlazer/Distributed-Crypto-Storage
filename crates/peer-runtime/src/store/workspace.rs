//! Strict read-only namespace preflight, then cooperative exclusive-lock startup.
use crate::{OBJECT_PROFILE_ID, objects};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
pub(super) const PENDING: &str = "write-v2.pending";
const PROFILE: &str = "custody-v2.profile";
use super::PROFILE_BYTES;
const MAGIC: &[u8; 8] = b"DCSDIR02";
fn invalid() -> io::Error {
    io::Error::other("Incompatible custody workspace namespace")
}
fn canonical_name(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix).is_some_and(|stem| {
        stem.len() == 64
            && stem
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
/// The sole exception is our just-created empty lock in a previously empty root.
/// Current-format pending is disposable even if its write was interrupted before
/// a complete header. No legacy/unknown pending file is recognized or removed.
pub(super) fn preflight(path: &Path, initializing: bool) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => return Err(invalid()),
        Ok(_) => (),
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        if entries.len() >= 1035 {
            return Err(invalid());
        }
        entries.push(entry?);
    }
    if entries.is_empty()
        || (initializing && entries.len() == 1 && entries[0].file_name() == "peer.lock")
    {
        return Ok(true);
    }
    let mut profile = fs::File::open(path.join(PROFILE))?;
    if profile.metadata()?.len() != PROFILE_BYTES as u64 {
        return Err(invalid());
    }
    let mut bytes = [0; PROFILE_BYTES];
    profile.read_exact(&mut bytes)?;
    if &bytes[..8] != MAGIC || bytes[8..] != OBJECT_PROFILE_ID {
        return Err(invalid());
    }
    let mut objects = 0;
    let mut journals = 0;
    for entry in entries {
        let meta = entry.metadata()?;
        if !meta.is_file() || entry.file_type()?.is_symlink() {
            return Err(invalid());
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(invalid)?;
        if name == PROFILE || name == "peer.lock" {
            continue;
        }
        if name == PENDING {
            if meta.len() > peer_transport::MAX_FRAME_BYTES as u64 {
                return Err(invalid());
            }
        } else if canonical_name(name, ".object2") {
            objects += 1;
            if objects > 1024 || meta.len() > peer_transport::MAX_FRAME_BYTES as u64 {
                return Err(invalid());
            }
            let mut header = [0; objects::DISK_HEADER_BYTES + 2];
            fs::File::open(entry.path())?.read_exact(&mut header)?;
            objects::check_disk_header(&header)?;
            if header[objects::DISK_HEADER_BYTES..] != 2u16.to_le_bytes() {
                return Err(invalid());
            }
        } else if canonical_name(name, ".journal2") {
            journals += 1;
            if journals > 8 || meta.len() > version_journal::MAX_JOURNAL_BYTES {
                return Err(invalid());
            }
            version_journal::DurableJournal::check_namespace(entry.path(), OBJECT_PROFILE_ID)
                .map_err(io::Error::other)?;
        } else {
            return Err(invalid());
        }
    }
    Ok(false)
}
pub(super) fn initialize(path: &Path) -> io::Result<()> {
    let mut profile = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path.join(PROFILE))?;
    profile.write_all(MAGIC)?;
    profile.write_all(&OBJECT_PROFILE_ID)?;
    profile.sync_all()
}
