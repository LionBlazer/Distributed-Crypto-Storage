//! Owned PUBLIC component spool for the local experiment, not a network protocol.
use crate::{COMPONENTS, Error, MAX_COMPONENT_BYTES, MAX_STREAM_BYTES, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
pub(crate) struct PublicSpool {
    base: PathBuf,
    path: PathBuf,
    next: usize,
    bytes: usize,
    failed: bool,
}
impl PublicSpool {
    pub fn new() -> Result<Self> {
        let base = std::env::temp_dir().canonicalize()?;
        let name = format!(
            "dcs-complete-relin-public-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Shape)?
                .as_nanos()
        );
        let candidate = base.join(&name);
        std::fs::create_dir(&candidate)?; // Exclusive ownership; never reuse a directory.
        let path = candidate.canonicalize()?;
        if !path.is_absolute()
            || path.parent() != Some(base.as_path())
            || path.file_name() != Some(std::ffi::OsStr::new(&name))
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            base,
            path,
            next: 0,
            bytes: 0,
            failed: false,
        })
    }
    pub fn write_next(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(Error::Stage);
        }
        if self.next >= COMPONENTS || bytes.len() > MAX_COMPONENT_BYTES {
            return Err(Error::ResourceLimit);
        }
        let total = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(Error::ResourceLimit)?;
        if total > MAX_STREAM_BYTES {
            return Err(Error::ResourceLimit);
        }
        let write = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path.join(format!("{:02}.component", self.next)))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write {
            self.failed = true; // Partial write/sync is terminal, not a retryable spool transaction.
            return Err(error);
        }
        self.next += 1;
        self.bytes = total;
        Ok(())
    }
    pub fn read(&self, ordinal: usize) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::Stage);
        }
        if ordinal >= self.next {
            return Err(Error::Incomplete);
        }
        // Bounded Read, not fs::read after a racy metadata-only length check.
        let file = File::open(self.path.join(format!("{ordinal:02}.component")))?;
        let mut bytes = Vec::new();
        file.take((MAX_COMPONENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_COMPONENT_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn count(&self) -> usize {
        self.next
    }
    fn checked_path(&self) -> Result<PathBuf> {
        let resolved = self.path.canonicalize()?;
        if !resolved.is_absolute()
            || resolved != self.path
            || resolved.parent() != Some(self.base.as_path())
        {
            return Err(Error::Shape);
        }
        Ok(resolved)
    }
    /// Successful normal completion propagates real filesystem cleanup errors.
    pub fn finish(self) -> Result<()> {
        std::fs::remove_dir_all(self.checked_path()?)?;
        if self.failed {
            Err(Error::Stage)
        } else {
            Ok(())
        }
    }
}
impl Drop for PublicSpool {
    fn drop(&mut self) {
        // Resolve the exact exclusive immediate child BEFORE recursive Windows cleanup.
        if let Ok(resolved) = self.checked_path() {
            let _ = std::fs::remove_dir_all(&resolved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_spool_write_error_is_terminal_and_checked_cleanup_still_removes_owned_files() {
        let mut spool = PublicSpool::new().unwrap();
        let path = spool.checked_path().unwrap();
        File::create_new(path.join("00.component")).unwrap();
        assert!(spool.write_next(b"public fixture").is_err());
        assert_eq!(spool.count(), 0);
        assert!(matches!(spool.write_next(b"retry"), Err(Error::Stage)));
        assert!(matches!(spool.read(0), Err(Error::Stage)));
        assert!(matches!(spool.finish(), Err(Error::Stage)));
        assert!(!path.exists());
    }
    #[test]
    fn public_spool_checked_finish_removes_the_exclusive_canonical_child() {
        let mut spool = PublicSpool::new().unwrap();
        let path = spool.checked_path().unwrap();
        spool
            .write_next(b"public framing fixture, not computation evidence")
            .unwrap();
        assert_eq!(
            spool.read(0).unwrap(),
            b"public framing fixture, not computation evidence"
        );
        assert!(spool.read(1).is_err());
        spool.finish().unwrap();
        assert!(!path.exists());
    }
}
