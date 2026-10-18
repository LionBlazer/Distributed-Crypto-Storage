use super::{Error, Result};
pub(in crate::opening) struct OwnedDirectory {
    path: std::path::PathBuf,
    base: std::path::PathBuf,
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if let Ok(resolved) = self.path.canonicalize()
            && resolved == self.path
            && resolved.parent() == Some(self.base.as_path())
        {
            let _ = std::fs::remove_dir_all(resolved);
        }
    }
}
impl OwnedDirectory {
    pub(in crate::opening) fn new() -> Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.local/proof-peer-process-fixtures");
        std::fs::create_dir_all(&base)?;
        let base = base.canonicalize()?;
        let path = base.join(format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Binding)?
                .as_nanos()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self {
            path: path.canonicalize()?,
            base,
        })
    }
    pub(in crate::opening) fn peer_path(&self) -> std::path::PathBuf {
        self.path.join("peer")
    }
}
