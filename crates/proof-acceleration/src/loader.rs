use crate::{Kind, Timings, abi, ffi};
use std::fmt;
use std::path::{Path, PathBuf};

/// A deployment, CPU-support or ABI failure. A present invalid kernel never
/// causes selection to silently try another implementation.
#[derive(Debug)]
pub enum LoadError {
    InvalidPath { path: PathBuf, reason: &'static str },
    Io { path: PathBuf, reason: String },
    UnsupportedCpu(Kind),
    MissingKernel { kind: Kind, path: PathBuf },
    Library { path: PathBuf, reason: String },
    Descriptor { kind: Kind, reason: &'static str },
}
impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, reason } => {
                write!(
                    f,
                    "invalid proof kernel directory {}: {reason}",
                    path.display()
                )
            }
            Self::Io { path, reason } => {
                write!(f, "proof kernel path {}: {reason}", path.display())
            }
            Self::UnsupportedCpu(kind) => write!(f, "CPU/OS does not support {kind} proof kernels"),
            Self::MissingKernel { kind, path } => {
                write!(f, "missing {kind} proof kernel {}", path.display())
            }
            Self::Library { path, reason } => {
                write!(f, "cannot load proof kernel {}: {reason}", path.display())
            }
            Self::Descriptor { kind, reason } => write!(f, "invalid {kind} proof kernel: {reason}"),
        }
    }
}
impl std::error::Error for LoadError {}

/// A bounded operation rejected by the selected backend or its ABI boundary.
/// Status values are the stable numbers in [`abi`], never Rust enum layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallError {
    status: u32,
    reason: &'static str,
}
impl CallError {
    pub fn status(&self) -> Option<u32> {
        Some(self.status)
    }
    pub(crate) const fn new(status: u32, reason: &'static str) -> Self {
        Self { status, reason }
    }
    pub(crate) fn from_status(status: u32) -> Result<(), Self> {
        match status {
            abi::SUCCESS => Ok(()),
            abi::STATEMENT_SHAPE => Err(Self::new(status, "invalid arithmetic statement shape")),
            abi::REQUEST_BINDING => Err(Self::new(status, "request binding differs")),
            abi::NON_CANONICAL_RESIDUE => Err(Self::new(status, "noncanonical BFV residue")),
            abi::PROOF_LENGTH => Err(Self::new(status, "invalid proof length")),
            abi::PROOF_ENCODING => Err(Self::new(status, "invalid proof encoding")),
            abi::PROOF_RESOURCE_LIMIT => Err(Self::new(status, "proof decoding resource limit")),
            abi::TRAILING_PROOF_BYTES => Err(Self::new(status, "trailing proof bytes")),
            abi::SECURITY_PROFILE => Err(Self::new(status, "proof security profile differs")),
            abi::PREPROCESSING => Err(Self::new(status, "proof preprocessing failed")),
            abi::PROVING => Err(Self::new(status, "proof generation failed")),
            abi::VERIFICATION => Err(Self::new(status, "proof verification failed")),
            abi::INVALID_ABI => Err(Self::new(status, "backend rejected the ABI contract")),
            abi::BUFFER_TOO_SMALL => Err(Self::new(status, "backend output buffer is too small")),
            abi::PANIC => Err(Self::new(status, "backend caught an internal panic")),
            _ => Err(Self::new(abi::INVALID_ABI, "unknown backend status")),
        }
    }
}
impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proof backend rejected operation ({}): {}",
            self.status, self.reason
        )
    }
}
impl std::error::Error for CallError {}

/// Host-owned serialized result. No native allocator or SDK type crosses the ABI.
pub struct Proved {
    output: Vec<u8>,
    proof: Vec<u8>,
    timings: Timings,
}
impl Proved {
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn timings(&self) -> Timings {
        self.timings
    }
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, Timings) {
        (self.output, self.proof, self.timings)
    }
}

/// A trusted installed kernel selected once at startup. Loaded libraries stay
/// mapped until process exit, including after this handle drops, because native
/// proof workers can outlive individual calls. Calls perform no CPU detection.
///
/// The directory is part of the trusted application installation: native code
/// can execute during loading, before its compatibility descriptor is checked.
pub struct Kernel {
    kind: Kind,
    library: ffi::Loaded,
}
impl fmt::Debug for Kernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kernel")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl Kernel {
    /// Select the highest supported installed SIMD kernel. Missing files permit
    /// a lower kind; `None` selects the host's linked portable implementation.
    pub fn select(directory: &Path) -> Result<Option<Self>, LoadError> {
        let Some(directory) = validate_directory(directory)? else {
            return Ok(None);
        };
        for kind in [Kind::Avx512, Kind::Avx2] {
            if !kind.is_supported() {
                continue;
            }
            if let Some(path) = kernel_path(&directory, kind)? {
                return Self::load_path(path, kind).map(Some);
            }
        }
        Ok(None)
    }

    /// Load a particular installed kind, for example to test proof interoperability.
    /// Real CPU and OS support is checked before loading any native library.
    pub fn load(directory: &Path, kind: Kind) -> Result<Self, LoadError> {
        if !kind.is_supported() {
            return Err(LoadError::UnsupportedCpu(kind));
        }
        let original_path = directory.join(abi::kernel_file_name(kind));
        let directory = validate_directory(directory)?.ok_or_else(|| LoadError::MissingKernel {
            kind,
            path: original_path.clone(),
        })?;
        let path = kernel_path(&directory, kind)?.ok_or(LoadError::MissingKernel {
            kind,
            path: original_path,
        })?;
        Self::load_path(path, kind)
    }

    fn load_path(path: PathBuf, kind: Kind) -> Result<Self, LoadError> {
        let (library, descriptor, status) = ffi::Loaded::open(&path)?;
        validate_descriptor(kind, descriptor, status)?;
        Ok(Self { kind, library })
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn prove(&self, input: &[u8]) -> Result<Proved, CallError> {
        validate_input(input)?;
        // Initialized host memory makes truncation safe even if a trusted backend
        // returns a malformed written count; that count is checked before use.
        let mut output = vec![0; abi::OUTPUT_BYTES];
        let mut proof = vec![0; abi::MAX_PROOF_BYTES];
        let (output_written, proof_written, timings) =
            self.library.prove(input, &mut output, &mut proof)?;
        output.truncate(output_written);
        proof.truncate(proof_written);
        Ok(Proved {
            output,
            proof,
            timings,
        })
    }

    pub fn verify(&self, input: &[u8], output: &[u8], proof: &[u8]) -> Result<Timings, CallError> {
        validate_input(input)?;
        if output.len() != abi::OUTPUT_BYTES {
            return Err(CallError::new(
                abi::STATEMENT_SHAPE,
                "invalid canonical output length",
            ));
        }
        validate_proof_length(proof.len())?;
        self.library.verify(input, output, proof)
    }
}

fn validate_input(input: &[u8]) -> Result<(), CallError> {
    if input.len() != abi::MAX_INPUT_BYTES {
        return Err(CallError::new(
            abi::STATEMENT_SHAPE,
            "invalid canonical request length",
        ));
    }
    Ok(())
}
pub(crate) fn validate_proof_length(length: usize) -> Result<(), CallError> {
    if !(8..=abi::MAX_PROOF_BYTES).contains(&length) {
        return Err(CallError::new(
            abi::PROOF_LENGTH,
            "proof frame is outside its bounds",
        ));
    }
    Ok(())
}

fn validate_descriptor(
    kind: Kind,
    descriptor: abi::Descriptor,
    status: u32,
) -> Result<(), LoadError> {
    let reason = if status != abi::SUCCESS {
        Some("descriptor call failed")
    } else if descriptor.abi_version != abi::ABI_VERSION {
        Some("ABI version differs")
    } else if descriptor.kind != kind as u32 {
        Some("compiled SIMD kind differs")
    } else if descriptor.profile_id != abi::PROFILE_ID {
        Some("cryptographic profile differs")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(LoadError::Descriptor { kind, reason }),
        None => Ok(()),
    }
}

fn invalid_path(path: &Path, reason: &'static str) -> LoadError {
    LoadError::InvalidPath {
        path: path.to_owned(),
        reason,
    }
}
fn validate_directory(directory: &Path) -> Result<Option<PathBuf>, LoadError> {
    if !directory.is_absolute() {
        return Err(invalid_path(
            directory,
            "an absolute installation directory is required",
        ));
    }
    if !ffi::is_local_path(directory) {
        return Err(invalid_path(
            directory,
            "network and device paths are not allowed",
        ));
    }
    let canonical = match std::fs::canonicalize(directory) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LoadError::Io {
                path: directory.to_owned(),
                reason: error.to_string(),
            });
        }
    };
    if !canonical.is_dir() {
        return Err(invalid_path(
            directory,
            "installation path is not a directory",
        ));
    }
    if !ffi::is_local_path(&canonical) {
        return Err(invalid_path(
            directory,
            "installation directory resolves to a network or device path",
        ));
    }
    Ok(Some(canonical))
}
fn kernel_path(directory: &Path, kind: Kind) -> Result<Option<PathBuf>, LoadError> {
    let candidate = directory.join(abi::kernel_file_name(kind));
    match std::fs::symlink_metadata(&candidate) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LoadError::Io {
                path: candidate,
                reason: error.to_string(),
            });
        }
    }
    let canonical = std::fs::canonicalize(&candidate).map_err(|error| LoadError::Io {
        path: candidate.clone(),
        reason: error.to_string(),
    })?;
    if canonical.parent() != Some(directory)
        || !canonical.is_file()
        || !ffi::is_local_path(&canonical)
    {
        return Err(invalid_path(
            &candidate,
            "kernel must be a regular file inside the installation directory",
        ));
    }
    Ok(Some(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_requires_exact_version_kind_and_cryptographic_profile() {
        let valid = abi::Descriptor {
            abi_version: abi::ABI_VERSION,
            kind: Kind::Avx2 as u32,
            profile_id: abi::PROFILE_ID,
        };
        assert!(validate_descriptor(Kind::Avx2, valid, abi::SUCCESS).is_ok());
        assert!(validate_descriptor(Kind::Avx2, valid, abi::PANIC).is_err());
        for invalid in [
            abi::Descriptor {
                abi_version: 2,
                ..valid
            },
            abi::Descriptor {
                kind: Kind::Baseline as u32,
                ..valid
            },
            abi::Descriptor {
                profile_id: [0; 32],
                ..valid
            },
        ] {
            assert!(validate_descriptor(Kind::Avx2, invalid, abi::SUCCESS).is_err());
        }
    }

    #[test]
    fn unknown_backend_status_is_an_abi_error() {
        assert_eq!(
            CallError::from_status(100).unwrap_err().status(),
            Some(abi::INVALID_ABI)
        );
        for code in 1..=abi::PANIC {
            assert_eq!(
                CallError::from_status(code).unwrap_err().status(),
                Some(code)
            );
        }
    }
}
