use crate::{BackendKind, CheckedOperation, Error, GeneratedOperation};
use std::path::Path;

/// Instruction-set packing compiled into the linked engine. This is a compile-time
/// diagnostic; selecting a trusted dynamic kernel additionally checks CPU/OS support.
pub const fn compiled_kind() -> BackendKind {
    if cfg!(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx512f"
    )) {
        BackendKind::Avx512
    } else if cfg!(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    )) {
        BackendKind::Avx2
    } else {
        BackendKind::Baseline
    }
}

/// Initializes one process-wide backend from the caller's trusted installation
/// directory. Call before serving jobs. CPU detection and dynamic loading happen
/// only here. The first selection (including failure) is retained; later calls do
/// not change it. Without explicit initialization, ordinary library callers use
/// the linked engine. Missing optional kernels select that engine; an invalid
/// present selected kernel fails closed. This library invents no filesystem path.
pub fn initialize_backend(directory: &Path) -> Result<BackendKind, Error> {
    #[cfg(feature = "runtime-dispatch")]
    {
        runtime::initialize(directory)
    }
    #[cfg(not(feature = "runtime-dispatch"))]
    {
        let _ = directory;
        Ok(compiled_kind())
    }
}

/// Selected process-wide backend, or the linked engine before initialization.
/// If initialization failed, this diagnostic reports the linked packing while
/// prove/verify continue rejecting with BackendUnavailable.
pub fn backend_kind() -> BackendKind {
    #[cfg(feature = "runtime-dispatch")]
    {
        runtime::kind()
    }
    #[cfg(not(feature = "runtime-dispatch"))]
    {
        compiled_kind()
    }
}

pub(super) fn prove(input: &[u8]) -> Result<GeneratedOperation, Error> {
    #[cfg(feature = "runtime-dispatch")]
    {
        runtime::backend()?.prove(input)
    }
    #[cfg(not(feature = "runtime-dispatch"))]
    {
        crate::prove_engine(input)
    }
}

pub(super) fn verify(input: &[u8], output: &[u8], proof: &[u8]) -> Result<CheckedOperation, Error> {
    #[cfg(feature = "runtime-dispatch")]
    {
        runtime::backend()?.verify(input, output, proof)
    }
    #[cfg(not(feature = "runtime-dispatch"))]
    {
        crate::verify_engine(input, output, proof)
    }
}

#[cfg(feature = "runtime-dispatch")]
mod runtime {
    use super::*;
    use crate::{Operation, ProverTimings, VerifierTimings};
    use proof_acceleration::{CallError, Kernel, abi};
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    pub(super) trait Backend: Send + Sync {
        fn kind(&self) -> BackendKind;
        fn prove(&self, input: &[u8]) -> Result<GeneratedOperation, Error>;
        fn verify(
            &self,
            input: &[u8],
            output: &[u8],
            proof: &[u8],
        ) -> Result<CheckedOperation, Error>;
    }

    struct Linked;
    impl Backend for Linked {
        fn kind(&self) -> BackendKind {
            compiled_kind()
        }
        fn prove(&self, input: &[u8]) -> Result<GeneratedOperation, Error> {
            crate::prove_engine(input)
        }
        fn verify(
            &self,
            input: &[u8],
            output: &[u8],
            proof: &[u8],
        ) -> Result<CheckedOperation, Error> {
            crate::verify_engine(input, output, proof)
        }
    }

    impl Backend for Kernel {
        fn kind(&self) -> BackendKind {
            self.kind()
        }
        fn prove(&self, input: &[u8]) -> Result<GeneratedOperation, Error> {
            let total = Instant::now();
            let operation = Operation::from_input(input)?;
            let generated = Kernel::prove(self, input).map_err(call_error)?;
            let (output, proof, timings) = generated.into_parts();
            // Kernel success is reachable only after its genuine engine has
            // generated the proof. Keep construction private to this boundary.
            Ok(GeneratedOperation {
                operation,
                output,
                proof,
                timings: ProverTimings {
                    encrypted_operation: Duration::from_nanos(timings.operation_ns),
                    public_preprocessing: Duration::from_nanos(timings.preprocessing_ns),
                    proving_and_encoding: Duration::from_nanos(timings.proof_ns),
                    total: total.elapsed(),
                },
            })
        }
        fn verify(
            &self,
            input: &[u8],
            output: &[u8],
            proof: &[u8],
        ) -> Result<CheckedOperation, Error> {
            let total = Instant::now();
            let operation = Operation::from_input(input)?;
            let timings = Kernel::verify(self, input, output, proof).map_err(call_error)?;
            // No public unchecked constructor is exposed. A checked marker exists
            // only after the selected trusted engine verified this exact evidence.
            let input_digest = Sha256::digest(input).into();
            let output_digest = Sha256::digest(output).into();
            Ok(CheckedOperation {
                operation,
                input_digest,
                output_digest,
                timings: VerifierTimings {
                    public_preprocessing: Duration::from_nanos(timings.preprocessing_ns),
                    proof_verification: Duration::from_nanos(timings.proof_ns),
                    total: total.elapsed(),
                },
            })
        }
    }

    fn call_error(error: CallError) -> Error {
        match error.status() {
            Some(abi::STATEMENT_SHAPE) => Error::StatementShape,
            Some(abi::REQUEST_BINDING) => Error::RequestBinding,
            Some(abi::NON_CANONICAL_RESIDUE) => Error::NonCanonicalResidue,
            Some(abi::PROOF_LENGTH) => Error::ProofLength,
            Some(abi::PROOF_ENCODING) => Error::ProofEncoding,
            Some(abi::PROOF_RESOURCE_LIMIT) => Error::ProofResourceLimit,
            Some(abi::TRAILING_PROOF_BYTES) => Error::TrailingProofBytes,
            Some(abi::SECURITY_PROFILE) => Error::SecurityProfile,
            Some(abi::PREPROCESSING) => Error::Preprocessing,
            Some(abi::PROVING) => Error::Proving,
            Some(abi::VERIFICATION) => Error::Verification,
            _ => Error::BackendUnavailable,
        }
    }

    static LINKED: Linked = Linked;
    static BACKEND: OnceLock<Result<Box<dyn Backend>, Error>> = OnceLock::new();

    pub(super) fn initialize(directory: &Path) -> Result<BackendKind, Error> {
        let backend = BACKEND.get_or_init(|| match Kernel::select(directory) {
            Ok(Some(kernel)) => Ok(Box::new(kernel)),
            Ok(None) => Ok(Box::new(Linked)),
            Err(_) => Err(Error::BackendUnavailable),
        });
        match backend {
            Ok(backend) => Ok(backend.kind()),
            Err(error) => Err(*error),
        }
    }

    pub(super) fn backend() -> Result<&'static dyn Backend, Error> {
        match BACKEND.get() {
            Some(Ok(backend)) => Ok(backend.as_ref()),
            Some(Err(error)) => Err(*error),
            None => Ok(&LINKED),
        }
    }

    pub(super) fn kind() -> BackendKind {
        backend()
            .map(Backend::kind)
            .unwrap_or_else(|_| compiled_kind())
    }
}
