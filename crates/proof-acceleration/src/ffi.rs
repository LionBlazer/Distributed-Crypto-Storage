//! The only unsafe implementation boundary. Libraries are trusted installed code;
//! descriptor checks enforce compatibility, not a native-code security sandbox.
use crate::loader::{CallError, LoadError, validate_proof_length};
use crate::{Timings, abi};
use libloading::Library;
use std::mem::ManuallyDrop;
use std::path::Path;

pub(crate) struct Loaded {
    // Never unload: an initializer or the proof engine may start persistent
    // Rayon workers whose code remains in the DLL after the public Kernel drops.
    // No function pointer or borrowed symbol is exposed outside this owner.
    _library: ManuallyDrop<Library>,
    prove: abi::ProveFn,
    verify: abi::VerifyFn,
}
impl Loaded {
    pub(crate) fn open(path: &Path) -> Result<(Self, abi::Descriptor, u32), LoadError> {
        let failure = |error: libloading::Error| LoadError::Library {
            path: path.to_owned(),
            reason: error.to_string(),
        };
        // SAFETY: the safe loader has constrained this absolute local path to an
        // exact sibling name in the caller's trusted application installation.
        // Installed kernel initializers/finalizers obey the application contract.
        #[cfg(windows)]
        let library: Library = unsafe {
            libloading::os::windows::Library::load_with_flags(
                path,
                libloading::os::windows::LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
                    | libloading::os::windows::LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
            .map_err(failure)?
            .into()
        };
        // SAFETY: same deployment contract as the Windows branch; the target
        // filename itself is absolute and never found via PATH or working dir.
        #[cfg(not(windows))]
        let library = unsafe { Library::new(path).map_err(failure)? };
        // Pin immediately after successful OS loading, before any fallible symbol
        // or descriptor check. Even a rejected library may have initialized native
        // threads; without an explicit shutdown/join ABI it cannot safely unload.
        let library = ManuallyDrop::new(library);
        // SAFETY: these names and exact C POD signatures are the versioned ABI
        // required of trusted installed kernels. The library stays mapped until
        // process exit, including when symbol lookup or descriptor checking fails.
        let (info, prove, verify) = unsafe {
            (
                *library
                    .get::<abi::InfoFn>(abi::INFO_SYMBOL)
                    .map_err(failure)?,
                *library
                    .get::<abi::ProveFn>(abi::PROVE_SYMBOL)
                    .map_err(failure)?,
                *library
                    .get::<abi::VerifyFn>(abi::VERIFY_SYMBOL)
                    .map_err(failure)?,
            )
        };
        let mut descriptor = abi::Descriptor::default();
        // SAFETY: descriptor is initialized, aligned host memory of the exact
        // shared repr(C) type and remains live for this synchronous call.
        let status = unsafe { info(&mut descriptor) };
        Ok((
            Self {
                _library: library,
                prove,
                verify,
            },
            descriptor,
            status,
        ))
    }

    pub(crate) fn prove(
        &self,
        input: &[u8],
        output: &mut [u8],
        proof: &mut [u8],
    ) -> Result<(usize, usize, Timings), CallError> {
        let mut call = abi::ProveCall {
            input: abi::Span::from_slice(input),
            output: abi::Buffer::from_slice(output),
            proof: abi::Buffer::from_slice(proof),
            timings: Timings::default(),
        };
        let expected = call;
        // SAFETY: each POD span/buffer describes a live nonoverlapping host slice
        // valid for the whole synchronous call. Kernel owns no host allocations
        // and may only write within capacities and update written/timings fields.
        let status = unsafe { (self.prove)(&mut call) };
        validate_prove_buffers(&expected, &call)?;
        CallError::from_status(status)?;
        validate_proved_lengths(&call)?;
        Ok((call.output.written, call.proof.written, call.timings))
    }

    pub(crate) fn verify(
        &self,
        input: &[u8],
        output: &[u8],
        proof: &[u8],
    ) -> Result<Timings, CallError> {
        let mut call = abi::VerifyCall {
            input: abi::Span::from_slice(input),
            output: abi::Span::from_slice(output),
            proof: abi::Span::from_slice(proof),
            timings: Timings::default(),
        };
        let expected = call;
        // SAFETY: spans refer to immutable live host slices for this synchronous
        // call; the versioned kernel may only write the call's timings field.
        let status = unsafe { (self.verify)(&mut call) };
        validate_verify_spans(&expected, &call)?;
        CallError::from_status(status)?;
        Ok(call.timings)
    }
}

fn abi_error(reason: &'static str) -> CallError {
    CallError::new(abi::INVALID_ABI, reason)
}
fn validate_proved_lengths(call: &abi::ProveCall) -> Result<(), CallError> {
    if call.output.written != abi::OUTPUT_BYTES {
        return Err(abi_error("backend returned a truncated canonical output"));
    }
    validate_proof_length(call.proof.written)
}
fn same_span(left: abi::Span, right: abi::Span) -> bool {
    left.ptr == right.ptr && left.len == right.len
}
fn same_buffer(left: abi::Buffer, right: abi::Buffer) -> bool {
    left.ptr == right.ptr && left.capacity == right.capacity && right.written <= right.capacity
}
fn validate_prove_buffers(
    expected: &abi::ProveCall,
    actual: &abi::ProveCall,
) -> Result<(), CallError> {
    if !same_span(expected.input, actual.input)
        || !same_buffer(expected.output, actual.output)
        || !same_buffer(expected.proof, actual.proof)
    {
        return Err(abi_error(
            "backend changed a host buffer or exceeded its capacity",
        ));
    }
    Ok(())
}
fn validate_verify_spans(
    expected: &abi::VerifyCall,
    actual: &abi::VerifyCall,
) -> Result<(), CallError> {
    if !same_span(expected.input, actual.input)
        || !same_span(expected.output, actual.output)
        || !same_span(expected.proof, actual.proof)
    {
        return Err(abi_error("backend changed an immutable host span"));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn is_local_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return false;
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
        _ => return false,
    };
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDriveTypeW(root_path: *const u16) -> u32;
    }
    // SAFETY: root is a valid, null-terminated UTF-16 drive-root string for the
    // duration of this read-only Windows API call. This also rejects mapped SMB.
    let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
    matches!(kind, 2 | 3 | 5 | 6)
}
#[cfg(not(windows))]
pub(crate) fn is_local_path(path: &Path) -> bool {
    // Unix mounted filesystems belong to the trusted installation boundary; no
    // URLs, loader search names or arbitrary network plugin paths are accepted.
    path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proving_rejects_foreign_pointer_capacity_and_written_count_changes() {
        let input = [1; 4];
        let mut output = [0; 4];
        let mut proof = [0; 8];
        let expected = abi::ProveCall {
            input: abi::Span::from_slice(&input),
            output: abi::Buffer::from_slice(&mut output),
            proof: abi::Buffer::from_slice(&mut proof),
            timings: Timings::default(),
        };
        let mut changed = expected;
        changed.output.ptr = std::ptr::null_mut();
        assert!(validate_prove_buffers(&expected, &changed).is_err());
        changed = expected;
        changed.output.capacity += 1;
        assert!(validate_prove_buffers(&expected, &changed).is_err());
        changed = expected;
        changed.proof.written = changed.proof.capacity + 1;
        assert!(validate_prove_buffers(&expected, &changed).is_err());
        changed = expected;
        changed.input.len += 1;
        assert!(validate_prove_buffers(&expected, &changed).is_err());
        changed = expected;
        changed.output.written = output.len();
        changed.proof.written = proof.len();
        assert!(validate_prove_buffers(&expected, &changed).is_ok());
    }

    #[test]
    fn verification_allows_only_timing_changes() {
        let bytes = [1; 8];
        let expected = abi::VerifyCall {
            input: abi::Span::from_slice(&bytes),
            output: abi::Span::from_slice(&bytes),
            proof: abi::Span::from_slice(&bytes),
            timings: Timings::default(),
        };
        let mut changed = expected;
        changed.timings.total_ns = 123;
        assert!(validate_verify_spans(&expected, &changed).is_ok());
        changed.proof.len -= 1;
        assert!(validate_verify_spans(&expected, &changed).is_err());
    }

    #[test]
    fn success_requires_full_output_and_a_bounded_nonempty_proof() {
        // These PODs test length validation only; no foreign function is invoked.
        let mut call = abi::ProveCall {
            input: abi::Span {
                ptr: std::ptr::null(),
                len: abi::MAX_INPUT_BYTES,
            },
            output: abi::Buffer {
                ptr: std::ptr::null_mut(),
                capacity: abi::OUTPUT_BYTES,
                written: abi::OUTPUT_BYTES,
            },
            proof: abi::Buffer {
                ptr: std::ptr::null_mut(),
                capacity: abi::MAX_PROOF_BYTES,
                written: 8,
            },
            timings: Timings::default(),
        };
        assert!(validate_proved_lengths(&call).is_ok());
        call.output.written -= 1;
        assert_eq!(
            validate_proved_lengths(&call).unwrap_err().status(),
            Some(abi::INVALID_ABI)
        );
        call.output.written += 1;
        call.proof.written = 0;
        assert_eq!(
            validate_proved_lengths(&call).unwrap_err().status(),
            Some(abi::PROOF_LENGTH)
        );
        call.proof.written = abi::MAX_PROOF_BYTES + 1;
        assert_eq!(
            validate_proved_lengths(&call).unwrap_err().status(),
            Some(abi::PROOF_LENGTH)
        );
    }
}
