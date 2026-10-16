//! Trusted fixed-profile proof engine compiled separately for each supported ISA.
//! All ABI memory is caller-owned. No Rust allocation or panic crosses this edge.
#![deny(unsafe_op_in_unsafe_fn)]

use bfv_query_proof::{Error, ProverTimings, VerifierTimings};
use proof_acceleration::{Timings, abi, worker_budget};
use std::mem::{align_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::OnceLock;
use std::time::Duration;

fn worker_pool() -> Result<&'static rayon::ThreadPool, u32> {
    static POOL: OnceLock<Result<rayon::ThreadPool, u32>> = OnceLock::new();
    POOL.get_or_init(|| {
        let available = std::thread::available_parallelism().map_or(1, usize::from);
        let requested = std::env::var("RAYON_NUM_THREADS").ok();
        let workers = worker_budget(available, requested.as_deref());
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .thread_name(|index| format!("dcs-proof-{index}"))
            .build()
            .map_err(|_| abi::PREPROCESSING)
    })
    .as_ref()
    .map_err(|status| *status)
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn prover_timings(timings: ProverTimings) -> Timings {
    Timings {
        operation_ns: nanos(timings.encrypted_operation),
        preprocessing_ns: nanos(timings.public_preprocessing),
        proof_ns: nanos(timings.proving_and_encoding),
        total_ns: nanos(timings.total),
    }
}

fn verifier_timings(timings: VerifierTimings) -> Timings {
    Timings {
        operation_ns: 0,
        preprocessing_ns: nanos(timings.public_preprocessing),
        proof_ns: nanos(timings.proof_verification),
        total_ns: nanos(timings.total),
    }
}

fn status(error: Error) -> u32 {
    match error {
        Error::StatementShape => abi::STATEMENT_SHAPE,
        Error::RequestBinding => abi::REQUEST_BINDING,
        Error::NonCanonicalResidue => abi::NON_CANONICAL_RESIDUE,
        Error::ProofLength => abi::PROOF_LENGTH,
        Error::ProofEncoding => abi::PROOF_ENCODING,
        Error::ProofResourceLimit => abi::PROOF_RESOURCE_LIMIT,
        Error::TrailingProofBytes => abi::TRAILING_PROOF_BYTES,
        Error::SecurityProfile => abi::SECURITY_PROFILE,
        Error::Preprocessing => abi::PREPROCESSING,
        Error::Proving => abi::PROVING,
        Error::Verification => abi::VERIFICATION,
        Error::BackendUnavailable => abi::INVALID_ABI,
    }
}

fn valid_struct<T>(value: *const T) -> bool {
    !value.is_null()
        && (value as usize).is_multiple_of(align_of::<T>())
        && (value as usize).checked_add(size_of::<T>()).is_some()
}

fn region(pointer: *const u8, length: usize) -> Option<(usize, usize)> {
    if pointer.is_null() || length > isize::MAX as usize {
        return None;
    }
    let start = pointer as usize;
    Some((start, start.checked_add(length)?))
}

fn separated(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 == a.1 || b.0 == b.1 || a.1 <= b.0 || b.1 <= a.0
}

fn disjoint(regions: &[(usize, usize)]) -> bool {
    regions
        .iter()
        .enumerate()
        .all(|(i, a)| regions[..i].iter().all(|b| separated(*a, *b)))
}

/// Reports the ABI, cryptographic profile and ISA compiled into this library.
///
/// # Safety
/// `descriptor` must be null or point to writable, aligned Descriptor storage for
/// the duration of this call. This is a trusted native-library ABI, not a sandbox.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dcs_proof_backend_info_v1(descriptor: *mut abi::Descriptor) -> u32 {
    if !valid_struct(descriptor) {
        return abi::INVALID_ABI;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // A DLL owns a separate Rayon registry from its host. Prepare its bounded
        // private pool before reporting readiness, without changing either global
        // registry. The loader keeps this library mapped for the process lifetime.
        if let Err(status) = worker_pool() {
            return status;
        }
        // SAFETY: the caller supplies valid writable storage; its null/alignment
        // and address-range conditions were checked before accessing it.
        unsafe {
            ptr::write(
                descriptor,
                abi::Descriptor {
                    abi_version: abi::ABI_VERSION,
                    kind: bfv_query_proof::compiled_kind() as u32,
                    profile_id: abi::PROFILE_ID,
                },
            );
        }
        abi::SUCCESS
    }))
    .unwrap_or(abi::PANIC)
}

/// Computes and proves the exact fixed-profile canonical encrypted statement.
/// Output/proof buffers retain their caller-owned pointer and capacity. A failed
/// call reports zero written bytes, including caught Rust unwinds.
///
/// # Safety
/// `call` must be null or valid aligned writable ProveCall storage. All nonnull
/// spans/buffers must refer to initialized readable/writable memory of the stated
/// sizes for this call and must not be concurrently accessed. The descriptor and
/// data regions must be disjoint. Arbitrary invalid addresses cannot be validated
/// by a C ABI; the host and installed kernel are one trusted process boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dcs_proof_backend_prove_v1(call: *mut abi::ProveCall) -> u32 {
    if !valid_struct(call) {
        return abi::INVALID_ABI;
    }
    // SAFETY: caller-owned descriptor validity is the ABI's explicit precondition.
    let mut request = unsafe { ptr::read(call) };
    request.output.written = 0;
    request.proof.written = 0;
    request.timings = Timings::default();
    // SAFETY: checked descriptor address and caller-owned writable storage.
    unsafe { ptr::write(call, request) };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(input_region) = region(request.input.ptr, request.input.len) else {
            return abi::INVALID_ABI;
        };
        let Some(output_region) = region(request.output.ptr, request.output.capacity) else {
            return abi::INVALID_ABI;
        };
        let Some(proof_region) = region(request.proof.ptr, request.proof.capacity) else {
            return abi::INVALID_ABI;
        };
        let call_region = (call as usize, call as usize + size_of::<abi::ProveCall>());
        if !disjoint(&[input_region, output_region, proof_region, call_region])
            || request.input.len > abi::MAX_INPUT_BYTES
            || request.output.capacity > abi::MAX_OUTPUT_BYTES
            || request.proof.capacity > abi::MAX_PROOF_BYTES
        {
            return abi::INVALID_ABI;
        }
        if request.output.capacity < abi::OUTPUT_BYTES
            || request.proof.capacity < abi::MAX_PROOF_BYTES
        {
            return abi::BUFFER_TOO_SMALL;
        }
        // SAFETY: bounded readable span provided by the caller; no references to
        // output buffers exist while the genuine proof engine runs.
        let input = unsafe { std::slice::from_raw_parts(request.input.ptr, request.input.len) };
        let pool = match worker_pool() {
            Ok(pool) => pool,
            Err(status) => return status,
        };
        let generated = match pool.install(|| bfv_query_proof::prove(input)) {
            Ok(generated) => generated,
            Err(error) => return status(error),
        };
        if generated.output().len() > request.output.capacity
            || generated.proof().len() > request.proof.capacity
        {
            return abi::BUFFER_TOO_SMALL;
        }
        // SAFETY: writable disjoint caller-owned buffers were bounded above;
        // generated vectors belong to this kernel and remain alive for the copy.
        unsafe {
            ptr::copy_nonoverlapping(
                generated.output().as_ptr(),
                request.output.ptr,
                generated.output().len(),
            );
            ptr::copy_nonoverlapping(
                generated.proof().as_ptr(),
                request.proof.ptr,
                generated.proof().len(),
            );
        }
        request.output.written = generated.output().len();
        request.proof.written = generated.proof().len();
        request.timings = prover_timings(generated.timings());
        abi::SUCCESS
    }))
    .unwrap_or(abi::PANIC);
    if result != abi::SUCCESS {
        request.output.written = 0;
        request.proof.written = 0;
        request.timings = Timings::default();
    }
    // SAFETY: descriptor remains caller-owned writable storage until return.
    unsafe { ptr::write(call, request) };
    result
}

/// Verifies a genuine proof against the caller's independently trusted complete
/// input and claimed encrypted output. It never re-executes the FHE operation.
///
/// # Safety
/// `call` must be null or valid aligned writable VerifyCall storage. All nonnull
/// spans must be valid initialized readable memory for the stated bounded sizes,
/// remain alive until return and not overlap the writable call descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dcs_proof_backend_verify_v1(call: *mut abi::VerifyCall) -> u32 {
    if !valid_struct(call) {
        return abi::INVALID_ABI;
    }
    // SAFETY: valid caller-owned descriptor required by the documented ABI.
    let mut request = unsafe { ptr::read(call) };
    request.timings = Timings::default();
    // SAFETY: descriptor is writable and aligned as documented/checked.
    unsafe { ptr::write(call, request) };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let call_region = (call as usize, call as usize + size_of::<abi::VerifyCall>());
        for span in [request.input, request.output, request.proof] {
            let Some(span_region) = region(span.ptr, span.len) else {
                return abi::INVALID_ABI;
            };
            if !separated(span_region, call_region) {
                return abi::INVALID_ABI;
            }
        }
        if request.input.len > abi::MAX_INPUT_BYTES || request.output.len > abi::MAX_OUTPUT_BYTES {
            return abi::STATEMENT_SHAPE;
        }
        if request.proof.len > abi::MAX_PROOF_BYTES {
            return abi::PROOF_LENGTH;
        }
        // SAFETY: each read-only span was bounded and cannot overlap the writable
        // descriptor. The caller guarantees actual address readability/lifetime.
        let (input, output, proof) = unsafe {
            (
                std::slice::from_raw_parts(request.input.ptr, request.input.len),
                std::slice::from_raw_parts(request.output.ptr, request.output.len),
                std::slice::from_raw_parts(request.proof.ptr, request.proof.len),
            )
        };
        let pool = match worker_pool() {
            Ok(pool) => pool,
            Err(status) => return status,
        };
        match pool.install(|| bfv_query_proof::verify(input, output, proof)) {
            Ok(checked) => {
                request.timings = verifier_timings(checked.timings());
                abi::SUCCESS
            }
            Err(error) => status(error),
        }
    }))
    .unwrap_or(abi::PANIC);
    if result != abi::SUCCESS {
        request.timings = Timings::default();
    }
    // SAFETY: caller-owned descriptor remains valid until this function returns.
    unsafe { ptr::write(call, request) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_reuses_one_private_bounded_pool() {
        let first = worker_pool().unwrap();
        let second = worker_pool().unwrap();
        assert!(ptr::eq(first, second));
        assert!((1..=proof_acceleration::MAX_PROOF_WORKERS).contains(&first.current_num_threads()));
        assert_eq!(
            first.install(rayon::current_num_threads),
            first.current_num_threads()
        );
    }

    #[test]
    fn descriptor_matches_the_shared_abi_and_linked_instruction_set() {
        let mut descriptor = abi::Descriptor::default();
        // SAFETY: test supplies a valid aligned writable descriptor.
        assert_eq!(
            unsafe { dcs_proof_backend_info_v1(&mut descriptor) },
            abi::SUCCESS
        );
        assert_eq!(descriptor.abi_version, abi::ABI_VERSION);
        assert_eq!(descriptor.profile_id, abi::PROFILE_ID);
        assert_eq!(descriptor.kind, bfv_query_proof::compiled_kind() as u32);
        // SAFETY: null is explicitly rejected without dereferencing it.
        assert_eq!(
            unsafe { dcs_proof_backend_info_v1(ptr::null_mut()) },
            abi::INVALID_ABI
        );
    }

    #[test]
    fn insufficient_buffers_and_invalid_pointers_return_no_written_bytes() {
        let input = [0_u8; 8];
        let mut output = [0_u8; 1];
        let mut proof = [0_u8; 1];
        let mut call = abi::ProveCall {
            input: abi::Span::from_slice(&input),
            output: abi::Buffer::from_slice(&mut output),
            proof: abi::Buffer::from_slice(&mut proof),
            timings: Timings::default(),
        };
        call.output.written = 999;
        call.proof.written = 999;
        // SAFETY: all descriptor/data regions are valid disjoint owned arrays.
        assert_eq!(
            unsafe { dcs_proof_backend_prove_v1(&mut call) },
            abi::BUFFER_TOO_SMALL
        );
        assert_eq!((call.output.written, call.proof.written), (0, 0));
        call.input.ptr = ptr::null();
        // SAFETY: null is explicitly rejected before creating a reference.
        assert_eq!(
            unsafe { dcs_proof_backend_prove_v1(&mut call) },
            abi::INVALID_ABI
        );
        assert_eq!((call.output.written, call.proof.written), (0, 0));
    }

    #[test]
    fn malformed_statements_preserve_the_genuine_engine_status() {
        let bytes = [0_u8; 8];
        let mut call = abi::VerifyCall {
            input: abi::Span::from_slice(&bytes),
            output: abi::Span::from_slice(&bytes),
            proof: abi::Span::from_slice(&bytes),
            timings: Timings {
                total_ns: 999,
                ..Timings::default()
            },
        };
        // SAFETY: shared read-only arrays do not overlap the writable descriptor.
        assert_eq!(
            unsafe { dcs_proof_backend_verify_v1(&mut call) },
            abi::STATEMENT_SHAPE
        );
        assert_eq!(call.timings, Timings::default());
    }
}
