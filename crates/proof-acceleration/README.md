# proof-acceleration

Startup selection of trusted native proof kernels for the existing BFV arithmetic
proof protocol. This crate does not change FHE parameters, the arithmetic relation,
the proof frame, security settings, authorization or freshness checks.

The default `loader` feature depends directly on `libloading = 0.8.9`. The
`--no-default-features` build is `no_std` and exports `Kind`, `Timings`,
`worker_budget`, `MAX_PROOF_WORKERS` and the shared `abi` POD definitions/constants;
kernel wrappers depend on that mode. `worker_budget(available, requested)` is a
pure deployment policy: it clamps available/requested CPU workers to 1..8 and
retains no environment, process, pool or SQL state. Invalid or zero requests use
the bounded default; callers own environment reads and actual pool creation.
No storage, SQL, playground or application crate is a dependency.

## Host contract

```rust,no_run
use proof_acceleration::Kernel;
let directory = std::env::current_exe()?.parent().unwrap().join("proof-kernels");
let selected = Kernel::select(&directory)?;
if let Some(kernel) = selected {
    // canonical_input must be the real, fixed-profile arithmetic request.
    # let canonical_input: &[u8] = &[];
    let generated = kernel.prove(canonical_input)?;
    kernel.verify(canonical_input, generated.output(), generated.proof())?;
    let (output, proof, timings) = generated.into_parts();
    # let _ = (output, proof, timings);
} else {
    // The caller uses its linked portable implementation with the same profile.
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Call `Kernel::select` once at startup and retain its result. It checks actual CPU
and operating-system AVX register support, then tries AVX-512 (AVX2, F, DQ, BW,
VL), AVX2, and the linked baseline. `prove` and `verify` do no feature detection.
`Kernel::load(directory, Kind)` permits explicitly loading a supported kind for
interoperability tests, including a separately packaged baseline kernel.

Only exact sibling names from `abi::kernel_file_name` are considered, such as
`dcs-proof-avx512.dll` and `dcs-proof-avx2.dll` on Windows. Directories must be
absolute. Windows UNC/device paths and mapped network drives are rejected;
canonicalized kernels must remain regular files in their installation directory.
On Unix, the installation's mounted filesystem is trusted. Windows loading uses
`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`; there is
no application PATH, working-directory or environment-variable plugin search.

Missing supported kernels permit a lower implementation. A present supported
kernel with an invalid image, missing symbol, wrong ABI, kind or cryptographic
profile is an error. An operation failure is returned without trying a different
implementation. Every successfully opened library is pinned until process exit,
even if symbol or descriptor checks subsequently reject it or a `Kernel` handle
is dropped. The proof engine's persistent Rayon workers can outlive a handle; an
explicit native worker shutdown/join ABI would be required for safe unloading.
Select once rather than repeatedly loading libraries. Native libraries remain
trusted application code, with the same installation/upgrade permissions as the
launcher: descriptor checks establish
compatibility and do not authenticate or sandbox native code.

## ABI boundary

`abi` defines version 1 symbols, status numbers, fixed profile SHA-256 and C-layout
`Span`, `Buffer`, `Timings`, `Descriptor`, `ProveCall` and `VerifyCall`. Inputs are
public canonical BFV ciphertext arithmetic requests; no secret key or plaintext
crosses this interface. Host-owned initialized buffers bound requests to 1,310,760
bytes, outputs to exactly 655,400 bytes and proof frames to 2 MiB. Only raw pointers,
lengths, capacities and integers cross the interface. The wrapper may change
`Buffer::written` and timings, never replace a host pointer or capacity. Error
status, buffer shape and returned lengths are checked before accepting a result.

All native loading and foreign calls are isolated in `src/ffi.rs`. The remaining
crate denies unsafe code. The kernel wrapper must contain panics inside the C
boundary and implement the exact same serialized proof format across CPU builds.

Tests cover ABI/profile identity, deployment path rules, real feature checks,
missing/corrupt libraries, descriptor rejection and buffer invariants. These
tests do not use a fabricated backend that claims to prove or verify successfully.
Cross-kernel cryptographic tests belong to the real proof-kernel consumer.
