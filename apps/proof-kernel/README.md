# Trusted proof kernel

Builds the genuine fixed-profile BFV arithmetic proof engine as a native `cdylib`
for one instruction set. The launcher builds the baseline host and separate AVX2
and AVX-512 kernels; the host selects a compatible installed kernel once at startup.
SIMD changes packing only. Canonical FHE inputs/results, STARK parameters, decoder
bounds and serialized proof formats are identical across variants.

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-query-proof](../../crates/bfv-query-proof/README.md) | Genuine arithmetic generation and verification; runtime dispatch disabled in production kernel builds |
| [proof-acceleration](../../crates/proof-acceleration/README.md) | Fixed-profile C ABI, ISA/profile identifiers and bounded CPU worker policy; loader disabled in production kernel builds |

The three exports are `dcs_proof_backend_info_v1`,
`dcs_proof_backend_prove_v1`, and `dcs_proof_backend_verify_v1`. The host owns every
input, output and proof buffer. Pointers, sizes, capacities, address overflow and
descriptor/data overlap are checked before use; the caller must still supply valid
native memory. Returned proof/checked markers never cross the ABI as Rust objects.
The kernel maps genuine proof errors to stable status codes, catches Rust unwinds,
and reports zero written bytes on failure. It does not change caller buffer pointers
or capacities. Native code loaded into the same process is trusted, not sandboxed.

Each loaded kernel creates one private Rayon pool before its descriptor reports
success. Its worker count defaults to `min(available_parallelism, 8)`, with at least
one worker. A lower positive `RAYON_NUM_THREADS` reduces that count; zero, malformed,
overflowing or non-Unicode values use the bounded default, and a higher request
cannot exceed available CPUs or eight workers. All prove/verify work runs inside
this pool, including direct ABI calls made without querying the descriptor first.
Initialization and failure are retained once, and the host's independently owned
global Rayon pool is unaffected. Failure to start the private workers returns the
preprocessing status. The loader pins the DLL until process exit, keeping persistent
worker code mapped. This limits this kernel's Rayon workers, not total process RAM
or the combined host/network thread count.

Build an individual kernel explicitly, so unrelated host dependencies cannot enable
the proof crate's runtime-dispatch feature through workspace feature unification:

```powershell
cargo build --release --locked -p dcs-proof-kernel
cargo test --release --locked -p dcs-proof-kernel --lib
```

The launcher's exact per-ISA flags and deployment filenames belong to the launcher
and ABI loader. Unit tests cover descriptor identity, malformed buffers, stable
rejection codes and private-pool reuse. Shared worker-budget cases belong to
proof-acceleration's tests. The explicit cross-variant
integration test builds genuine addition and product proofs and verifies them across
installed supported variants. After `dcs-launch --build-only`, run the following
from the repository root with a portable test host build, without native/AVX-only
`RUSTFLAGS`; ISA-specific kernel flags remain owned by the launcher:

```powershell
$env:DCS_TEST_KERNEL_DIR = Join-Path $PWD '.local/target-playground/x86_64-pc-windows-msvc/release/proof-kernels'
cargo test --release --locked -p dcs-proof-kernel --test runtime_interoperability --test runtime_startup -- --ignored --nocapture --test-threads=1
```

This module has no credentials, database contents, SQL authorization, consensus or
secret-key role.
