# DCS launcher

This build-and-run CLI packages the native playground, independent peer daemon and
proof acceleration libraries. It uses the Rust standard library and
[proof-acceleration](../../crates/proof-acceleration/README.md) with default features
disabled solely for the shared ISA identifiers and library filenames. It does not
load a kernel, execute SQL or select a proof backend.

From the repository root:

```sh
cargo run --release --locked -p dcs-launch -- playground
```

The launcher builds everything before starting the GUI. To build and print
`playground=`, `peer=` and `proof_kernels=` absolute paths without opening a window:

```sh
cargo run --release --locked -p dcs-launch -- playground --build-only
```

The compiler's `rustc -vV` host triple is used explicitly; inherited cross-target
settings cannot redirect these builds. All outputs reside under the checkout:

| Build | Target directory | ISA flags |
| --- | --- | --- |
| `dcs-peer` and `fhe-playground` | `.local/target-playground` | `target-cpu=x86-64` on x86-64; portable compiler defaults elsewhere |
| `dcs-proof-kernel` AVX2 | `.local/target-proof-avx2` | `target-cpu=x86-64`, `target-feature=+avx2` |
| `dcs-proof-kernel` AVX-512 | `.local/target-proof-avx512` | `target-cpu=x86-64`, `target-feature=+avx2,+avx512f,+avx512dq,+avx512bw,+avx512vl` |

Each target directory contains `<host-triple>/release`. On x86-64 both kernel
variants are built even when this CPU cannot execute them. Their known cdylib
artifacts are copied into the applications' adjacent `proof-kernels/` directory
using the shared ABI filenames. The full PostgreSQL keyword-data permission
notice is installed as `POSTGRESQL-LICENSE.txt` beside both applications. Non-x86-64 hosts build only the portable
applications; the SDK's compiled platform backend remains available. No build uses
`target-cpu=native`.

Child Cargo invocations replace `RUSTFLAGS`, remove inherited encoded/target
rustflags, and pass an explicit target directory. The explicit environment flags
override Cargo configuration ISA flags. Zed keeps the launcher's own artifacts in
`.local/target-launcher`, apart from child builds. The launcher copies complete
temporary files into place; it does not terminate a running GUI or peer. A failed
build, missing artifact or failed replacement stops launch with an error.

The launcher starts the GUI with `--exit-on-stdin-close` and keeps its private stdin
pipe open while waiting. Ctrl+C, a crash or forced launcher termination closes the
OS handle; the GUI exits and its corresponding lifetime pipes stop the local peer
processes. Cleanup does not depend on destructors or on checking reusable PIDs.
The launcher never searches for or terminates unrelated running processes.

The [GUI](../../playground/README.md) and
[peer](../../apps/dcs-peer/README.md) each initialize their proof backend once,
before processing requests. Runtime CPU/OS feature detection and ABI validation
belong to proof-acceleration, not this packaging tool. The same cryptographic
parameters and verification rules apply to every ISA variant; these builds do not
establish a latency guarantee.

Argument, host-target containment, command-environment and package-plan tests run
without building libraries or starting a GUI:

```sh
cargo test --release --locked -p dcs-launch
```
