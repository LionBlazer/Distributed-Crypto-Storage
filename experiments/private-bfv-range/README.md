# Complete age-range retrieval and fresh BFV

Measured opt-in research package: 96 exact full queries over one real million-row
compact table, plus one fresh query after owner replacement. EQ/GE at 256 rows
and cached private range reads were below 500 ms in this bounded run; all eight
uncached private range reads exceeded 500 ms (567.5194–590.7199 ms). See the
[complete report](../../docs/experiment-private-bfv-range.md) for every sample,
resource/key accounting, rejected page crossings and trust limitations.

This package owns composition and measurement, keeping the published EQ16 and
BFV packages unchanged. It has no production backend entry point.

| Direct project dependency | Role |
| --- | --- |
| [compact-store](../../crates/compact-store/README.md) | Authenticated encrypted pages and exact trusted heads |
| [BFV byte-limb core](../bfv-byte-limb-core/README.md) | Owner fresh encoding/encryption, public-only evaluation, unverified decryption |
| Pinned Spiral SDK fdb7206517c249603b0c91b65f1f29f95272107c | Actual native single-server PIR |

`src/main.rs` owns the explicit fixture, complete index selection, visible/private
transport, BFV role composition, whole-query timers, after-timer comparisons and
replacement/failure controls. `padded_index_codec.rs` and its contract tests retain
the published PaddedV2 adapter. `resources.rs` gates current and native-peak resident
and private-commit process bytes at 2,000,000,000 B. `run.ps1` is the opt-in entry;
it packages reviewed sources locally, records hashes, builds the unique standalone
`private-bfv-range-composition` binary and retains ignored JSONL measurements.

The public fixture has background ages 0..199 and rare complete cases: closed
250..252 (21), EQ255 and GE255 (256 all-max amounts), EQ240 (64), closed240..241
(256), and absent EQ253. Complete candidate count must be <=256; one posting page
and one data page must suffice. Actual EQ230 posting-page and EQ243 data-page
crossings fail precisely, without truncation. Fixture oracle maps are prepared
during setup; only comparisons run after each whole timer. Query code never
receives those maps.

Both AddressOnly/Fixed256 and Cached/Uncached compare Visible/Private with the
same genuine Rows256 BFV circuit. Fixed256 uses authenticated dummy reads for
empty inputs and encrypted zero low/high/count weights for inactive rows.
The owner is online, decrypts selected fields, and freshly encrypts BFV inputs;
the peer gets public setup and ciphertext wire only. Range endpoints are encrypted
in peer requests. Predicate kind, geometry, heads/versions, timing, write events
and public mode choices remain visible. Length equality does not establish full
active-network privacy. Results explicitly have proof unavailable.

BFV retains N8192/t114689/Q218 and CBD(20), variance10 for secret/error, native
NTT, unfused GE, level0 input/output and validated additive closed range. The run
uses the direct-profile initialization published in f46d0bb; no arithmetic or
cryptographic parameters change. Independent >=128-bit security/noise validation
and malicious-peer arithmetic verification remain open.

## Reproduction

Use the existing Rust 1.99/MSVC toolchain, project-local Cargo cache and a dedicated
target. Supply the reviewed current core (f46d0bb in the measured run) and pinned
SDK directory explicitly when running from an older research checkout:

    ./experiments/private-bfv-range/run.ps1 -PrepareOnly -Offline -PirSdkDirectory <pinned-sdk-directory> -BfvCoreDirectory <reviewed-core-directory>
    cargo test --release --locked --offline --manifest-path .local/private-bfv-range/package/Cargo.toml --jobs 2 -- --test-threads=1
    cargo clippy --release --locked --offline --manifest-path .local/private-bfv-range/package/Cargo.toml --all-targets --no-deps --jobs 2 -- -D warnings
    ./experiments/private-bfv-range/run.ps1 -Offline -Rows 1000000 -Rounds 2 -Threads 8 -Cargo <cargo-executable> -CargoHome <local-cargo-cache> -TargetDirectory <dedicated-target> -PirSdkDirectory <pinned-sdk-directory> -BfvCoreDirectory <reviewed-core-directory>

Set CARGO_HOME and CARGO_TARGET_DIR for the two Cargo commands to the same values
passed to the runner. No global install is required. Nineteen focused tests and
strict authored Clippy passed; the unmodified SDK emits four upstream warnings.
Two rounds mean two samples per each of 48 cells, not 96 tables or a tail bound.
Setup/cache fill, nonce generation and after-timer fixture comparisons are separate;
network, disk I/O and arithmetic proof verification are not measured.
