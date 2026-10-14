# Native Spiral within-round expansion scheduling

Measured: Combined private complete ranges take379–393ms Cached and456–465ms
Uncached (two samples per case), while TrialsOnly Uncached takes506–525ms.
All32 full queries are exact; all26 direct-expansion/four-response/authentication
controls and11 before-BFV rejections pass. See the
[complete report](../../docs/experiment-private-pir-expansion.md) for every sample,
actual388/393MB process peaks and security/proof limitations. This opt-in package
preserves the frozen trial-parallel package. It investigates the remaining native
PIR expansion bottleneck without changing SDK files or cryptographic parameters.

`expansion_schedule.rs` derives the pinned coefficient_expansion/expand_query
control flow with the same native ring operations. Expansion rounds remain
sequential. For each local index i, scalar_multiply copies OLD source into its
new sibling before either mutation; then Rayon join schedules two independent
actions, preserving original LOCAL i, exact key choice and stop conditions. A
round finishes before the next. server_schedule.rs is the exact frozen trial
baseline (F9B343...); LICENSE-BLYSS retains the SDK MIT copyright/permission.

`expansion_controls.rs` owns public fixture controls and owner authentication;
it does not pass an owner key to the server module. main.rs owns real complete
PaddedV2 index selection, actual visible/private retrieval and fresh Rows256 BFV.
resources.rs enforces decimal2GB current/native-peak resident/private limits.
The pinned SDK is fdb7206517c249603b0c91b65f1f29f95272107c, source server.rs20–120,
525–591 and650–748. Direct dependencies are
[compact-store](../../crates/compact-store/README.md),
[BFV core](../bfv-byte-limb-core/README.md), native Spiral, Rayon and serde/JSON.
This is an experimental binary, not a production API or arithmetic verifier.

Completed bounded validation:

- Four schedules: Official, TrialsOnly, ExpansionOnly, Combined. Two fresh
  ciphertexts for each PIR position0/1/2/63/64/127/128/255/256/488/511. Direct
  expanded selector/folding matrices AND final serialized responses must match
  exactly; every recovered record passes actual Merkle/AEAD/full-record oracle.
- Boundary positions use a separate public512-page,64B/page authenticated fixture
  with the same512x8192B native PIR parameters. Slot511 is not mislabeled as a
  page from the million-row table. Its transient cache is separately counted.
- Four additional controls use the real million-row index0/488 and data0/488,
  checking the same expanded buffers/final responses/authentication under all4.
- Predeclared gate: average Combined server time across ALL22 boundary controls
  must be <=95% of TrialsOnly, with all exactness checks passing, before running
  the full32-query matrix. No slow boundary sample is dropped.
- Full matrix (if gated): range21/range256,Fixed256,cached/uncached,visible/private,
  TrialsOnly/Combined,two actual samples. Header->posting->data stays sequential;
  complete counts/varints and one-page budgets are unchanged. Preserve all
  outliers,11 before-BFV rejections and actual owner replacement/freshness read.

No parameter/noise reduction, speculative unknown-address batching, plaintext
aggregate, persistent FHE rows or precomputed answer is introduced. BFV still
returns unverified arithmetic and independent security/composition gates remain
open. No sub500ms or production privacy/security claim precedes measurements.

## Reproduction

    ./experiments/private-pir-expansion/run.ps1 -PrepareOnly -Offline -PirSdkDirectory <pinned-sdk> -BfvCoreDirectory <reviewed-core>
    cargo test --release --locked --offline --manifest-path .local/private-pir-expansion/package/Cargo.toml --jobs 2 -- --test-threads=1
    cargo clippy --release --locked --offline --manifest-path .local/private-pir-expansion/package/Cargo.toml --all-targets --no-deps --jobs 2 -- -D warnings
    ./experiments/private-pir-expansion/run.ps1 -Offline -Rows 1000000 -Rounds 2 -Threads 8 -Cargo <cargo> -CargoHome <cache> -TargetDirectory <dedicated-target> -PirSdkDirectory <pinned-sdk> -BfvCoreDirectory <reviewed-core>

Use matching CARGO_HOME/CARGO_TARGET_DIR for direct Cargo commands. The unique
package/target private-pir-expansion avoids prior same-name shared artifacts.
Generated source copies, fixtures and JSONL stay in ignored .local storage.

Twenty-three focused tests and strict authored Clippy pass; four existing SDK
warnings remain. No source-level backend/security promotion follows from this
bounded local latency measurement.
