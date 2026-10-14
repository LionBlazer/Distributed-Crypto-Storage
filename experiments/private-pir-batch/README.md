# Native Spiral trial scheduling and independent-request batch control

Measured: four same-ciphertext responses are byte-identical,32 full ranges and11
rejection controls pass, plus one exact fresh read after owner replacement.
Private uncached ranges improve574–590 to508–531ms, still all above500ms. See the
[complete report](../../docs/experiment-private-pir-batch.md) for every sample and
actual408/422MB peaks. This new opt-in package preserves the earlier frozen range package. Its candidate changes only
execution scheduling of four independent native PIR database trials. Every ring
operation, query generation/serialization, answer encoding and owner recovery
uses the unmodified pinned SDK and the unchanged 512x8192B parameters.

`src/server_schedule.rs` is a scheduling derivative of the SDK's process_query
with ordered Rayon collection of four trials; it records expansion/trial/pack
stages. The original process_query is the live baseline. SDK origin is
fdb7206517c249603b0c91b65f1f29f95272107c, lib/spiral-rs/src/server.rs650–748,
Copyright2023 Blyss Inc.; its MIT license is retained in LICENSE-BLYSS.
`src/main.rs` owns explicit public fixtures, actual index/PIR/auth/fresh-BFV
composition and independent-request controls. resources.rs retains the strict
current/native-peak resident/private-commit decimal2GB gate. The PaddedV2 codec
and tests are unchanged. run.ps1 packages reviewed sources locally and records
hashes, using the unique private-pir-batch-composition binary and dedicated
target/private-pir-batch.

Dependencies: [compact-store](../../crates/compact-store/README.md) authenticates
encrypted storage, [BFV core](../bfv-byte-limb-core/README.md) provides fresh
Rows256 encrypted aggregation, and pinned native Spiral performs single-server
PIR. Rayon schedules tasks; serde/JSON records measurements. This is a binary
research harness, with no production API/backend promotion.

Completed bounded validation:

1. Four fresh request ciphertexts (actual index0/index488/data0/data488) did
   produce byte-identical server answers under both schedules and pass actual
   owner recovery, Merkle verification, AEAD decryption and complete record oracle.
2. Independent batches2/4 compare sequential/parallel requests under both trial
   schedules, two samples each (16 batch operations). Whole-batch and amortized
   time are distinct; amortized time is never claimed as individual latency.
   These already known public-fixture addresses are not a SQL dependency shortcut.
3. Thirty-two actual whole queries: range21 and range256, Fixed256, cached/uncached,
   visible/private, original/parallel-trial, two samples with reversed schedule
   order. The real header->posting->data dependency remains sequential.
4. Existing actual owner replacement and eleven before-BFV rejection controls
   remain. Unit tests cover actual selected-page/count budgets and profile gates.

Header counts/offsets must be authenticated before posting addresses are known;
posting records must be decoded before data addresses are known. This candidate
cannot merge those dependent requests into one RPC. It adds no speculative
reads, plaintext selector, precomputed answer, changed record format, expanded
query reuse or owner-prepared header answer. Setup, serialized keys, both real
NTT overlays, wire and actual combined native peak are recorded separately.
The online owner reads fields and freshly encrypts BFV; no owner secret enters
the public-only PIR/BFV evaluator. Output arithmetic remains unverified and the
independent BFV/security composition gates remain open.

## Reproduction

    ./experiments/private-pir-batch/run.ps1 -PrepareOnly -Offline -PirSdkDirectory <pinned-sdk> -BfvCoreDirectory <reviewed-main-core>
    cargo test --release --locked --offline --manifest-path .local/private-pir-batch/package/Cargo.toml --jobs 2 -- --test-threads=1
    cargo clippy --release --locked --offline --manifest-path .local/private-pir-batch/package/Cargo.toml --all-targets --no-deps --jobs 2 -- -D warnings
    ./experiments/private-pir-batch/run.ps1 -Offline -Rows 1000000 -Rounds 2 -Threads 8 -Cargo <cargo> -CargoHome <local-cache> -TargetDirectory <dedicated-target> -PirSdkDirectory <pinned-sdk> -BfvCoreDirectory <reviewed-main-core>

Use matching CARGO_HOME/CARGO_TARGET_DIR for direct Cargo commands. No global
installation, changed cryptographic parameter, network service or UI is needed.

Twenty-one focused tests and strict authored Clippy pass; four upstream SDK warnings
remain. The frozen measured module may be copied with origin/license for research;
there is no separate production library API in this binary package.
