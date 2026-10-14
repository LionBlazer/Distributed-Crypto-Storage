# Fresh selected-gadget expansion scratch

Measured negative result: all26 direct-buffer/four-response/authentication controls
pass, but SelectedCombined/PairedCombined total server ratio0.99527456 fails the
predeclared <=0.95 gate. Full32 queries,11 runtime rejection controls and owner
replacement/UPDATE controls were NOT run. Twenty-five tests and strict authored
Clippy pass. See the [complete report](../../docs/experiment-private-pir-scratch.md)
for every88 server timing, exact native resources and scope. No useful latency
improvement or new whole-query measurement is established. Frozen baselines stay
byte-identical; only fresh scratch allocation changes, with no SDK/crypto edit.
scratch_schedule.rs keeps the same key/dimension branch, then allocates ONLY the
chosen zero-initialized raw/NTT pair. It does not reuse a buffer or assume any
uninitialized bytes. Original paired expansion allocated left8 AND right56 pairs
before selecting either. With N2048/CRT2, unused right scratch is2,752,512B per
left action and unused left scratch393,216B per right action; these are source
payload calculations, not measured peak-memory or latency improvements.
Round barriers, local indices, old-before-mutation copies, paired Rayon join and
four-trial scheduling remain fixed for the full-query comparison.

Frozen expansion_schedule.rs931FD2... and server_schedule.rsF9B343... remain exact
baselines with LICENSE-BLYSS. They derive pinned native SDK
fdb7206517c249603b0c91b65f1f29f95272107c, server.rs20–120/525–591/650–748,
Copyright2023Blyss Inc., MIT. No diagnostic CLIENT_TEST key enters derivatives.
main.rs owns complete PaddedV2 selection/PIR/auth/fresh Rows256 BFV, and
expansion_controls.rs owns public fixtures plus owner checks. resources.rs gates
current/native-peak resident/private process bytes at decimal2GB. Dependencies:
[compact-store](../../crates/compact-store/README.md),
[BFV core](../bfv-byte-limb-core/README.md), pinned Spiral, Rayon and serde/JSON.
This is a research binary, not a production reusable library or arithmetic proof.

## Predeclared validation and actual outcome

- Schedules: Official, PairedCombined (frozen931), SelectedExpansion (serial
  trials), SelectedCombined (parallel trials). Hold key/profile/round scheduling
  fixed; isolate selected scratch allocation in the full comparison.
- Two fresh ciphertexts for each position0/1/2/63/64/127/128/255/256/488/511 on
  the separate public512-page,64B/page authenticated fixture. Direct native,
  frozen-paired and selected selector/folding buffers must match exactly. All4
  serialized responses must match and pass owner Merkle/AEAD/full-record oracle.
- Four actual million-row index0/488+data0/488 controls repeat all checks.
  No slot511 is presented as a page of the million-row table.
- Run the entire32-operation full matrix only if ALL22 boundary requests are
  exact and total SelectedCombined server time <=95% of PairedCombined. Retain
  all samples and failures; no selected benchmark cases.
- Full matrix: range21/range256, Fixed256, Cached/Uncached, Visible/Private,
  frozen PairedCombined/new SelectedCombined, two samples, reversed order.
  Real header->postings->data dependencies remain sequential. Preserve complete
  count/varint selection, honest page-budget errors,11 before-BFV rejection
  controls, actual owner replacement and fresh authenticated read.

Setup, wire/key/state payloads, both real NTT caches, temporary boundary cache
and current/native process peaks remain separately counted. No speculative
address shortcut, plaintext answer, weaker crypto/noncollusion assumption,
persistent expanded FHE rows or proof claim is introduced. BFV still returns
UnverifiedAggregate. Independent security/noise and active-response composition
validation remain open; no new sub500ms claim precedes measurement.

## Reproduction

    ./experiments/private-pir-scratch/run.ps1 -PrepareOnly -Offline -PirSdkDirectory <pinned-sdk> -BfvCoreDirectory <reviewed-core>
    cargo test --release --locked --offline --manifest-path .local/private-pir-scratch/package/Cargo.toml --jobs 2 -- --test-threads=1
    cargo clippy --release --locked --offline --manifest-path .local/private-pir-scratch/package/Cargo.toml --all-targets --no-deps --jobs 2 -- -D warnings
    ./experiments/private-pir-scratch/run.ps1 -Offline -Rows 1000000 -Rounds 2 -Threads 8 -Cargo <cargo> -CargoHome <cache> -TargetDirectory <dedicated-target> -PirSdkDirectory <pinned-sdk> -BfvCoreDirectory <reviewed-core>

Use matching CARGO_HOME/CARGO_TARGET_DIR for direct Cargo commands. Unique package
and target/private-pir-scratch avoid shared-name stale artifacts. Generated local
copies/fixtures/measurements stay ignored. Heavy work requires the CPU lease.

Actual result:22 boundary plus4 real-page controls pass; gatefalse. The full
32-query and lifecycle/rejection portions remain unexecuted in this candidate.
