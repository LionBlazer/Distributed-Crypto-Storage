# Bounded typed SELECT observations

The real-daemon fixture in [dcs-peer](../../apps/dcs-peer/README.md) exercises the
[typed client](../../crates/storage-client/README.md) against 300 public rows and
four independently bound, genuine byte-projection proofs. This measurement
consumer adds no SQL evaluator, public API or production telemetry.

## Compared operation and configuration

`SELECT label, id, payload FROM typed_rows ORDER BY id DESC` returns all 300 rows,
including Unicode text and binary values, in exact descending order. The source
also contains an unrequested nullable column. Original full rows cross four
8,191-byte BFV blocks; a peer homomorphically applies each projection mask and
returns actual encrypted output plus a full-residue STARK. Complete private
selection, every proof/checked completion, final journal synchronization,
confirmed-head checks and row decoding are inside the full-operation timer.
Public expected values are used only by the test assertion after the result.
Import, key generation and daemon startup are outside the query timer.

The baseline exported exact source `0619807a01df1dfe2a6dfc427762d5a9bf010ff8`
into ignored `.local/typed-select-baseline-source/`. Only the identical new fixture,
its module declaration and existing-project `relational-types` dev dependency/lock
entry were added to that export. Its production code stayed unchanged. The after
owner uses the bounded worker/query-context implementation in this task branch.
Both are native MSVC release builds with Rust 1.99.0,
`RUSTFLAGS=-C target-cpu=native`, build jobs 2, owner/each peer Rayon threads 8.
The Windows x64 host reports `AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD`.
Other heavy jobs were paused for all six latency samples.

Both sides use the **same baseline-built app-v2 peer executable bytes**, copied
into the after test's baked peer path after validation; the after-build peer was
preserved separately. The copied peer must not be mislabeled as an after-source
rebuild. Both sides use the same unchanged profile-v3 AVX-512 kernel (AVX2 also
packaged), N8192/Q218, all 81,920 residues, FRI blowup 8, 192 queries, extension
degree 5 and the unchanged 128-bit security floor. The peer still admits one heavy
operation and a bounded DLL worker pool. The test's easy work target and one
confirmation are a public protocol fixture, not a production attack budget.
No preprocessing-cache or parallel journal-verifier experiment is used.

| Artifact | Actual SHA256 |
| --- | --- |
| Identical `support/typed_sql.rs` fixture source | `9E11B601974E51625B808DAA3607CC192BB78B8A7F22A878CF47D71E4129AC7F` |
| Baseline owner/test executable | `15504030FD7AB7ABA03872E7672171DC0F428DD66002F283C4AB4F4E174BE282` |
| After owner/test executable | `9FB29D4C2D37FAF59E859D7F77F27AFC3578FBB99515C1CBB71728E11A3924B0` |
| Baseline-built peer used on both sides | `FCA7AE1327447CA5B72E4A1C1058F54A759E285EEA3F75F0C7510B164E67FB90` |
| Unchanged AVX-512 kernel | `6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975` |
| Unchanged AVX2 kernel | `EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C` |

## Full accepted latency, 2026-10-16

`DCS_TEST_TYPED_PIDS` and `DCS_TEST_RPC_PROFILE` were both unset. No monitor ran in
any latency sample. Each fresh whole scenario returned exact typed rows and four
verified proofs; every assertion passed. Individual milliseconds, in run order:

| Implementation | Run 1 | Run 2 | Run 3 | Median |
| --- | ---: | ---: | ---: | ---: |
| Sequential baseline | 605.842 | 590.620 | 609.223 | 605.842 |
| Bounded two-worker typed blocks | 407.993 | 387.930 | 379.455 | 387.930 |

These six observations demonstrate a benefit for this fixed local four-block
projection only. They establish no larger-table, tail-latency, WAN or general
500-ms SQL guarantee. The changed execution policy remains subject to actual
holder availability and the peer's unchanged admission/resource bounds.
Logs and artifact manifests remain under ignored `.local/typed-select-runs/`:
`20261016-034946-621-before/` and `20261016-034950-128-after/`.

## Separate resource observation

One additional genuine after scenario passed with the opt-in test PID hook.
The monitor started the exact owner process, read only that fixture's directly
owned peer PIDs before import, and retained all three process handles. It used
Windows PSAPI working-set/peak counters and `Process.PeakWorkingSet64`; there was
no CIM discovery, no unrelated process inspection and no missed lifetime.
Six samples requested 100-ms intervals; the actual maximum gap was 313 ms.
Concurrent development load was uncontrolled. This run is excluded from latency.

| Process | PSAPI OS peak working set, bytes | PeakWorkingSet64, bytes |
| --- | ---: | ---: |
| Owner | 215465984 | 215166976 |
| First peer | 175636480 | 175636480 |
| Second peer | 175558656 | 175558656 |

The independent PSAPI peaks are approximately 205.484 / 167.500 / 167.426 MiB.
The maximum sampled simultaneous working-set sum was 333107200 bytes
(317.676 MiB). It is neither the sum of independent process peaks nor a continuous
whole-system peak measurement. Raw counters, actual gaps and stdout/stderr are in
`.local/typed-select-runs/20261016-035006-272-memory/`.

The locked scalar field is transparent `Goldilocks { value: u64 }`, eight bytes.
One 8192-by-100 public matrix is 6.25 MiB; its raw blowup-eight LDE is 50 MiB, so
two checks mean 100 MiB of raw LDE storage before clones, FFT/Merkle/canonical
frames and SDK overhead. At most two prepared/proof workspaces coexist. Completed
zeroizing bytes total at most the existing 8-MiB original-source limit (at most
1,025 chunks). Neither these size calculations nor the small process observation
establish a production RAM bound or adversarial-concurrency guarantee.

## Reproduction and acceptance checks

Build before timing with a separate ignored target and the native configuration
above. For baseline comparison, export the pinned base, add only the identical
owning fixture/dev dependency, and build in a separate target. Preserve both test
executables and the baseline peer; verify the source/artifact hashes and copy only
the same app-v2 peer and profile-v3 kernels into both baked peer paths. A rebuild
is not assumed to be byte-identical.

```powershell
$env:RAYON_NUM_THREADS = '8'
$env:DCS_TEST_PEER_THREADS = '8'
Remove-Item Env:DCS_TEST_TYPED_PIDS -ErrorAction SilentlyContinue
Remove-Item Env:DCS_TEST_RPC_PROFILE -ErrorAction SilentlyContinue
$fixture = '.local/target-typed-select-workers/release/deps/proved_sql-43b267abd6ab93e6.exe'
& $fixture typed_sql::typed_300_row_select_accepts_complete_ordered_proved_bytes --exact --nocapture --test-threads=1
```

Run three fresh scenarios for each side in a quiet window, retaining failures as
well as successful `accepted_typed_sql_ms` labels. Run memory separately with
`DCS_TEST_TYPED_PIDS=1`, retain only those owned process handles, and report actual
sampling gaps and missed lifetimes. The parallel-progress test uses a bounded
callback gate and must not be a latency sample.

Owning validation uses `cargo test --release --locked -p storage-client`,
`cargo test --release --locked -p dcs-peer --test proved_sql`,
`cargo test --release --locked -p dcs-peer --test proved_faults` and the
`compact-query` `byte_select::tests` filter with `bfv-experiment`. Tests cover exact
cross-chunk order/types, real two-holder progress, one stopped-endpoint attempt
per query, actual final freshness I/O, later-block cancellation without fallback,
all-worker completion, genuine altered proof/output/other-chunk rejection, the
existing write/overflow/pending/authorization boundaries, formatting and strict
all-target Clippy. Required tests set no latency thresholds.
