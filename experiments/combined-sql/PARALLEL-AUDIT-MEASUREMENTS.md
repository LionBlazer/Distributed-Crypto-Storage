# Bounded parallel complete-custody audit comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`7984d87113d6232aa7c6927c36ba327adaf0e91c` and
`43eda8b9b3251db3ccdbf558d4a3d655a9f0f5a4`. The latter's parent `01162cf`
adds only the [owned Delta measurement record](OWNED-DELTA-MEASUREMENTS.md).
Both retain owned canonical Delta reconstruction, streamed persistence, bulk
codecs, Boolean fixed predicates, static UPDATE sources, custody profile 2,
RPC v2, application v4 and the unchanged arithmetic proof profile/kernel ABI.

## Change and preserved boundaries

The core owned-image factory now accepts an explicit `AuditWorkers::One` or
`Two` policy. Existing decoders remain serial. Both policies use the same parser,
hard Limits, manifest/head/length checks, complete serial revision preflight,
SHA-256 leaf domains, serial Merkle reducer and exact root comparison.
For images at least 4 MiB with at least two pages, Two may split the bounded leaf
vector into disjoint contiguous ranges. The caller hashes one range and one
scoped helper hashes the other, without packet copies or a retained executor.

One nonblocking permit per linked library image spans helper cleanup and join,
including concurrent Copy audits before the store mutex. Contention or spawn
failure hashes every leaf serially. The helper requests a 512-KiB stack; OS
rounding, guards and metadata are additional costs. Helper panic is joined and
propagated; caller unwind also joins before releasing the permit. No partially
checked capability escapes either panic. No validation cache is introduced.

Runtime resolves the existing bounded CPU policy once from available parallelism
and RAYON_NUM_THREADS, then clamps custody hashing to at most two workers. A
one-worker budget remains serial. This does not share the proof DLL's private
pool, bound all process workers or establish a RAM guarantee. At this fixture's
geometry the 3,187,648-byte data image remains below the parallel threshold;
the 34,416,624-byte index image is eligible. These are geometry, not isolated
hashing timings. Every physical audit still checks both complete images and tails.
Authorization, nonce/object binding, frame/quota limits, full target persistence,
flush/sync/rename, genuine FHE/STARK, final freshness and pending recovery remain.

## Full accepted operations

Three fresh alternating before/after pairs ran in
`.local/bounded-parallel-audit-measurements/20261016-121510-254/`.
All six independent TLS-peer scenarios passed and produced twelve complete
operation timers. The unchanged fixture has 1,000,000 rows and one final matching
row. UPDATE adds one to its amount; subsequent SELECT returns exactly `[[42, 2]]`
from the encrypted result. Startup, keys, initial table and Status remain outside
timing. Each timer wraps the complete `Session::execute`, as in the
[decoder record](BULK-DECODING-MEASUREMENTS.md).

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 423.247 / 571.440 / 599.607 | 528.700 / 543.908 / 569.482 |
| SELECT | 228.144 / 232.897 / 241.147 | 215.749 / 216.509 / 219.684 |

Differences between variant medians are -4.82% for UPDATE and -7.04% for SELECT,
not medians of paired percentages. UPDATE ranges overlap: paired differences
are -42.740, +120.661 and -30.125 ms. The valid 423.247-ms before sample is
retained; every after UPDATE exceeds 500 ms. Each SELECT after sample is below
every before sample in this window. Three pairs establish neither causation nor
tail latency or general improvement across workloads. Separate historical windows
do not establish cumulative gains. No sample was excluded or rerun.

Both owner and peer request eight Rayon threads; every peer log reports AVX-512.
The three presence-gated diagnostic variables were removed and asserted absent;
no log contains RPC/PID markers. No development build, other proof test or memory
monitor ran during the window. Unrelated host background load was uncontrolled.
No WAN, cold-cache, whole-process RAM or general 500-ms claim follows.

## Frozen artifacts and validation

Both use Rust 1.99.0/MSVC release, implicit Windows x64 host target, native CPU
flags and locked dependencies on AMD Ryzen 9 9950X3D2. N8192/Q218 arithmetic
profile v3, blowup 8, 192 FRI queries and degree-five extension remain unchanged.
Its existing 128-bit floor does not certify the complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-owned-delta-reconstruction/release/deps/proved_sql-18a2eaec0e34c184.exe` | `24B105B405DF5BDC52856CB624A57F162E3EE914BDAE87025474F036E6086851` |
| Before `.local/target-owned-delta-reconstruction/release/dcs-peer.exe` | `2165567D3E2EBD78A81BCDAA269B84DDB17A0683D496668FF898DA024F553386` |
| After `.local/target-bounded-parallel-audit/release/deps/proved_sql-e6e263165489b721.exe` | `BB3A608EDC194D315EE768D0DA91DE952C08038F9FA2D07D950A71CC24F07078` |
| After `.local/target-bounded-parallel-audit/release/dcs-peer.exe` | `BA6399877DE89150E9E0F988440C8AB7A767B24665E26A220D2393209B60A668` |

The [object-profile record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction)
has the unchanged kernel hashes and exact eight-thread/no-hook fixture command.
Preserve each owner's baked peer path and adjacent kernels. Raw evidence archives
eight exact executable/kernel copies, all logs/timers, source/path/hash metadata
and the executed driver. Generated outputs and ciphertext are not committed.

The ten-file change passed 297 native behavioral tests: compact-query 72,
compact-store 60, runtime 70, client 23, relational TLS 10, real-process transport
15, faults 4 and SQL 43. One aggregate measurement remained ignored. Six
compile-fail docs, strict five-package all-target Clippy, formatting and exact
requirements mirroring passed. Ten new tests cover serial/parallel equivalence,
odd/even/empty/partial and maximum-page geometry, exact allocation retention,
unrequested corrupt tails, revision/head/length/root error ordering, lower caps,
eight overlapping callers, spawn failure, both panic lifecycles and CPU policy.

Frozen source and artifact identities are in
`.local/bounded-parallel-audit-source-manifest.json`,
`.local/bounded-parallel-audit-validation/validation.json` and
`.local/bounded-parallel-audit-publication.json`. Validation used two Cargo/Rayon
and peer workers, separately from the eight-worker latency window. GUI source
and contracts did not change, so its suite was not repeated. Full PostgreSQL,
private locks, public source-completeness proofs, production finality and
whole-process resource bounds remain unestablished.
