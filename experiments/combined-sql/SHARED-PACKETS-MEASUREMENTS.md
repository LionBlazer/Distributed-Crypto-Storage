# Shared ciphertext snapshot ownership

Baseline `b596b23c43a230cbdbbcf16bd5c545e847da7e7d` already includes the
[authenticated candidate handoff](CANDIDATE-MEASUREMENTS.md). Two subsequent
candidates were measured: `7362520db32eb876988ccde168f07b1006ce5024` uses private
`Arc<Vec<u8>>` packets; final `f538a15ac5ff9226cbfc1f1a5d44ba3693a9c4e7` uses
`Arc<[u8]>`. The root integrates the latter. Neither comparison establishes an
UPDATE latency improvement or a whole-lifecycle peak-memory reduction.

## Ownership change

Snapshot clones share immutable encrypted packet allocations, while page slots
and Merkle levels remain independent. Editing either snapshot cannot alter the
other. Imports copy directly from checked packet slices into combined reference
count/payload allocations, without an intermediate Vec. Owner-created and
replacement Vecs still copy when converted into shared slices. Clones therefore
avoid copying every ciphertext payload; canonical encoding, Merkle metadata,
full physical audits and their hashes remain. This adds no plaintext/key cache,
mutable packet access or serialized Arc. Public lookups return owned buffers.

The initial Arc/Vec representation added a separate reference-count allocation
after each packet Vec allocation. The final decoder removes that allocation.
The complete-operation data below do not prove this was the cause of the initial
regression or that the correction makes UPDATE faster. See the
[owning API and memory accounting](../../crates/compact-store/README.md).

## Two separate complete-operation windows

Both windows used three fresh before/after pairs, alternating before then after.
Each scenario has one million public synthetic rows on one actual peer: 999,999
age-7 rows and one final age-42 row, initially amount 1. The UPDATE must affect
one row; the subsequent SELECT must return exactly `[42, 2]`. All twelve scenarios
passed the original exact-result, layout, genuine proof and version assertions.

Native Rust 1.99/MSVC, the same AMD host as the [combined record](README.md),
eight Rayon threads in owner and peer, AVX-512 kernels, unchanged profile-v3 and
application-v3, and all 81,920 residues were used. Other development build/proof
jobs had ended. RPC/PID hooks and memory monitoring were disabled for these
timers. Each timer wraps complete `Session::execute`, including actual I/O,
proof verification, completion and final freshness; UPDATE includes durable
publication/confirmation/collection. Startup, keys, table creation and fixture
assertions are outside. Host background activity was not controlled.

| First window: baseline vs Arc/Vec | Version | Minimum ms | Median ms | Maximum ms |
| --- | --- | ---: | ---: | ---: |
| `UPDATE records SET amount = amount + 1 WHERE age = 42` | Before | 952.263 | 966.697 | 1053.721 |
| Same UPDATE | After | 1017.795 | 1034.313 | 1046.868 |
| `SELECT * FROM records WHERE age = 42`, after UPDATE | Before | 338.070 | 340.636 | 343.259 |
| Same SELECT | After | 338.318 | 359.800 | 360.593 |

The first UPDATE median increased by 7.0%. This candidate was corrected before
root publication; its measurements are retained rather than replaced.

| Second window: baseline vs final Arc/slice | Version | Minimum ms | Median ms | Maximum ms |
| --- | --- | ---: | ---: | ---: |
| Same UPDATE | Before | 935.996 | 1058.920 | 1077.063 |
| Same UPDATE | After | 1028.790 | 1061.788 | 1127.201 |
| Same SELECT | Before | 339.223 | 340.976 | 343.260 |
| Same SELECT | After | 343.790 | 350.072 | 391.461 |

Final UPDATE medians differ by +0.27%, with overlapping ranges; one after sample
was faster than its adjacent before sample. No latency win is claimed. Compare
versions within a window, not the two windows as a matched correction estimate.
Three pairs do not establish tails or throughput. UPDATE still exceeds 500 ms.

## Separate lifecycle memory observation

One additional fresh scenario per baseline/final version was monitored separately
using Windows PSAPI and retained exact owner/peer handles announced by the fixture.
This covered process startup, encrypted creation, UPDATE, agreed restore, SELECT
and cleanup; no CIM discovery or other development heavy job ran. Both scenarios
passed, with zero missed lifetimes. OS peak working sets matched the independent
`PeakWorkingSet64` counters. Values are bytes:

| Process / counter | Baseline | Final |
| --- | ---: | ---: |
| Owner peak working set | 199532544 | 199376896 |
| Peer peak working set | 228343808 | 228147200 |
| Owner peak pagefile/commit | 219389952 | 219574272 |
| Peer peak pagefile/commit | 262746112 | 262512640 |

The process peaks are effectively unchanged in these two observations. Each run
had 13 samples, requesting 100-ms intervals; maximum observed gaps were 281 ms
before and 251 ms after. Owner/peer queries numbered 13/11 in each run. Maximum
sampled simultaneous working-set sums were 313860096 and 295682048 bytes. These
are sampled sums, not continuous combined peaks or sums of independent OS peaks.
Neither those sums nor one lifecycle per version proves a peak-memory saving or
the general 1–2-GiB process target under concurrency/larger catalogs.

## Separate RPC diagnostic

Before correcting Arc/Vec, one extra baseline/candidate scenario recorded bounded
actual-I/O metadata. Both passed with 42 untruncated events and 14 successful RPCs.
These instrumented times are separate from both distributions and the final
Arc/slice version; they are not CPU measurements or a causal allocation analysis.

| Complete RPC | Baseline ms | Arc/Vec ms |
| --- | ---: | ---: |
| Fetch | 181.691 | 189.242 |
| FHE proof | 139.866 | 136.319 |
| StoreDelta | 299.401 | 210.532 |
| Final FetchVersion | 167.118 | 188.623 |

Each full fetch response contained 37604546 application bytes; the padded Delta
request contained 1188143 bytes. The final ownership change does not change this
protocol footprint. Removing the private index tail from mutation transfers needs
a separately reviewed identity, authenticated patch and placement/freshness design;
an incomplete Bundle or skipped physical audit is not an implementation.

## Artifacts, reproduction and verification

Ignored raw records and exact artifact copies are preserved under:

- `.local/shared-packet-runs/20261016-070721-404/`: initial six logs/twelve timers.
- `.local/shared-slice-runs/20261016-072120-575/`: final six logs/twelve timers.
- `.local/shared-packet-rpc/20261016-071050-286/`: separate metadata/logs.
- `.local/shared-slice-memory/20261016-072513-020-before/` and
  `.local/shared-slice-memory/20261016-072516-165-after/`: lifecycle counters/logs.

| Version | Owner SHA256 | Peer SHA256 |
| --- | --- | --- |
| Baseline | `198CCA1C833E21F85A96F214C0702590C2CFB5F7E299151A2AB41BA1266224E0` | `887156E6C436B308CADC49F18DDCFB5722ADF82723E39E2856EDB5837C130D15` |
| Arc/Vec | `5C2BDB50F8756329321F226BB246C294A38F207CA13664D30AB6655A789C6C03` | `59DECBAB2892FDCE2EDED9B7C9B7B8C297DF7BF5DE7F409BD9516303653F43AE` |
| Final Arc/slice | `527B78B40D486603AF3669943E49B9AC2F8DC001ECF6450C3CCB6B6B5D8EAAC5` | `D9592771C0A3B2FE745D3833E7E751BEA1ADEC7FF55313FA59079F7C25AD2AB5` |

Both windows use AVX2 SHA256
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 SHA256
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
Build outside timing, then run
`million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`
with `--exact --nocapture --test-threads=1`, `RAYON_NUM_THREADS=8` and
`DCS_TEST_PEER_THREADS=8`. Clear the RPC/PID environment hooks for latency; enable
only `DCS_TEST_RPC_PROFILE` for diagnostics or `DCS_TEST_FIXED_PIDS` for a separate
retained-handle memory run. Copied owners retain their baked peer paths: baseline
uses `.local/target-verified-candidate-handoff/release/dcs-peer.exe`; both later
candidates use `.local/target-shared-ciphertext-packets/release/dcs-peer.exe`.
Install the matching archived peer/kernels there outside timing; a peer copy beside
the owner does not redirect lookup. Manifests record the exact absolute paths.

Final source passed 203 affected behavioral tests, one compile-fail contract,
strict native Clippy, formatting and requirements mirroring. Root independently
reran three snapshot API tests, the failure-after-data-staging rollback regression
and all 29 real-process SQL tests. Source review checked every packet admission,
clone/read/replacement path. IDs, codecs, resource limits, authorization, genuine
proofs and final freshness remain unchanged. Full PostgreSQL, publicly verifiable
private-source/completeness proofs and production finality remain open, as recorded in
the [SQL contract](../../docs/postgresql-contract.md).
