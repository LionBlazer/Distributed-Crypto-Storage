# Owned canonical Delta reconstruction comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`544449b109982cacc0eafa3cd7c63a3c51e1f5df` and
`7984d87113d6232aa7c6927c36ba327adaf0e91c`. The latter's parent `958e238`
adds only the [streamed persistence report](STREAMED-PERSISTENCE-MEASUREMENTS.md).
Both retain streamed persistence, complete owned image audits, bulk codecs,
Boolean fixed predicates, static UPDATE sources, custody profile 2, RPC v2,
application v4 and the unchanged arithmetic proof profile/kernel ABI.

## Change and preserved boundaries

`OwnedVerifiedSnapshotBytes::apply_verified_replacements` consumes the unique
audited canonical allocation. It shares transition/page validation and Merkle
path reduction with snapshot reconstruction. It checks all replacement heads,
addresses, revisions, lengths and exact byte ranges before touching its private
tree. The complete resulting root must equal the target before replacement
packets and the manifest are copied into their original ranges. An error drops
the consumed in-memory capability; it cannot modify the external durable base.

ReconstructedDelta retains two such capabilities. Candidate rechecks both exact
target heads and supplied nonce/object binding, then moves their buffers into
the existing RawBundle. Codec/frame preflight and streamed flush/sync/rename
remain. No Snapshot materialization or full-image encode occurs in this path.
At this geometry that avoids 12,213 packet allocations/copies containing
37,604,048 bytes and two full-image encode buffers totaling 37,604,272 bytes.
These are avoided allocations/copies, not an additive peak-RAM measurement.

Every required physical read still audits both complete images, including tails.
Every target write remains complete. Replacement membership, complete roots,
authorization, 257-page wire bound/padding, exact nonce/ID, replay after base GC,
quota, genuine FHE/STARK, final freshness and pending recovery remain unchanged.
The change adds no unchecked constructor, mutable checked-byte API, custody cache
or wire/disk representation. Failed reconstruction must reread/audit its base on retry.

## Full accepted operations

Three fresh alternating before/after pairs ran in
`.local/owned-delta-reconstruction-measurements/20261016-113144-367/`.
All six independent TLS-peer scenarios passed and produced twelve complete
operation timers. The unchanged fixture has 1,000,000 rows and one final matching
row. UPDATE adds one to its amount; subsequent SELECT yields exactly `[[42, 2]]`
from the encrypted result. Startup, keys, initial table and Status remain outside
timing. Each timer wraps the complete `Session::execute`, as in the
[decoder record](BULK-DECODING-MEASUREMENTS.md).

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 587.027 / 607.089 / 633.269 | 579.122 / 594.641 / 609.134 |
| SELECT | 234.440 / 235.526 / 249.590 | 227.097 / 227.688 / 233.973 |

Differences between variant medians are -2.05% for UPDATE and -3.33% for SELECT,
not medians of paired percentages. UPDATE ranges overlap, and two of three paired
UPDATEs regress (+7.614 and +2.045 ms). Every UPDATE exceeds 500 ms. Each SELECT
after sample is below every before sample in this window. Three pairs establish
neither causation nor tail latency or general improvement across workloads;
separate historical windows do not establish cumulative gains. No sample was
excluded or rerun.

Both owner and peer use eight Rayon threads; every peer log reports AVX-512.
All three presence-gated diagnostic variables were removed and asserted absent;
no log contains RPC/PID markers. No development build, other proof test or memory
monitor ran during the window. Unrelated host background load was uncontrolled.
No WAN, cold-cache, whole-process RAM or general 500-ms claim follows.

## Frozen artifacts and validation

Both use Rust 1.99.0/MSVC release, implicit Windows x64 host target, native CPU
flags and locked dependencies on AMD Ryzen 9 9950X3D2. The N8192/Q218 arithmetic
profile v3, blowup 8, 192 FRI queries and degree-five extension remain unchanged.
Its existing 128-bit floor does not certify the complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-streamed-custody-persistence/release/deps/proved_sql-18a2eaec0e34c184.exe` | `344699E9DF35F2A1280D6980EE6EFB8F2AEDCB0ECAD764633DC052FE33100366` |
| Before `.local/target-streamed-custody-persistence/release/dcs-peer.exe` | `0E0E5E12CA6921DEFC00CF2E359F9267D9268750FD2E9782844697E8CC5F14DB` |
| After `.local/target-owned-delta-reconstruction/release/deps/proved_sql-18a2eaec0e34c184.exe` | `24B105B405DF5BDC52856CB624A57F162E3EE914BDAE87025474F036E6086851` |
| After `.local/target-owned-delta-reconstruction/release/dcs-peer.exe` | `2165567D3E2EBD78A81BCDAA269B84DDB17A0683D496668FF898DA024F553386` |

The [object-profile record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction)
has the unchanged kernel hashes and exact eight-thread/no-hook fixture command.
Preserve each owner's baked peer and adjacent kernels. Raw evidence archives
eight exact executable/kernel copies, all logs/timers, source/path/hash metadata
and executed driver; their identities were independently audited. Generated
outputs and ciphertext are not committed.

The seven-file refactor passed 287 native behavioral tests: compact-query 72,
compact-store 51, runtime 69, client 23, relational TLS 10, real-process transport
15, faults 4 and SQL 43. One aggregate measurement remained ignored. Six
compile-fail docs, strict five-package all-target Clippy, formatting and exact
requirements mirroring passed. Five new core API tests exercise exact targets,
allocation identity, odd/even/empty/partial geometry, unchanged ranges, error
ordering, lower limits and existing reordered/extra-member semantics. Two new
runtime tests cover both original allocations at 1/2/64/256/257 pages and a later
index failure leaving only the exact durable base. Existing byte/ObjectInfo,
corrupt-tail, replay/GC/quota and lost-ACK/pending cases remain covered.

The frozen source and artifact identities are in
`.local/owned-delta-reconstruction-validation.json` and
`.local/owned-delta-reconstruction-publication.json`; the native log is
`.local/owned-delta-reconstruction-native.log`. GUI source/contracts did not
change, so its suite was not repeated. Full PostgreSQL/private locks, public
source-completeness proofs, production finality and whole-process resource bounds
remain unestablished.
