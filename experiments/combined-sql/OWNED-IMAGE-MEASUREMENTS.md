# Owned full-image custody comparison

On 2026-10-16, complete accepted million-row UPDATE and SELECT ran on
`dbf034204fc45d549b5517884c6bc029187425c5` and
`6e38660393f9bfb16482043643f26898eba3f045`. The latter's parent is the
documentation-only child `a1aa313`. Both include bounded bulk decoding, bulk
serialization, Boolean fixed predicates, static UPDATE sources, custody profile
2, RPC v2 and application v4. The [decoder record](BULK-DECODING-MEASUREMENTS.md)
describes the unchanged fixture and full accepted-operation boundaries.

The change adds sealed `OwnedVerifiedSnapshotBytes`, consuming the original
canonical Vec through the existing complete parser. It retains the checked head
and Merkle levels. Consuming `into_bytes` returns the original allocation;
`into_snapshot` materializes packets only when needed, moving the checked tree
without rehashing. No Clone, Deserialize or mutable-byte API is provided.

Peer `CheckedObject` retains the original raw envelope version, nonce and head
buffers with two such images. Raw Fetch, Copy, startup, full admission and proof
source checks can release exact buffers without discarded packet copies.
PageBatch looks up both checked images directly; ReadImage materializes data
only; Delta still materializes both images for actual reconstruction. This is
distinct from the earlier [owner-side borrowed validation](BORROWED-VALIDATION-MEASUREMENTS.md).

All packet revisions, complete roots, limits and original check ordering remain.
Every physical read still audits both whole images, including unrequested bytes.
Owner authorization, quota, retry, nonce/ID binding, genuine FHE/STARK, final
freshness and pending recovery remain. No wire, disk, proof parameter, kernel ABI,
protocol profile, unchecked object or cross-RPC custody cache changes.

## Full accepted operations

Three fresh alternating before/after pairs ran in
`.local/owned-verified-images-measurements/20261016-104059-328/`. All six actual
TLS-peer scenarios and twelve accepted-operation/result/head checks passed.
The unchanged fixture has 1,000,000 rows and one matching final row. UPDATE adds
1 to its amount; the subsequent SELECT returns exactly `[[42, 2]]` from the real
encrypted result. Startup, keys, table creation and initial Status inspection
remain outside the timers. Each timer wraps the entire `Session::execute`.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 682.243 / 684.386 / 690.673 | 559.364 / 633.851 / 646.315 |
| SELECT | 281.802 / 285.468 / 289.521 | 245.895 / 256.916 / 276.167 |

Differences between variant medians are **-7.38%** for UPDATE and **-10.00%**
for SELECT, not medians of paired percentages. Each after sample is below every
before sample for its operation in this window. Three pairs establish neither
causation nor tail latency or general performance across PostgreSQL workloads.
Every UPDATE still exceeds 500 ms. Do not infer cumulative improvement from
separate windows with different baselines. No WAN, cold-cache or RAM claim follows.

No development build, other proof test or memory monitor ran in the window.
The driver removed and asserted absence of all three presence-gated diagnostic
variables; no clean log contains RPC/PID markers. Owner and peer each use eight
Rayon threads; every peer log reports AVX-512. Unrelated host background load was
not controlled. No timing sample was excluded or rerun.

## Artifacts and reproduction

Both use Rust 1.99.0/MSVC release, implicit Windows x64 host target, native CPU
flags and locked dependencies on AMD Ryzen 9 9950X3D2. The N8192/Q218 arithmetic
proof profile v3, 192 FRI queries, blowup 8 and extension degree 5 remain unchanged.
Its existing 128-bit floor does not certify the complete storage protocol.

| Variant | Exact owner under repository root | Baked peer directory |
| --- | --- | --- |
| Before | `.local/target-bounded-bulk-custody-decoding/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-bounded-bulk-custody-decoding/release/` |
| After | `.local/target-owned-verified-images/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-owned-verified-images/release/` |

| Artifact | SHA256 |
| --- | --- |
| Before owner | `315140190972B7E6E5FD00E52E01B473FF2B0B65BECA8A4A7B71DA1D89C6BF5B` |
| Before peer | `63F18EE1288AACC740AD11D7F446F8811F03D3AEE81A1F5C5DEA93C6FECB06A7` |
| After owner | `1EB9F9612A534D649B4CC0FAEBD131F3BD0BFB2036F307F9DA481726734810CF` |
| After peer | `45396CA310967166C336E52F15B1A32F487B1BAA6756770891747753B8B66D58` |

The unchanged kernel hashes and eight-thread/no-hook fixture command are in the
[object-profile record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
The ignored window retains all logs, timers, source/hash/path metadata, eight
exact executable/kernel copies and the executed `driver.ps1`. Original and
archived hashes, the unchanged fixture source and timer boundaries were
independently checked. Preserve the matching peer and kernels at the owner's
baked path; copying an owner alone does not pin the peer. Generated outputs and
ciphertext are not committed.

## Validation and remaining limits

The refactor passed 274 native behavioral tests: compact-query 72, compact-store
46, runtime 61, client 23, relational TLS 10, real-process transport 15, faults 4
and SQL 43; one aggregate measurement remained ignored. Six compile-fail docs
and strict five-package all-target Clippy passed. Tests cover original allocation,
capacity and exact bytes; odd/even/empty/partial geometry; canonical error and
lower-limit parity; full Fetch/FetchVersion/Copy rejection of unrequested tail
corruption; Delta replay; and corrupt post-ACK tail/pending recovery. Formatting,
requirements mirroring and module links passed. Native logs and frozen source/
artifact identities are in `.local/owned-verified-images-native.log` and
`.local/owned-verified-images-publication.json`. GUI source and existing public
GUI/client contracts did not change; the portable GUI suite was not repeated.

This removes unused packet allocation/copy, not the complete hash audit or checked
tree allocation. Materialization still briefly overlaps canonical bytes and copied
packets; Delta still encodes its snapshots into RawBundle and then a complete disk
Vec in this version. Whole-process peak memory was not measured. These results
establish neither full PostgreSQL/private SQL locks, public source-completeness
proofs, production finality nor whole-process resource bounds.
