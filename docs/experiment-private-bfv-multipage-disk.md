# Private BFV multipage disk experiment

One fresh three-table run completed on 2026-10-15: **480/480 exact matrix reads**,
**25/25 rejections before fresh BFV**, and one genuine full-predicate control.
The full local matrix maximum was **491.6511 ms, with 0/480 over 500 ms**. This
is a bounded result on this machine, not an SLA, a network measurement, a 1000-table
result or completion of general SQL. The prior one-page measurements remain separate.

The [standalone compositor](../experiments/private-bfv-multipage-disk/README.md)
directly uses the published [owning BFV core](../crates/bfv-query-core/README.md),
[compact-store](../crates/compact-store/README.md),
[Spiral owner recovery](../experiments/spiral-owner-state/README.md) and
[native cache preparation](../experiments/spiral-cache-core/README.md).
No frozen baseline, owning library, SDK or GUI source changed for this experiment.

## Selection and actual work

Each of three independently freshly sealed tables contains 1,000,000 public synthetic
3-byte rows, with 2048 rows/data page and independently held exact data/index heads.
One full BFV/PIR keyset is shared; a capacity-one loader holds only one decoded
table/cache pair. Supplied table IDs 0, 1 and 2 are table routing, not global SQL.

Complete exact owner-index EQ/GE/closed-range selection is bounded to 256 rows,
two distinct posting pages and two data pages. Header count/offset preflight, full
canonical varint decoding, distinct/in-range ordinals and all selected age checks
reject the whole operation on an error, before fresh BFV. Returned selected ordinals
and arithmetic are checked against a public fixture oracle after the timer.

EQ230 selects ordinals1931..2186; its first two-byte varint starts at index byte4095.
Range250..251 selects6025..6280 split128+128; its first varint starts8191. Both cross
real posting-page boundaries and require two real data pages. There is no artificial
posting padding. Cases also cover absence,1/4/16/range21,EQ250128,duplicate row values,
and EQ255/GE255 of256 maximum65535 amounts. Actual amount values vary by table where
defined; unchanged constant and duplicate groups are deliberate controls.

**New Fixed256 schedule:** every accepted query, including absence, fetches two
authenticated posting pages and two data pages, plus an uncached header when selected.
Unused slots make real authenticated page0 fetches; header reuse does not remove a
posting slot. AddressOnly fetches only real pages. Private transport contains the
existing store/root header and serialized encrypted PIR query, without new plaintext
ordinals. Diagnostics disclose real/dummy counts for these public fixtures; accepted
Fixed256 wire shape is equal across operators/cardinalities per access/header mode.
Failure shape is not padded to successful shape. All fetches are sequential.

Owning BFV arithmetic/profile are unchanged: N8192,plaintext114689,Q218,CBD(20),
Rows256; exact indexed COUNT/SUM performs eight rotations and no ciphertext
multiplication. No plaintext answer substitutes for FHE. The owner authenticates
complete exact matching selection; outputs remain explicitly Unverified with
ProofStatus::Unavailable. The full encrypted-predicate read path remains exercised.

## Validation and execution

All31 authored release tests passed (7.02s), including complete crossing varints,
a bad/stale second posting page, authenticated age mismatch, a third posting/data
page rejection, duplicates and32 actual visible/private PIR/BFV path checks. Strict
authored all-target Clippy, cargo fmt check and release build passed. Unchanged
dependency SDK warnings remain; no SDK edits or CLIENT_TEST feature were used.
The reviewed new-package Cargo.lock was accepted unchanged with --locked --offline.
Before validation, only three local package identity lines differed from the
historical baseline: the new experiment name and owning bfv-query-core name/reference.
No dependency version or registry checksum changed; both lock images are retained.

Prepared sibling manifests add explicit isolated workspaces and replace inherited
store manifest values only in ignored generated copies. Provenance separates original
manifest hashes from injected hashes. The full runtime source/executable archive
was frozen before the only benchmark launch. Historical source-only review ledgers
and initial-copy PROVENANCE hashes are not current runtime source hashes.

The first strict Clippy attempt failed on unused production test-only invalidation
and two collapsible-if styles; final checks passed after those routine changes.
A pre-run archive attempt omitted .ps1 in its extension whitelist and stopped after
partial source copies. That partial directory remains; a new complete archive was
used. No benchmark process/dataset was launched by the failed archive attempt.

Reproduction after source preparation and an exclusive CPU lease:

```powershell
$env:CARGO_HOME='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-multipage-disk'
$env:RAYON_NUM_THREADS='8'
$cargo='E:/Users/white/.cargo/bin/cargo.exe'
$manifest='.local/private-bfv-multipage-disk/package/Cargo.toml'
& $cargo test --release --locked --offline --jobs 2 --manifest-path $manifest -- --test-threads=1
& $cargo clippy --release --locked --offline --jobs 2 --all-targets --no-deps --manifest-path $manifest -- -D warnings
& $cargo fmt --manifest-path $manifest -- --check
& $cargo build --release --locked --offline --jobs 2 --manifest-path $manifest
# Archive the executable/source before execution; use a NEW dataset directory.
& <frozen-executable> 3 1 8 0,1,2 67108864 <new-ignored-directory> combined
```

Process291972 ran01:47:54.861Z..01:50:31.842Z, exit0, wrapper wall156980.6542ms,
own-child CPU565000ms. Eight Rayon workers; maximum sampled process threads13.
No competing authorized heavy jobs ran. The shell wrapper peak-working-set property
was unavailable after exit; in-process native Windows counters below are authoritative.

## Full-operation latency

One sample:10 cases x8 access/profile/header combinations x3 supplied IDs xmiss/hit
=480 queries; each mode/miss-hit cell below has30 observations. Percentiles use
nearest rank. Every observation, not sums of component timings, is the outer
Loader.execute interval: eviction/read/decode/native readiness plus all sequential
lookup/proof/AEAD, owner encryption/serialization, peer wire decode/FHE/output and
owner completion. Table misses are application-cache misses; OS file cache is allowed.
Key/table setup and post-timer fixture oracle are separate.

| Access/profile/header/cache | p50 ms | p95 ms | Max ms | >500 |
|---|---:|---:|---:|---:|
| Private/AddressOnly/Cached/miss | 225.5966 | 381.7067 | 394.7581 | 0 |
| Private/AddressOnly/Cached/hit | 179.6479 | 336.9824 | 337.1048 | 0 |
| Private/AddressOnly/Uncached/miss | 304.4358 | 466.1953 | 467.8617 | 0 |
| Private/AddressOnly/Uncached/hit | 256.2862 | 415.4975 | 417.4670 | 0 |
| Private/Fixed256/Cached/miss | 379.9228 | 399.7086 | 414.1224 | 0 |
| Private/Fixed256/Cached/hit | 334.7101 | 347.4081 | 353.0243 | 0 |
| Private/Fixed256/Uncached/miss | 461.8006 | 480.3226 | 491.6511 | 0 |
| Private/Fixed256/Uncached/hit | 409.9340 | 428.5455 | 484.2664 | 0 |
| Visible/AddressOnly/Cached/miss | 27.8600 | 33.3916 | 33.5889 | 0 |
| Visible/AddressOnly/Cached/hit | 23.7152 | 28.2611 | 28.5223 | 0 |
| Visible/AddressOnly/Uncached/miss | 28.8354 | 38.3273 | 38.6147 | 0 |
| Visible/AddressOnly/Uncached/hit | 23.6128 | 28.9698 | 33.6748 | 0 |
| Visible/Fixed256/Cached/miss | 30.0178 | 37.4314 | 38.5478 | 0 |
| Visible/Fixed256/Cached/hit | 23.4933 | 29.4170 | 30.6189 | 0 |
| Visible/Fixed256/Uncached/miss | 31.4877 | 35.3245 | 37.6936 | 0 |
| Visible/Fixed256/Uncached/hit | 25.0738 | 28.3477 | 28.4261 | 0 |

Whole-matrix p50=37.6936,p95=459.9350,min22.5092,max491.6511ms. These aggregate
percentiles mix materially different visible/private schedules; use mode cells.

| Case (48 observations each) | Count | Max full ms |
|---|---:|---:|
| eq0 | 0 | 470.9574 |
| eq1 | 1 | 480.3226 |
| eq4 | 4 | 475.1635 |
| eq16 | 16 | 471.2445 |
| eq256_two_posting_two_data | 256 | 471.8391 |
| eq256_max | 256 | 484.2664 |
| ge255_max | 256 | 491.6511 |
| range256_two_posting_two_data | 256 | 467.8617 |
| eq128_crossing_range_first_bucket | 128 | 464.5238 |
| range21 | 21 | 469.3560 |

The separate full-predicate visible/cached/Fixed256 control took97.1189ms, returned
COUNT1/SUM100, and actually performed five ciphertext multiplications/eleven rotations.
Total peer evaluations481. All25 negative controls held the fresh-BFV counter unchanged:
16 count/third-data-page cases over all8 modes,8 corrupt/wrong-index second-real-page
controls over visible/private transport, and one wrong trusted cached head pair.
Timed negative maximum311.5204ms; cached-head mismatch is asserted without a reported
timer. The actual age249 three-row selection spans data pages3/4/5; age240count3809
rejects instead of truncating. Stale proof/invalid authenticated age and synthetic
third-posting-interval cases are also owning tests, not additional runtime samples.

## Traffic and resources

| Fixed256 accepted shape | Request bytes | Response bytes | Sequential RPCs |
|---|---:|---:|---:|
| Private/Cached | 289391 | 528728 | 5 |
| Visible/Cached | 223759 | 468696 | 5 |
| Private/Uncached | 305840 | 549208 | 6 |
| Visible/Uncached | 223800 | 473144 | 6 |

RPC counts include four actual real-or-dummy page fetches, optional header and one
BFV request. BFV exact wire is223595B request/446808B response. All per-page query,
server/recovery/proof/decrypt, native preparation, conversion/FHE and wire-stage
records remain in raw JSONL. No network is measured.

| Accounting item | Bytes |
|---|---:|---:|
| Logical payload | 9000000 |
| Canonical data + PaddedV2 indexes | 15195444 |
| Both shared public setup wires | 19424770 |
| Catalog JSONL | 2085 |
| All nine dataset files | 34622299 |
| Shared owner PIR image + BFV secret serialized count | 8531 |
| Three owner key/head/cached-header payloads | 7596 |
| Catalog live struct bytes (overlaps those payloads) | 7920 |
| Live PIR expanded public payload | 23855104 |
| One native data/index cache pair | 67108864 |
| One loaded canonical snapshot encoding | 5065148 |
| Loaded rebuildable Merkle payload | 63008 |
| Native whole-process peak working set | 348000256 |
| Native whole-process peak private commit | 353337344 |
| Dataset files + native peak private | 387959643 |

Each data file3023584B and index2041564B; six files15195444B, canonical1.6883826667x.
Canonical overhead is not the all-in result: fixed setup keys dominate tiny3.
Dataset + peak private=387959643B /9000000B =43.106627x, so this run **does not meet
the <=2x total storage/memory goal**. The whole-process peak353337344B stayed below
the decimal2GB admission/monitor bound. No native cache is persisted; unloaded table/
cache bytes remain zero. Peak counts already include native key/runtime allocations;
do not add their separately listed payloads again. All six physical image lengths
and112B heads independently matched catalog; files total34622299B. The64B keyset
digests are live process state, and trusted heads/catalog payloads are separately
reported without falsely summing overlapping live structs. OS filesystem cache
outside the process, replicas, network and machine-wide resources are excluded.

## Frozen evidence and limits

Evidence under WT .local/private-bfv-multipage-disk/:

* Raw: `multipage-3-s1-t8-combined-20261015-014742-901.jsonl`; SHA256 `AC8279EB8C7DBD9147AE080CD5365142C3E0FD64A7C339997D80D7B1B51E5919`.
* Executable: `frozen-pre-run-20261015-014742-901/private-bfv-multipage-disk.exe`; SHA256 `74950A194DEC597F67FE245028715F28BE548FA78872F8B0115B13FE1E62858D`.
* Historical baseline lock SHA256 `B44D3870FEBFAC2FAB3118E82779C28252E44EC6AD52C4F641EF604876C7B218` (`Cargo.lock.baseline-original`).
* Reviewed new-package lock SHA256 `BA5F7932FE2C06262EAA8007A064148267FDC5960EDBF13F626CB0DA54064E2E`, unchanged through Cargo validation (`Cargo.lock.original-copied` is the source-to-generated copy).
* `preparation-runtime-frozen.jsonl`: exact runtime/dependency and injected-manifest hashes.
* `archive-manifest.json` in the frozen archive: source/exe/log inventory before the run.
* `active-run.json`, `run-process.json`, `run-completion.json`: exact args/PID/timing and paths.
* `test-release-final.log`, `clippy-release-final.log`, `build-release-final.log`; initial attempts retained.
* `audit-multipage.py` / `audit-multipage-result.json`: independent formula, shape, physical-head/length and every-mode checks.
* Final `handoff-manifest.json` contains current source/docs and all evidence hashes.

This adds bounded authenticated complete two-page read orchestration, not a new
crypto API or parameter relaxation. It is owner-online, supplied-table, single-replica,
read-only composition; secret owner keys/images are not persisted to participant files.
It does not establish complete owner restart, hidden writes, durable fsync/crash
atomicity, general SQL/routing, arithmetic proofs or CCA-feedback safety. Independent
numeric parameter-security/noise and single-peer computation/completeness proof gates
remain open. No1000-table run was authorized or performed for this new schedule.
