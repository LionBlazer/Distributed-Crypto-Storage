# Private BFV multipage disk: actual 1000-table run

One fresh run on 2026-10-15 retained **1000 distinct independently sealed tables**
of1,000,000 public synthetic rows each:3,000,000,000 logical bytes. All480 bounded
exact-index matrix reads and one genuine full-predicate control were correct;
25 negative controls rejected before fresh BFV. Actual files plus this process's
observed native OS peak private commit were **5,441,187,168B =1.813729056x** logical
payload. Peak private commit355,913,728B remained below the decimal2GB bound.

**The full500ms latency goal is not met by all supported tested modes:**5/480
matrix reads exceeded500ms, maximum522.1062ms. All five were private Fixed256,
uncached header, application table-cache misses. They are retained below. This
result is measured on this new schedule and scale, not a projection or memory
figure spliced from the historical one-page or tiny3 runs.

## Unchanged source and run boundary

This is the [multipage compositor](../experiments/private-bfv-multipage-disk/README.md)
described in the [frozen tiny3 report](experiment-private-bfv-multipage-disk.md).
The exact same pre-run archived release EXE was used; no rebuild, runtime/manifest/
lock edit, parameter reduction or source change occurred. Its published owning
[BFV core](../crates/bfv-query-core/README.md) remains the direct dependency.
The existing31 authored tests/strict Clippy/fmt/build were not needlessly rerun.

The new process generated one fresh full BFV/PIR keyset and shared it over all
1000 actual tables. Key identities are not asserted equal to the earlier process.
Each table was freshly generated/sealed/written sequentially and the fixture dropped;
table counts are not clones, deduplication or multiplication. All2000 image files
remain on disk with a single capacity-one loaded table/native cache pair. Owner
keys/heads/cached headers remain live. The2003 files include2000 canonical images,
two public setups and a public catalog; no secret key/owner image file is written.

Exact selection is complete and bounded to256 matching rows on at most TWO posting
and TWO data pages, with every varint/ordinal/count/selected age checked against
the authenticated index/data heads before fresh BFV. EQ230 ordinals1931..2186
cross varint bytes4095/4096; range250..251 ordinals6025..6280 cross8191/8192.
Both actually fetch two real posting and two real data pages. No prefix truncation
or inactive-row substitution makes an oversized selection fit. Age249 spans three
data pages and rejects; age240count3809 exceeds the row budget.

New Fixed256 performs two authenticated posting fetches and two data fetches for
every accepted query, including absence, plus a separate uncached header fetch.
Unused slots make actual verified/decrypted page0 fetches. AddressOnly only fetches
real pages. Real Spiral private requests add no plaintext ordinals. Page addresses/
real-dummy counts in diagnostics belong to explicitly public fixtures. No network
is measured. Fetches are sequential; component throughput does not establish latency.

Profile/arithmetic remain N8192,t114689,Q218,CBD(20),full public keyset,Rows256.
Exact BFV performs actual eight-rotation encrypted COUNT/SUM with no ciphertext
multiplications. Owner fixture oracle executes after the timer; peer arithmetic is
not replaced with plaintext answers. Unverified/ProofStatus::Unavailable remains.

## Actual invocation and validation

Root authorized one scale run after an explicit exclusive CPU handoff. C released
its bulk experiment at02:00:05.988Z. Free disk1,190,591,885,312B and the frozen EXE/
all19 tiny3 source/document handoff paths were rechecked before launch. Arguments:

```text
private-bfv-multipage-disk.exe 1000 1 8 0,499,999 6500000000 <fresh-directory> combined
```

The supplied IDs0/499/999 select tables; this is not global SQL routing or scanning
all tables per query. One sample contains10 cases x8 access/profile/header modes
x3 supplied IDs xtrue miss/hit=480 reads. Each mode/cache cell has30 observations;
each case has48. Native cache preparation uses8 Rayon workers; maximum sampled
process threads13. PID272804 ran02:00:52.900Z..02:04:23.209Z, exit0; wrapper wall
210308.2051ms, own-child CPU658609.375ms. No rerun occurred. The process has no
warm-start restoration or full owner restart claim. OS file cache is allowed.

An independent stdlib audit checked every selected COUNT/SUM/limb against public
fixture formulas, all matrix combinations, fresh ciphertexts, real/dummy counts,
equal Fixed256 wire shapes,480 exact+1 full-predicate evaluations,25 before-BFV
rejections,2003 physical lengths and all2000 physical112B heads versus catalog.
Each of1000 data/index head strings is unique. This is a header/length inventory;
it is not an additional full-file decode of each of997 unqueried tables.

## Complete timing matrix

Every whole_local_ms is the outer Loader.execute timer: eviction/admission, file
read/decode/native readiness, all sequential lookup/Merkle/AEAD, owner encryption/
serialization, peer wire/decode/FHE/output and owner completion. Setup and after-
timer oracle are separate. TableMiss means an application-cache miss, not a
physical-cold-disk guarantee. Nearest-rank p50/p95; all30 values per cell retained.

| Access/profile/header/cache | p50 ms | p95 ms | Max ms | >500 |
|---|---:|---:|---:|---:|
| Private/AddressOnly/Cached/miss | 244.4221 | 405.6610 | 436.0356 | 0 |
| Private/AddressOnly/Cached/hit | 188.4648 | 351.2825 | 368.4863 | 0 |
| Private/AddressOnly/Uncached/miss | 323.2732 | 489.2218 | 495.2347 | 0 |
| Private/AddressOnly/Uncached/hit | 276.6036 | 435.6991 | 435.7302 | 0 |
| Private/Fixed256/Cached/miss | 400.0966 | 411.8014 | 414.3913 | 0 |
| Private/Fixed256/Cached/hit | 348.1758 | 366.7860 | 374.2249 | 0 |
| Private/Fixed256/Uncached/miss | 481.3960 | 521.4769 | 522.1062 | 5 |
| Private/Fixed256/Uncached/hit | 427.3765 | 453.7807 | 461.0660 | 0 |
| Visible/AddressOnly/Cached/miss | 34.6618 | 46.4600 | 63.1067 | 0 |
| Visible/AddressOnly/Cached/hit | 26.8989 | 31.2509 | 31.2561 | 0 |
| Visible/AddressOnly/Uncached/miss | 33.9117 | 44.1460 | 62.4173 | 0 |
| Visible/AddressOnly/Uncached/hit | 24.9524 | 31.9416 | 32.3969 | 0 |
| Visible/Fixed256/Cached/miss | 32.4731 | 44.7196 | 45.3343 | 0 |
| Visible/Fixed256/Cached/hit | 25.5767 | 31.0234 | 31.9025 | 0 |
| Visible/Fixed256/Uncached/miss | 34.3516 | 43.8663 | 45.6695 | 0 |
| Visible/Fixed256/Uncached/hit | 25.8976 | 37.3449 | 39.0193 | 0 |

Mixed-mode whole-matrix min22.1929,p50 45.6695,p95 479.2622,max522.1062ms.
These combined percentiles mix visibly different schedules; mode cells are the
appropriate comparisons. All individual query-stage timings remain in raw JSONL.

| Case (48 observations) | Max ms | >500 |
|---|---:|---:|
| eq0 | 522.1062 | 2 |
| eq1 | 475.2966 | 0 |
| eq4 | 486.4232 | 0 |
| eq16 | 521.4769 | 1 |
| eq256_two_posting_two_data | 503.5150 | 1 |
| eq256_max | 494.3575 | 0 |
| ge255_max | 483.3507 | 0 |
| range256_two_posting_two_data | 506.3052 | 1 |
| eq128_crossing_range_first_bucket | 489.2218 | 0 |
| range21 | 499.9834 | 0 |

All five outliers, all Private/Fixed256/Uncached/TableMiss:

| Case | Table | Whole ms | Loader readiness ms | Nested query ms |
|---|---:|---:|---:|---:|
| eq0 | 0 | 522.1062 | 87.6857 | 434.4171 |
| eq0 | 499 | 500.8002 | 57.4064 | 443.3910 |
| eq16 | 499 | 521.4769 | 55.5931 | 465.8795 |
| eq256_two_posting_two_data | 999 | 503.5150 | 52.2247 | 451.2824 |
| range256_two_posting_two_data | 499 | 506.3052 | 55.5161 | 450.7811 |

The522.1062ms outlier includes43.9363ms measured admission work and87.6857ms total
loader readiness. These are observations, not a causal diagnosis of OS scheduling
or an optimization claim. Readiness/query intervals are nested portions of the
recorded full time, not substitute timers used to discard outliers.

The separate genuine FullPredicate visible/cached/Fixed256 control took107.0357ms
(COUNT1/SUM100, five ciphertext multiplications/eleven rotations). Total peer FHE
evaluations481. All25 negative controls held the preparation counter unchanged:
16 budget cases over all8 modes,8 corrupt/wrong-index second-real-page responses
over visible/private access, and one wrong trusted cached head pair. Timed negative
maximum324.3158ms. Cached-head mismatch has an assertion but no reported timer.

## Wire and actual resource ledger

| Accepted Fixed256 mode | Request bytes | Response bytes | Sequential RPCs |
|---|---:|---:|---:|
| Private/Cached | 289391 | 528728 | 5 |
| Visible/Cached | 223759 | 468696 | 5 |
| Private/Uncached | 305840 | 549208 | 6 |
| Visible/Uncached | 223800 | 473144 | 6 |

These shapes were equal across all operators/cardinalities. Exact BFV wire is
223595B request/446808B response; other bytes are real PIR/lookup proof transport.
The uncached private shape is855048B total and six sequential RPCs. Counts do not
convert local CPU measurements into a network-latency claim.

| Item | Actual bytes |
|---|---:|
| Logical payload | 3000000000 |
| 1000 canonical data files | 3023584000 |
| 1000 PaddedV2 index files | 2041564000 |
| Canonical data + index | 5065148000 |
| PIR public wire | 6029344 |
| BFV full public wire | 13395426 |
| Catalog JSONL | 700670 |
| All2003 files | 5085273440 |
| Shared PIR owner image + BFV secret serialized count | 8531 |
| 1000 live owner key/head/header payloads | 2532000 |
| Live catalog structs (overlap payloads) | 2640000 |
| Shared live public keyset digests | 64 |
| Live expanded PIR public payload | 23855104 |
| One native cache pair | 67108864 |
| Loaded canonical snapshot encoding | 5065148 |
| Loaded rebuildable Merkle payload | 63008 |
| Native whole-process peak working set | 351051776 |
| Native whole-process peak private commit | 355913728 |
| All files + current working set | 5407346016 |
| All files + native peak working set | 5436325216 |
| All files + native peak private commit | 5441187168 |

**5,085,273,440+355,913,728=5,441,187,168B /3,000,000,000B =1.813729056x**.
Canonical data/index alone=1.6883826667x. File+peak-private is conservative within
this one-process/single-replica scope: it includes actual files, all live table
owner metadata, shared keys/digests, native key/runtime allocations, oracle scratch
and native cache allocation. Do not add separately listed overlapping live payloads
again. Known files+serialized secret counts5085313971B is a different ledger, not a
portable complete secret backup. No cache is persisted and unloaded table/cache
bytes remain zero. The outer shell peak-working property was unavailable after
exit; native in-process Windows peak counters through the completion sample are
authoritative. No post-exit peak observation is claimed here. Other processes,
OS filesystem cache outside the process, replicas and network resources are excluded.

Setup/keygen/fresh-table generation was separately measured at39281.5552ms.
All canonical file lengths are3023584B data and2041564B index. None of the1000 table
images were substituted with a multiplied count or shared immutable snapshot.

## Frozen evidence and limits

Same ignored evidence directory: .local/private-bfv-multipage-disk/.

* Raw `multipage-1000-s1-t8-combined-20261015-015709-739.jsonl` SHA256 `4C45B00047B97CA8476167A21379C8DB52F1D53C85C776EDB9AC92F8B92FCE6A`.
* Frozen EXE SHA256 `74950A194DEC597F67FE245028715F28BE548FA78872F8B0115B13FE1E62858D`.
* Original runtime source/prepared dependency hashes: `preparation-runtime-frozen.jsonl`.
* Tiny3 immutable source/archive inventory: `handoff-manifest.json` (published report commit fd9667a).
* `scale1000-preflight-20261015-015709-739.json`, `scale1000-launch.json`, `scale1000-process.json`, `scale1000-completion.json`: actual args/hash/free-space/PID evidence.
* `audit-multipage-scale1000.py` / `audit-multipage-scale1000-result.json`: exact formulas, modes, every outlier and physical-head/length audit.
* `scale1000-handoff-manifest.json`: report/evidence/source-reference/file-inventory hashes.

The tiny3 result remains491.6511ms/0over500; this scale result is522.1062ms/5over500.
Both are retained. The bounded storage/resource target passed in the stated actual
scope, while all-mode500ms remains open. No independent numeric parameter-security
or noise bound, single-peer arithmetic/completeness proof, CCA-feedback safety,
full owner restart, hidden UPDATE, crash durability, general SQL, global routing,
replication or consensus is established by this read-only experiment. All successful
outputs remain Unverified; no cryptographic or privacy parameter was relaxed.
