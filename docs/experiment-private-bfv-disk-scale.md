# Actual 1,000-table disk scale probe

This measured run stores 1,000 independently sealed one-million-row tables and keeps
only one table/native cache pair loaded. Actual dataset files plus the whole-process
native peak private commit total **5,449,801,056 B / 3,000,000,000 logical B =
1.816600352x**. All 288 same-table matrix queries and five additional full operations
return exact results. The general 500 ms target remains unmet: six uncached private
range misses take 506.1063–518.3285 ms. All cached-header cells in this sample stay
within 500 ms; their maximum is the retained **455.4659 ms EQ256 miss**, rather than
the lower range-only maximum 453.9674 ms.

This is the same source/executable as the final [three-table disk probe](experiment-private-bfv-disk.md),
with the same contracts, parameters, fixed Rows256 BFV and published combined native
Spiral scheduling. No source or algorithm changed between runs. It uses one shared
BFV owner/public setup and one shared PIR client/public setup, separate per-table
AEAD owners, capacity1, Rayon8, IDs **0/499/999**, one sample and a conservative
6,500,000,000-byte canonical write budget. No second scale run or discarded outlier
is used. This is one owner's 1,000 tables, not a multi-owner/global-index benchmark.

## Whole operations

Every selected ID executes every EQ absent/1/16/256, GE256 and closed-range256 case,
both AddressOnly/Fixed256 profiles, cached/uncached headers and visible/private
retrieval. A real miss then same-table hit gives 288 unique cells. Complete ordinals
come from actual authenticated encrypted index postings and real data-page retrieval;
fixture expected rows/SUMs are checked only after the timer. EQ/GE256 returns the exact
maximum 16,776,960; range256 includes all64+192 rows with boundary amounts.

The complete timer includes admission/eviction, actual held-handle reads, full image
commitment reconstruction, native cache construction on private misses, real index
and data retrieval/authentication, fresh BFV encryption/serialization, public-only
peer predicate COUNT/SUM, output decoding and owner decryption. It excludes the
separately reported shared key setup, initial table creation/header bootstrap and
pre-timer query nonce generation. Nested stage times are not added to infer latency.
Cached metadata was authenticated locally during creation; this is not a privately
fetched header bootstrap. The online owner sees selected fields before fresh BFV.

Milliseconds are min/median/max, n=3 supplied tables per condition. All 288 raw cells
are retained. Different cardinalities are not pooled into a headline median.

| Case | Profile | Header | Visible miss | Visible hit | Private miss | Private hit |
|---|---|---|---:|---:|---:|---:|
| eq0 | AddressOnly | Cached | 104.6/108.4/109.0 | 84.1/84.9/92.1 | 142.3/145.0/152.1 | 87.8/89.3/89.7 |
| eq0 | AddressOnly | Uncached | 96.9/100.0/104.5 | 86.9/92.1/99.1 | 213.7/218.2/218.4 | 173.5/176.1/176.3 |
| eq0 | Fixed256 | Cached | 98.1/104.8/106.1 | 83.0/90.9/93.1 | 292.2/308.4/308.6 | 246.8/259.0/266.4 |
| eq0 | Fixed256 | Uncached | 95.5/102.8/105.4 | 84.2/85.5/93.2 | 375.0/380.4/393.9 | 326.6/337.2/340.8 |
| eq1 | AddressOnly | Cached | 108.0/111.0/112.7 | 94.6/98.8/99.3 | 291.9/307.0/314.8 | 249.4/254.1/261.0 |
| eq1 | AddressOnly | Uncached | 95.6/102.4/105.2 | 97.7/102.4/104.2 | 387.5/391.5/409.0 | 336.7/348.7/350.0 |
| eq1 | Fixed256 | Cached | 95.1/102.9/108.7 | 87.8/88.2/97.5 | 293.9/313.4/317.4 | 249.5/254.7/263.5 |
| eq1 | Fixed256 | Uncached | 105.5/105.9/113.5 | 88.2/89.5/89.7 | 375.4/377.9/380.7 | 332.7/336.9/340.0 |
| eq16 | AddressOnly | Cached | 91.1/93.4/101.6 | 98.3/99.3/100.6 | 292.2/308.7/312.3 | 248.4/253.4/263.1 |
| eq16 | AddressOnly | Uncached | 94.0/94.1/100.3 | 99.4/101.9/119.8 | 379.9/380.6/391.9 | 329.0/333.7/341.4 |
| eq16 | Fixed256 | Cached | 93.4/102.9/123.3 | 97.6/104.5/106.8 | 309.0/315.0/315.6 | 251.9/256.4/267.1 |
| eq16 | Fixed256 | Uncached | 91.0/93.9/102.1 | 87.4/95.6/101.0 | 382.4/387.4/387.5 | 336.1/346.5/347.8 |
| eq256 | AddressOnly | Cached | 90.5/94.8/110.5 | 92.9/98.4/102.4 | 291.4/305.8/306.6 | 247.9/248.2/256.7 |
| eq256 | AddressOnly | Uncached | 92.4/98.5/101.1 | 95.9/97.1/100.9 | 377.5/383.6/384.4 | 327.7/336.5/340.9 |
| eq256 | Fixed256 | Cached | 115.0/156.5/234.3 | 83.7/95.6/105.8 | 290.0/440.5/455.5 | 254.7/255.9/259.4 |
| eq256 | Fixed256 | Uncached | 104.2/105.9/112.3 | 84.0/90.7/94.6 | 381.1/383.2/390.2 | 333.1/335.2/337.0 |
| ge256 | AddressOnly | Cached | 134.6/136.7/143.8 | 128.0/133.9/134.4 | 335.6/340.8/347.2 | 282.2/283.3/292.0 |
| ge256 | AddressOnly | Uncached | 141.4/142.0/145.9 | 124.4/128.3/135.4 | 409.7/412.2/412.4 | 368.2/369.0/369.6 |
| ge256 | Fixed256 | Cached | 140.0/142.6/145.9 | 129.2/129.6/136.1 | 338.5/347.2/362.1 | 289.2/303.4/322.7 |
| ge256 | Fixed256 | Uncached | 135.0/139.0/143.7 | 125.7/130.9/138.5 | 410.3/411.4/425.3 | 367.1/371.1/375.8 |
| range256 | AddressOnly | Cached | 223.6/232.2/239.8 | 219.8/227.0/235.3 | 428.0/433.6/451.0 | 385.1/394.4/398.2 |
| range256 | AddressOnly | Uncached | 227.6/236.0/242.4 | 221.0/225.3/234.6 | 506.3/507.1/518.3 | 463.4/476.0/476.6 |
| range256 | Fixed256 | Cached | 223.2/226.1/236.6 | 219.8/236.4/238.2 | 439.0/442.3/454.0 | 382.9/383.1/405.9 |
| range256 | Fixed256 | Uncached | 237.4/250.1/250.1 | 228.5/242.0/242.1 | 506.1/507.7/516.4 | 463.4/464.7/464.7 |

Every failed 500 ms cell is listed explicitly:

| Case | Profile | Table | Header/access/event | Whole ms |
|---|---|---:|---|---:|
| range256 |AddressOnly|0|Uncached/Private/Miss|506.3457|
| range256 |AddressOnly|499|Uncached/Private/Miss|518.3285|
| range256 |AddressOnly|999|Uncached/Private/Miss|507.0741|
| range256 |Fixed256|0|Uncached/Private/Miss|506.1063|
| range256 |Fixed256|499|Uncached/Private/Miss|507.6829|
| range256 |Fixed256|999|Uncached/Private/Miss|516.4475|

The previous dry3's two overruns and original trial-only baseline's 74 overruns remain
reported separately; the scale run does not erase them. No physical cold-disk result
is claimed: real file APIs execute, but OS file cache is not flushed. Table/root
identity, load/update events and public predicate kind remain visible. Within-table
private PIR and visible-page access are both actually measured. Fixed256 preserves
structural wire/RPC shape through real dummy fetches and fresh encrypted zero weights;
there is no constant-time or active-feedback privacy proof. Positive AddressOnly
1/16/256 groups already share fixed BFV/fetch wire here; absence skips fetches.

## Actual files, owners and process state

Creation plus shared setup took **34,253.24 ms**, measured before the first query.
It performed actual independent sealing/writes for every table and prepared no native
cache during setup. A post-run independent audit reads 1,000 current catalog entries,
all 2,000 physical 112-byte complete heads and exact file lengths. Every head/length
matches the catalog. There are 1,000 distinct database IDs, 1,000 distinct public
owner key domains, and 1,000 distinct data roots and index roots; each table's two
heads share its own domain. Source executes 1,000 separate OS-random Owner.generate
calls. No secret-key accessor exists, so key bytes are not exported or directly
compared; distinct public domains are not presented as direct secret-key proof.

All ratios below use **3,000,000,000 logical bytes** (1 billion rows ×3).

| Item | Actual bytes |
|---|---:|
| 2,000 canonical data+index files |5,065,148,000 (1.688382667x)|
| Shared BFV public wire |13,395,426|
| Shared original PIR public wire |6,029,344|
| Current public catalog file |700,670|
| All 2,003 actual dataset files |5,085,273,440|
| 1,000 per-table AEAD secret-key counts |32,000|
| Shared BFV secret serialized count / PIR owner envelope |8,195 /336|
| Files + known secret counts (payload subtotal) |5,085,313,971|
| Owner keys + duplicate trusted heads + header payload |2,532,000|
| Catalog structs (overlaps inline payload; not additive) |2,640,000|
| Owner cached header payload alone |2,276,000|
| Expanded shared PIR public polynomial payload |23,855,104|
| Shared PIR live secret/identity matrix payload (source-derived) |180,224|
| One loaded canonical snapshot pair / Merkle payload |5,065,148 /63,008|
| One retained native NTT overlay pair |67,108,864|
| Transient raw proof-record inputs during pair construction |8,388,608|
| Persisted NTT / retained raw records / unloaded snapshots/caches |0|
| Final process RSS / private commit |331,730,944 /335,941,632|
| Whole-process native peak RSS / private commit |358,719,488 /364,527,616|
| All files + final RSS |5,417,004,384 (1.805668128x)|
| All files + native peak RSS |5,443,992,928 (1.814664309x)|
| All files + native peak private commit |5,449,801,056 (1.816600352x)|

Whole-process counters include the owner and evaluator, expanded keys/context,
canonical snapshot copy, native overlay and temporary buffers. Secret payload counts
are alternatives to partitioning native state, not an additional charge on top of
that inclusive RAM. Unpartitioned BFV native key/context allocation is included in
those native counters. Loaded table count never exceeds1, final loaded ID999;
evictions drop old caches before allocation. Maximum sampled threads13, final10.
The decimal2GB guard retains current/native-peak RSS/commit checks, checked arithmetic
and80 MiB reserve. Admission time is measured inside the complete timer.

The scope is dataset file lengths plus native process memory; filesystem allocation
metadata, OS file cache outside this process, development/build outputs and raw logs
are not a complete-machine footprint. No NTT expansion is omitted or silently treated
as free because it is RAM-only. The result is a measured bounded profile, not a
production full-state/security/availability conclusion or general SQL closure.

## Failure and replacement lifecycle

Nine actual malformed/wrong-table/stale cases again reject before BFV preparation.
Failed loads publish no partial cache. The owner-authorized compact replacement of
one row in table999 writes real data/index/catalog files, invalidates loaded caches
and performs a fresh full private miss: **424.3329 ms** overall, **127.4189 ms**
write/catalog/invalidation and **296.9000 ms** fresh miss. The result is COUNT1/SUM1100.
A later restored full miss takes287.6741 ms. Canonical/catalog lengths do not grow.
This is not FHE UPDATE. No fsync/atomic-commit/crash-durability guarantee is established.
The complete trusted/secret owner restart image remains unavailable; counted BFV
secret serialization and per-table keys are not a portable authenticated backup.

BFV arithmetic outputs remain explicitly unverified. AEAD/Merkle input authentication
and query/head binding are not computation proofs; no network, malicious-response
feedback proof, hidden table selection or unrestricted SQL operation is added. The
existing complete-selection bound is256 rows and one posting/data page, with honest
rejection on overflow/crossing. BFV upstream about128 security/noise-failure analysis
remains an unresolved gate, unchanged from the dry report.

## Reproduction and frozen evidence

The validated executable remained SHA256
`F1A7695BB6AEFB30A0268B173ABAD7C26B45ACCA2BA4D9DDCB3BA660743308CA`.
The measured disk-probe implementation is published in main
`a745ce98e06c7b32d97d6630b7e812c438189402`. Exact pin/core/source contracts and the
28 focused tests/strict authored Clippy evidence are in the dry report. No rebuild
or crypto change was performed for the scale run.

```powershell
./experiments/private-bfv-disk/run.ps1 -Tables 1000 -Samples 1 -TableIds '0,499,999' `
  -Threads 8 -MaxCanonicalBytes 6500000000 -ServerSchedule combined -Offline `
  -Cargo E:/Users/white/.cargo/bin/cargo.exe `
  -CargoHome E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home `
  -TargetDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-disk
```

The actual execution invoked that already-validated binary directly with these same
arguments, a fresh ignored directory and CreateNew initial files. It did not rerun
Cargo. Offline reproduction requires the previously prepared pinned dependencies;
initial SDK source preparation can use the documented runner.

Raw WT `.local/private-bfv-disk/disk-1000-s1-t8-combined-20261014-235243-252.jsonl`, SHA256
`8138D95816CA613B3995FEF1F2B14E25D297B51FA4920BE8CFCC7CE200F64621`.
Dataset WT `.local/private-bfv-disk/snapshots-1000-20261014-235243-252`.
Current catalog SHA256
`197E6976B6D5A1F9B541E9F398AF4D37250482494634E28D2BB3892570477E4B`.
The independent file/catalog audit is retained in
`.local/private-bfv-disk/actual1000-file-catalog-audit.json`.
