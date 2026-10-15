# Genuine BFV indexed UPDATE with compact disk writeback

Status: measured isolated owner-online experiment, not a production SQL/storage
protocol. The same frozen executable passed a three-table dry run and one fresh
1000-table run, each with 100 ordered committed point updates and all controls.
At 1000 independent million-row tables, actual files plus whole-process native
peak private commit were **5,442,854,240 B / 3,000,000,000 B = 1.8142847467x**.
The 100 point UPDATE requests through compact commit/cache invalidation reached
**316.1619 ms maximum**. Their separate reopen + subsequent SELECT + validation
compound reached **635.3670 ms**, with **25/100 above 500 ms**. The dry compound
had **26/100 above 500 ms**, maximum **674.7945 ms**. These slow outcomes are retained.

## Scope and owning boundary

The [isolated compositor](../experiments/private-bfv-update-disk/README.md) copies
[B's eight-case exact-disk source](../experiments/private-bfv-exact-disk/README.md)
and uses the owning [BFV core](../experiments/bfv-byte-limb-core/README.md),
[compact-store](../crates/compact-store/README.md),
[Spiral owner recovery](../experiments/spiral-owner-state/README.md) and
[native-cache helper](../experiments/spiral-cache-core/README.md). No frozen core,
SDK, previous disk experiment, demo or GUI source was changed.

Supported operation: `UPDATE records SET amount = amount + delta WHERE age ...`
for **all** exact matching indexed rows, at most 256, entirely within one posting
page and one data page. Equality, GE and closed-range selection retain inherited
read semantics; writes exercise equality and range21. The table ID is supplied.
This is not global SQL routing, scanning all tables, arbitrary SQL, joins or
indexed-field updates. Amount changes leave postings unchanged; their header's
data-head binding must still change. There is one replica.

Before conversion, bounded held-handle file reads check exact lengths, full
snapshot roots and independently held heads. Actual retrieved index/data pages
are Merkle-verified and owner AEAD-decrypted before BFV input preparation. The
complete owner-built index, counts, unique ordinals, page budgets and every selected
age must pass; a generic candidate set is not accepted as complete exact matching.
Selection never truncates or silently filters mismatches. With this explicit
owner-online index contract the new operations omit a redundant FHE age predicate.
The owner sees selected plaintext; the peer receives no owner secret or plaintext.
Visible versus private PIR access, public geometry/operator, table choice, timing
and update traffic have their documented leakage; writes are not oblivious.

The owner freshly encrypts selected **original** amount limbs and active-masked
delta limbs in two ciphertexts. The peer decodes the actual request and performs
one real ciphertext addition, no multiplication or rotations. Each byte-limb sum
is at most 510; the owner validates all active/inactive/reserved slots, reconstructs
`low + 256 * high` as u32, and rejects any unsigned result above 65535 globally.
No updated answer is prepared in plaintext as a substitute for homomorphic work.
The compositor's checked-add oracle runs only after actual peer evaluation/wire
and owner Unverified decryption. An in-bounds forged echo can pass cryptographic
decoding and is rejected by this local oracle before staging.

Only then are ciphertext snapshots staged. The data page gets a fresh nonce and
revision; all nonselected bytes and ages remain identical. Index page0 is resealed
with only its first 112 B data-head binding changed: the **entire decrypted suffix
[112..]**, including counts/offsets/co-located postings, must remain identical.
Both encoded lengths stay fixed. Data, index and buffered catalog writes finish
before live trusted heads/header publish; both old native caches and loaded
snapshots are invalidated. Reopen must be a fresh TableMiss under the new heads,
then a genuine independent exact COUNT/SUM confirms the actual committed values.
Old UPDATE output is retried with the **same query ID and new heads**, isolating
head freshness instead of merely a fresh ID. Cached-header old-head reuse rejects.

No-op policy is explicit: absence and delta 0 still perform fresh FHE but do not
reseal or change files/revisions; they invalidate/reopen and run the fresh read.
Fixed256 absence retains real dummy fetches and fresh zero encryption. AddressOnly
absence has a different fetch shape. Maximum 256 positive delta overflows rather
than weakening the frozen all-maximum fixture to make a positive case fit.

## Frozen profile and verification

BFV uses pinned `fhe 0.1.1`, N8192, t114689, Q with bit sizes 43/43/44/44/44:
`8796092858369, 8796092792833, 17592186028033, 17592185438209, 17592184717313`.
Secret/error remain CBD(20), variance 10; initial/output level 0. The full original
rotation and relinearization keyset is retained, shared across all tables; UPDATE
needs only Add but no smaller-key accounting is substituted. The unchanged Spiral
SDK is `fdb7206517c249603b0c91b65f1f29f95272107c`, with reviewed combined
server scheduler and parallel native-cache conversion. Rayon workers 8; sampled
whole-process threads peak 13, final 10. No concurrent project CPU benchmark ran.

The upstream parameter label does not establish independent security. The
[numerical security gate](../experiments/bfv-security/README.md), adversarial
arithmetic proof, chosen-ciphertext feedback safety and production noise/security
review remain open. All BFV outputs are Unverified / ProofStatus::Unavailable.
An honest local fixture oracle is not a query proof for an adversarial deployment.

Final owning boundary checks: **42 runtime tests passed** (31 inherited +11 new),
strict authored release Clippy `--all-targets --no-deps -- -D warnings`, release
build and fmt check passed. The 11 new checks cover selection extraction/budgets,
full suffix/nonselected-byte staging, stale context, wrong arithmetic/false
overflow, actual successful disk carry/head refresh/reopen, genuine Add followed
by forged public echo, partial write failure, exact JSONL bytes/short writes,
tail write/flush errors and staged-head catalog projection. Independent source
review approved the final runtime hashes. The unchanged SDK reports four upstream
warnings; CLIENT_TEST is not enabled or touched.

Two source-review evidence fixes preceded all final measurements: replay diagnostics
now retain the old query ID while changing both heads; diagnostic fresh encryptions
are counted separately from peer-evaluated preparations. Final tests passed after
both fixes and the final Clippy-only cfg/test-state cleanup.

## Timing boundary and all 100 point cycles

Every millisecond value below comes from retained same-executable raw reports;
nearest-rank quantiles use ceil(p*n). The eight modes have n=12 or 13, so their p95
is also their maximum. Mixed-mode medians do not represent private-query latency.
The initial input is a cache hit after controls/previous read; initial conversion
on a cold first request is not hidden inside a claimed cold UPDATE.

* UPDATE through commit/invalidate includes head checks, real selected-page
  lookup/proofs/AEAD, fresh encryption, request/response serialization and decode,
  actual peer Add, owner decryption/oracle, compact staging/encoding, all image and
  catalog writes/flush, trusted-head publication and BOTH cache invalidation.
* Reopen/native readiness is separate: bounded reads/decode under new heads,
  fresh cache pair for private mode; visible mode has no NTT conversion.
* Independent exact SELECT includes its real lookups/proofs, fresh BFV preparation,
  peer eight-rotation aggregate, result decoding/decryption and owner comparison.
* Compound TOTAL includes all three plus stale-output diagnostics and final exact
  length/answer checks. This is a two-request measured cycle, never relabeled as
  the duration of one UPDATE or one SELECT. All I/O allows the OS file cache.

Three-table dry (target 0, public inputs 100+i ->101+i):

| Phase | p50 ms | p95 ms | max ms | >500 |
|---|---:|---:|---:|---:|
| UPDATE to commit/invalidate | 28.3498 | 305.7926 | 329.5997 | 0 |
| Reopen/native readiness | 4.7512 | 44.6653 | 55.2771 | 0 |
| Independent exact SELECT | 33.2907 | 271.0793 | 296.2502 | 0 |
| Same-query old-output gate | 6.5743 | 7.9896 | 8.6275 | 0 |
| Compound TOTAL | 70.2354 | 625.1804 | 674.7945 | 26 |
| Catalog serialize/write/flush (inside UPDATE) | 0.2769 | 0.4399 | 0.6550 | 0 |

| Access / selection shape / header | n | UPDATE max | Readiness max | SELECT max | TOTAL p50 | TOTAL p95 = max | TOTAL >500 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Visible / AddressOnly / Cached | 12 | 26.7506 | 4.2680 | 27.8192 | 56.7908 | 65.1248 | 0 |
| Visible / AddressOnly / Uncached | 12 | 26.3558 | 4.1700 | 28.4871 | 57.5446 | 63.8457 | 0 |
| Visible / Fixed256 / Cached | 13 | 27.5945 | 4.7512 | 30.3659 | 57.0652 | 66.8873 | 0 |
| Visible / Fixed256 / Uncached | 13 | 28.3498 | 4.6004 | 33.2907 | 58.5213 | 70.2354 | 0 |
| Private / AddressOnly / Cached | 12 | 226.0596 | 43.7483 | 189.7902 | 450.9357 | 461.5251 | 0 |
| Private / AddressOnly / Uncached | 12 | 318.2581 | 46.3609 | 273.1385 | 613.1805 | 626.9701 | 12 |
| Private / Fixed256 / Cached | 13 | 236.0076 | 52.6296 | 225.7185 | 453.7322 | 511.2335 | 1 |
| Private / Fixed256 / Uncached | 13 | 329.5997 | 55.2771 | 296.2502 | 611.0578 | 674.7945 | 13 |

Fresh 1000 (target 999, public inputs 1099+i ->1100+i, i=0..99):

| Phase | p50 ms | p95 ms | max ms | >500 |
|---|---:|---:|---:|---:|
| UPDATE to commit/invalidate | 31.6598 | 308.9525 | 316.1619 | 0 |
| Reopen/native readiness | 5.7498 | 45.1438 | 50.4519 | 0 |
| Independent exact SELECT | 30.4130 | 271.9104 | 274.4667 | 0 |
| Same-query old-output gate | 6.8392 | 8.1274 | 8.9516 | 0 |
| Compound TOTAL | 73.6832 | 628.0652 | 635.3670 | 25 |
| Catalog serialize/write/flush (inside UPDATE) | 2.1762 | 4.0781 | 6.7624 | 0 |

| Access / selection shape / header | n | UPDATE max | Readiness max | SELECT max | TOTAL p50 | TOTAL p95 = max | TOTAL >500 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Visible / AddressOnly / Cached | 12 | 31.6598 | 5.0139 | 30.4130 | 61.1213 | 73.4688 | 0 |
| Visible / AddressOnly / Uncached | 12 | 27.8189 | 5.2359 | 28.9025 | 61.9317 | 69.0242 | 0 |
| Visible / Fixed256 / Cached | 13 | 28.3885 | 5.7498 | 30.1462 | 64.5898 | 70.3762 | 0 |
| Visible / Fixed256 / Uncached | 13 | 30.3806 | 5.5149 | 29.7554 | 62.0431 | 73.6832 | 0 |
| Private / AddressOnly / Cached | 12 | 241.0420 | 45.8366 | 193.2729 | 460.4237 | 480.3751 | 0 |
| Private / AddressOnly / Uncached | 12 | 314.1809 | 45.5068 | 273.8849 | 617.7344 | 631.0064 | 12 |
| Private / Fixed256 / Cached | 13 | 233.1909 | 45.6535 | 191.8420 | 460.5411 | 469.2615 | 0 |
| Private / Fixed256 / Uncached | 13 | 316.1619 | 50.4519 | 274.4667 | 619.7524 | 635.3670 | 13 |

All 25 actual point-cycle compound overruns were private/uncached. Actual private
cached maximum was 480.3751 ms, but dry Private/Fixed256/Cached reached 511.2335 ms.
This establishes neither a universal 500 ms bound nor an SLA. Initial eight-case
exact-read controls were 64/64 correct in each run, including 0/1/16/256, GE255,
range256, EQ240=64 and range21; maxima 291.1082 ms dry and 291.3673 ms actual, zero
above 500. One additional genuine FullPredicate control passed; that control has
no separately logged latency, so none is claimed.

## All 50 post-cycle controls, including negative outcomes

Each of the six grouped rows covers **all eight modes**, not a best sample.
Maxima per phase may come from different samples. For GlobalOverflowNoCommit,
UPDATE means time through rejection; readiness/SELECT/catalog 0 mean not run.
The two carry/endpoint rows use untouched already-created table 1 (dry)/table 0 (actual),
private Fixed256/uncached, after all positive-mode controls. Full individual inputs,
limb outputs and phases remain in raw JSONL; summaries retain each of the 48 mode/
control combinations. No duplicate endpoint row is silently excluded.

Dry3, ms:

| Control | n | Outcome | UPDATE max | Readiness max | SELECT max | Old-output gate max | TOTAL max | TOTAL >500 | Catalog max |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| four_rows | 8 | Committed | 265.7336 | 44.4796 | 266.9757 | 8.5635 | 575.5388 | 2 | 0.3681 |
| sixteen_rows | 8 | Committed | 265.0405 | 48.8485 | 298.2676 | 7.5313 | 616.4346 | 2 | 0.4675 |
| range21 | 8 | Committed | 268.2985 | 47.5195 | 262.6761 | 7.5839 | 586.0933 | 2 | 0.4293 |
| absence | 8 | NoOpNoReseal | 250.0493 | 44.5250 | 262.9815 | 0.0005 | 547.9203 | 1 | 0.0000 |
| max256_overflow | 8 | GlobalOverflowNoCommit | 256.5920 | 0.0000 | 0.0000 | 0.0000 | 256.5921 | 0 | 0.0000 |
| max256_zero_delta_noop | 8 | NoOpNoReseal | 268.4053 | 54.1025 | 268.8166 | 0.0005 | 591.4473 | 2 | 0.0000 |
| actual_four_row_byte_carry | 1 | Committed | 296.7588 | 43.6077 | 252.6851 | 7.4509 | 600.9136 | 1 | 0.2753 |
| actual_sixteen_row_65535_endpoint | 1 | Committed | 259.6113 | 34.9105 | 265.6477 | 6.6620 | 566.9639 | 1 | 0.2206 |

Actual 1000, ms:

| Control | n | Outcome | UPDATE max | Readiness max | SELECT max | Old-output gate max | TOTAL max | TOTAL >500 | Catalog max |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| four_rows | 8 | Committed | 267.6385 | 49.2090 | 273.9774 | 9.7508 | 582.3682 | 2 | 2.6087 |
| sixteen_rows | 8 | Committed | 260.2906 | 46.3898 | 298.2356 | 8.4780 | 612.7857 | 2 | 2.2201 |
| range21 | 8 | Committed | 284.7519 | 57.3000 | 271.6357 | 7.9077 | 612.9004 | 2 | 3.0987 |
| absence | 8 | NoOpNoReseal | 256.0684 | 50.0582 | 269.3096 | 0.0001 | 575.5533 | 1 | 0.0000 |
| max256_overflow | 8 | GlobalOverflowNoCommit | 261.7498 | 0.0000 | 0.0000 | 0.0000 | 261.7499 | 0 | 0.0000 |
| max256_zero_delta_noop | 8 | NoOpNoReseal | 270.6383 | 44.0758 | 270.4839 | 0.0002 | 584.0200 | 2 | 0.0000 |
| actual_four_row_byte_carry | 1 | Committed | 324.1041 | 45.9929 | 266.8870 | 7.9664 | 645.0660 | 1 | 2.7140 |
| actual_sixteen_row_65535_endpoint | 1 | Committed | 270.5304 | 38.2214 | 271.7493 | 6.7422 | 587.3622 | 1 | 1.6974 |

Actual carry: age 251 inputs 201..204 +55 ->256..259. Actual endpoint: age 252
inputs 305..320 +65215 ->65520..65535. Dry table 1 uses 202..205 +54 and 306..321
+65214 for the same outputs. These are real writeback/reopen/read controls, not
core-only arithmetic tests. Nonselected amount 65535 / age 249 bytes remain unchanged.

Each run has 100 main point commits +24 four/sixteen/range commits +2 boundary
commits = 126 positive compact commits; 16 NoOpNoReseal controls; eight max256
overflows plus one mixed 64 safe/overflow global rejection; and one in-bounds public
echo rejection after real Add. The last two before-cycle rejection records are
separate from the 50 timed controls; the echo has no per-phase timing because it
returns an error before staging. No failed/no-op control changes files/heads/catalog.
There are 359 peer-evaluated BFV preparations including fresh reads, plus 126
separately counted diagnostic replay preparations. No diagnostic encryption is
represented as a peer request. Loader ends with 142 invalidations, 51 native
upgrades, 144 misses, 357 hits and one eviction in both runs.

## Actual bytes and native resources

The 1000 tables are distinct, freshly sealed and physically retained: one million
rows x 3 B each, 2048 rows/page, no clones/deduplication or multiplication of one image.
There are 2003 actual files: 2000 canonical images, two shared public setups and one
public catalog. One selected table/cache pair is loaded; other snapshots and all
other native pairs are dropped. No expanded NTT image is persisted.

| Actual 1000 accounting | Bytes | / logical 3,000,000,000 B |
|---|---:|---:|
| Data+PaddedV2 canonical images | 5,065,148,000 | 1.6883826667x |
| Shared public BFV+PIR wires | 19,424,770 | 0.0064749233x |
| Public 1000-entry catalog | 700,670 | 0.0002335567x |
| All 2003 files | 5,085,273,440 | 1.6950911467x |
| Whole-process native peak private commit | 357,580,800 | 0.1191936000x |
| Files + native peak private commit | 5,442,854,240 | **1.8142847467x** |
| Whole-process native peak working set | 352,739,328 | 0.1175797760x |
| Files + native peak working set | 5,438,012,768 | 1.8126709227x |

These totals already include live key material, all 1000 owner objects/heads/cached
headers, selected plaintext temporaries, encodes, decoded snapshots, native keys,
allocation overhead and transient buffers through native counters. Do not add
payload subdivisions to native memory again. Documented payload subdivisions:
catalog owner/key/head/header 2,532,000 B; catalog struct 2,640,000 B; expanded shared
PIR public payload 23,855,104 B; loaded canonical encode 5,065,148 B, Merkle 63,008 B,
native pair 67,108,864 B; cached BFV public-key fingerprints 64 B. The BFV native key
allocation is included in native peak but not individually partitioned.

Shared BFV public wire 13,395,426 B includes parameter 46 B, relinearization 1,116,273 B
and rotation 12,279,077 B payloads; framing also counts. PIR public wire 6,029,344 B
is the retained original setup, never a presumed reproducible replacement.
The known secret-image/count subtotal is 8531 B (shared: Spiral owner 336 B + BFV
serialized secret count 8195 B), plus 32,000 B of per-table AEAD key counts. These are
already live/native-counted and are **not written to disk or a complete portable
owner backup**. Current trusted catalog/owner state is live. Complete owner restart
remains false; no regeneration of new keys is presented as restart recovery.

Dry3 had 34,622,299 B actual files and 354,684,928 B native peak private commit:
389,307,227 /9,000,000 =43.2563585556x. Fixed keys/native overhead therefore do not
meet 2x at three tables. Actual 1000 amortizes the same full shared keyset. Neither
number counts filesystem cache outside the process or machine-wide memory; no
full-machine 2x claim follows. Native peaks are below 2 GB; bounded file/allocation
admission and a process-local watchdog were retained, with 80 MiB reserve before
native loading, not described as a universal hard allocation proof.

All 2003 physical lengths and all 2000 exact 112 B file heads match the 1000 catalog
entries after the actual run. Per-table data 3,023,584 B and index 2,041,564 B never
grow. Both target 999 revisions are 124, both boundary 0 revisions 2, all other 998
remain 0; all 1000 DB IDs/domains and 2000 roots are distinct. No post-exit full 5 GB
rehash or AEAD check is claimed (owner keys were not persisted); live operations
performed actual page authentication. Independent root audit also checked every
recorded amount/limb, all mode transitions, 64 read shapes, counter arithmetic and
physical headers/lengths. Catalog SHA256:
`D3DAB337DA37292C5CE23E0B09AB692312A610603493EDD655288C2CC1814D77`.

## Wire and catalog I/O

Positive point UPDATE request 446,884 B + response 446,808 B = 893,692 B. The
independent exact SELECT request 223,595 B + response 446,808 B = 670,403 B.
Per-query authenticated fetch traffic is 73,858 B private/cached (two fetches) or
110,787 B private/uncached (three); visible 11,026 B/cached or 15,515 B/uncached.
Actual byte totals are equal in both positive-point selection geometries:

| Access / header | UPDATE bytes | Independent SELECT bytes | Compound bytes |
|---|---:|---:|---:|
| Visible / Cached | 904,718 | 681,429 | 1,586,147 |
| Visible / Uncached | 909,207 | 685,918 | 1,595,125 |
| Private / Cached | 967,550 | 744,261 | 1,711,811 |
| Private / Uncached | 1,004,479 | 781,190 | 1,785,669 |

Private compound includes six request/response exchanges with cached header or
eight with uncached header (four/six fetches plus UPDATE and SELECT). No transport
latency is measured. Local replay diagnostics are not peer traffic. Absence/no-op/
negative controls retain their actual different traffic in raw stage records.

Only the new compositor uses the reviewed 64 KiB BufWriter seam. JSON serialization,
JSONL separators and short-write semantics are byte-identical to the original;
both buffered-tail write errors and inner flush errors propagate explicitly.
Public projected heads serialize before live head publication. The 1000-entry
rewrite/flush inside 100 main UPDATEs measured p50=2.1762, p95=4.0781, max=6.7624 ms;
dry p50=0.2769, p95=0.4399, max=0.6550 ms. The earlier 127.4189 ms owner-replacement
write/catalog stage is a different composite measurement. No paired causal claim
that buffering alone produced its difference is supported by this run.

Images/catalog are overwritten sequentially. Error invalidates and aborts without
publishing success; a real owning test demonstrates partial file modification and
old trusted heads after an index-write error. There is no rollback, sync_all/fsync,
atomic three-file/crash commit, distributed consensus, durable recovery journal,
network/transport latency or hidden write pattern. Flush success is not power-loss
durability. Peer arithmetic correctness still needs a proof or another justified
verification mechanism before this is a production protocol.

## Reproduction and retained artifacts

Prepare with [run.ps1](../experiments/private-bfv-update-disk/run.ps1), explicit
owning dependency directories as shown in the module README. Use the real Rust
Cargo, not an unrelated PATH executable:

```powershell
$env:CARGO_HOME = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-update-disk'
$cargo = 'E:/Users/white/.cargo/bin/cargo.exe'
$manifest = '.local/private-bfv-update-disk/package/Cargo.toml'
& $cargo test --release --locked --offline --jobs 2 --manifest-path $manifest -- --test-threads=1
& $cargo clippy --release --locked --offline --jobs 2 --manifest-path $manifest --all-targets --no-deps -- -D warnings
& $cargo fmt --manifest-path $manifest -- --check
& $cargo build --release --locked --offline --jobs 2 --manifest-path $manifest
$exe = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-update-disk.exe'
$stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
$freshDry = Join-Path '.local/private-bfv-update-disk' "snapshots-3-$stamp"
$freshActual = Join-Path '.local/private-bfv-update-disk' "snapshots-1000-$stamp"
# Frozen exe arguments: tables cycles rayon_threads supplied_table_id budget fresh_directory schedule
& $exe 3 100 8 0 67108864 $freshDry combined
# Run the larger experiment only after auditing the dry run and its resource budget.
& $exe 1000 100 8 999 6500000000 $freshActual combined
```

Each fresh directory must not exist and must be under the explicit ignored parent;
public synthetic dataset/public key writes only. Default is the small run; actual
1000 required successful tests/source review/dry audit and a separate conditional
lease. There was one actual run, with 1,212,677,095,424 B free prechecked,
6,500,000,000 B budget and 6,291,456,000 B conservative canonical preflight.
Setup (keygen/seal/write) was 972.5027 ms dry and 31,782.0907 ms actual, separate
from UPDATE timings. No runtime change, rebuild, remeasurement or dataset
regeneration occurred between runs. The pre-actual archive retains exact source/
dependency snapshots, exe and dry raw; it explicitly does not duplicate datasets.
Both original datasets/raw remain.

Retained under the worktree's ignored `.local/private-bfv-update-disk/`:

* `source-preparation-frozen.jsonl`: exact runtime/dependency source hash map.
* `test-release-frozen.log`, `clippy-release-frozen.log`,
  `build-release-frozen.log`: actual 42-test/build validation. The passing fmt
  command was observed during validation; no separate fmt log was retained.
* `update-3-c100-t8-combined-20261015-004308-355.jsonl`, `dry3-summary.json`.
* `update-1000-c100-t8-combined-20261015-004733-240.jsonl`, `actual1000-summary.json`.
* `dry3-frozen-20261015-004651-451/manifest.json`: pre-actual archive.
* `final-artifacts.json`: final source/doc/raw/log hashes and frozen handoff.

Frozen exe SHA256:
`2F881670B9959AC57AFABDC61796498D2DF25EAEF4C5EE7FD75DB8F366B3CFBF`.
Dry raw SHA256:
`F05589D04F8ED650E09D4AC25DD259CDC64289377AF09601A33407716D5233D1`.
Actual raw SHA256:
`E95CEF37260AD6F897D3753EF176589A1F8E93EC0B4E69859377FA9A7582FDBF`.
Owning BFV lib SHA256:
`F4EC7930D306AE933142AFE7455B500B61A23D53F3DBA69454E796F33EF88CCB`;
UPDATE child `CE4342513795062F81A9CC467E7F6D177CC1E3AD43EAF5A931D87AED22E6B6C6`.
Historical initial-copy hashes in module PROVENANCE.json are provenance, not hashes
of later modified compositor files. Runtime artifacts remain frozen; final
README/report/provenance wording changes do not alter their source or executable.
