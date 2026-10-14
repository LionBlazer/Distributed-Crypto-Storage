# Native Spiral trial parallelism and independent batches

Measured2026-10-15: four same-query server responses are bit-identical;32 full
ranges, one fresh replacement read and11 rejection controls pass. Private uncached
range time decreases574.1045–590.1032ms to508.2244–530.6197ms. All four candidate
uncached samples still fail500ms. Private cached range time decreases457.9884–
465.8433ms to413.5054–424.0399ms. This is a bounded local improvement, not goal
closure. The [new opt-in package](../experiments/private-pir-batch/README.md)
preserves the frozen [Rows256 experiment](experiment-private-bfv-range.md).

## Source finding and scheduling boundary

Primary source is pinned
[process_query](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L650).
It expands a fresh query once and parallelizes over instances. Our profile has
instances1, so its four n*n database multiply/inverse-NTT/fold trials are serial.
The candidate uses the same8-worker pool to run four independent trial tasks;
indexed collect retains their original packing order. Every ring operation calls
unmodified native expand_query/get_v_folding_neg/multiply_reg_by_database/from_ntt/
fold_ciphertexts/pack/encode. No arithmetic, sampler, key, parameter or ciphertext
format changes. CLIENT_TEST is never assigned/read by the derivative: no diagnostic
owner key enters it. SDK provenance and full MIT license are retained.

[load_db_from_seek](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L320)
is unchanged; the two33,554,432B NTT caches remain serially prepared. The separate
cold-cache optimization is not combined with this run. Native already shares one
query expansion across four trials. Fresh independent queries need independent
query-dependent expansions; no API merges their selectors into one cheaper query.

The current format requires authenticating/decrypting header counts/offsets before
posting addresses are known, and actual posting decoding before data addresses
are known. These three retrieval stages remain sequential. Cached mode removes
one header RPC using2276B owner metadata only while both complete trusted heads
match. That is the existing authenticated cache, not a proof of global optimality.
Independent batch throughput cannot replace this dependent request's latency.

## Exact same-ciphertext control

Each actual page uses one fresh serialized native query for both schedules. Every
20,480-byte server response matches exactly, then owner recovery, current-head
Merkle verification, AEAD decryption and complete8192B record oracle pass. Timers
below cover server execution only. Their request count includes standard33B
store/root framing; actual outer frames are constructed/parsed in the later batch
and whole-query paths. Controls always run Official first; the reversed-order
whole matrix supplies the paired timing evidence. Fixtures are public.

| Actual store/page | Official server ms | ParallelTrials server ms | Candidate expansion ms | Trial wall ms |
| --- | ---: | ---: | ---: | ---: |
| index0/header | 133.8950 | 112.2013 | 92.6068 | 11.0604 |
| index488/postings | 120.1515 | 98.7607 | 84.1405 | 7.7918 |
| data0 | 123.1383 | 91.7131 | 76.5922 | 8.2163 |
| data488/last partial page | 122.2156 | 96.6678 | 79.8510 | 9.0402 |

Candidate folding-neg4.3896–5.2875ms, pack1.5367–2.3684ms and encode0.2521–0.3134ms
are recorded. Expansion dominates after this change. Public-constant transform
caching or expansion allocation/scheduling changes are unmeasured possibilities;
these results establish no such further gain.

## Paired complete range queries

Exclusive CPU lease, Rust1.99/MSVC release,8 Rayon workers, maximum13 native threads.
Fixed256, actual complete range21 closed250..252/SUM5910 and range256 closed240..241/
SUM6330384, both cached/uncached and visible/private. Two samples per16 cells give
32 operations; schedule order reverses in round1. Actual varint decode supplies
all ordinals. Count<=256 and one posting/data page budgets reject rather than
truncate. Fresh Rows256 BFV range is unchanged:15 products,20 rotations,depth5.

Every entry is round0 /round1 milliseconds; no slow value is dropped:
| Case | Header | Access | Official ms (round0 / round1) | ParallelTrials ms (round0 / round1) |
| --- | --- | --- | ---: | ---: |
| range21 | Cached | Visible | 220.8743 / 225.3192 | 217.3510 / 220.9487 |
| range21 | Cached | Private | 465.8433 / 459.9497 | 417.0795 / 424.0399 |
| range21 | Uncached | Visible | 214.3777 / 220.6352 | 216.3368 / 229.5888 |
| range21 | Uncached | Private | 574.1045 / 574.3258 | 508.2244 / 522.1336 |
| range256 | Cached | Visible | 219.9860 / 241.5064 | 216.8848 / 253.8716 |
| range256 | Cached | Private | 457.9884 / 461.2124 | 413.5054 / 414.2664 |
| range256 | Uncached | Visible | 215.7126 / 219.7704 | 214.3774 / 220.8985 |
| range256 | Uncached | Private | 590.1032 / 578.9166 | 530.6197 / 515.5081 |

The full timer covers header/index handling, actual native query/answer wire and
recovery, Merkle/AEAD and canonical posting decode, field extraction, fresh owner
BFV prepare/serialize, peer decode/evaluate/encode and owner context/decryption.
Ciphertext-only freshness extraction is conservatively included. Query-ID nonce
creation precedes the timer. Setup/oracle maps, after-timer fixture comparisons,
logging, actual network/disk/consensus and computation-proof verification are
separate. Index elapsed already includes header/posting work; do not add twice.
Visible's253.8716ms sample is retained without claiming its cause.

Request counts/lengths are unchanged: Private Cached has3 sequential exchanges
(posting,data,BFV),1,414,045B; Uncached has4,1,450,974B. Visible has1,351,213/
1,355,702B. Range BFV is893,423B request+446,764B output. Each private page uses
16,449+20,480B. Public setup19,424,770B is separate; no remote framing is invented.

## Independent-request batching control

This uses already known fixture addresses index0/index488/data0/data488, not SQL
stages. Fresh serialized requests run sequentially or concurrently, sharing public
setup/cache references. The server closure captures public params, public keys,
encrypted DBs and request ciphertexts only. Owner/client secrets remain outside.
Every answer is authenticated/decrypted before ending the whole-batch timer;
fixture byte comparisons occur afterwards. Each row has two actual samples.
Amortized time is division by batch size, not observed individual query latency.
| Batch size | Requests | Trial schedule | Full batch ms (round0 / round1) | Amortized ms/request (round0 / round1) |
| ---: | --- | --- | ---: | ---: |
| 2 | Sequential | Official | 241.1148 / 233.9523 | 120.5574 / 116.9762 |
| 2 | Sequential | ParallelTrials | 195.6461 / 198.7224 | 97.8230 / 99.3612 |
| 2 | Parallel | Official | 168.0705 / 180.4205 | 84.0353 / 90.2103 |
| 2 | Parallel | ParallelTrials | 161.5205 / 148.9600 | 80.7602 / 74.4800 |
| 4 | Sequential | Official | 462.4327 / 471.9221 | 115.6082 / 117.9805 |
| 4 | Sequential | ParallelTrials | 375.7688 / 376.8430 | 93.9422 / 94.2107 |
| 4 | Parallel | Official | 261.5597 / 275.0494 | 65.3899 / 68.7623 |
| 4 | Parallel | ParallelTrials | 260.3004 / 237.4429 | 65.0751 / 59.3607 |

Batch2 wire is32,898B requests+40,960B answers; batch4 is65,796+81,920B. Concurrent
independent work completes sooner, but no dependent RPC or response bytes vanish.
This is no59ms indexed-range claim, precomputed header answer, plaintext selector,
noncolluding-server substitute or changed privacy assumption.

## Fixed profile, accounting and lifecycle

Spiral retains polyN2048,CRT268369921/249561089,p256,q2_bits20,n2,instances1,
nu1=7/nu2=2,t_gsw8,t_conv4,t_exp_left8/t_exp_right56,Gaussian sampler s6.4,
version0,expanded queries,512x8192B. A runtime gate rejects another profile/extent.
BFV core83D3E4.../kernel1D719A... stays N8192/t114689/Q218,CBD(20)variance10,
native/unfused/level0. Independent >=128-bit security/noise validation and active
response composition remain open. QueryID+two112B trusted heads bind context,
not arithmetic; outputs remain UnverifiedAggregate/proofUnavailable.

| Actual item | Bytes |
| --- | ---: |
| Logical1M compact rows | 3,000,000 |
| Canonical data+fixed-per-N index | 5,065,148 (1.6883827x) |
| Additional rebuildable Merkle hashes | 63,008 |
| Spiral /BFV public serialized setup | 6,029,344 /13,395,426 |
| BFV owner secret serialized count | 8,195 |
| Spiral base /derived live secret payload | 49,152 /131,072 |
| Compact key+independent heads+cached owner header | 32+224+2276 |
| Known canonical+key/owner payload subtotal | 24,680,869 (8.2269563x) |
| Both retained NTT caches (persisted0B) | 67,108,864 |
| Decoded PIR public matrix payload | 23,855,104 |
| Actual whole-run peak resident working set | 408,059,904 |
| Actual whole-run peak private commit | 422,379,520 |

The named subtotal mixes serialized/raw payload and excludes unserialized PIR
framing/sampler/CDF/container/allocator and decoded-key/scratch overhead. Actual
combined owner+peer peaks include live allocations. These native peaks are
cumulative across setup, both schedules, concurrent batches, queries/replacement;
they do not isolate a per-schedule RAM difference. Current and native-peak
resident/private counters are all gated at2,000,000,000B, sampled every25ms.
No persistent FHE row copy/precomputed answer/full-state2x claim. Separate20-table
Rows16 results cannot be combined as one measured deployment with this run.

Cold setup remains1243.3601ms, including serial data/index NTT116.0039/109.1378ms,
PIR keys440.7463ms, BFV keygen202.5637ms/public restore202.8677ms and real private
owner-header fill130.9719ms. Control/batch work warms both schedules before the
paired full-query matrix. This experiment does not integrate later cache helpers.

Actual owner replacement100->101 rebinds index page0, drops/rebuilds both NTT
caches and privately refreshes the owner header. A fresh ParallelTrials private
Fixed256 cached EQ250 read returns exactCOUNT1/SUM101 with unchanged canonical
lengths. Whole replacement+refresh+read624.5737ms; cache/header-ready334.4028ms,
fresh full read290.1400ms. This is owner replacement, not BFV UPDATE, hidden writes
or durable restart. Immutable in-process borrows are not distributed consensus.

All11 controls reject before BFV preparation: omitted/tampered/wrong-page index,
omitted data, complete count>256, actual posting/data crossings, reversed range,
stale owner header, stale index/data responses. Pre-replacement response/budget
controls use AddressOnly; the positive matrix/post-replacement read use Fixed256.
Actual endpoints remain encrypted; visible addresses, public predicate/profile,
geometry, heads/versions, timing, cache/write events and aborts remain observable.
Length equality establishes no full active-network or decryption-feedback privacy.

## Reproduction and frozen evidence

Use the module README's opt-in commands and dedicated target/private-pir-batch.
Twenty-one tests and strict authored Clippy pass after one is_multiple_of style
fix; four warnings in the unmodified SDK remain. The fast unit tests do not
replace real same-cipher response equality, owner authentication or FHE exactness.
No SDK patch, parameter change, global install, main edit or commit is part of this
run. The binary's reviewed module may be copied with provenance/license for
research; it is not a separately extracted production library.

Ignored raw:
`.local/private-pir-batch/private-pir-batch-1000000-2-t8-20261014-232312-037.jsonl`
SHA256 BDE947A68C0A6530C93A346DE0F353AE73E22846354D9A227AA5DA681613519B.
66 records: provenance+setup+4same-cipher controls+16batches+32queries+11rejections+
one replacement. Executable SHA256
0C624848E2BCE1D9C9BCE37E16C022098DE7926F03961BAD19242ABE528CC7C8.
Main40A59DA88EC92D7F2114A7D69ECE08C119A1CD22DA35522D16AD4F2035E02B25;
moduleF9B343135A377CF6559415C7C62584A66B823E007DA98DBF43B1EC88C861B3FC.
Pinned native server source18E4DD4EC23C6FDD4AD60B1943D43F14B4CDFFDFABE8C49E727619DF882463D4.
Raw provenance includes exact core/kernel/codec/test/resource hashes.
