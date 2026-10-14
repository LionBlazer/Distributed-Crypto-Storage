# Native Spiral paired expansion scheduling

Measured 2026-10-15: Combined (paired expansion plus four-trial parallelism) returns
exact arithmetic for all 16 of its actual full queries. Private complete ranges
with 21/256 rows take 379.0627–393.1026 ms Cached and 456.3161–464.6840 ms Uncached.
The paired TrialsOnly control takes 506.2653–524.9621 ms Uncached; all four of those
failures of 500 ms are retained. There are 32 full queries total, two samples per
case/header/access/schedule. This is a local ready-cache result, not a network,
tail, independent-security or malicious-computation-proof guarantee.

The [new opt-in package](../experiments/private-pir-expansion/README.md) preserves
the frozen [trial scheduler](experiment-private-pir-batch.md). It changes no SDK
source, cryptographic parameter, record format, query privacy assumption, BFV
circuit or complete index selection. It does not combine its latency with the
separate twenty-table or disk/cache-preparation experiments as one measurement.

## Dependency-preserving scheduling change

Primary source is pinned SDK
[coefficient_expansion](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L19)
and [expand_query](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L525).
The original already parallelizes each half of a round, but executes old and new
halves in separate phases. For round r, each local i first copies OLD source to
its new sibling with scalar_multiply. Only then may the two independent actions
mutate old_i and new_i. The derivative uses split_at_mut, parallel zip and
Rayon join for those two actions. It preserves LOCAL i for both halves (the native
second enumerate resets to zero), exact r0 key choice and all stop conditions.
Every round completes before the next sequential round. No round is parallelized
with a later round. The gain is barrier/early-round utilization, not introducing
parallelism where the SDK had none.

All ring operations remain native from_ntt/automorph/gadget_invert_rdim/
to_ntt_no_reduce/multiply/barrett reduction, then the same reorientation and
regev_to_gsw. Scratch remains fresh and task-local. Both original left/right
scratch buffers are still allocated; selected-dimension allocation is not tested
here. Frozen server_schedule.rs F9B343... supplies the unchanged trial baseline.
The four explicit controls are Official, TrialsOnly, ExpansionOnly and Combined.
Copied SDK portions retain Copyright 2023 Blyss Inc. and the full MIT license.
No diagnostic CLIENT_TEST key is assigned/read by either derivative.

## Direct expanded-buffer and answer equivalence

A separate public fixture has 512 authenticated 64-byte pages, using the same
512x8192B native PIR profile. Slots 0/1/2/63/64/127/128/255/256/488/511 each get two
fresh serialized request ciphertexts. Slot511 is explicitly a page of this fixture,
not mislabeled as a page of the million-row table (489 data/493 index pages).

For all 22 requests, original and paired expand_query outputs match every u64 in
the reoriented selector and every dimension/u64 of every folding matrix. All four
schedules produce identical 20,480-byte serialized responses to each identical
query. Owner recovery, exact trusted-head Merkle verification, AEAD decryption and
full 8192-byte record oracle pass. Four additional actual controls for index0/488
and data0/488 pass the same direct-buffer/four-answer/authentication checks.
Native request frames are actually serialized/deserialized with store ID/root,
16,449 bytes total. All 26 controls retain the real secret-key-free server boundary.

The table preserves every server timing in ms. Fresh0 uses forward schedule order;
Fresh1 reverses it. Direct expansion equality, recovery/authentication and oracle
work are separate from these server-only times, not claimed as full-query latency.
| Slot | Fresh | Official ms | TrialsOnly ms | ExpansionOnly ms | Combined ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 115.9863 | 96.9085 | 99.8138 | 72.3225 |
| 0 | 1 | 113.7147 | 97.4050 | 95.0123 | 78.2459 |
| 1 | 0 | 123.4012 | 96.0854 | 98.7941 | 77.4197 |
| 1 | 1 | 114.0239 | 105.9415 | 91.5752 | 83.0507 |
| 2 | 0 | 114.0287 | 93.2959 | 90.6185 | 82.6956 |
| 2 | 1 | 130.8088 | 115.5798 | 93.8266 | 77.2976 |
| 63 | 0 | 117.2141 | 99.8618 | 90.2761 | 80.6612 |
| 63 | 1 | 119.1296 | 109.6557 | 93.1256 | 84.1418 |
| 64 | 0 | 114.3903 | 91.3411 | 101.5692 | 73.4448 |
| 64 | 1 | 116.0347 | 93.1353 | 101.8990 | 72.3784 |
| 127 | 0 | 110.1313 | 98.2143 | 93.6434 | 77.1800 |
| 127 | 1 | 115.0478 | 90.9344 | 98.1593 | 74.6115 |
| 128 | 0 | 111.7845 | 100.6844 | 91.3014 | 79.1849 |
| 128 | 1 | 122.1970 | 96.6528 | 100.1689 | 75.3092 |
| 255 | 0 | 112.5467 | 99.0650 | 93.5803 | 80.8196 |
| 255 | 1 | 113.8827 | 97.1705 | 92.5292 | 79.4590 |
| 256 | 0 | 116.0416 | 97.9565 | 92.2355 | 79.9752 |
| 256 | 1 | 113.5007 | 94.6015 | 88.8424 | 77.6584 |
| 488 | 0 | 121.5206 | 89.0053 | 99.0546 | 74.1052 |
| 488 | 1 | 106.4479 | 94.9549 | 95.1387 | 75.2668 |
| 511 | 0 | 113.8253 | 90.3063 | 99.0057 | 70.4566 |
| 511 | 1 | 110.1297 | 90.7095 | 97.4802 | 72.3433 |

Predeclared gate: run the complete 32-query matrix only when Combined total server
time over ALL22 boundary requests is <=95% of TrialsOnly, with exactness intact.
Observed totals are1698.0279/2139.4654 ms, ratio0.79366925. The gate passes with no
sample removed. Official/TrialsOnly/ExpansionOnly/Combined mean server times are
115.7176/97.2484/95.3477/77.1831 ms. These boundary-fixture numbers do not replace
the actual million-row pipeline measurements below.

## Actual full-query matrix

One actual million-row public age:u8/amount:u16 table and its complete PaddedV2
index are used. range21 is closed250..252 with COUNT21/SUM5910; range256 is
closed240..241 with COUNT256/SUM6330384. Decoded canonical postings supply every
ordinal. Candidate count<=256, one posting page and one data page are enforced
without truncation. Fixed256 always uses the actual bounded Rows256 circuit and
fresh encrypted inactive zero weights. Range endpoints stay encrypted to peers.
The same additive range BFV circuit performs15 products/20 rotations/depth5.

Exclusive CPU lease, Windows Rust1.99/MSVC release, eight Rayon workers, maximum13
native threads observed. Each cell contains round0 /round1 actual milliseconds;
TrialsOnly/Combined order reverses in round1. No value is retried or dropped:
| Case | Header | Access | TrialsOnly ms (round0 /round1) | Combined ms (round0 /round1) |
| --- | --- | --- | ---: | ---: |
| range21 | Cached | Visible | 223.8847 / 233.5961 | 221.2809 / 221.8367 |
| range21 | Cached | Private | 405.1858 / 413.5182 | 379.6265 / 393.1026 |
| range21 | Uncached | Visible | 216.0258 / 225.6621 | 217.3715 / 221.9405 |
| range21 | Uncached | Private | 506.2653 / 524.9621 | 464.6840 / 456.5570 |
| range256 | Cached | Visible | 221.0283 / 218.5927 | 223.6301 / 217.0775 |
| range256 | Cached | Private | 415.2976 / 421.1087 | 379.0627 / 391.1868 |
| range256 | Uncached | Visible | 221.1444 / 216.4620 | 226.7633 / 236.2584 |
| range256 | Uncached | Private | 518.3279 / 518.9733 | 459.4158 / 456.3161 |

The full timer starts before header/index handling and ends after owner BFV
context checks/decryption. It includes actual query/response serialization,
PIR recovery, Merkle/AEAD, complete posting decode, field extraction, fresh BFV
prepare/serialize and public-only peer decode/evaluate/encode. Ciphertext-only
freshness extraction is conservatively included. Query-ID nonce creation precedes
the timer; setup, fixture oracle maps/comparisons, logging, actual network/disk,
consensus and arithmetic-proof verification are separate. Index timing already
contains header/posting work, so stage subtotals must not be added twice.

Header->posting->data remains sequential: each next address requires actual
prior authenticated decode. No unknown address is guessed or fetched speculatively.
Cached mode holds2276B bound to both complete trusted heads; Uncached privately
reads the real header each time. This candidate removes no RPC. Private Cached
has3 exchanges and1,414,045B; Uncached has4 and1,450,974B. Visible is1,351,213/
1,355,702B. BFV range request/output remains893,423/446,764B. Public setup wire is
19,424,770B separately. Visible timings remain a genuine same-BFV control; no speedup
is inferred from their ordinary variation. AddressOnly positive timings and EQ/GE
full queries are not repeated in this bounded matrix.

## Exact profile, state accounting and limitations

Spiral keeps N2048, CRT268369921/249561089, p256,q2_bits20,n2,instances1,
nu1=7/nu2=2,t_gsw8,t_conv4,t_exp_left8/t_exp_right56,Gaussian sampler width s6.4,
version0,expanded queries,512x8192B. Frozen baseline profile_gate rejects different
parameters/database extent. BFV keeps exact core83D3E4.../kernel1D719A...,
N8192/t114689/Q218,CBD(20)variance10,native/unfused/level0. The ABOUT128 label is not
independent >=128-bit security/noise validation. Active-response/CCA composition
and malicious-peer arithmetic verification remain open. Output is explicitly
UnverifiedAggregate/proofUnavailable; queryID+two trusted112B heads bind context,
not arithmetic. The online owner reads selected fields before fresh BFV encryption.

| Actual retained or transient item | Bytes |
| --- | ---: |
| Logical million-row table | 3,000,000 |
| Canonical encrypted data+fixed-per-N index | 5,065,148 (1.6883827x) |
| Additional rebuildable data/index Merkle hashes | 63,008 |
| Shared public Spiral /BFV serialized setup | 6,029,344 /13,395,426 |
| BFV owner secret serialized count | 8,195 |
| PIR base /derived secret payload | 49,152 /131,072 |
| Compact key+independent heads+cached owner header | 32+224+2276 |
| Known canonical+key/owner payload subtotal | 24,680,869 (8.2269563x) |
| Both retained real-table NTT arrays (persisted0B) | 67,108,864 |
| Separate boundary fixture logical /canonical bytes | 32,768 /57,456 |
| Boundary fixture Merkle hashes /transient NTT cache | 32,736 /33,554,432 |
| Actual combined whole-run peak resident working set | 388,030,464 |
| Actual combined whole-run peak private commit | 392,818,688 |

The boundary fixture/cache and plaintext buffer are dropped before the full matrix;
they are included in the actual combined owner+peer native peaks. Peaks are
cumulative across setup, all four schedules/direct-buffer controls, full queries
and replacement, not isolated per-schedule RAM measurements. Decimal2GB gates cover
current and OS-native peak resident/private counters, sampled every25ms. Known
subtotal mixes serialized and raw payload counts; it excludes unserialized PIR
framing/sampler/CDF/container/allocator and decoded-key/scratch overhead, which
remain in native process measurements. No portable complete owner image,
persistent FHE data copy, full-state2x or replicated-system claim follows.

One cold setup is1248.5245ms, including BFV keygen205.1211ms, public peer-key
restore206.7512ms and initial real private header fill122.3962ms. Native cache
construction remains serial. Boundary controls are separate and warm the code
before the paired matrix; their extra fixture NTT preparation takes105.4966ms.
No later cold-cache helper result is added to these measured query times.

Actual owner replacement changes amount100->101, rebinds encrypted index page0,
drops/rebuilds both native caches and privately refreshes the owner header. A
fresh Combined private Fixed256 cached EQ250 returns COUNT1/SUM101 with unchanged
canonical lengths. Replacement+refresh+read552.0475ms; caches/header ready308.0774ms,
fresh complete read243.9520ms. This is owner replacement, not BFV UPDATE, concealed
writes or durable restart. Immutable local borrows do not implement distributed
freshness consensus or a persistent replay ledger.

All11 runtime controls abort before BFV preparation: omitted/tampered/wrong-page
index, omitted data, complete count>256, actual posting/data page crossings,
reversed range, stale owner header/index/data response. Public profile/predicate,
geometry, heads/versions, timings, visible page addresses, write/cache events and
abort behavior remain observable. Equal lengths establish no general active-network
or decryption-feedback privacy. General cross-page SQL remains outside scope.

## Reproduction and frozen evidence

See the module README commands. Unique package/target private-pir-expansion and
recorded source hashes avoid stale same-name artifacts. Twenty-three focused tests
and strict authored Clippy pass. A stale private import and three derivative-style
warnings were corrected before any measured run; no arithmetic change was made.
Four unmodified upstream SDK warnings remain. Runtime direct-buffer/response
and real-FHE/authentication checks provide evidence beyond those fast unit tests.
No SDK edit, parameter reduction, global install, main edit, commit or destructive
reset occurred. All previous frozen experiment paths remain intact.

Ignored raw JSONL:
`.local/private-pir-expansion/private-pir-expansion-1000000-2-t8-20261014-233417-003.jsonl`
SHA256 E25E62EFE194D54C482BBCF215C2C241822C85208AB7BD192627C59EA7347A3C.
It has74 records: provenance+setup+fixture+22boundary+4real-page+gain-gate+
32full queries+11rejections+one actual replacement. Executable SHA256
345ADBC479744D33551832229CDD8B55160725D659CB41DFAC71DE6263F6B6AD.
Expansion module931FD2B0775E10D83872F8E35D04D9C8CBBC055D373BBA221B6C097F01E78F98;
mainDC1DA2AB0E02B3985781D08626AEA11CB3D21AF45E071B8417CD6FED9E38677C;
controlsC3E8C07D4703B6E14A4C9F93D8A71AFCAEAF5EAC2C67D17BB2EA636AA823B851.
Frozen trial baseline F9B343135A377CF6559415C7C62584A66B823E007DA98DBF43B1EC88C861B3FC
and LICENSE-BLYSS retain their exact bytes. Raw provenance records every source.
