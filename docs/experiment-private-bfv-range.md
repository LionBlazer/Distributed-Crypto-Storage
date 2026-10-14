# Actual complete range/EQ/GE index -> PIR -> BFV

Status 2026-10-15: this isolated Rows256 composition passes 96 actual full queries
and one fresh query after an owner-authorized compact replacement. The complete
21-row range, 64-row EQ, 256-row EQ/GE and 256-row range are decoded from the real
authenticated age index. EQ255/GE255 return exact maximum SUM 16,776,960. All eight
uncached private range queries exceed 500 ms: 567.5194–590.7199 ms. Every other
observed matrix query is below 500 ms. These two samples per cell establish no
tail or network bound. The main backend and earlier frozen experiments stay
unchanged; [the new package](../experiments/private-bfv-range/README.md) is opt-in.

The scope is an online owner, one posting page and one data page per complete
selection, already built in-memory PIR caches, fixed Rows256 BFV and unverified
arithmetic. The canonical table/index is 1.6883827x its 3,000,000 B plaintext;
known joint serialized/secret payload is 8.2269563x for this single table. Neither
whole-system <=2x nor arbitrary SQL nor malicious-peer proof is achieved. Do not
combine these Rows256 results with the separate 20-table Rows16 amortization run
as if they measured one joint deployment.

## Exact operation, fixture and completeness

The owner authenticates the full data/index 112-byte heads independently. Cached
restores counts/offsets only against both exact heads; Uncached fetches/authenticates
the encrypted header. Complete counts preflight <=256 before posting transport.
The real callback decoder reads every canonical selected bucket varint to its
exact end, checks positive gaps, ordinal bounds and duplicates, then returns the
full selected ordinals. Owner Merkle verification and AEAD decryption precede field
extraction. No fixture address selector or precomputed aggregate feeds BFV.

The owner freshly encrypts 256 slots, encrypted query bits, amount low/high-byte
weights and COUNT weights. Inactive rows carry encrypted zero weights. Actual
public-only BFV request decode/evaluation/output encoding occurs on the peer;
no plaintext field or owner AEAD/PIR/BFV secret enters that role. The owner checks
query ID plus both complete trusted heads and decrypts unsigned outputs with
COUNT<=active_rows<=256, each limb<=255*COUNT<=65280 and checked
SUM=low+256*high<=65535*COUNT<=16,776,960. These sanity bounds and context bindings
are not an arithmetic proof; all outputs retain `ProofStatus::Unavailable`.

The public one-million-row fixture has ordinary background ages 0..199 plus a
common age0 cluster. Rare groups and expected exact aggregates are:

| Case | Predicate | Complete rows | SUM |
| --- | --- | ---: | ---: |
| range21 | closed 250..252 | 21 (1+4+16) | 5,910 |
| eq256_max | age=255 | 256 | 16,776,960 |
| ge256_max | age>=255 | 256 | 16,776,960 |
| eq64 | age=240 | 64 | 1,576,944 |
| range256 | closed 240..241 | 256 (64+192) | 6,330,384 |
| absent | age=253 | 0 | 0 |

All 256 age255 amounts are65535; age240 includes 0/1/255/256/257/65280/65534/65535
and age241 includes mixed bytes. Every successful rare selection lies in real data
page0 and posting page488. The actual age230 bucket crosses posting pages487/488;
age243 has ordinals2047/2048 on two data pages. Those are precise `PageBudget`
rejections, never partial results. EQ0 has6723 matches and fails `SelectionBudget`;
closed252..250 fails `InvalidRange` before transport. Nineteen tests include these
actual fixture/index contracts and canonical codec failure cases.

## Timing and observed read shape

Exclusive CPU lease, Windows Rust1.99/MSVC release build, 8 Rayon threads, maximum13
native threads observed. The full timer starts before header/index handling and
ends after BFV answer binding/decryption. It includes actual request/response
serialization and PIR recovery, Merkle/AEAD, posting decode, selected field
extraction, fresh BFV encode/encrypt/serialize, peer decode/evaluate/encode and
owner decode/decrypt. It conservatively includes ciphertext-only freshness
extraction (not context bytes). Query-ID nonce generation occurs before the timer;
setup, fixture oracle maps/comparisons, output logging, actual network, disk I/O
and arithmetic-proof verification are separate. Oracle maps are built during
setup and compared only after `read` stops its timer. Stage subtotals overlap:
`index_verify_decrypt_select_ms` already includes header/posting work.

The following table preserves all96 actual samples; each entry is round0 / round1
in milliseconds. No sample is omitted or retried for being over500ms.
| Case | Profile | Header | Visible ms (round0 / round1) | Private ms (round0 / round1) |
|---|---|---|---:|---:|
| range21 | AddressOnly | Cached | 216.1824 / 228.3754 | 463.9715 / 469.8601 |
| range21 | AddressOnly | Uncached | 228.3453 / 221.6884 | 577.2384 / 578.9065 |
| range21 | Fixed256 | Cached | 218.4123 / 230.5899 | 449.6096 / 460.5762 |
| range21 | Fixed256 | Uncached | 225.9532 / 225.8424 | 576.3868 / 568.7481 |
| eq256_max | AddressOnly | Cached | 83.6701 / 88.0634 | 320.4548 / 328.8135 |
| eq256_max | AddressOnly | Uncached | 83.9835 / 89.5723 | 436.3134 / 450.5624 |
| eq256_max | Fixed256 | Cached | 92.7819 / 87.1348 | 324.7851 / 324.8863 |
| eq256_max | Fixed256 | Uncached | 87.4633 / 88.0293 | 445.8587 / 455.3383 |
| ge256_max | AddressOnly | Cached | 125.6642 / 132.5414 | 361.5308 / 374.7612 |
| ge256_max | AddressOnly | Uncached | 132.1348 / 130.1311 | 469.9149 / 479.1782 |
| ge256_max | Fixed256 | Cached | 131.7004 / 133.5727 | 366.0683 / 374.2046 |
| ge256_max | Fixed256 | Uncached | 134.8334 / 126.9971 | 475.3155 / 482.1064 |
| eq64 | AddressOnly | Cached | 94.0398 / 93.0430 | 330.1807 / 325.7540 |
| eq64 | AddressOnly | Uncached | 90.0114 / 87.5810 | 436.7843 / 439.8459 |
| eq64 | Fixed256 | Cached | 99.4299 / 95.5517 | 326.3724 / 325.1754 |
| eq64 | Fixed256 | Uncached | 93.4872 / 90.0309 | 439.9769 / 449.2337 |
| range256 | AddressOnly | Cached | 208.4586 / 230.4288 | 455.9326 / 447.7901 |
| range256 | AddressOnly | Uncached | 220.5374 / 218.6124 | 567.5194 / 590.7199 |
| range256 | Fixed256 | Cached | 217.0398 / 216.2455 | 454.4050 / 446.7507 |
| range256 | Fixed256 | Uncached | 216.9429 / 219.9114 | 578.2875 / 570.6812 |
| absent | AddressOnly | Cached | 87.3748 / 96.8805 | 97.4103 / 85.9985 |
| absent | AddressOnly | Uncached | 92.3857 / 95.3971 | 210.4874 / 208.6284 |
| absent | Fixed256 | Cached | 84.2487 / 86.8542 | 321.6266 / 328.7550 |
| absent | Fixed256 | Uncached | 84.5241 / 93.8862 | 448.5925 / 444.6993 |

All48 Visible samples are83.6701–230.5899ms. Private EQ256 maximum is455.3383ms;
GE256 maximum482.1064ms. Private cached ranges are446.7507–469.8601ms; all private
uncached ranges are567.5194–590.7199ms. Thus caching removes one real PIR header
exchange, but the uncached closed-range case fails the local500ms target.

Both profiles use the same fixed Rows256 encrypted computation. AddressOnly omits
posting/data reads for empty results, exposing that schedule. Fixed256 always
fetches authenticated posting and data, including dummy pages for absent EQ.
Request/response lengths and RPC counts are equal across observed EQ cardinalities
0/64/256 separately per access/header, and range21/256 separately. GE is measured
only at256; no empty-range/empty-GE shape coverage is claimed. Predicate kind is
public: EQ/GE use3 input ciphertexts, range4. Range endpoints are absent from
plaintext peer requests and freshly encrypted in BFV/PIR inputs. Visible reveals
requested addresses; Private uses real native single-server Spiral. Public
profile/header/cache geometry, heads/versions, timings, write/cache events and
abort behavior remain observable. Equal lengths do not establish active-network
or malicious-response/decryption-feedback privacy.

## Fixed cryptography, wire and setup

The measured core is f46d0bb lib83D3E4E23803F96544617E88AA6EF2B17DFEC274DCB962C168BDAFD7DBA82C7A,
kernel1D719AA6193470C6F3B8C7D28FBC56A87A90D4D14E152A9CE63E5FF47400AE54.
Only direct construction of the exact official profile differs from the older
EQ16 setup; arithmetic is unchanged. fhe/fhe-traits0.1.1, N8192, t114689, Q primes
8796092858369/8796092792833/17592186028033/17592185438209/17592184717313
(43+43+44+44+44=218bits), unchanged secret/error CBD(20) variance10, native NTT,
unfused GE, initial/output level0. The official ABOUT128 label has not passed
independent >=128-bit security/noise validation; production eligibility stays
blocked by that gate and missing arithmetic verification. Closed range requires
validated lower<=upper, using exact GE(age,lo)+GE(hi,age)-1, depth5. EQ/GE/range
perform5/8/15 ciphertext products and11/14/20 rotations. Actual peer evaluation
ranges are67.8058–82.7353 /105.1627–118.1598 /188.8396–216.9995ms; these are nested
kernel observations, not replacement whole-query claims.

Spiral is unchanged pinned
[fdb7206517c249603b0c91b65f1f29f95272107c](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs),
512x8192B records for each of two databases: polyN2048, CRT268369921/249561089,
p256, q2_bits20, n2, t_gsw8/t_conv4/t_exp_left8/t_exp_right56, nu1=7/nu2=2,
Gaussian sampler width s6.4. [The preceding report](experiment-private-bfv-index.md)
records the same PIR boundary/assumptions; no noncolluding-server substitute or
new independent security validation is introduced.

BFV EQ/GE wire is670,134B request+446,764B output; range893,423+446,764B. The
following full retrieval+BFV totals apply to nonempty cases and every Fixed256
case of that predicate kind, with3 Cached/4 Uncached sequential exchanges:

| Access/header | EQ/GE request /response /total B | Range request /response /total B |
| --- | ---: | ---: |
| Visible Cached | 670216 /457708 /1127924 | 893505 /457708 /1351213 |
| Visible Uncached | 670257 /462156 /1132413 | 893546 /462156 /1355702 |
| Private Cached | 703032 /487724 /1190756 | 926321 /487724 /1414045 |
| Private Uncached | 719481 /508204 /1227685 | 942770 /508204 /1450974 |

AddressOnly absent Cached is1 BFV exchange/1,116,898B for either access; Uncached
is2 exchanges, Visible1,121,387B or Private1,153,827B. Setup public wire is
19,424,770B (Spiral6,029,344+BFV13,395,426), counted separately. Local serialized
protocol bytes do not include invented remote transport envelopes.

One cold combined setup is1236.6033ms: PIR key generation435.2449ms; data/index
record construction0.6830/0.5651ms and native NTT114.6566/107.8118ms; BFV key
generation205.8016ms, serialization/owner secret-byte count17.8101ms, actual
public decode/peer-key restoration214.1832ms; real private header fill117.3257ms.
Setup includes actual canonical seal/encode/decode, not network/disk service.

## Actual canonical, key and memory ledger

| Item | Bytes |
| --- | ---: |
| Logical1M age:u8/amount:u16 rows | 3,000,000 |
| Canonical encrypted data (489 pages) | 3,023,584 |
| Canonical fixed-per-N PaddedV2 index (493 pages) | 2,041,564 |
| Canonical data+index | 5,065,148 (1.6883827x) |
| Additional rebuildable data/index Merkle hashes | 31,392+31,616 |
| Shared Spiral public serialized setup | 6,029,344 |
| Spiral base /derived owner secret payload counts | 49,152 /131,072 |
| BFV parameters /relinearization /rotation serialized keys | 46 /1,116,273 /12,279,077 |
| Full BFV public serialized setup (framing included) | 13,395,426 |
| BFV owner secret serialized count | 8,195 |
| Compact owner AEAD key | 32 |
| Independently trusted data/index heads | 224 |
| Cached header counts/offsets+duplicated two heads | 2,276 (2052+224) |
| Known canonical+shared public+owner payload subtotal | 24,680,869 (8.2269563x) |
| Above subtotal+rebuildable hashes | 24,743,877 (8.2479590x) |
| Both retained native NTT arrays, persisted0B | 67,108,864 |
| Decoded native PIR public matrix payload | 23,855,104 |
| Temporary record buffer | 4,194,304 |
| Setup fixture capacities, dropped before queries | 7,000,000 |
| Actual whole-process peak resident working set | 352,423,936 |
| Actual whole-process peak private commit | 357,302,272 |

The named subtotal includes mixed serialized and raw owner-payload counts, not a
complete portable owner-state image. Unserialized PIR framing/sampler/CDF and
matrix/parameter/container/allocator overhead are excluded from that subtotal;
BFV decoded public objects and transient randomness/key work are also reflected
in the real combined native process peak rather than treated as serialized wire.
This experiment does not implement the separate336B owner recovery wrapper. Its
live native secrets and both NTT overlays are retained and reported. Persisting
an overlay would add those bytes to storage; no persistent FHE row copy exists.
Current and OS-native peak resident/private counters are all gated at decimal
2,000,000,000B, sampled every25ms. Peaks include owner+peer role objects together,
including setup/key restore/replacement allocations. This is one in-memory table,
not actual20-table retention, disk I/O, replicated storage or a joint2x claim.

## Freshness, failures and reproduction

After the96 matrix queries, actual owner replacement changes row0 amount100->101,
updates canonical data and rebinds encrypted index page0 to the new complete data
head. Old NTT caches are dropped before rebuilding both, the owner header is
privately refreshed, and a new actual private Fixed256 cached EQ250 query returns
COUNT1/SUM101. Whole replacement+cache refresh+read662.6515ms; caches/header ready
338.1251ms and fresh full read324.4952ms. Canonical lengths stay exactly constant.
This is an owner compact replacement, not BFV UPDATE, hidden writes or durable
restart. Both trusted heads and queryID bind pending BFV context; they do not prove
its arithmetic. Immutable snapshot borrows provide the in-process freshness scope,
not distributed consensus or a persistent concurrent replay ledger.

All11 runtime rejection controls abort before BFV preparation: omitted index,
tampered index, wrong index page, omitted data, complete group>256, actual posting
page crossing, actual data page crossing, reversed range, stale owner header,
stale index response and stale data response. Source review independently found
no concrete completeness/shape/context defect; unit tests and exact oracle are
still the measured authority, not a cryptographic proof.

Use the module README commands with the reviewed main f46d0bb core and pinned SDK.
The unique package and dedicated target/private-bfv-range avoid same-name shared
artifact collisions. `cargo test --release --locked --offline ...` passes19 tests;
strict authored `cargo clippy --all-targets --no-deps ... -D warnings` passes.
Four unmodified upstream Spiral warnings remain. No extra feature variant,
parameter change, global installation, main edit or commit is part of this run.

Raw ignored JSONL:
`.local/private-bfv-range/private-bfv-range-1000000-2-t8-20261014-230951-755.jsonl`
(SHA25654264AB0F05BBD143DF94CD7A14E40653DF14299FD10A19C9975F40AE353DA07).
It has110 records: provenance+setup+96 exact reads+11 rejections+one replacement.
Measured executable SHA25698668560AD7EB84BFFE760C5EF5D8FBB23441578C2D0BF7A6806BF74F24F9942;
composition main83C9C664AC141AD41A886BCC69AC32BE13F9895856A55D43FDEB13A442F7D123.
The raw provenance includes exact core, kernel, adapter, tests and resource hashes.
