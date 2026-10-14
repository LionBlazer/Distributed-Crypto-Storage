# Actual authenticated private index -> Spiral -> byte-limb BFV

Status 2026-10-15: the new isolated composition passes 64 complete one-million-row
EQ COUNT/SUM queries and a fresh read after an actual owner-authorized compact
replacement. All 64 observed query times are below 500 ms locally. For the fully
padded Fixed16 profile, the private 16-row reads are 337.253–338.899 ms with a cached
owner header and 451.596–452.371 ms with an uncached header (two samples each).
This is a measured whole operation, not a sum of independent subsystem timings.

The scope remains narrow: online owner, complete age groups of at most 16 rows
that fit one posting page and one data page, already constructed in-memory
native PIR caches, EQ, and unverified BFV arithmetic. It establishes neither a
network 500 ms bound nor >=128-bit independent BFV security/noise validation,
arbitrary SQL, hidden writes, a BFV UPDATE or malicious-peer query proofs.
Cold setup takes 2459.280 ms. The complete measured compact replacement, cache
rebuild/header refresh and fresh private read takes 695.437 ms.

The [standalone package](../experiments/private-bfv-index/README.md) adds new
sources only. The earlier private TFHE and multi-bit probes stay unchanged.
The [extracted BFV core](../experiments/bfv-byte-limb-core/README.md) owns only
BFV roles; it has no storage, PIR, SQL, fixture or TFHE dependency.

## Actual operation and trust boundary

1. The owner chooses independently trusted complete 112-byte data/index heads.
   Uncached reads and authenticates the real encrypted index header; Cached
   restores the owner metadata only if both exact head encodings match.
2. Complete authenticated per-age counts preflight the 16-row bound. Real
   PageSource callbacks fetch serialized responses through actual native
   Spiral for Private, or an explicit page request for Visible. Membership
   verification precedes owner AEAD decryption. The PaddedV2 decoder obtains
   every selected ordinal from decrypted delta-varint postings; no fixture
   selector or guessed address supplies the operation's ordinals.
3. The owner authenticates/decrypts the actual selected data page and extracts
   age:u8 and amount:u16 by each decoded ordinal. A second-page posting or
   data requirement is rejected, never silently truncated. The source codec
   itself retains its broader tested page decoder; this wrapper declares the
   narrower operation budget.
4. The owner freshly encrypts all 16 BFV input slots, the EQ target and value
   weights, using the core's Rows16 geometry. Active rows have low/high/count
   weights amount&255, amount>>8,1; inactive rows have encrypted 0/0/0 weights.
   The actual active count stays only in the one-use owner pending token.
   Even absent results perform the complete encrypted predicate and SUM/COUNT
   circuit: 5 ciphertext products, 7 rotations, depth 5.
5. Public-only PeerEvaluator decodes the real bounded serialized request,
   evaluates BFV, then serializes its encrypted answer. It receives no store,
   original storage ciphertext/nonce/page/ordinal, AEAD/PIR/BFV secret key or
   plaintext fields. Both complete global heads and a fresh 128-bit query ID
   are the public context. The owner rechecks its trusted heads against the
   pending token, checks output context before secret decryption, and returns
   UnverifiedAggregate with ProofStatus::Unavailable.

The whole timer starts before header handling and ends after answer decode,
context checks and owner decryption. It includes native PIR request/response
serialization and recovery, membership/AEAD work, posting decode, fresh BFV
preparation/serialization, peer decode/evaluation/encode and owner decode.
It also conservatively includes 0.65–1.1 ms ciphertext-only freshness evidence
in representative cases; that check excludes IDs/heads/geometry. Setup and
after-timing public-fixture oracles are separate. Stage counters overlap:
index_verify_decrypt_select_ms includes header and posting work, so those
counters must not be added to that subtotal again.

The owner is online and already reads the selected plaintext before encrypting
BFV inputs. This is not offline-owner execution or universal transciphering.
The single-process harness holds role objects for both parties so its measured
native peaks include owner and peer allocations together. Immutable snapshot/
head borrows prevent an in-flight write in this harness; there is no persistent
concurrent freshness/replay ledger or remote head-distribution protocol.

## Profiles and actual leakage

Both profiles use the same fixed 16-slot BFV circuit and real ciphertexts in both
access controls. Neither BFV request serializes actual active cardinality.
For this one-page workload, AddressOnly reveals empty versus nonempty by its
omitted posting/data calls; it does not inherently reveal 1 versus 4 versus 16
from BFV lengths/RPC counts. Owner-side public-fixture result logs are not peer
wire. This experiment does not approve an access-leakage policy.

Fixed16 always performs one authenticated posting and one authenticated data
read. Absent results use real native PIR reads of authenticated dummy pages,
then inactive encrypted value weights. Assertions compare request/response
byte lengths and sequential RPC counts across all four cardinalities for
each access/header mode. Visible discloses the actual requested page addresses
and repetition; Private uses freshly randomized native encrypted queries.
Fixed16 equalizes the measured read schedule/lengths, not every active-network
timing, abort or malicious-response feedback channel.

Both modes reveal the selected public profile, header mode, fixed table/cache
geometry, predicate kind EQ, global heads/versions, setup material, timing and
write/cache-rebuild events. Private addresses rely on native Spiral's declared
single-server assumptions; colluding storage peers are not treated as two
non-colluding PIR servers. Active-response corruption/decryption feedback
remains an open composition issue. The peer obtains no owner secret key.

Cached holds 2276 B: 2052 B counts/offsets and 224 B duplicated complete head
bindings; the independent trusted heads are separately counted 224 B. It is
installed/refreshed by a real private authenticated header read. Uncached
fetches that header each query. Cached/nonempty and all Fixed16 operations
have 3 sequential request/response exchanges (posting,data,BFV), Uncached has 4.
AddressOnly/absent has 1 Cached or 2 Uncached exchanges, including real BFV.

## Fixed parameters and reproducibility

BFV is fhe/fhe-traits=0.1.1's official default_parameters_128(17) N=8192
entry, t=114689, coefficient primes
8796092858369,8796092792833,17592186028033,17592185438209,17592184717313
(bits 43,43,44,44,44; total 218). Initial/output level 0, unchanged CBD(20)
variance 10 for secret/error, native NTT, unfused GE and additive-only range
implementation are retained. This composition measures EQ only. It does not
inherit the standalone core's GE/range timing as a composed measurement.
The runtime gate compares exact actual parameters, geometry and implementation
profile between owner and peer and records actual serialized key counts.

The release's ABOUT128 label remains conditional evidence, not an independent
>=128-bit result. Worst-case noise/security estimates remain open, especially
after a separately preserved deeper range failure in the
[standalone arithmetic probe](experiment-bfv-byte-limbs.md). No parameter is
weakened or substituted in this composition. The core's bounded unsigned
decode enforces COUNT <= active_rows <= 16, each limb <= 255*COUNT <= 4080, and
SUM = low+256*high <= 65535*COUNT <= 1,048,560. These are sanity bounds, not a proof.

Spiral source is pinned to
[fdb7206517c249603b0c91b65f1f29f95272107c](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs).
Its unchanged CFG_20_256 parameters use 512 fixed 8192-byte records per database
(nu1=7, nu2=2): N=2048, CRT 268369921/249561089, p=256, q2_bits=20,
t_gsw=8, t_conv=4, t_exp_left=8, t_exp_right=56, n=2, Gaussian width 6.4.
The width is the sampler's s, not a claim of sigma 6.4. The earlier
[private-access report](experiment-private-access.md) records its precise
assumptions, unaudited source boundary and unsuccessful DoublePIR alternatives.

The index adapter and contract-test files are byte-identical to the frozen
6763556 adapter: codec 05A3BAF2AD3AB697B3CC9AD8EEB1B392D1C5B34FDB06AD3DFE0101ABF89F44ED,
tests 1D649C6E9C05DDA25221BBFC9671146076057731FF2574B37DD7FA5092A63EE4.
The codec adds transport callbacks to that current PaddedV2 format, rather
than equating a callback with proof of current data. The main index source
at the inspected f80065e revision has no difference from 6763556.

The new unique package and dedicated target/private-bfv-index avoid known
same-named shared-target stale artifacts. Core/adapter/composition source
hashes are in the raw run's first record. Core lib 6576ADF2F81F886D3C6CA0480566E920C8DCADB9F6CF3D4AA0418D5AE9E7DD12;
kernel 1D719AA6193470C6F3B8C7D28FBC56A87A90D4D14E152A9CE63E5FF47400AE54.
Use the [runner](../experiments/private-bfv-index/run.ps1) and its module
README commands. No dependency installation outside project-local Cargo
cache/target, vendor commit, UI or network service is required.

## Complete paired latency measurements

Exclusive CPU lease, existing Windows Rust 1.99/MSVC toolchain, 8 Rayon threads,
maximum 13 native threads observed, native process sampling every 25 ms.
Rounds 8 means two samples of each age/profile/header/access cell: 64 queries.
The public million-row fixture has complete age 250/251/252/255 groups of
1/4/16/0 rows, respectively. Their exact aggregate sums are 100/810/5000/0.
All fixture ordinals/result comparisons occur after the whole timer.

Each time cell is minimum/median/maximum in milliseconds; n=2 in EVERY cell.
No mixed-cardinality median or throughput-to-latency conversion is used.

| Profile | Header | Age (rows) | Visible min/median/max ms | Private min/median/max ms |
| --- | --- | ---: | ---: | ---: |
| AddressOnly | Cached | 250 (1) | 83.410/88.997/94.585 | 339.216/342.342/345.469 |
| AddressOnly | Cached | 251 (4) | 80.615/85.028/89.442 | 332.113/335.334/338.554 |
| AddressOnly | Cached | 252 (16) | 90.127/90.408/90.688 | 332.128/341.581/351.034 |
| AddressOnly | Cached | 255 (0) | 80.383/86.383/92.383 | 87.688/91.406/95.124 |
| AddressOnly | Uncached | 250 (1) | 81.543/87.044/92.545 | 458.633/462.953/467.273 |
| AddressOnly | Uncached | 251 (4) | 85.854/89.542/93.231 | 450.198/457.928/465.657 |
| AddressOnly | Uncached | 252 (16) | 85.753/87.125/88.496 | 457.505/459.064/460.623 |
| AddressOnly | Uncached | 255 (0) | 84.407/86.860/89.313 | 209.171/213.482/217.794 |
| Fixed16 | Cached | 250 (1) | 83.194/86.093/88.992 | 334.199/335.014/335.829 |
| Fixed16 | Cached | 251 (4) | 86.708/89.294/91.881 | 333.104/337.607/342.110 |
| Fixed16 | Cached | 252 (16) | 81.709/84.811/87.912 | 337.253/338.076/338.899 |
| Fixed16 | Cached | 255 (0) | 82.365/83.747/85.128 | 330.006/343.190/356.373 |
| Fixed16 | Uncached | 250 (1) | 84.583/86.096/87.610 | 457.033/461.949/466.865 |
| Fixed16 | Uncached | 251 (4) | 82.521/84.405/86.289 | 453.365/459.099/464.833 |
| Fixed16 | Uncached | 252 (16) | 86.740/87.016/87.291 | 451.596/451.984/452.371 |
| Fixed16 | Uncached | 255 (0) | 85.204/88.707/92.211 | 452.819/470.861/488.904 |

The first actual query (Private, AddressOnly, Uncached, age 250) is 467.273 ms.
It includes the query's full operation after construction; it does not include
the 2459.280 ms one-time setup. Fixed16's slowest observed query is the uncached
absent 488.904 ms. Two samples are not a tail guarantee and leave little network
headroom. No network transmission, durable disk, restart or remote peer was
measured. An actual 1.23 MB exchange over sequential RPCs can materially change
the total.

For Fixed16/Cached/16, fresh BFV preparation is 8.763–11.029 ms, actual encrypted
peer evaluation 69.024–74.664 ms, and owner output decode/decrypt 3.217–3.527 ms
in Private. These are measured nested stages of 337.253–338.899 ms totals,
not a substitute for the complete operation measurement.

## Exact bytes, keys and native memory

All expansion factors use the same 3,000,000 B logical plaintext denominator.

| Resource | Measured bytes |
| --- | ---: |
| Canonical data, 2048 rows/page; 489 pages | 3,023,584 |
| Canonical PaddedV2 index, 4096 B/page; 493 pages | 2,041,564 |
| Canonical combined | 5,065,148 (1.6883827x) |
| Retained data/index Merkle hashes, separately | 31,392 /31,616 |
| Shared native PIR public wire | 6,029,344 |
| Expanded native PIR public polynomial payload RAM | 23,855,104 |
| BFV parameter wire /relinearization key /rotation keys | 46 /1,116,273 /7,813,957 |
| Complete serialized BFV public setup | 8,930,306 |
| BFV owner secret serialized count | 8,195 |
| PIR owner base /derived secret payload counts (not serialization) | 49,152 /131,072 |
| Compact owner secret /independent trusted heads | 32 /224 |
| Cached owner header, including duplicated heads | 2,276 |
| Known joint canonical+keys+owner state subtotal | 20,215,749 (6.738583x) |
| Retained transient data/index native NTT cache RAM | 33,554,432 each; 67,108,864 total |
| Temporary one-database record buffer | 4,194,304 |
| Fixture setup capacities, dropped before queries | 7,000,000 |
| Native whole-process peak working set | 690,491,392 |
| Native whole-process peak private commit | 697,425,920 |

The known joint subtotal includes the two PIR owner payload counts, so it is
not a claim that every secret has a portable serialized representation. It
counts canonical snapshots, one shared public PIR setup, one BFV public setup,
BFV owner secret count, PIR base/derived payloads, compact key, trusted heads
and owner header. Portable PIR owner-secret serialization/framing is not
implemented: matrix/allocator headers, sampler/CDF and parameter/scratch
containers are excluded from that named payload subtotal. The native combined
process peaks include those live allocations and transient RNG/key work.
Consequently the known subtotal is not a complete portable owner-state image.
Native NTT overlays are retained RAM and persisted 0 B; they
must be counted as stored bytes if a future implementation persists them.
No permanent FHE rows, precomputed query answers or plaintext peer index exist.
The native peaks measure the actual combined process, including transient
BFV setup/key restoration; they are not sums of independently measured peaks.
Both current/native-peak resident and private-commit counters are gated at
2,000,000,000 B. Peak RSS is 658.504 MiB and commit 665.117 MiB.

The canonical table/index meets 2x for this layout, but the single-table known
joint key subtotal does not. Sharing 15,148,069 B fixed material across identically
sized independent tables is only an arithmetic next-stage hypothesis: 17 tables
would give 1.9862476x without retained hashes, 18 would give 1.9907491x including
their hashes. Those multi-table retention/RAM/latency/lifecycle cases were not
run here; no <=2x joint-system claim is made. A fresh retained-state experiment
must count all tables, owner state, caches, key sharing, versions and peak RAM.

## Actual serialized request and response traffic

BFV always sends 670,134 B request and 446,764 B output for EQ/Rows16: 1,116,898 B
total before retrieval. A private page request is 16,449 B including store/head
framing and its answer 20,480 B. Visible page requests are 41 B; actual full index
and data responses in this fixture are 4448 B and 6496 B.

| Operation shape | Private request B | Private response B | Total B | RPCs |
| --- | ---: | ---: | ---: | ---: |
| Nonempty Cached; any Fixed16 Cached | 703,032 | 487,724 | 1,190,756 | 3 |
| Nonempty Uncached; any Fixed16 Uncached | 719,481 | 508,204 | 1,227,685 | 4 |
| AddressOnly absent Cached | 670,134 | 446,764 | 1,116,898 | 1 |
| AddressOnly absent Uncached | 686,583 | 467,244 | 1,153,827 | 2 |

Visible nonempty/Fixed16 traffic is 1,127,924 B Cached and 1,132,413 B Uncached,
with the same respective 3/4 RPCs. Setup public material is a separate actual
14,959,650 B wire total (Spiral+BFV). Transport envelopes/remote framing are not
invented or counted as measured network bytes.

## Setup, replacement and rejected inputs

One measured setup includes data sealing 4.715 ms, complete index build/seal
9.257 ms, canonical encode/decode 4.124 ms, Spiral key setup 441.267 ms,
data/index record construction 0.672/0.589 ms, data/index native NTT
114.537/107.653 ms, BFV key generation 582.079 ms, public serialization/secret
byte count 13.770 ms, actual public BFV decode/key restore 1055.754 ms, and
real private header installation 121.553 ms. The whole setup is 2459.280 ms;
reported nested stages need not add exactly because lifetimes/bookkeeping
are also measured by the whole timer.

After 64 queries, the actual owner changes amount 100->101 in canonical data
page 0 with replace_page, rebinds index page 0 to the new full data head, drops
both old NTT caches, builds the actual two new caches, privately refreshes the
owner header and runs a fresh private Fixed16 query from the index again.

| Actual replacement lifecycle stage | ms |
| --- | ---: |
| Canonical data replacement +index rebind | 0.070 |
| Data records +native NTT rebuild | 0.720 +119.933 |
| Index records +native NTT rebuild | 0.573 +106.488 |
| Actual private authenticated header refresh | 122.876 |
| Replacement through caches/header ready | 352.587 |
| Full private index->PIR->BFV read after replacement | 342.812 |
| Whole replacement +cache/header refresh +fresh read | 695.437 |

Canonical data/index sizes remain byte-for-byte equal in length, COUNT 1/SUM 101
is exact, and neither old cache is retained while creating its replacement.
This is an owner-authorized compact replacement, not an FHE/BFV UPDATE.
Write addresses and global version changes are visible; durability/recovery/
private write protocols are not implemented.

The run injects omitted index/data responses, a tampered authenticated index
response and a valid response for the wrong index page at the real untrusted
wire boundary. After replacement it injects stale owner header, stale encrypted
index response and stale encrypted data response. All seven abort with the
BFV preparation counter unchanged. A complete common-age group above 16 also
rejects before preparation. Copied codec tests cover malformed varints,
duplicate ordinals, corrupted authenticated count/offset/head metadata,
uniform/skew/random/single-age complete selection, true callback fetching,
padding integrity and cross-page/budget rejection. These checks do not prove
index consistency against an equivocating owner or malicious BFV computation.

## Evidence and next boundary

16 focused release tests and authored strict Clippy pass; the extracted core
separately passes its 10 role/arithmetic tests. The frozen upstream Spiral
dependency emits four existing lifetime/static-mut warnings; its CLIENT_TEST
debug hook remains untouched and receives no owner key. No unreviewed
debug shortcut is enabled.

The prototype checkout independently reran the 16 composition tests and strict
Clippy after preparing a fresh pinned SDK clone, and reran the core's ten tests.
An independent raw-record audit checked all 64 exact results, all 32 Fixed16
public shapes, seven pre-prepare rejections, parameter/byte accounting and the
real replacement read. Timings above remain the original isolated run.

Raw ignored report:
.local/private-bfv-index/private-bfv-index-1000000-8-t8-20261014-223457-360.jsonl
SHA256 F6866157CD521053A702F40F8FC2A540FC314493D38F09F92EA00A5BE81DB507.
It contains source hashes, actual parameter/key setup, 64 complete queries,
seven rejection records and the successful real replacement/fresh-read record.
The executable exits successfully only after every correctness, freshness,
shape and complete-group/budget assertion passes.

The useful next boundary is a retained multi-table key/cache lifecycle plus
actual network/disk operation, while independently resolving BFV security and
worst-case noise. General range/index navigation, groups spanning pages or
above 16, arbitrary SQL, remotely trusted current heads, concealment under
active feedback, private writes and computation/SQL-completeness proofs remain
open. The overall optimization goal remains active.
