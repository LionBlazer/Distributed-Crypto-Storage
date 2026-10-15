# Comparing index access privacy

The user requested comparison of both policies; visible accesses have not been
approved as the final design. Both candidates retain owner-only secret keys,
encrypted peer data and an independently authenticated snapshot head.

The latest [paired original-owner restart experiment](experiment-private-bfv-restart-disk-scale.md)
measures both policies on the SAME 1,000 independent million-row tables and full
shared keyset. Complete authenticated exact selection permits eight encrypted
rotate/add steps instead of repeating the encrypted age predicate. The owner
checks every selected age before encryption; inconsistent selections reject.

| Exact-index mode | Maximum complete local hit, ms | Maximum complete local miss, ms |
| --- | ---: | ---: |
| Visible, both header policies | 30.532 | 37.288 |
| Private, cached authenticated header | 219.378 | 279.092 |
| Private, privately retrieved header | 271.467 | 320.674 |

All 384 exact-index matrix answers pass, covering EQ0/1/16/64/256, GE256 and
range21/256, AddressOnly/Fixed256 and supplied table IDs 0/499/999. The paired
FullPredicate control retains one observation above 500 ms (maximum 520.214 ms).
Actual 2,005 dataset files including both sealed checkpoints plus the conservative
observed parent/through-exit serial-child native private peak bound total
5,444,478,278 bytes / 3 GB logical = 1.814826093x in this same run. This does not
establish a 2x bound for tiny tables.

Selections must fit 256 rows, one posting page and one data page. The owner is
online; OS file cache is allowed. PIR conceals within-table addresses; table/root,
operation mode, timing and load events remain public. ExactIndex wire does not
encode predicate kind; its benchmark query labels are owner-side metadata.
Fixed256 equalizes tested wire/RPC shapes, without a formal timing/privacy proof.
Writer actually exits before a new reader restores the original owner keys and
public setups. Reader initialization is 2,047.202 ms separately; the live broker
holds the external wrapping key. Network, arithmetic proofs, general SQL, durable
publication and full-machine recovery remain outside this measurement. The
[earlier disk baseline](experiment-private-bfv-exact-disk.md) remains separately
recorded. Neither leakage policy has been selected.

The [GUI/SQL integration](experiment-bfv-gui-integration.md) now uses the same BFV
arithmetic through the explicit exact-index storage adapter. Its 147 visible-access
operations on 128 public rows across 1/3/16 simulated peers are exact, maximum
383.8544 ms; native peak commit is 246,702,080 B. It introduces no private retrieval.
Its tiny-table sizes and zero virtual delay are separate from the 3 GB disk result
above; combining those measurements would not establish a new latency/storage bound.

The subsequent [multipage comparison](experiment-private-bfv-multipage-disk.md)
uses three independently sealed million-row tables and the same owning BFV core.
Complete selections can span two posting and two data pages, with actual varints
crossing both index boundaries. All 480 operations are exact. For the new Fixed256
schedule, the worst visible local miss is 38.548 ms; private cached-header miss
414.122 ms and private uncached-header miss 491.651 ms. That padded schedule always
performs four page fetches, plus the optional header and fresh BFV, including
absence. The tiny fixture's files plus native peak commit are 43.106627x; it does
not inherit the baseline's 1,000-table overhead result or prove timing privacy.
Neither access policy has been selected.

| Question | Visible accesses | Concealed accesses |
| --- | --- | --- |
| Retrieval | Request the selected encrypted index/data pages directly | Use an oblivious index with ORAM, or suitable single-server PIR retrieval |
| What a peer observes | Page positions, repetition, timing, sizes and visited peers | Protocol traffic and its allowed leakage; padding is needed to hide result length, and timing needs its own policy |
| Search work | A suitable index can select few candidates | Depends on construction: ORAM adds path traffic and state; PIR may process a whole shard for a single private retrieval |
| Data storage | Symmetric page overhead can be small | ORAM dummy slots/rebuild space or PIR layout/preprocessing must also be counted |
| Owner/application state | Keys, trusted head and any cached index nodes | Also position maps/stash or PIR hints, according to protocol |
| Updates | Authenticated index and data changes published atomically | Include oblivious rewriting, state synchronization and hint maintenance |
| Collusion | Colluding peers combine visible traces | Prefer a single-server construction; a two-server noncollusion assumption is a separate unapproved relaxation |
| Malicious results | Authenticate selected data and prove complete selection/computation | Same obligations; private retrieval does not establish correct SQL execution |
| Current measured paths | [BFV GUI exact selection, genuine encrypted aggregates and compact updates](experiment-bfv-gui-integration.md) | [Exact-index disk retrieval](experiment-private-bfv-exact-disk.md) and [two-page composition](experiment-private-bfv-multipage-disk.md) with real PIR and fresh BFV; online owner and explicit page limits |

These compare protocol families rather than promise a universal latency multiplier.
The same query, records, selected result size, thread count, memory, cache and
network profile must be used for an empirical comparison.
ORAM/PIR within one shard does not automatically conceal which shard or peer is
contacted, the requester identity, or subsequent execution traffic. Network routing
privacy and cover traffic are separate protocol and resource choices.

## Concrete concealed candidates

[Path ORAM](https://pages.cs.wisc.edu/~yxy/pubs/PathORam.pdf) reads and rewrites a
randomized tree path, with client position-map/stash state. Its basic padded tree
uses roughly Z times as many block slots as real blocks; the paper discusses
integrity via a Merkle tree and excludes access timing from its privacy definition.
Therefore its basic configuration does not satisfy a strict 2x total data budget
merely by wrapping our compact pages. Other constructions need their own accounting.

[SimplePIR / DoublePIR](https://github.com/ahenzinger/simplepir) are single-server
PIR implementations under LWE. Their 1 GB reference setting needs respectively
121/16 MB client hints and 242/345 KB communication per query; server processing
scans the encoded database. Published throughput is not an end-to-end SQL latency
or our local measurement. Preprocessing and changing databases need separate tests.

The [native local probes](experiment-private-access.md) now test both families
without a noncolluding-server assumption. DoublePIR retrieves a raw three-byte
ciphertext in 215–383 ms, but widening its current geometry to a complete
authenticated page would require a hint above 12 GB. Spiral instead retrieves an
authenticated 2048-row page from the same million-row fixture in 134–143 ms.
It retains a 32 MiB RAM-only NTT cache and about 6 MB serialized public parameters;
canonical data is 1.007861x, before keys and rebuildable hashes. A replacement,
full cache rebuild and fresh private read took 245 ms. These are local component
measurements, with no transport, SQL index navigation or FHE computation proof.

## Composition with FHE

Hiding an index lookup is insufficient if the later execution request reveals the
chosen stored ciphertext, its public nonce, row ID or physical location. A colluding
storage/execution peer could match those bytes against its database. This is a
composition risk inferred from our proposed protocol, not a failure claim about
ORAM or PIR themselves.

The [composed probe](experiment-private-fhe-pipeline.md) privately fetches an
authenticated compact page to the owner's application, verifies/decrypts it there
and freshly TFHE-encrypts the selected fields. The evaluator receives no original
stored bytes, nonce or address. Both modes perform real encrypted >=, COUNT and SUM
on the same million-row fixture: visible reads took 47–51 ms; warm private reads
took 178–204 ms, with a measured combined peak of 418 MiB. This includes both local
exchanges and all cryptographic work, with network/proofs excluded. The private
path sends 498,088 bytes across two sequential round trips.

That initial experiment is a known-row comparison, not a hidden SQL index or computation
proof. The owner is online and sees its selected plaintext. Its availability is an
explicit experiment assumption, not a newly approved requirement. SQL index
navigation, authorized input/output proof binding, shard choice, padding, malicious
feedback/retries and actual transport still need composition work. An accepted
private FHE increment through cache readiness took 382 ms; including a subsequent
private FHE read took 621 ms. Reusing selected stored ciphertext in the later FHE
request would still defeat the intended address privacy.

## Measured indexed comparison

The [next isolated experiment](experiment-private-index-fhe-pipeline.md) now decodes
complete postings from the real authenticated PaddedV2 age index, then retrieves
the selected data through native PIR and sends freshly encrypted fields to FHE.
It compares both access policies on the same million-row fixture, including
complete groups of 0/1/4/16 rows. All 64 complete operations and 19 focused tests
passed. The accepted group must fit one posting page and one data page; larger
groups/pages are explicitly rejected rather than truncated.

With a version-bound 2276-byte owner header cache, visible/private one-row queries
took 62.785–76.697 / 312.547–337.744 ms, and four-row queries
274.514–279.046 / 534.128–550.907 ms, two samples per case. These modes expose
candidate count and request schedule. Sixteen-row private queries took
1084.819–1095.492 ms. Reading the header privately on every query adds another
sequential exchange; first-use costs and all per-case results are in the report.

A second profile always performs one posting read, one data read and sixteen FHE
slots, with freshly encrypted validity bits and actual authenticated dummy PIR
reads for absent results. All 32 fixed-profile public shapes were checked: sizes,
slot counts and RPC counts match across these four cases. Cached private queries
took 1056.427–1222.381 ms and transferred 4,224,082 bytes in three sequential RPCs.
This hides these groups' public cardinality within the stated budget, not arbitrary
query timing, rejected budgets, peer/shard choice or writes. Neither privacy
profile is selected as the final protocol.

Canonical encrypted data plus the padded index occupy 5,065,148 bytes, 1.688383x
the same 3 MB logical fixture. The two native caches consume 64 MiB RAM, and the
whole owner+peer process peaked at 449.90 MiB. The known serialized material
subtotal including fixed keys is 63.913x, with PIR owner-key serialization still
missing; it is not a <=2x whole-system result. An owner-authorized compact
replacement, cache/header refresh and fresh private indexed read took 669.100 ms.
This replacement was not a FHE SQL UPDATE. Computation proofs, active-server
feedback security, independently trusted freshness and distributed publication
remain unresolved.

## Measured byte-limb BFV comparison

The [new composition](experiment-private-bfv-index.md) replaces the scalar TFHE
arithmetic with the separately tested byte-limb BFV core. It performs actual
complete index selection, visible or native Spiral retrieval, authentication,
fresh 16-slot encryption and peer EQ COUNT/SUM. All 64 queries are exact and
under 500 ms locally. Neither privacy policy is selected by this result.

For the padded Fixed16 profile, with two samples per 0/1/4/16-row group:

| Header policy | Visible complete ms, range across tested groups | Private complete ms, range across tested groups |
| --- | ---: | ---: |
| Cached | 81.709–91.881 | 330.006–356.373 |
| Uncached | 82.521–92.211 | 451.596–488.904 |

Both controls always run the same 16 encrypted slots. AddressOnly also uses
fixed BFV geometry here, so its omitted empty reads reveal absence rather than
inherently exposing every nonempty cardinality. Fixed16 additionally equalizes
the tested retrieval lengths and schedules. Visible still exposes page addresses
and repetition. Private Cached/Uncached sends 1,190,756/1,227,685 bytes in 3/4
sequential exchanges; actual network time is excluded.

Native process peak is 690 MB. Canonical data/index remain 1.688383x on the
3 MB logical fixture; known keys/owner payload raise its subtotal to 6.738583x,
with portable PIR secret-state framing still absent. This is not a joint 2x
result. Online-owner, one-page groups, EQ, ready native caches and unverified
arithmetic remain explicit limits. Cold setup is 2459 ms and the owner compact
replacement/rebuild/fresh read is 695 ms; no BFV UPDATE is implemented.

The subsequent [owner-state recovery module](experiment-spiral-owner-state.md)
provides an actual 336-byte secret envelope and tests restored-client PIR reads
against the retained original 6,029,344-byte public setup. Its live secret matrices
remain a separate RAM cost. This closes the earlier secret-backup framing gap for
that pinned profile; it does not retime or replace the frozen single-table ledger,
provide authenticated durable backup, or establish a combined 2x result.

## Latest retained-table and range comparisons

The [twenty-table experiment](experiment-private-bfv-amortization.md) now keeps
all independent snapshots and forty native caches live under the decimal 2 GB
process guard. All 192 full paired EQ reads are exact and below 436 ms. Fixed16
Visible takes 77–91 ms, Private Cached 297–321 ms and Private Uncached 406–429 ms,
covering 0/1/4/16 complete candidates and supplied first/middle/last table IDs.
Two samples per cell are observations, not a percentile latency guarantee.

For 60 MB logical data, canonical images plus shared key/owner known payload are
1.938696x, or 1.959699x with Merkle payload. All retained NTT overlays alone are
1.342 GB; canonical once plus known auxiliary representations is 24.729909x,
before unpartitioned native BFV key/container costs. Native peak RSS/commit is
1.710/1.717 GB. Therefore the smaller image/key subtotal is not a full-state 2x
claim. Actual primary files, resident snapshots, native process memory and
remaining backup limitations are separately accounted in that report.

A [separate Rows256 composition](experiment-private-bfv-range.md) performs 96
actual reads over one million-row table, with complete posting selection and
the same private/visible choices. Ranges cover 21 or 256 selected rows; EQ covers
0/64/256, and GE is tested at 256. Both AddressOnly and Fixed256 are measured:

| Supported operation | Visible ms, both header modes | Private Cached ms | Private Uncached ms |
| --- | ---: | ---: | ---: |
| EQ64/256 | 83.67–99.43 | 320.45–330.18 | 436.31–455.34 |
| GE256 | 125.66–134.83 | 361.53–374.76 | 469.91–482.11 |
| Ranges21/256 | 208.46–230.59 | 446.75–469.86 | 567.52–590.72 |

All 96 answers are exact, including unsigned COUNT256/SUM16776960. All eight
private uncached range observations exceed 500 ms; they are retained as failures
of that latency target. Native peak RSS/commit is 352/357 MB. This Rows256 run has
its own larger public setup and one-table ledger; its timings cannot be combined
with the separate twenty-table Rows16 storage subtotal as one measured system.

Both compositions retain the online-owner, complete one-posting-page and
one-data-page budget, ready native caches and unverified arithmetic. PIR hides
page choice within the supplied table; table/root identity, public predicate
kind, timing and rejected budgets remain visible. Network, consensus, general
SQL, durable complete owner recovery and arithmetic proof costs remain absent.
Neither leakage policy has been selected.

The subsequent [native trial scheduling control](experiment-private-pir-batch.md)
preserves exact serialized responses for the same queries, while executing the
four independent database trials concurrently. Its 32 full range reads compare
Official and ParallelTrials on the same fixture. Private Cached ranges improve
from 458–466 to 414–424 ms; Uncached improves from 574–590 to 508–531 ms. All four
candidate uncached observations still fail the 500 ms target. Query expansion
remains the main cost. Separate independent-request batch results describe
amortized throughput and do not establish an individual-query latency bound.

A further [query-expansion scheduling comparison](experiment-private-pir-expansion.md)
keeps the original sequential rounds and runs independent siblings with fewer
barriers. The SDK already parallelizes within each half; the gain comes from
scheduling and early-round utilization. All 26 direct expanded-buffer/serialized
response controls agree with the original implementation. In 32 full range reads,
Combined private Cached takes 379–393 ms and Uncached 456–465 ms; all four tested
uncached cases now fit 500 ms, compared with 506–525 ms for TrialsOnly. These are
ready-cache measurements. Reading files and rebuilding a cache after eviction
still require a separate full-operation test.

The [disk-backed comparison](experiment-private-bfv-disk.md) now includes those
costs on three independent million-row tables, with capacity for exactly one
loaded table/cache pair. All 288 same-table matrix answers are exact. Visible
queries take 84–254 ms across hits/misses; private cached-header maxima are
382 ms hit and 437 ms miss. Private uncached-header ranges reach 465 ms hit and
514 ms miss: two misses still exceed 500 ms. All observations, including the
slower baseline, are retained. Native peak RSS/commit is 355/361 MB. These are
application-cache misses through real file APIs with OS cache allowed, an online
owner and live shared keys; physical cold disk, network and arithmetic proofs
remain unmeasured. The small three-table files+peak-memory total is 44.01x,
so this result does not establish full-state 2x.

The subsequent [actual 1,000-table run](experiment-private-bfv-disk-scale.md) uses
the same implementation and one loaded table/cache pair. For 3 GB logical data,
2,003 files plus native peak private commit total 5,449,801,056 B (1.816600352x).
All 288 same-table answers are exact. Visible queries take 83–251 ms; private
cached-header maxima are 406 ms hit and 456 ms miss. Private uncached-header
ranges reach 477 ms hit and 519 ms miss, with all six tested misses above 500 ms.
These are the same bounded local privacy/owner assumptions, with OS file cache
allowed and no transport or arithmetic proof. Neither policy is selected.

A range or JOIN may visit many pages even with an index. A hidden point lookup
does not establish a hidden general SQL planner. A complete comparison must cover
absent keys, repeated keys, duplicate groups, indexed-field changes, access padding,
concurrent clients, failure recovery and peak rebuild space. The benchmark ledger
is [optimization-goal.md](optimization-goal.md).
