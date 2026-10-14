# Comparing index access privacy

The user requested comparison of both policies; visible accesses have not been
approved as the final design. Both candidates retain owner-only secret keys,
encrypted peer data and an independently authenticated snapshot head.

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
| Current local code | [Owner-built age index with genuine FHE and compact updates](experiment-compact-query.md) | [Real encrypted age-index and data PIR with fresh FHE](experiment-private-index-fhe-pipeline.md), online owner and bounded one-page groups |

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

A range or JOIN may visit many pages even with an index. A hidden point lookup
does not establish a hidden general SQL planner. A complete comparison must cover
absent keys, repeated keys, duplicate groups, indexed-field changes, access padding,
concurrent clients, failure recovery and peak rebuild space. The benchmark ledger
is [optimization-goal.md](optimization-goal.md).
