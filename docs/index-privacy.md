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
| Current local code | [Owner-built age index with genuine FHE and compact updates](experiment-compact-query.md) | [Composed authenticated Spiral page retrieval and fresh FHE](experiment-private-fhe-pipeline.md); no hidden SQL index navigation yet |

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

This is an implemented known-row comparison, not a hidden SQL index or computation
proof. The owner is online and sees its selected plaintext. Its availability is an
explicit experiment assumption, not a newly approved requirement. SQL index
navigation, authorized input/output proof binding, shard choice, padding, malicious
feedback/retries and actual transport still need composition work. An accepted
private FHE increment through cache readiness took 382 ms; including a subsequent
private FHE read took 621 ms. Reusing selected stored ciphertext in the later FHE
request would still defeat the intended address privacy.

A range or JOIN may visit many pages even with an index. A hidden point lookup
does not establish a hidden general SQL planner. A complete comparison must cover
absent keys, repeated keys, duplicate groups, indexed-field changes, access padding,
concurrent clients, failure recovery and peak rebuild space. The benchmark ledger
is [optimization-goal.md](optimization-goal.md).
