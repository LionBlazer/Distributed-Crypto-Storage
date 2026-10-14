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
| Current local code | Direct authenticated row-address retrieval experiment | No measured implementation yet |

These compare protocol families rather than promise a universal latency multiplier.
The same query, records, selected result size, thread count, memory, cache and
network profile must be used for an empirical comparison.

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

## Composition with FHE

Hiding an index lookup is insufficient if the later execution request reveals the
chosen stored ciphertext, its public nonce, row ID or physical location. A colluding
storage/execution peer could match those bytes against its database. This is a
composition risk inferred from our proposed protocol, not a failure claim about
ORAM or PIR themselves.

One candidate privately fetches an authenticated compact page to the owner's
application, then freshly masks the selected encrypted bytes and supplies an FHE
mask token to the evaluator. The token must bind the intended query and snapshot
without revealing the selected stored nonce/address. This is a proposal, not an
implemented proof or an approved requirement for owner availability. Costs include
the private fetch, fresh input preparation, FHE execution, verification, and any
second network exchange. Reusing unchanged selected bytes would defeat this goal.

A range or JOIN may visit many pages even with an index. A hidden point lookup
does not establish a hidden general SQL planner. A complete comparison must cover
absent keys, repeated keys, duplicate groups, indexed-field changes, access padding,
concurrent clients, failure recovery and peak rebuild space. The benchmark ledger
is [optimization-goal.md](optimization-goal.md).
