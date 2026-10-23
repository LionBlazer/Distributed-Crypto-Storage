# Typed online Merkle extraction analysis

This research module makes the shared-oracle snapshot algorithm and its failure
events reproducible. It supports the [direct classical-ROM argument](EXTRACTION.md)
for the fixed SHA suite. It is not imported by a core library, native verifier,
peer or SQL application. Python's standard library is its only dependency.
The recorded checks use Python 3.11.

`merkle_extraction.py` owns deterministic assigned-answer oracle traces, atomic
query/child-target ordering, trusted typed schemas, immutable first snapshots,
canonical base/EF5 leaf splitting, and a separate bottom-up opening check.
Missing query answers fail the experiment; they are never fabricated as a hash.
Supplied digests and all fixtures are explicitly public, nonsecret toy values.

`test_merkle_extraction.py` covers complete trees, late root/child target hits,
zero defaults, cached queries, immutable snapshots, distinct matrix cuts/depths,
cycles, malformed fields/extents and per-matrix salts. Independent byte vectors
also match the actual engine's native leaf/node tests. These finite examples
validate the algorithm; they do not sample a SHA256 random oracle or prove the
probability inequality experimentally.

Run without creating bytecode output, from the repository root:

```sh
python -B -m unittest discover -s experiments/hash-hiding-fri/analysis -p test_merkle_extraction.py -v
```

`exhaustive_merkle_extraction.py` separately enumerates all functions on six raw
inputs to a two-digest alphabet, all stated query/notification prefixes, and all
later openings at depths 0/1/2 under nine typed configurations. Its independent
reference computes openings bottom-up and bad events by pairwise earlier-event
comparisons, without the model's parser or target set. Every surviving opening
must equal the first frozen snapshot, with nonvacuous coverage of all nine
configurations. This is exhaustive only for that finite universe. It prints its
counts and limitations as JSON without creating or overwriting result files:

```sh
python -B experiments/hash-hiding-fri/analysis/exhaustive_merkle_extraction.py
```

The [native receiving test](../../../crates/registry200-proof/src/registry_progress/word/read/NATIVE-TRACE-VALIDATION.md)
separately executes real proofs. Its complete-stream check is not a simulation
of arbitrary adaptive raw oracle queries. Typed notification/source association,
the generalized RBR/FS reduction, hiding, external bindings and SQL admission
retain their explicit obligations. No production cryptographic acceptance or
500ms query result follows from this analysis module.

On 2026-10-23 all 24 behavior/framing examples passed. The separate finite runner
also passed in 8.282s: 127,872 prefix/notification traces, 895,104 valid later
openings, 5,568 replayed without bad events, and 248,832 atomic event traces. Each
of the nine configurations had surviving examples. These counts describe finite
algorithm coverage, not a measured cryptographic error rate or SQL latency.
The ignored r674 result SHA256 is
`8048EA76EE674EC195AC24AC1885316F8180B3D64EECDEB31830A46EF039CED0`;
its source-pinned receipt SHA256 is
`E2ABD482F71F280F511919F72EC789DFAE8FCE110CF2C3F5BC9A0D932CBCE1F9`.
