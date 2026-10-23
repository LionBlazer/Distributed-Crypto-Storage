# Stable typed Merkle snapshots in a shared classical random oracle

This note gives a direct analysis for the actual binary SHA256 leaf/node formats.
The [finite model](merkle_extraction.py) implements its dictionary/snapshot
algorithm with supplied toy outputs. It does not implement or replace a native
verifier. The result below is conditional on a classical random-oracle model;
it is neither an unconditional SHA256 theorem nor a composed proof assessment.

## Experiment and result

Let H be one uniformly random function from raw byte strings to 256-bit strings.
All applications of this primitive, including auxiliary domains, use its same
query table. A trusted schema fixes one binary tree depth, ordered matrix widths,
base/EF5 flattening, four salts per matrix and physical row order. Each commitment
has one height partition; different commitments may use different schemas.

Allow adaptive raw queries and typed root notifications. Bound the total number
of distinct H queries by T and total notifications by C, including final receiver
verification, prior public preprocessing and any reduction work. Repeated calls
can conservatively be counted in these upper bounds. At the first notification
of each (schema, root), freeze a complete algebraic word as specified below.

Then all later successfully authenticated rows agree with these frozen words
outside a bad event satisfying

```
Pr[Bad] <= min(1, (3*T*(T-1)/2 + C*T) / 2^256).
```

No independence between schemas or openings is assumed. No extra opening-count
factor is needed when verification queries are already included in T. This is
agreement with later valid openings: a defaulted word need not hash to the root.

## Atomic oracle trace and immutable extraction

Maintain a raw input-to-answer table D with creation serials, a reverse table R
that retains the first preimage of each answer, and a target set S. For a fresh
query, sample its answer uniformly. Mark Bad if it equals a previous output or
belongs to S. Insert the new pair. If the raw input is exactly
`NODE_DOMAIN || left32 || right32`, register both child digests in S. This entire
operation is atomic before control returns to the adversary. A repeated query
returns its old answer without creating a fresh bad event.

At a notification, register the root in S and freeze the current serial cutoff.
Cache by the complete (schema, root), preserving the FIRST cutoff. All row lookups
use only preimages present at that cutoff. Later dictionary growth cannot change
a snapshot, including on bad executions.

To obtain a physical row, descend from the root using its fixed index bits. At
positive remaining depth, a known exact binary-node input selects the appropriate
child; missing or wrong-type inputs give an all-zero algebraic row. At depth zero,
accept only a canonical leaf of the exact schema-derived field count. Split it in
ordered matrix order, drop each matrix's four salts, and decode EF5 in the fixed
basis order. All unknown, noncanonical or wrong-width leaves give the same fixed
zero row. Bounded depth terminates even for digest cycles. A lazy row oracle plus
the frozen dictionary cutoff describes a complete word without materializing it.

The actual encodings are

```
leaf = LEAF_DOMAIN || canonical_Gold_LE8* || count_LE64
node = NODE_DOMAIN || left_digest32 || right_digest32
```

Their literal domains are distinct and not prefixes of one another. Counts,
lengths and schema arithmetic are bounded before allocation. The model uses the
same bytes; independent known digests are also checked by the actual native
[LeafHash/NodeCompress tests](../../../crates/bfv-hiding-stark/src/hash/merkle/tests.rs).

## Deterministic path argument outside Bad

Fix any notified root, trusted schema and later successful row opening. Compare
the opening from its root downwards with the frozen dictionary:

1. A digest with a known correct-type preimage must use that same preimage. Any
   different input with its answer creates an output collision. Hence both paths
   descend to the same child.
2. A digest known under a wrong type or width cannot acquire a different valid
   preimage without the same output-collision event.
3. An unknown digest encountered on this descent was already a target when the
   snapshot was frozen: it is the notified root or a child of a node known then.
   A successful opening must evaluate a later input with that digest as answer,
   creating a target hit. Such a branch cannot open successfully outside Bad.

Fixed-depth induction reaches the identical canonical leaf, and therefore the
identical unsalted row. This applies simultaneously to all notified schemas and
all later openings. A node output equal to its own child does not need a separate
same-query hit charge: depth still decreases, and reaching a valid leaf with the
node's digest would require a different-type output collision.

A later independently reconstructed complete public PP tree supplies valid paths
for every row. Counting its reconstruction queries in T therefore makes its word
equal the previously frozen one outside Bad. This requires no inversion of a PP
seed or full Expected. The separate generalized IOP must still check the frozen
word's fixed shape and polynomial degree; arbitrary PP field multiplicities do
not automatically have the owning schema's integer bounds.

## First-bad probability calculation

Immediately before distinct query q there are at most q-1 previous outputs,
2(q-1) registered child targets, and C_q earlier notified roots. These values are
fixed before the fresh uniform answer, even under adaptive interleaved work.
Thus the conditional chance of a first bad event is at most

```
(3*(q-1) + C_q) / 2^256.
```

Union over q=1..T and use C_q<=C. The output-collision terms sum to T(T-1)/2,
child-target terms to T(T-1), and root-target terms to at most CT. This gives the
displayed bound. The argument includes receiver queries and all raw H domains;
using a prover-only budget or treating public prepared trees as free correlated
advice would not satisfy the experiment. Ordinary collision resistance alone
does not account for the earlier-target terms.

Concrete collision-free example: query a node with an unknown child h, notify
its root, then obtain a new leaf output h. The newly opened row can differ from
the frozen default even though no two raw queries share an output. The new output
is precisely an earlier-child target hit. Tests also retain the charge when the
late leaf happens to contain zero and therefore equals the default numerically.

## Native association and remaining composition

Native framing comes from
[merkle.rs](../../../crates/bfv-hiding-stark/src/hash/merkle.rs) and
[the fixed configuration](../../../crates/bfv-hiding-stark/src/hash/config.rs).
Pinned P3 0.8.0 hiding MMCS appends four salts separately to every matrix; the
extension adapter flattens EF5 before inner salting. Receiver-owned dimensions,
matrix order and row indices must map each actual cap to the schema above. The
[owning correspondence note](../../../crates/registry200-proof/src/registry_progress/word/read/NATIVE-RBR.md)
records the equal-height-per-commit source derivation.

Notifications must include caps in every potentially canonical auxiliary/raw
SHA512 prefix at FIRST examination, before later Expected-dependent setup. They
cannot be restricted to the final five proofs' roots. Under the five closed
programs' maximum 17 caps per raw query and 75 final caps, a conservative count
is `C <= 17*Q512 + 75`; the PP-only count is `Q512 + 3`. Applying these ceilings
requires the generalized raw-prefix recognizer and its source correspondence.
The honest complete-stream native test alone does not establish that reduction.

The independent-oracle Merkle multi-configuration theorem is not invoked for our
shared primitive. As precedent, Chiesa--Yogev describe extraction with arbitrary
defaults and stateful multiple extraction; their multiple-configuration setting
uses separate random oracles. See their [author source](https://raw.githubusercontent.com/hash-based-snargs-book/hash-based-snargs-book/main/snargs-book.tex),
`construction:mt-extractor` and `section:merkle-commitment-multi-configuration-multi-extractability`.
The shared-dictionary bound here is derived above rather than attributed to that
theorem.

Remaining obligations include generalized adaptive instance/notification mapping,
uniform native pointwise RBR, the full SHA512 state-restoration simulation,
hiding, product/BFV assessment and external bindings. No live admission guard,
freshness/finality rule, locking policy or protocol profile changes here.
