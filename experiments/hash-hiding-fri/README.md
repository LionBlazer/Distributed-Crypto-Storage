# Hash-based hiding-FRI candidate

The implementation has been extracted into the reusable
[`bfv-hiding-stark::hash`](../../crates/bfv-hiding-stark/src/hash/README.md) module
and closed owning proof libraries. This directory retains the original research
record; it is no longer a Cargo package or a duplicate engine implementation.
The [typed extraction analysis](analysis/README.md) adds a standalone finite
dictionary/snapshot model and its direct shared-oracle argument. It is research
code, with no dependency from core or live acceptance path.
The actual Source facade/tests now belong to
[`registry200-proof::source::hash`](../../crates/registry200-proof/src/source/hash/README.md).

This isolated research consumer proves the **actual existing SourceVersion AIR**
with a separate SHA-256 Merkle / full-prefix SHA-512 Fiat–Shamir configuration.
It neither changes production profiles nor enables Predicate journal acceptance.
It is a candidate component, not a completed SQL implementation or a 500 ms result.
The first bounded native measurements are recorded in [VALIDATION.md](VALIDATION.md).

The AIR, encrypted source pages, canonical index relation, private witness, public
state/key commitments and independent expected statement come from
[`registry200-proof`](../../crates/registry200-proof/README.md). This dependency
points from experiment to core; core never depends on this experiment.
`bfv-hiding-stark` supplies the unchanged Gold/EF5 types, hiding parameters and
symbolic algebraic assessment. No owner fixture calculates a query answer.

`source::prove(expected, witness)` returns an **unverified** bounded candidate
frame. `source::verify(independently_expected, bytes)` canonically decodes it and
runs the native verifier with newly constructed AIR/configuration. Success mints
no `VerifiedSourceVersion`, journal, authorization, freshness or SQL capability.
The frame has its own `DCSHSF01` magic and profile digest; the old suite cannot be
selected through it. Decoder sequence/total-element and whole-frame limits apply
before native verification. Source geometry is fixed locally, never decoded as
policy from the sender.

The three implementation modules have distinct ownership:

- `merkle` hashes canonical Gold fields as LE8 words followed by their LE64
  count. Leaf and ordered binary-node encodings have different fixed prefixes.
  The digest remains all 32 bytes; no reduction into Gold loses hash bits.
- `challenger` keeps an unfinalized SHA-512 state of the **entire event prefix**.
  A draw clones that state and appends DRAW/counter/retry. It accepts the first
  LE64 word only below the Gold modulus. Accepted samples themselves join the
  prefix with a different tag. Fields, raw Merkle caps and samples have injective
  typed encodings. Slice/scalar and owned/borrowed observations agree. EF5 is
  five successive uniform Gold draws; FRI indices use the low bits of one Gold
  draw, retaining the previously analyzed index bias.
- `config` fixes the actual Plonky3 0.8.0 hiding PCS: 192 queries, blowup 8,
  extension degree 5, five random codewords, four salt fields per matrix, binary
  FRI, final polynomial length one, cap zero and zero grinding. Separate OS-seeded
  `StdRng` streams own polynomial masks, input salts and FRI salts. No positive
  grinding operation is accepted. Merkle processing is scalar in this candidate.

All literal data/keys in tests are explicitly public nonsecret fixtures. Tests
require an honest native proof and reject changed state (including the same
version tag), changed key, altered native openings, different transcript context,
bad shape, old profile, truncated/trailing bytes and oversized input.
Run optimized owning tests with the pinned toolchain:

```sh
cargo test --release --locked -p bfv-hiding-stark hash:: -- --test-threads=1
cargo test --release --locked -p registry200-proof source::hash:: -- --test-threads=1
```

Native measurements must bound the whole process and report public producer and
independent receiver separately. Their sum covers only this Source component;
Word, DATA, Role3, Query, product certification, network, fresh quorum and locks
are absent. Initial source work may eventually be amortized only under proven
immutable-version retention, not by caching an answer to another query.

## Cryptographic scope and remaining work

This construction removes the known old structural equality between the common
Poseidon leaf sponge and node compressor, and the need to transfer a duplex
theorem to that particular length-tagged implementation. Semantic Poseidon
commitments **inside** the unchanged AIR remain their own explicit assumption.

The proposed model is classical ROM with independent SHA-256 leaf/node domains
and a separate SHA-512 oracle. Domain separation supplies disjoint encoded input
sets, not a proof that concrete hash functions are ideal random oracles. The
[full-prefix Fiat–Shamir construction](https://raw.githubusercontent.com/hash-based-snargs-book/hash-based-snargs-book/main/snargs-book.tex)
and [concrete FRI analysis](https://www.pratyush.site/publication/concsecfri/concsecFri.pdf)
are starting points for the remaining reduction. No quantitative composed
Fiat–Shamir/Merkle bound or production security approval is assigned here.

In particular, each Gold sample uses **64** output bits, not a 512-bit verifier
challenge. The model must group the five codec draws into one EF5 challenge and
account for every hash query/retry, including offline failed attempts. Rejection
is exactly uniform in ROM; a single retry occurs with probability
`(2^32 - 1)/2^64`. Its loop has no deterministic worst-case latency bound. A future
production resource abort must fail closed; it cannot fall back to biased modulo
sampling. Hiding/opening budgets, actual LogUp RBR arguments, Merkle extraction,
all-five-AIR composition, and a new complete live contract remain prerequisites
to adoption. The existing live Predicate guard stays closed.
