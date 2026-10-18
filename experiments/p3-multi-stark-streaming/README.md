# Streamed counted lookup witnesses

This isolated experimental source copy of p3-multi-stark0.8.0 adds an opt-in
`streaming-lookups` prover implementation. It removes dense lookup leaf storage
and the retained fractional-GKR tree. It does not change AIR arithmetic, lookup
planning, proof types, verifier, transcript, commitment scheme, security analysis
or proof caps. No SQL, freshness, query privacy or admission policy is added.

The original checksum-pinned registry SDK and its cache remain untouched.
[UPSTREAM.json](UPSTREAM.json) records all83 packaged file hashes and exact VCS
revision. [LICENSE-MIT](LICENSE-MIT) contains the chosen upstream MIT permission;
Cargo.toml.orig preserves the original manifest, and UPSTREAM.json records the
original archive lock hash. The current Cargo.lock is the reviewed resolution for
this standalone workspace. Ten upstream path-only development dependencies,
omitted from the normalized registry manifest, are restored; p3-goldilocks is
added for the new EF5 parity test. All eleven direct edges are pinned at0.8.0.
All resolved p3 packages remain0.8.0. Root workspace members, default members,
dependencies and lock are unchanged; this package is not a default core dependency.

## Responsibilities and public contract

| Owner/dependency | Responsibility |
| --- | --- |
| [Lookup plan/reduction](src/lookup/mod.rs) | Unchanged AIR-derived bus/contribution order, multiplicity bound and public prove dispatch |
| [Bounded leaf source](src/fractional_gkr/materialize/streaming.rs) | Reuse original symbolic row evaluation over the SAME committed main/preprocessed table views |
| [Streamed GKR](src/fractional_gkr/streaming.rs) | Root prepass, one requested reduced layer, direct first leaf fold; original round kernels |
| [AIR-link shares](src/lookup/streaming.rs) | Recompute private per-AIR shares from those same leaves after theta |
| p3-air/lookup/field | Existing symbolic expressions, finite-field and counted lookup semantics |
| p3-multilinear-util/sumcheck | Existing scalar/packed polynomials, layout and equality/folding kernels |
| p3-challenger/security/commit | Existing transcript contracts, analytical assumptions and PCS interfaces |

The published `prove`, `prove_with_backend` and `prove_with_security` signatures
are unchanged. With no feature, the original dense implementation runs. With
`streaming-lookups`, only the counted LogUp witness reduction and its private
share calculation use the new path. Indexed LogUp-star, binary buses and
zerocheck backend selection retain their existing implementations. There is no
public provider, callback, trusted root, serialized prefix or checked receipt.
The original dense GKR/materialization remain available as the parity reference.
The unchanged verifier still authenticates terminal claims against the actual
committed AIR tables and PCS openings.

## Lifecycle and invariants

The source owns only a fixed row scratch, immutable table views, plan-derived
contribution metadata and alpha/beta powers. Each leaf uses the original exact
height/declaration/bus offset, payload and multiplicity expression, public inputs,
first/last selectors and clamped final next row. The unused tail is exactly0/1.
Request indexes and representable allocation dimensions are checked before row
access. This is shape validation, not a new global RAM or CPU quota.

A root prepass reduces leaves by the SAME prefix-bit pairing. For each subsequent
root-to-input bracket, the prover regenerates only that current four-array layer;
its consumption drops those arrays before the next layer. Packed arrays are filled
directly without a full scalar clone. The first input round streams the leaves;
its equality vector is dropped before the folded arrays are allocated. Private
per-AIR link shares are regenerated after theta using split equality factors,
not rematerialized leaves. No witness data is spooled to disk.

The complete original statement/commitments still precede alpha/beta. Root
numerator/denominator checks, lambda, round polynomials, challenges, closing
claims/branch draws and final theta have exactly the original order. Recomputing
lookup witness expressions happens only in the PROVER. The verifier does not
rerun the query, NTT or witness generation. Current source/row storage is ordinary
allocator memory; neither this feature nor upstream promises secure erasure or
hiding. Streaming does not turn the existing non-hiding protocol into a private
query proof.

## Candidate resource bound and verification

For Goldilocks/EF5 and a padded lookup cube N=2^24, the original dense leaves cost
48N bytes and all reduced layers80N-160 bytes:2,147,483,488B before equality,
trace/PCS data and allocator overhead. The new largest current layer has four
quarter-length EF arrays:40N=671,088,640B. Its equality suffix costs at most
5N=83,886,080B. The separately lived first input equality costs10N bytes and is
dropped before that layer. Thus the principal GKR arrays have a provisional
45N=754,974,720B bound, plus bounded packing scratch, plan/row metadata and
O(log(N)^2) proof messages. Vec truncation is not counted as releasing capacity.

This is an ARRAY calculation, not a whole-process RSS/1-2GiB PASS. Committed trace,
preprocessing, WHIR/PCS state, keys and allocator behavior remain resident outside
it. Regenerating layers adds prover work, approximately one leaf pass per layer;
actual batch4 time and complete-process memory still require Root measurement.
No proof cap, security floor or composition assumption is weakened to achieve fit.

The [native validation](VALIDATION.md) passed513 dense and514 streamed runtime
cases:1027 invocations and514 distinct cases, including all11 added cases.
Tests compare dense/streamed proof bytes, openings and final challenges for tiny,
scalar, packed, base and genuinely extension-valued numerators, including binary
interpolation nodes and actual Goldilocks/EF5. Matched fraction pairs are permuted
so cancellation occurs only at the full root; direct rational subtree sums assert
nonzero intermediate numerators independently of the reduction algorithm. They compare every multiheight/local/global/preprocessed
leaf and neutral padding, private shares and public dispatch, reject malformed
shape/index input, and link a genuine foreign reduction to the actual AIR
zerocheck. One feature-gated inherited consumer test creates a complete WHIR proof,
roundtrips its canonical bytes, closes a fresh original verifier transcript and
rejects damage. All inherited test bodies remain intact. The three copied
serialized compatibility fixtures are public, nonsecret upstream test inputs;
their bytes remain unchanged. Exactly two originally ignored fixture-writing
tests are excluded from the native gate so validation does not rewrite them.

~~~text
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --lib
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --lib --features streaming-lookups
~~~

The validation record gives the complete six-integration-target command and
explicit fixture-writer exclusions. Use a fresh target and the reviewed lock.
The original verifier/proof/security/full transcript source files remain
byte-identical to UPSTREAM.json. Small SDK regressions do not establish complete
NTT batch performance, process RAM, private query proofs or SQL acceptance.
