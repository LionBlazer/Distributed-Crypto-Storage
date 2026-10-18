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
| [Prover batch](src/instance.rs) | Caller-local resident/streaming storage choice, excluded from the statement and verifier |
| [Lookup plan/reduction](src/lookup/mod.rs) | Unchanged AIR-derived bus/contribution order and multiplicity bound; dispatch this batch's selected storage |
| [Bounded leaf source](src/fractional_gkr/materialize/streaming.rs) | Reuse original symbolic row evaluation over the SAME committed main/preprocessed table views |
| [Streamed GKR](src/fractional_gkr/streaming.rs) | Root prepass, recomputed prefix rounds and direct folded-layer allocation; original round kernels |
| [AIR-link shares](src/lookup/streaming.rs) | Recompute private per-AIR shares from those same leaves after theta |
| p3-air/lookup/field | Existing symbolic expressions, finite-field and counted lookup semantics |
| p3-multilinear-util/sumcheck | Existing scalar/packed polynomials, layout and equality/folding kernels |
| p3-challenger/security/commit | Existing transcript contracts, analytical assumptions and PCS interfaces |

The published `prove`, `prove_with_backend` and `prove_with_security` signatures
are unchanged. `ProverInstances::new` always selects
`LookupMaterialization::Resident`, including when another dependency enables
`streaming-lookups`. The feature makes `LookupMaterialization::Streaming`
available; a caller opts in for one batch with
`instances.with_lookup_materialization(LookupMaterialization::Streaming)`.
Only that batch's counted LogUp witness reduction and its private share
calculation use the streamed path. The mode is not global, serialized, or part
of setup, the public statement, proof profile or verification policy. Indexed LogUp-star, binary buses and
zerocheck backend selection retain their existing implementations. There is no
public provider, callback, trusted root, serialized prefix or checked receipt.
The original dense GKR/materialization remain available as the parity reference.
The unchanged verifier still authenticates terminal claims against the actual
committed AIR tables and PCS openings.

The [full graph validation](../bfv-mul-relin-proof/VALIDATION.md) executes this
per-call selector: default/streaming library407/409 and WHIR41/42 tests pass,
including exact Resident -> Streaming -> Resident proof/transcript parity and
original-verifier rejection of damage. Arithmetic and atomic NTT batch consumers
explicitly opt in and pass their owning tests; the full graph uses resident
single NTT/relinearization batches. The historical reports below measured the
earlier global feature dispatch and retain their own source/resource scope.

## Lifecycle and invariants

The source owns bounded raw-row scratch per active original AIR, immutable table views, plan-derived
contribution metadata and alpha/beta powers. Each leaf uses the original exact
height/declaration/bus offset, payload and multiplicity expression, public inputs,
first/last selectors and clamped final next row. The unused tail is exactly0/1.
Request indexes and representable allocation dimensions are checked before row
access. Each cache entry holds only the current/next main and preprocessing rows;
logical field storage is `2 * sum(main_width + preprocessing_width)`. Inactive
AIRs allocate no field cells. Cache hits still reevaluate each block's expressions,
multiplicity, public values and bus prefix. No evaluated fraction is cached.
This is shape validation, not a new global RAM or CPU quota.

A root prepass reduces leaves by the SAME prefix-bit pairing. The first round of
each reduced layer and the first two input rounds stream recomputed fractions.
Already drawn challenges fix the same prefix variables inside both rational
halves. Only the remaining current layer becomes four arrays; its consumption
drops them before the next layer. Packed arrays are filled directly without a
full scalar clone. Each streamed round's equality vector is dropped before these
folded arrays are allocated. Tiny layers already reduced to constants close
directly without constructing an empty-point Layer. Private per-AIR link shares
are regenerated after theta using split equality factors, not rematerialized
leaves. No witness data is spooled to disk.

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
trace/PCS data and allocator overhead. After two streamed input rounds, the four
current arrays have at most N/8 extension elements each:20N bytes. The largest
reduced layer reaches the same size after its first streamed round. The remaining
equality suffix costs at most2.5N bytes. The first and second input-round equality
arrays cost10N and5N bytes respectively and die before fraction materialization.
Thus the principal GKR arrays have a provisional22.5N bound:377,487,360B at2^24
or754,974,720B at2^25, plus bounded packing scratch, plan/row metadata and
O(log(N)^2) proof messages. Tiny constant arrays have fixed additional storage;
Vec truncation is not counted as releasing capacity.

This is an ARRAY calculation, not a whole-process RSS/1-2GiB PASS. Committed trace,
preprocessing, WHIR/PCS state, keys and allocator behavior remain resident outside
it. Streaming rounds adds further prover recomputation. The
[atomic NTT experiment](../bfv-ntt-batch-proof/VALIDATION.md) now records actual
complete 2/4/8-operation runs, using sequential two-operation proof units. Those
observations do not validate the earlier monolithic four/eight-operation policy.
No proof cap, security floor or composition assumption is weakened to achieve fit.

The [current cache validation](PER-AIR-ROW-CACHE-VALIDATION.md) passed 516 dense and
517 streamed runtime cases: 1033 invocations and 517 distinct cases. All existing
test bodies and raw prefixes are retained unchanged. The new cache case checks
reversed AIR order, unequal widths/heights, preprocessing, complete proof bytes,
challenger state and actual lookup verification. The earlier
[streamed-round validation](STREAMED-ROUNDS-VALIDATION.md) remains its own historical
record. Its two appended tests compare every recomputed
reduced/folded value and quadratic round with the original dense kernels, and
complete proof/challenger bytes at tiny and actual SIMD boundaries. The
[earlier validation](VALIDATION.md) remains the historical record for the
previous one-input-round implementation.

Existing tests compare dense/streamed proof bytes, openings and final challenges for tiny,
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
their bytes remain unchanged. The historical cache validation excluded two
originally ignored fixture-writing tests. The new full-graph validation includes
the WHIR generator under `--include-ignored`; it rewrites the experimental copy's
public fixture to identical guarded bytes. Original registry sources/cache remain
untouched. See that report for the exact current selections.

~~~text
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --lib
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --lib --features streaming-lookups
~~~

The validation record gives the complete six-integration-target command and
explicit fixture-writer exclusions. Use a fresh target and the reviewed lock.
The original verifier/proof/security/full transcript source files remain
byte-identical to UPSTREAM.json. Small SDK regressions do not establish complete
NTT batch performance, process RAM, private query proofs or SQL acceptance.
