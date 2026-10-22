# Conditional Word read mathematics

[`classical::analyze`](classical.rs) derives conditional error accounting from
the five actual closed AIRs and the separate product PIT, without constructing
preprocessing, private witnesses or proofs. Its explicit budget expression and
unfinished transcript/model correspondence are recorded in
[the classical composition note](CLASSICAL.md). It grants no admission.

This normal library boundary joins the existing immutable SourceVersion/Role3/
dense DATA Formation, Word Predicate, fused Query Formation and unrelinearized
FHE product relations. It checks fixed mathematics relative to independently
retained complete endpoints. Product Fiat–Shamir and BFV confidentiality remain
unassessed; this is not SQL admission, authenticated OldRoot/history, current
weighted finality or a finalized lock.

`Expected::checked` owns public Word/DATA expectations and derives the query and
product expectations from the original ordered ciphertext pair, original nonce,
Stmt96 root, Cw root and claimed canonical Ct3. It rejects Control and compares
the complete Source values, both heads and packets. Matching a version tag alone
is insufficient. Read-only expectation getters support independent owner and
public evaluator preparation; constructing metadata verifies no proof.

`query::encoding_context` derives the acyclic Cw context from the complete DATA
binding, statement root and literal request. `query::expected` derives the sole
fused Query expectation, preserving the original33 mask public words, exact
Stmt96 header13, DATA Cs/context, ordered inputs and nonce. These pure operations
are usable by the protected owner and the test-only Word serializer. No AIR,
plan, verifier, randomness, accepted flag or alternative suite is supplied by a
caller.

`verify` bounds six unverified borrowed frames, checks public product arithmetic,
then performs actual independent Source/Role3/DATA, Word and fused Query native
verification. `verify_retained` accepts only an actual privately constructed
`VerifiedDataFormation`; its full original expectation must match. Every call
still checks Word, Query and the product afresh. The immutable theorem replaces
only its own prior Source/Role3/DATA verification. Neither path trusts serialized
verification results. Only these functions can construct the move-only borrowed
`ArithmeticCheckedRead`, which retains the actual sealed arithmetic result and
exposes it by borrow through `product()` for protected client-side completion.
It exposes the checked original Ct3 too. No new wire format, old-profile
conversion or verdict cache is added.

`verify_and_retain` performs the same complete six-proof native verification as
`verify`, in the same product/DATA/query order, and returns both the checked read
and its actual `VerifiedDataFormation`. Neither result is released on any failed
check. This lets an application retain the independently verified immutable DATA
theorem without verifying those same three proofs a second time. It does not
retain Word/Query/product verdicts; later calls must use `verify_retained` with
complete matching DATA metadata and fresh per-query native checks.

Owners first retain complete Source and Word expectations, prepare DATA using
`two_lane_encoding::data_formation`, derive the query context/root and use
`bfv_query_core::gold::Owner::prepare_query` with the original private Stmt96
to produce the fused Query proof without exporting a secret key. The guarded
low-level opening API remains available to independent owner implementations.
The public evaluator receives only ciphertexts and parameters, computes their real FHE product and produces its certificate using
`bfv_unrelinearized_product`. Receivers build their own `Expected`, call one of
the closed receiving functions, and permit owner decryption only after success.
Freshness, authenticated prior state, key entropy/lattice assessment and finality
must be established separately before any application accepts an SQL result.

Direct dependencies are the [Word API](../README.md), this crate's
[DATA composition](../../../two_lane_encoding/README.md), its bounded prerequisite
codec, [Gold Formation](../../../../../bfv-ciphertext-formation/src/gold/README.md),
[product certificates](../../../../../bfv-unrelinearized-product/README.md),
`p3-field` and SHA2. The optional `owner-read` feature additionally depends on
`bfv-query-core/gold-owner`; Owner itself has no registry dependency. The owning
example generates, seals, destroys and restores an opaque Owner before actual
Source/Role3/DATA/Word/Query/product receiving and protected completion. It
reuses the same immutable DATA for a second different actual query. Public
fixture Source/Word serializers, independent post-verification full-ring oracle
and tamper helpers are compiled only for tests at this boundary. InputScope
pins in that example are metadata; a production SQL compiler, authenticated
prior state and fresh finality are still required. See
[validation](VALIDATION.md) and the historical
[private read measurements](../../word_inventory/query_mask_inventory/READ-VALIDATION.md).

`read::Verifier::new(&Expected)` independently prepares Word and Query receiving
for one complete captured read. Its `verify_retained` still requires the actual
immutable DATA result, compares its full expectation and freshly checks all
three per-query proofs. It cannot accept a different read expectation or imported
setup. This lets a receiver start public preparation before the proofs arrive;
construction checks no proof or head. The owning new-query interval includes
all preparation, proof production, actual receiving and protected completion.

The separate optional [`owner` receiver](OWNER.md) consumes an opaque originating
owner's checked private input. It still verifies actual immutable DATA, fresh
Word and product arguments. Its distinct result makes no public Query-proof claim
and cannot replace public receiving or peer predicate/lock admission.
Moving public preparation earlier does not remove its cost or establish500ms.

The actual local receiving/production overlap, sequential control and remaining
costs are recorded in the [Query receiving measurements](../../../../../bfv-ciphertext-formation/src/gold/program/query_formation/RECEIVING.md).

Later [CPU-budget and product-check measurements](CPU-SCALING.md) report actual
2/8/16-worker pools and complete local intervals before/after four-field PIT
parallelism. They retain all native, hostile-proof and original input checks.
