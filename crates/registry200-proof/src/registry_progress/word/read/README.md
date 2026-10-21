# Conditional Word read mathematics

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
are shared with the remaining test-only owner adapter. No AIR, plan, verifier,
randomness, accepted flag or alternative suite is supplied by a caller.

`verify` bounds six unverified borrowed frames, checks public product arithmetic,
then performs actual independent Source/Role3/DATA, Word and fused Query native
verification. `verify_retained` accepts only an actual privately constructed
`VerifiedDataFormation`; its full original expectation must match. Every call
still checks Word, Query and the product afresh. The immutable theorem replaces
only its own prior Source/Role3/DATA verification. Neither path trusts serialized
verification results. Only these functions can construct the move-only borrowed
`ArithmeticCheckedRead`, which exposes the checked original Ct3 for client-side
decryption. No new wire format, old-profile conversion or verdict cache is added.

Owners first retain complete Source and Word expectations, prepare DATA using
`two_lane_encoding::data_formation`, derive the query context/root and use
`gold::{ScaledOpening,SecretOpening,data::Prepared,query::Prepared}` to produce
the original Query proof. The public evaluator receives only ciphertexts and
parameters, computes their real FHE product and produces its certificate using
`bfv_unrelinearized_product`. Receivers build their own `Expected`, call one of
the closed receiving functions, and permit owner decryption only after success.
Freshness, authenticated prior state, key entropy/lattice assessment and finality
must be established separately before any application accepts an SQL result.

Direct dependencies are the [Word API](../README.md), this crate's
[DATA composition](../../../two_lane_encoding/README.md), its bounded prerequisite
codec, [Gold Formation](../../../../../bfv-ciphertext-formation/src/gold/README.md),
[product certificates](../../../../../bfv-unrelinearized-product/README.md),
`p3-field` and SHA2. Fixed public examples, SDK encryption/decryption, owner serializers and
tamper helpers are compiled only for tests at this boundary. See
[validation](VALIDATION.md) and the historical
[private read measurements](../../word_inventory/query_mask_inventory/READ-VALIDATION.md).
