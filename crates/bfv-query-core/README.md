# BFV query core

Experimental owner-online exact BFV roles, extracted from the frozen
`experiments/bfv-byte-limb-core` baseline. This crate is the ongoing owner of its
cryptographic implementation; product adapters depend on this crate and never on
that historical experiment. No production security or query-proof claim follows.

The schema-neutral byte projection path is independent of the historical
`age/amount` layout. `Owner::prepare_byte_select` encrypts original encoded bytes
and binds an opaque schema/table/query/chunk/catalog digest plus both storage
heads. Its public mask selects byte positions corresponding to requested columns;
it must never encode a plaintext row predicate. Each chunk holds up to
`BYTE_SELECT_CAPACITY` (8,191) bytes, including arbitrary text, null markers and
binary data. Streaming callers can split wide rows or large values and have no
128-row bound in this primitive. One reserved zero lane makes even full projection
use a nonidentity polynomial; returning the original ciphertext is not the same
canonical operation.

`PublicUpdateEvaluator::{evaluate_byte_select,byte_select_circuit_request,
restore_byte_select_circuit_output}` expose genuine ciphertext-by-public-polynomial
projection and its exact canonical proof statement. The caller independently
verifies arithmetic through [bfv-query-proof](../bfv-query-proof/README.md).
`compact-query::byte_select::{check,complete_checked}` composes checked evidence
with final client decryption. The low-level
`Owner::decrypt_byte_select_unverified` always returns an explicitly unverified
result. Pending tokens retain only shape, public masks and bindings, never original
plaintext values. Complete authenticated indexed selection, schema semantics,
chunk coverage, authorization and fresh agreed state belong to the storage client.
The byte kernel does not prove arbitrary SQL comparisons or hide access patterns.

`Owner::prepare_polynomial_aggregate` packs original selected amount low bytes at
coefficients 0..255, high bytes at 256..511 and one presence marker per row at
512..767, using `Encoding::poly`. The fixed public polynomial `1+x+...+x^255`
produces low sum, high sum and count at coefficients 255, 511 and 767. No source
aggregate is calculated by the owner. The product degree is at most 1022, below
8192, and every output coefficient is at most 65280, below the unchanged plaintext
modulus 114689. Unsigned decoding preserves sums above half the modulus. Geometry
is Rows256, original selection is at most 256 rows and request/response decoding is
capped at two MiB. `aggregate_circuit_request` independently constructs the exact
full-residue public-polynomial statement; `restore_aggregate_circuit_output`
restores its encrypted result only. A separate genuine proof consumer must check
the statement before `decrypt_polynomial_aggregate_unverified`. This contract uses
no rotations and leaves complete selection, source authentication and freshness
to its caller. The older exact-index rotation experiment remains unverified.

Owner owns the only secret key; PublicSetup contains only original parameters,
relinearization and rotation keys; PeerEvaluator restores public material only.
Inputs are fresh encrypted selected fields. Public contracts include generic
Equal/AtLeast/ClosedRange COUNT/SUM, explicitly caller-asserted exact-index aggregate,
indexed encrypted row projection, indexed amount addition and bounded encrypted batch
append. Indexed wire contracts bind operation/keyset/geometry/query ID and both
opaque 112-byte heads. Generic pending tokens also bind their local owner keyset;
they do not add malicious-response authentication. Results remain Unverified;
UPDATE/INSERT callers must locally check decoded values before writeback.

`PublicSetup::update_parameters` extracts the pinned parameters, geometry and full
keyset identity for indexed addition. `PublicUpdateEvaluator` performs the same
encrypted limb addition as the full evaluator, with identical request/output bytes,
without unused rotation/relinearization keys or wall-clock instrumentation. This
descriptor must be bound to the caller's trusted public setup; its identity is not
self-authenticating. Validated immutable public parameters are cached once per
process; no secret key or row data enters that cache. This reduced execution path
does not itself supply a computation proof or authorize accepting a SQL answer.

`PublicUpdateEvaluator::request_context` validates a supported original UPDATE,
exact-set SELECT or version-3 INSERT request, including every ciphertext's level,
component count and representation, then returns its public `QueryContext`. Runtime
and journal validators can compare both heads against independently agreed storage
state without exposing private request types or executing an SQL/FHE operation.
It rejects earlier INSERT versions and the private-active SELECT domain; returning
a well-formed opaque head does not establish that peers agreed on it or its freshness.

`PublicUpdateEvaluator::circuit_request` converts the exact original ciphertexts to
the canonical NTT residue representation of [bfv-linear-circuit](../bfv-linear-circuit/README.md).
`restore_circuit_output` reconstructs a
normal upstream ciphertext response without repeating the addition. Both are
representation adapters, not verification/acceptance APIs. The proof requester must
retain the canonical input digest and verify it, the output digest, and a trusted
circuit identity before decrypting/using the response. Freshly prepared updates are
tested against the upstream operator byte for byte for both geometries and limb
carry/overflow cases. The original query ID, complete data/index heads, geometry and
keyset remain bound through the original request digest. An opaque bound head is
not evidence that peers agreed on it or that it is current.

The private `canonical::public_product_request` owns the shared level-zero
two-component NTT product representation for row projection, byte projection and
coefficient aggregation. It checks both ciphertext polynomial contexts, converts
the caller-derived public plaintext, preserves every modulus/coefficient and binds
the complete original request bytes. Each operation retains its encoding, public
mask/kernel packing and request metadata checks; proof acceptance remains external.
This adapter retains no requests, rows, keys or proof results.

The indexed SELECT operation freshly encrypts original age/amount lanes and an
encrypted projection/active mask. The public-only peer performs one ciphertext
multiplication and relinearization; it returns encrypted projected lanes and presence
markers. Client completion checks the operation, keyset, context, geometry, projection,
active slots, value bounds and zeroed unrequested/reserved lanes. An in-bounds forged
answer can still pass: `UnverifiedSelectedRows` is explicitly not a computation proof.
The exact-index contract belongs to the caller, as for exact-index aggregates; this
operation does not conceal or re-evaluate an arbitrary SQL predicate.

`Owner::prepare_indexed_insert_for_experiment` independently encrypts the original
contiguous relation and an incoming batch at public append positions. The incoming
operand contains no existing rows, and the existing operand contains no incoming
rows. The public-only `PeerEvaluator::evaluate_indexed_insert_for_experiment` adds
these ciphertexts, including encrypted presence markers. No rotation is required:
the request exposes `existing_rows` and nonzero `incoming_rows`. This is input
placement for genuine encrypted addition, not owner assembly of the complete answer.
The append request version is 3; earlier single-row/staging requests are rejected
rather than interpreted under different arithmetic semantics.
`decrypt_indexed_insert_unverified_for_experiment` returns only decoded peer output
after binding, lane and value checks. This operation requires Rows256 and a complete
old-plus-incoming relation of at most 256 rows. Empty/oversized batches reject before
encryption. It retains the original parameters and public rotation keys.
`PublicUpdateEvaluator::{evaluate_insert,insert_circuit_request,restore_insert_circuit_output,insert_metadata}`
expose the same operation without rotation/relinearization keys. Canonical circuit
outputs match both full and minimal upstream evaluator bytes exactly. `insert_metadata`
validates both original ciphertexts before exposing the public counts and query heads;
it supplies neither an arithmetic proof nor a freshness decision.
Storage growth, authorization and validation against authenticated originals belong
to the caller. It does not provide a succinct computation proof.

`Owner::prepare_exact_select_for_experiment` is a separate path for a complete,
authenticated exact matching set in which every supplied row is active. It rejects
private-active holes. Original age/amount fields, encrypted presence bits and zero
padding are encrypted before projection; it never prepares a projected answer.
`PublicUpdateEvaluator::evaluate_exact_select` then performs real upstream
ciphertext-by-plaintext multiplication. Its mask contains only the already public
`RowProjection`, covering all 256 possible slots even for Rows16 or an empty result.
No count, row predicate, active pattern or original field appears in that mask.

For this all-active exact-set domain, the decoded output equals the original
encrypted-mask path: the public mask agrees on every present slot, and zero input
padding remains zero regardless of mask values there. Presence bits distinguish
zero-valued rows from padding and remain encrypted. Request shape and mask are
independent of selected count; fresh same-length BFV ciphertexts hide contents and
count under the original encryption assumption. This is a conditional equivalence
argument, not a new cryptographic security proof. The original private-active
ciphertext-by-ciphertext API remains available and cannot be substituted by this
path. The operation mode and column projection remain public in both contracts.

`select_circuit_request` converts the exact original ciphertext and public encoded
mask into [bfv-product-circuit](../bfv-product-circuit/README.md)'s complete NTT
products. `restore_select_circuit_output` reconstructs the normal upstream response
without repeating the multiplication. Conversion and restoration validate all
original ciphertext representations and bind the complete original request digest,
including query ID, both heads, geometry, projection and keyset. Restoration is not
proof verification. An external proof consumer must independently derive the same
canonical inputs, verify a real proof and separately establish authenticated index
completeness and the fresh agreed head before any live acceptance or mutation.

Private modules are canonical, kernel, exact_index, indexed_select, indexed_update and indexed_insert.
Direct project dependencies are bfv-linear-circuit and bfv-product-circuit. External
dependencies are pinned fhe/fhe-traits0.1.1, rand0.9.2, serde/bincode1.3.3, SHA256 and zeroize;
it has no storage, SQL, PIR, GUI, fixture or deployment dependency. Complete exact
selection, trusted heads/freshness, global transaction policy and resource accounting
belong to its caller. Original public setup must be retained for same-key recovery;
secret serialization is currently exposed as a COUNT only, not a recovery image.

Parameters stay native/unfused/level0 N8192/Q218/t114689, CBD variance10. The full
evaluator retains the unchanged keyset; indexed addition can omit keys unused by
that circuit. Independent security/noise/CCA and malicious arithmetic proof gates remain
open. The inherited37 tests/2 compile-fail doctests move with this implementation;
crate imports change only. Extraction validation passed all 37 runtime tests and
two compile-fail doctests in release/locked/offline mode, plus strict all-target
Clippy. Those measurements describe the extracted baseline. Indexed SELECT adds a
depth-one projection operation with the same parameters and public key material;
the existing aggregate/update circuits retain their contracts.
Rust 1.99 is retained from the measured baseline; lower MSRV is not claimed.

With indexed SELECT, release/locked/offline validation passed 45 runtime tests and
three compile-fail doctests. Controls include all 256 slots at maximum unsigned
values, every projection mask, inactive/zero rows, fresh ciphertexts, forbidden echo,
wrong operation/keyset/query/heads/geometry/projection and lower-level/wire rejection.
An accepted in-bounds forged value remains explicitly unverified.

With encrypted INSERT and the generic owner-keyset completion guard, owning
release/locked/offline validation passes 53 runtime tests and three compile-fail
doctests. INSERT controls cover empty and 255-row targets, zero/max values, real
addition of separate operands, fresh ciphertexts, unchanged public setup, full/unsupported
geometry, wire/binding/shape rejection and in-bounds malicious output.

The owning storage consumer is [compact-query](../compact-query/README.md), whose
explicit BFV module establishes the owner-built exact-index and compact writeback
contract. Headless GUI uses that module; no owner secret enters a peer evaluator.

Owning validation commands (Rust 1.99):

```sh
cargo test --release --locked --offline -p bfv-query-core -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-query-core --all-targets -- -D warnings
```
