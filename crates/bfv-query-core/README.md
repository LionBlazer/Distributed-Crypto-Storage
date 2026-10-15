# BFV query core

Experimental owner-online exact BFV roles, extracted from the frozen
`experiments/bfv-byte-limb-core` baseline. This crate is the ongoing owner of its
cryptographic implementation; product adapters depend on this crate and never on
that historical experiment. No production security or query-proof claim follows.

Owner owns the only secret key; PublicSetup contains only original parameters,
relinearization and rotation keys; PeerEvaluator restores public material only.
Inputs are fresh encrypted selected fields. Public contracts include generic
Equal/AtLeast/ClosedRange COUNT/SUM, explicitly caller-asserted exact-index aggregate,
indexed encrypted row projection, indexed amount addition and single-row encrypted
append. Indexed wire contracts bind operation/keyset/geometry/query ID and both
opaque 112-byte heads. Generic pending tokens also bind their local owner keyset;
they do not add malicious-response authentication. Results remain Unverified;
UPDATE/INSERT callers must locally check decoded values before writeback.

The indexed SELECT operation freshly encrypts original age/amount lanes and an
encrypted projection/active mask. The public-only peer performs one ciphertext
multiplication and relinearization; it returns encrypted projected lanes and presence
markers. Client completion checks the operation, keyset, context, geometry, projection,
active slots, value bounds and zeroed unrequested/reserved lanes. An in-bounds forged
answer can still pass: `UnverifiedSelectedRows` is explicitly not a computation proof.
The exact-index contract belongs to the caller, as for exact-index aggregates; this
operation does not conceal or re-evaluate an arbitrary SQL predicate.

`Owner::prepare_indexed_insert_for_experiment` independently encrypts the original
contiguous relation and an incoming row in staging slot 256. The public-only
`PeerEvaluator::evaluate_indexed_insert_for_experiment` rotates that row into the
next slot and adds the encrypted relation, including encrypted presence markers.
`decrypt_indexed_insert_unverified_for_experiment` returns only decoded peer output
after binding, lane and value checks. This operation requires Rows256 and fewer
than 256 existing rows; it retains the original parameters and public rotation keys.
Storage growth, authorization and validation against authenticated originals belong
to the caller. It does not provide a succinct computation proof.

Private modules are kernel, exact_index, indexed_select, indexed_update and indexed_insert. This crate depends
only on pinned fhe/fhe-traits0.1.1, rand0.9.2, serde/bincode1.3.3, SHA256 and zeroize;
it has no storage, SQL, PIR, GUI, fixture or deployment dependency. Complete exact
selection, trusted heads/freshness, global transaction policy and resource accounting
belong to its caller. Original public setup must be retained for same-key recovery;
secret serialization is currently exposed as a COUNT only, not a recovery image.

Parameters stay native/unfused/level0 N8192/Q218/t114689, CBD variance10, full unchanged
keyset. Independent security/noise/CCA and malicious arithmetic proof gates remain
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
rotations/addition, fresh ciphertexts, unchanged public setup, full/unsupported
geometry, wire/binding/shape rejection and in-bounds malicious output.

The owning storage consumer is [compact-query](../compact-query/README.md), whose
explicit BFV module establishes the owner-built exact-index and compact writeback
contract. Headless GUI uses that module; no owner secret enters a peer evaluator.

Owning validation commands (Rust 1.99):

```sh
cargo test --release --locked --offline -p bfv-query-core -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-query-core --all-targets -- -D warnings
```
