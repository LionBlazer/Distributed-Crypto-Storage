# Private control proof wire

This experiment-private module transports the complete actual SDK Source+Bootstrap
or cold Source+Locking proof pair. The caller supplies an independently expected
canonical source, genesis, parent and enrollment/plan commitments. No Expected,
StateLease, cache identity, private witness, plaintext registry or owner key is
accepted from this frame. It creates no Journal transition or live SQL lock grant.

Release compilation, strict Clippy, 26 numerical modes, both real wire gates,
15 affected leaf tests, eight shared decoder tests and two contract tests passed.
Actual discovery lists 263 leaf cases; unrelated bodies were not rerun. See the
[validation record](../../../PRIVATE-PROOF-WIRE-VALIDATION.md) for actual lengths and
process observations. Existing AIRs, profile digests, hiding parameters and older
proof consumers are unchanged.

| Module | Responsibility |
| --- | --- |
| [mod.rs](mod.rs) | Fixed borrowed envelope, original SDK Postcard serialization, bounded canonical decoding and panic containment. |
| [shape.rs](shape.rs) | Exact emitter topology before calling the actual SDK verifier. |
| [tests.rs](tests.rs) | Rejection inputs and attacks applied to actual serialized SDK proofs. |
| [Bootstrap wrapper](../registry_bootstrap/wire.rs) | Reconstruct the proposed registry root from independent Expected, then verify Source first and Bootstrap. |
| [Locking wrapper](../locking/wire.rs) | Reconstruct returned/owned/new roots, then verify Source first and cold Locking. |

Direct project dependency [bounded-postcard](../../../../../crates/bounded-postcard/README.md)
guards all nested Serde container slots before Vec reservation. Postcard encodes
the original linked p3-uni-stark 0.8.0 Proof, including random codewords, separate
MMCS salts, pruned authentication hashes and every PoW witness. No proof fields
are replaced by a receipt or hash. The existing backend owns real cryptographic
verification and its per-proof security floor; two such proofs have no new
composed-128 claim.

## Envelope and independent context

`DCSLKPW1` has an 88-byte header: magic8, role1 (Bootstrap1/Locking2), zero7,
CanonicalIndex source profile32, exact child profile32, source length u32LE and
child length u32LE. It is followed by one Bootstrap registry digest or three
Locking returned/owned/new digests (canonical Gold words), then Source and child
Postcard bytes in that order. All lengths, profiles, reserved bytes and exact EOF
are checked before SDK decoding. The role is selected by the owning API call.

The two owner `encode(expected, statement, proof)` functions require the existing
statement binding and two actual proofs. `verify(expected, bytes)` reconstructs
only a proposed child statement from fixed output roots, bounded-decodes both
proofs, checks canonical re-encoding and invokes the original Source-first
composite verifier inside catch_unwind. A returned experimental Statement is not
an authorization, fresh agreed head, durable receipt or grant. Unexpected panics
reject; allocation aborts and whole-process memory are not catch_unwind guarantees.

## Conditional bounds and exact SDK layout

New wire-only caps are Source 20 MiB, child 5 MiB and bundle 26 MiB. Sequence length
is at most 16384. Source 24 Mi and child 8 Mi slot budgets sum to 32 Mi slots; each
component's entire nested Serde decoding shares its own bounded budget. These are
container-slot policies, not bytes or a RAM guarantee. Binary Gold uses 8 fixed
bytes, and EF5 preserves all five coordinates.

The mandatory Source uses CanonicalIndex W11521, not packed W7161. Child widths
are 1082/1948 and public-value counts 104/116; Source has 691. The shape checker uses
the actual retained SDK analysis for quotient chunks (2..16), requires both
complete row openings, degree bits 10, no preprocessed openings and random 5. The
three input batches contain random width 10, Source/child width W+5, and Q quotient
matrices of width 10. Each has 192 queries and a separate 4-Gold salt per matrix.
Hidden OOD openings have three batches, one/one/Q matrices, one/two/one points,
and five EF5 codewords per point. Ten binary FRI rounds have 192 one-element
EF5 sibling rows, their own four-Gold salts and one-root caps; final_poly has one
EF5 value. All zero-difficulty witnesses must retain the emitter's zero value.

Pruned authentication counts depend on transcript-derived queries. The decoder
bounds their maximum (input192*13, round192*(12-round)); the SDK independently
reconstructs the exact frontier and rejects omitted, extra or reordered hashes.

Under these checked shapes, conservative serialized budgets including 32 KiB per
proof for container prefixes are 19,876,512B Source, 3,007,088B Bootstrap and
4,406,544B Locking. These are source calculations, not actual proof lengths or
performance results. Genuine owning cases and both CLI gates now accepted the
real emitter under these policies, including exact byte roundtrips and fresh
decode/verification; one observation does not prove a general RAM bound. If a genuine proof
exceeds a bound, record the failure and review the new wire policy; never truncate
proofs, omit fields or relax the cryptographic profile.

A future Journal adapter must separately check its entire body. Current Journal
body size is 117 + request_bytes + 456*update_count + proof_bytes, not merely proof
length; its existing 32 MiB maximum stays untouched. This module does not add that
adapter or controller authorization, agreed freshness, finality or writer fencing.

## Owning validation and byte measurement gates

All fixtures are explicitly PUBLIC NONSECRET. The owning scenarios require
actual Source+child generation, fresh SDK verification, exact component-byte
roundtrips, a genuine foreign pair first accepted under its own Expected, foreign
child splicing, all structural families, canonical Gold/varint/EOF rejection,
preallocation budgets, and same-shape cryptographic damage at every SDK layer.
The State certificate's postallocation heap accounting is not a wire decoder.

```sh
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml wire:: -- --test-threads=1
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry-bootstrap-wire
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove locking-selection-wire
```

Each prove gate creates and serializes a real pair, drops that pair, then fresh-
decodes and verifies the bytes. JSON reports actual source/child/bundle byte
lengths and fresh decode+verification time. The timer includes reconstruction,
shape/security analysis, fresh Backend configurations and both SDK verifications;
it excludes fixture setup, proof generation and encoding. An owned-process
observer must measure complete CLI time and RAM separately. No interactive SQL,
process memory or latency guarantee follows from byte size alone.
