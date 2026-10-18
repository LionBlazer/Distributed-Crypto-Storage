# Fixed BFV ciphertext wire

This library checks the borrowed canonical protobuf wire and exposes its stored
PowerBasis rows before an SDK decoder can allocate polynomials or perform NTT
work. Its only dependency is
[bfv-fixed-geometry](../bfv-fixed-geometry/README.md); it has no SDK, proof backend,
protobuf decoder, key, fixture or network dependency.

`parse(&[u8])` allocates no heap storage and returns a sealed read-only
`CiphertextView` borrowing the complete original wire. It first applies a
512 KiB byte limit, then accepts exactly the fixed level-zero N8192/five-Q grammar:
two unseeded NTT polynomials, or one NTT polynomial plus seed32. Each polynomial
contains 223232 packed power-basis bytes. Every residue is checked against its own
ordered modulus. Proto3 omitted-false and explicit-true variable-time metadata are
both valid. Explicit defaults, unknown/duplicate/reordered fields, nonminimal or
overflowing varints, other degrees/representations/levels, extra components and
trailing bytes reject. `WireError` distinguishes the outer byte limit from invalid
encoding. Geometry and byte limits cannot be selected by a submitted message.
Every field, residue, flag and the final EOF is checked before a complete view
is returned. `validate(&[u8])` delegates to this same parser and discards the view;
it retains its existing byte limits and error variants.

## Public borrowed API

`CiphertextView::original_bytes` preserves the exact complete input, including
the original seeded or unseeded form. `c0` returns a `StoredPowerBasis` handle;
`second` returns `SecondComponent::Stored` or `SecondComponent::Seed(&[u8; 32])`.
The seed is only borrowed public data. It is not expanded into a polynomial, and
there is no stored c1 variable-time flag in the seeded form.

`StoredPowerBasis::packed_bytes` borrows all five packed rows and
`allow_variable_time` returns that polynomial's original bool policy. The Ntt
tag2 is wire metadata: the packed payload is **PowerBasis**, never native NTT
coefficients. `row(0..4)` reads exactly 8192 canonical u64 coefficients in natural
coefficient order at the fixed Q index. An invalid modulus index returns None.
The zero-allocation iterator implements `ExactSizeIterator` and `FusedIterator`;
its lifetime follows the original buffer, so a short-lived view need not be
retained. All fields and constructors are private and no mutable bytes are exposed.

```rust
use bfv_ciphertext_wire::{Coefficients, SecondComponent, WireError, parse};

fn first_power_basis_row(bytes: &[u8]) -> Result<Coefficients<'_>, WireError> {
    let view = parse(bytes)?;
    // Q0 is fixed by bfv-fixed-geometry; no caller-selected modulus is created.
    Ok(view.c0().row(0).expect("fixed Q0 index"))
}

fn is_seeded(bytes: &[u8]) -> Result<bool, WireError> {
    Ok(matches!(parse(bytes)?.second(), SecondComponent::Seed(_)))
}
```

`preflight` owns the one canonical grammar and complete validation. `view` owns
the immutable handles and the shared lazy packed-row iterator. Neither module
deserializes an SDK Poly, transforms a row or constructs a seed-derived c1.

The algorithm is extracted from the existing Basis decoder. Basis and Core map its
errors into their own APIs, then retain the actual SDK decoding and semantic checks.
Passing this gate is not an encryption, key-ownership, computation, freshness or SQL
proof. It does not construct an SDK value; existing Core/Basis consumers retain
their SDK semantic and canonical-roundtrip checks. A
consumer still needs the complete Source/Encoding/Key/Basis/Formation prerequisites,
actual linked computation proofs and an independent freshness decision before any
completed SQL admission. The parser supplies no authority token or private-key access.

Synthetic wire tests are explicitly public and non-secret. API tests cover all 8192
values at every Q index, mixed stored bool policies, original seeded bytes, final
residue boundaries, invalid indices and borrowed iterator lifetime/fusion. Core
also compares every returned coefficient with independent actual SDK decoding and
PowerBasis conversion in all six seeded/unseeded bool-policy forms. The dcs-peer
test exercises malformed input over TLS against a separate peer process with real
stored heads and an installed setup. The [executed validation](VALIDATION.md)
records 19 distinct runtime cases, two compile-fail examples and strict Clippy.
The earlier preflight-only run remains unchanged in
[PREFLIGHT-VALIDATION.md](PREFLIGHT-VALIDATION.md).

Owning commands for the orchestrator:

```sh
cargo test --release --locked --offline -p bfv-ciphertext-wire
cargo test --release --locked --offline -p bfv-query-core ciphertext_preflight_tests
cargo test --release --locked --offline -p bfv-basis-convolution --lib
cargo test --release --locked --offline -p dcs-peer --test process_transport ciphertext_preflight
```
