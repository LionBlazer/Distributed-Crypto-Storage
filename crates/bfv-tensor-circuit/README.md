# BFV tensor circuit

A reusable public arithmetic relation for the actual three-component
intermediate of multiplying two two-component BFV ciphertexts. For one selected
fixed Q5||P5 modulus and all 8192 NTT-domain positions, it computes d0=a0*b0,
d1=a0*b1+a1*b0, and d2=a1*b1 modulo p. All four inputs and all three outputs are
complete vectors. This is a tensor stage, not MulRelin or SQL acceptance.

## Module boundary

The default arithmetic dependency is [bfv-fixed-geometry](../bfv-fixed-geometry/README.md),
which owns the unchanged degree and ordered ten-modulus basis. The optional
`multistark` feature also uses [limb-range-air](../limb-range-air/README.md),
which owns the fixed shared range supports and checked histogram accounting. This module owns a
sealed basis index instead of depending on the separate NTT library merely for a
type. `codec` owns bounded public frames; `profile` binds this distinct operation;
`math` evaluates complete vectors and public auxiliaries. The optional `plonky3`
feature owns the AIR adapter; default math/codecs export no P3/Goldilocks types.
The consumer owns proof configuration, transcript, frame cap and verification.

No key, private source witness, callback, loader, CheckedOperation permit, owner
fixture answer or network SQL authorization enters this library. Inputs are public
ciphertext-derived NTT residues. The representation label alone does not prove the
prior NTT, extension, formation or source certificate.

## Fixed public contract

`Basis::new(0..9)` selects one immutable modulus. `encode_request` returns canonical
bytes and `decode_request` a sealed `Request`. Four component-major input vectors
are ordered a0,a1,b0,b1. `evaluate_with_certificate` is prover-side public u128 math
and returns `Evaluation { output, aux }`. Output vectors are ordered d0,d1,d2.
Single products are below 2^124 and the cross sum below 2^125. Their exact quotients
fit u64: k0,k2<p and k1<2p. There is no approximate arithmetic or arbitrary modulus.

Each component has eight base-2^16 digit equations product_sum=output+p*k. Seven
shifted internal carries d=c+2^24 are in [0,2^25); both endpoint carries are zero.
Full four-limb products fit all eight positions without truncation. Digit residuals
are below 2^42, below Goldilocks; the proof never substitutes a single field product
for a large integer product. Limb iterators allocate no temporary digit vectors.

## Canonical framing

All frames have a common 80-byte header: magic8 (`BFVTENQ1/R1/C1`), profile32 at8,
independent request/context binding32 at40, basis at72, representation at73,
input count4 at74, output count3 at75, zero4 at76. Request/output representation is
native NTT2; Aux is3. Request contains all four vectors from80. Output adds
SHA256(exact request) at80, then all three vectors from112. Every residue is u64
little endian and strictly below p. The fixed request/output sizes are 262224/196720
bytes. No header permits a smaller geometry or omitted component.

Aux adds input SHA at80 and SHA256(exact output) at112. Its 8192 coefficient-major
records begin144; each108-byte record contains three u64 quotients at0..24, then
three seven-u32 carry chains at24..108. Its exact size is 884880 bytes. Private
validated containers expose immutable accessors. Decoders check exact lengths
before input-derived allocation, canonical residue/quotient/carry ranges, tags,
profiles, representation and reserved bytes; trailing or truncated frames reject.

## Optional proof adapter

`plonky3::prepare` checks only canonical ranges, identity and exact byte digests,
then splits public integers into limbs. It does not multiply operands, divide by
p, recompute quotients, or evaluate the tensor. `Prepared::into_parts`
returns `TensorAir` plus 32 digest field words (profile/request/output/aux).

The analytical layout is height 8192, one mandatory zero main column, and 61 public
preprocessing columns: inputs16/output12/quotients12/carries21. Each row checks all
three complete eight-digit equations. The declared degree hint is 2 (limb products
of public polynomials). The separate proof consumer confirms 25 constraints,
degree 2 and genuine proofs for all ten bases; see its
[native validation](../../experiments/bfv-tensor-proof/VALIDATION.md).
`TensorAir::shape` is for
analysis only and has no preprocessing. Consumers must require `is_prepared()` and
an actual public matrix before proof setup. Aux/Prepared is never proof evidence.

## Validation status

Owning tests cover all basis/header/length boundaries, complete golden
outputs and both cross terms, all-ten-modulus maximum quotients, high limbs,
canonical auxiliary ranges, full request binding, and coherent output/quotient/
carry forgeries reaching actual limb constraints in the optional test source.
On Rust 1.99.0, the default suite passes all seven tests and the optional feature
suite all nine tests, with no ignored or filtered cases. Both all-target strict
Clippy checks and explicit rustfmt checks pass. Reproduce from the repository root:

```sh
cargo test --release --locked -p bfv-tensor-circuit --no-default-features -- --test-threads=1
cargo test --release --locked -p bfv-tensor-circuit --features plonky3 -- --test-threads=1
```

These checks validate framing, public arithmetic and actual constraint rejection;
they do not themselves establish upstream SDK parity or a genuine serialized proof.
The separate proof consumer's validation covers those gates, independent verifier
preprocessing and hostile proofs. Existing circuit profiles and proof caps are unchanged.

This stage leaves extension, NTT provenance, inverse transform, downscale,
relinearization/evaluation-key consistency, same-key authority, source and selection
completeness, fresh agreed state, writer fences and live SQL guarantees unresolved.

## Compact main-witness adapter

The optional `multistark` feature adds a distinct PV0 machine with 54 main
certificate limbs and mandatory fixed range lookups. Only complete canonical
inputs/outputs enter its public preprocessing. The private integer kernel is
shared with the existing adapter; old profiles, codecs and public-auxiliary
semantics are preserved. The [module contract](src/multistark/README.md) documents
trusted transcript/namespace binding and support sharing. The
[executed validation](../../experiments/bfv-arithmetic-batch-proof/VALIDATION.md)
records all four feature configurations, actual SDK oracles and genuine positive/
hostile proofs for the complete arithmetic consumer. The earlier validation above
retains its original public-auxiliary adapter scope.
