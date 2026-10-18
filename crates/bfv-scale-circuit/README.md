# BFV RNS scale circuit

A reusable, public arithmetic relation for one complete degree-8192
natural-order PowerBasis polynomial. `Extend5To10` copies the original Q5 rows
verbatim and computes auxiliary P5 with factor 1. `Scale10To5` computes Q5 from
Q5||P5 with factor t/Q. No ciphertext decoding, NTT conversion, key material,
relinearization, query execution, proof configuration or accepting permit lives
here. Peers may use only public ciphertext-derived residues; these are not private
plaintext/key/noise scalers.

## Modules and dependencies

`codec` owns private validated request/output/auxiliary containers and exact
versioned framing. `constants` derives immutable fixed SDK-compatible parameters
once with num-bigint/num-traits. `math` independently evaluates every coefficient
with ethnum U256/I256 and builds public arithmetic auxiliaries. SHA-256 binds exact
bytes and profile. The normal pure dependency
[bfv-fixed-geometry](../bfv-fixed-geometry/README.md) owns the shared degree,
plaintext modulus and ordered Q5/P5 bases; this module re-exports those exact
constants with their original names and values.

The explicit optional `plonky3` feature enables the four pinned P3 AIR/field/matrix/
Goldilocks adapters. Default math/codecs expose no P3 or Goldilocks types. The
consumer owns its proof Config, frame caps, transcript/security gate and proof
verification; neither an auxiliary nor `Prepared` is a checked computation proof.

## Fixed arithmetic and ordering

The fixed Q5 is the existing level-zero BFV basis; P5 is the first five distinct
62-bit, 16384-compatible primes generated below 2^62 by pinned fhe0.1.1. Degree,
t114689, basis order, single-poly coefficient order, role and all constructor
constants are included in the new profile. This profile never replaces an old
addition/product/security profile. The separately owned proof experiment must
cross-check the actual SDK prime sequence and ALL8192 RnsScaler outputs for both
roles before any proof execution; an ideal CRT formula is not a substitute.

For input product M and unreduced Garner G_i=(M/m_i)*inverse(M/m_i mod m_i), the
constructor matches pinned fhe-math0.1.1: Gamma=round(a*M/b), Omega_i=round(a*G_i/b),
T_i=round(2^h*G_i/M), directed thetaGamma=floor and theta_i=ceil at scale2^127.
Here h=127/125 for extension/downscale and thetaGamma=0 in both fixed roles.
The public evaluator computes v=floor((sum r_i*T_i+2^(h-1))/2^h),
W=floor((sum r_i*theta_i+2^126)/2^127), ties toward positive infinity,
and y_j=(sum r_i*Omega_ji-v*Gamma_j+W) mod output_modulus_j. This deliberately
preserves the SDK approximate-v rounding near Q/2.

## Integer-safe public certificate

Every coefficient carries v64, remainder_v<h bits, Wb=W+2^45<2^46,
remainder_e<2^127, five U_j=k_j+2^64<2^66, and 56 shifted internal carries
in [0,2^25), exactly315 bytes. Range-checked 16-bit limbs constrain:

- sum rT+2^(h-1)=2^h*v+remainder_v (12 positions);
- positive rtheta+2^126+2^172=negative rtheta+2^127*Wb+remainder_e (11);
- sum rOmega+Wb+p*2^64=vGamma+y+p*U+2^45 (8 positions per computed row).

Carries c=d-2^24 have fixed c0=cL=0. Every digit equality has magnitude below
2^42, below Goldilocks; no full v/U/62-bit product is converted to one field
value. The fixed wide sums fit U256/I256. The optional AIR is linear in canonical
public preprocessing; its one main column is constrained zero. It checks all8192
coefficient rows. Full extension output commits10 rows; verifier preparation
checks every copied Q5 byte against trusted request before constraining P5.

## API and fixed codec

`encode_request`, `decode_request`, `evaluate_with_certificate`, `decode_output`
and `decode_aux` are pure public math/representation APIs. `Evaluation` owns its
output and auxiliary. Accessors expose immutable role, binding and full vectors.
All exact lengths are checked before vector allocation. Modulus aliases, unused
high bits, unknown roles/representation/profile, truncation and trailing bytes
reject. There are no variable-length nested allocations.

Common80-byte header: magic8 (`BFVSCLQ1/R1/C1`), profile32 at8, independent request
binding32 at40, role at72, PowerBasis1 at73, zero6 at74. Request residues begin80.
Output adds SHA256(exact request) at80 and begins residues112. Auxiliary adds that
input hash at80 and SHA256(exact output) at112, with315-byte rows from144.
Coefficient storage is modulus-major, then all8192 coefficients, u64 little endian.
Aux row offsets: v0, rv8, Wb24, re30, five9-byte U at46, 56four-byte carries at91.
The separate auxiliary frame is2580624 bytes; old proof caps are unchanged.

`plonky3::prepare` checks only exact framing/binding, canonical ranges, hashes and
copy equality, then splits public integers into limbs. It NEVER evaluates v, W,
quotients or a scalar scaler. `Prepared::into_parts` returns ScaleAir and32 public
field words (profile/request/output/aux digests). `ScaleAir::shape` performs no
coefficient work and has no preprocessing; consumers MUST reject proof setup
unless `is_prepared()` and an actual preprocessing matrix exist. The actual SDK
analyzer found 64 constraints of degree 1 for both roles. Proof configuration,
security and process observations belong to the
[validated consumer](../../experiments/bfv-rns-scale-proof/VALIDATION.md).

## Validation scope

Owning source tests cover complete fixed framing, residue/range aliases, copied
Q5 identity, last coefficient, signed rounding ties and a near-center SDK quotient
regression. Feature tests check actual limb constraints on valid and coherently
rebound false public output. Independent full SDK parity and real serialized
proof/rejection tests belong to the experiment consumer. Native Rust 1.99 validation
passed all 7 default tests, all 8 feature tests, and strict all-target Clippy with
both feature selections. The library belongs to the root core workspace and
default members; `plonky3` remains an explicit optional feature.

```sh
cargo test --release --locked -p bfv-scale-circuit --no-default-features
cargo test --release --locked -p bfv-scale-circuit --features plonky3
```

A natural-order label is a caller contract, not a proof of NTT/program/source
linkage. These stages alone establish no same-key authority, ciphertext-product
pipeline, entropy, source/selection completeness, fresh agreement or live SQL.

## Compact main-witness adapter

The new optional `multistark` feature adds a distinct PV0 machine with 160
range-checked main columns and only canonical input/output limbs in public
preprocessing. Its private equation kernel is shared with the existing adapter;
old profiles, frames and public-auxiliary semantics are preserved. See the
[module contract](src/multistark/README.md) for trusted transcript binding,
shared support ownership and exact layouts. The
[executed validation](../../experiments/bfv-arithmetic-batch-proof/VALIDATION.md)
records all four feature configurations and the complete arithmetic consumer's
genuine positive/hostile proofs. The earlier validation statements above retain
their original public-auxiliary adapter scope.
