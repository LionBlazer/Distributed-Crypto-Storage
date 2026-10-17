# BFV native NTT circuit

This reusable module checks complete degree-8192 NTT stages on public
ciphertext-derived residues. It supports all ten fixed Q5||P5 moduli and both
forward and inverse native fhe-math0.1.1 conventions. No secret, plaintext, key,
source certificate or SQL authority is accepted or produced. The library owns
public arithmetic and an optional AIR, not a proof backend or checked operation.

## Ownership and dependencies

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-fixed-geometry](../bfv-fixed-geometry/README.md) | Immutable degree and ordered Q5 followed by P5 modulus basis |

`codec` owns sealed request/output/auxiliary representations. `parameters` derives
immutable public SDK roots, twiddles and fixed gathers. `math` evaluates every
stage and builds public quotient/carry data with bounded u128 arithmetic. `plonky3` is an explicit
optional feature exposing only the AIR/preparation adapter; default codecs/math
do not expose Goldilocks or P3 types. No existing circuit/profile/cap is changed.

## Exact fixed transform

`Basis::new(0..9)` selects one immutable modulus; caller-supplied roots/moduli are
not an API. `Direction::Forward` consumes natural PowerBasis coefficients and
returns the exact native SDK NTT order. `Inverse` reverses that convention.
The root search matches pinned `fhe-math0.1.1/src/ntt/native.rs`: ChaCha8 seed0,
rand0.9.2 range sampling, first valid 2N-th root in at most 100 trials. Forward
omegas use root^rev13(k); inverse zetas use root^(-(rev13(k)+1)).
Forward uses 13 DIF layers l=N/2..1,k=2^s+chunk. Inverse uses 13 DIT layers
l=1..N/2,k=N-(N>>s)+chunk, followed by a separate N^-1 normalization layer.
All stage values are canonical residues. This agrees modulo p with SDK lazy
butterflies while never using a lazy intermediate as a canonical wire value.

The universal integer relation is a*x+b*y+p*2^64=out+p*U. Fixed public weights are
forward-left(1,w), forward-right(1,p-w), inverse-left(1,1), inverse-right(w,p-w),
normalization(Ninv,0). Its unused normalization y is fixed zero. This expresses
both sides without a row-side selector or cubic constraint. Canonical weights,
x,y,out<p give a*x+b*y<2p^2<2^125 and U=k+2^64<2^65, inside the encoded 66-bit
range. Whole sums including biases are below 2^127. Base2^16 eight-digit equations
have seven shifted carries d=c+2^24 in [0,2^25), with both endpoint carries zero.
Digit residuals are below 2^42<Goldilocks; no 62-bit product is reduced to a single
field equality. Twiddle limbs multiply input limbs, so the declared AIR degree
bound is 2. Actual SDK analysis confirmed degree 2 and 105/113 constraints for
forward/inverse. Configuration and security belong to the
[validated consumer](../../experiments/bfv-ntt-proof/VALIDATION.md).

## API and bounded wire

`encode_request(direction,basis,binding32,input8192)` and `decode_request` yield a
sealed request. `evaluate_with_certificate` is prover-side public arithmetic and
returns `Evaluation { output, aux }`; `decode_output`/`decode_aux` only validate
fixed framing/ranges. All exact role-dependent lengths are checked before any
input-derived vector allocation. Public `parameters` accessors expose immutable
roots/tables/Ninv, not configurable parameters or secret key material.

Common 80-byte header: magic8 (`BFVNTTQ1/R1/C1`), profile32 at8, independent
binding32 at40, direction at72, basis at73, representation at74, zero5 at75.
Representations are PowerBasis1/nativeNTT2 (direction fixes each request/output),
Aux3. Output adds SHA256(exact request) at80, residues begin112. Aux adds that
input hash at80 and SHA256(exact output) at112, records begin144.
Each stage has all8192 natural-index output records; each record is45 bytes:
canonical output u64 at0, U9 at8, seven u32 carries at17. Stages are ordered, with
13/14 complete vectors; auxiliary sizes are4792464/5161104 bytes. Output is one
complete8192-vector. Unknown tags/profiles, aliases, high unused bits, truncation
and trailing bytes reject; there is no reduced test profile or sampling.

Optional `plonky3::prepare` checks bindings/ranges/hashes, last-stage/output byte
identity and fixed gathers/weights only. It does not execute butterflies, NTTs,
quotients or modular coefficient products. Every public preprocessing row has
32 fields per stage: x4/y4/out4/a4/b4/U5/carry7. Height8192 and widths416/448 cover
all13/14 layers simultaneously. Main width1 is constrained zero; public values
are32 digest words (profile/request/output/aux). `NttAir::shape` has no public
preprocessing and is for analysis only: consumers must require `is_prepared()`
and an actual preprocessing matrix before proof setup. An Aux or Prepared value
is never proof acceptance.

## Validation boundary

Owning source tests cover all basis/direction headers, canonical ranges, exact
root/table exponent conventions, route boundaries, whole-vector roundtrips,
normalization, complete intermediate wire coverage, and coherent canonical public
forgeries reaching the AIR. The standalone experiment owns actual pinned SDK
full8192 parity on all20 cases, genuine serialized proof/rejection and resource
observation. Native validation passed all 7 default and 9 optional-feature tests,
strict all-target Clippy for both feature selections, and the consumer's complete
SDK/proof/rejection gates. This library is a root core/default workspace member;
the proof adapter remains an explicit optional feature.

```sh
cargo test --release --locked -p bfv-ntt-circuit --no-default-features
cargo test --release --locked -p bfv-ntt-circuit --features plonky3
```

These transforms alone do not prove a complete ciphertext multiplication, NTT
representation provenance, source/selection completeness, same-key authority,
relinearization, entropy, fresh agreed state or live SQL/locking correctness.
