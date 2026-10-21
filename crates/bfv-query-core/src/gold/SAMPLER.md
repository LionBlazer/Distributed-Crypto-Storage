# Owner-controlled input randomness

The protected owner now owns the query error and uniform-remasking streams. This
addresses a concrete gap between the numerical independent-LWE model and the
upstream encryption API: fhe0.1.1 accepts a caller CryptoRng for its CBD error,
but creates A using a separate internal thread-RNG seed and ChaCha8 expansion.
Passing a stronger RNG to `try_encrypt` alone does not change that A path.
This document records the input producer's sampling boundary, not imported key
provenance, pre-existing DATA sampling or complete confidentiality. The v3
[generation lifecycle](GENERATION.md) extends the same policy with these fixed domains:

| Purpose | ChaCha20 stream IDs |
| --- | --- |
| Query error / A remask | 0 / 1 |
| Generated SDK key / Cs salt | 2 / 3 |
| DATA error / A remask | 4 / 5 |

Each input encryption and key generation obtains a separate fresh OS seed.

## Construction and exact relation

`Owner::originate` calls the private `encryption::encrypt` before it constructs
PublicRequest or an OriginatingQuery. A fresh fallible OS seed initializes the
pinned rand_chacha0.9.0 ChaCha20Rng. Two private copies select stream0 for the
SDK CBD20 error and stream1 for uniform remasking, both at word position0.
No caller can select the seed, RNG, provider or candidate ciphertext. Failure
to obtain OS entropy returns Backend before SDK encryption and publishes no
query. There is no deterministic fallback or timestamp seed.

The unchanged SDK encodes the typed256-bit mask into p[255-age] and creates the
intermediate ciphertext(b,a), with phase b+a*s=M+e. The owner then draws rho in
the actual level0 N4096/Q2 NTT context and produces:

```text
a' = a + rho
b' = b - rho*s
b' + a'*s = b + a*s = M + e       in every Q0/Q1 coordinate.
```

This is an exact ring identity, not a decryption-only check. The intermediate
ciphertext never leaves the owner. The outgoing request binds the actual new
unseeded(b',a') as its original QueryCt. No input changes after that binding.
The original ciphertext's coefficient buffers are overwritten after remasking;
secret coefficients, secret NTT polynomial, rho and rho*s use scoped zeroizing
guards. Rand/SDK allocator, seed/state and OS copies are not promised erased.

The SDK's own plaintext embedding/scalers and CBD sampler remain in use.
No new input error is added; its coefficients, support[-20,20], variance10 and
lower Formation equations are unchanged. A subsequent product has different
ciphertext components and may have a different rounding-error realization. The
same published conditional noise bound still applies under its stated ideal-coin
assumptions; this is not equality of the two product noises. The output remains
the existing canonical unseeded CT2 accepted by the original bounded parser;
product certificates and all lower proof/profile equations remain unchanged.

## Sampling argument and explicit assumptions

With ideal independent uniform streams, the SDK sampler consumes disjoint40-bit
groups for CBD20. The old intermediate A may be arbitrary or correlated with
other earlier coins: conditional on it and all other fixed values, adding the
independent uniform rho is a bijection, so a' is uniform and independent of s,
M and e. RNS CRT and NTT are bijections, so uniform coordinates in the actual
Q0/Q1 NTT context are uniform in the same ring used by the numerical model.

The pinned `Poly::random` calls `Modulus::random_vec`, which uses the prebuilt
`Uniform<u64>` distribution and `UniformInt::sample` rejection loop. That path
is unbiased on ideal random words. It does not use rand0.9.2's potentially biased
`sample_single`/random_range shortcut; enabling a global feature is unnecessary.

The concrete streams share one secret256-bit OS seed and have distinct ChaCha20
stream IDs. They are computationally pseudorandom under the multi-stream
ChaCha20 assumption, not statistically independent random tapes. The exact
ring identity above is unconditional; the uniformity/confidentiality inference
is conditional on the OS and PRG assumptions. If T fresh seeds are ideal,
the seed-collision bound is T(T-1)/2^257; for T<=2^64 it is below2^-129.
This API does not enforce a key-lifetime counter or establish OS entropy quality.
The internal old ChaCha8 A is no longer the outgoing A's sole randomness source.

Owner-private NTT and polynomial arithmetic retain the SDK's constant-time mode.
Because SDK operators OR variable-time flags, both copied public operands are
explicitly reset BEFORE secret-dependent correction; rho is also reset. This
local source property is not a complete platform/compiler/side-channel audit.

## Profile and verification boundary

The v2 protected Gold owner profile introduced OS-seeded
ChaCha20 stream0-error/stream1-A-remasking and exact phase preservation. Existing
InputBinding/KeyExpected/request/custody associations carry that profile. No
legacy-profile conversion or migration is introduced. The fixed lower DATA,
Query Formation and product profiles, actual error relation and resource caps
are unchanged. V3 adds normal honest key/DATA generation and key custody, with
the six fixed domains above and no private key getter. Imported key entropy and
authenticated database-Source origin remain open. No native bounded-input proof
alone attests that its producer sampled honestly.

Owning tests pin the20-round zero-key block prefix and separate stream IDs/
initial counters. Two explicit PUBLIC test seeds remask both ciphertext inputs
while all8192 RNS/NTT phase coefficients remain identical to the actual original
SDK phase, and the outgoing bytes pass the unchanged DATA parser. A failing
private entropy provider returns no ciphertext; a fresh genuine attempt still
decrypts the complete4096-word mask. The existing full FHE product, independent
certificate check, full-ring oracle and hostile-custody tests use the new normal
origination path. Executed results and resource observations are recorded in
[VALIDATION.md](VALIDATION.md).

Normal dependencies are the existing pinned SDK, fhe-math/fhe-traits, rand0.9.2,
rand_chacha0.9.0 and zeroize. Source anchors are fhe0.1.1/src/bfv/keys/secret_key.rs,
fhe-util0.1.1/src/lib.rs::sample_vec_cbd, fhe-math0.1.1/src/{rq/mod,zq/mod}.rs,
rand0.9.2/src/distr/uniform_int.rs, rand_core0.9.5/src/lib.rs::try_from_os_rng and
rand_chacha0.9.0/src/{lib,chacha}.rs. The checked local source hashes accompany
the ignored sampler review receipt; third-party source is not vendored or edited.
The [classical estimate](../../../../experiments/lattice-cost-prefix/ESTIMATE.md)
still supplies heuristic attack costs, not a BFV security theorem. No FHE/key/
Source/fresh-head/lock/SQL acceptance flag is granted by this sampler change.
