# Private Goldilocks formation witness candidate

This private experimental module owns owner-side pre-proving arithmetic, not a
proof or a peer verifier. It consumes a real SDK serialized secret and the SAME
original plaintext buffers used for encryption. It supplies no Source/Key/SQL,
freshness, confidentiality, soundness, noise or finality authority. Native
arithmetic/SDK/tamper gates and strict Clippy passed; the
[executed validation](VALIDATION.md) records their scope and one local timing.
No public arithmetic certificate is accepted through this module.

`Witness::from_sdk_key(&Statement, raw[2], guarded_key_bytes)` derives one secret S,
two error vectors E and four quotient vectors K. Private `check` checks every
coefficient against the independently retained original inputs. There is no
Clone/Debug/serialization/key getter or witness output. One error vector is shared
across both Q bases of each operand; one secret is shared across both operands.
The full original request wire, including the exact ciphertexts, is bound by a
domain-separated SHA512 identity; a reused nonce cannot rebind the witness.

Direct dependencies are the parent experiment's fixed geometry/canonical
Statement and Error types, SHA512 and zeroize. `fft` is fixed-N integer modular
arithmetic with no new package. The existing dev-only `fhe-math` supplies an
independent SDK Poly oracle. This is not the old Basis/Formation ABI or a new
cryptographic profile. The public PIT certificate/protocol/profile is unchanged.

## Exact SDK relation

For N4096, Q=[1073692673,1073668097], t65537 and variance10, actual SDK
`Plaintext::to_poly` computes W=(16389*m) mod t, then multiplies each basis by
delta_i=(-t)^-1 mod q_i. Delta=[536854528,282551134]. It does NOT directly encode
floor(Q/t)*m. Actual `SecretKey::encrypt_poly` emits [c0,A] with c0=E-A*S+delta W.
Thus, in Z[X]/(X^4096+1), each coefficient satisfies

```
c0_ui + negacyclic(A_ui,S) - delta_i W_u - E_u - q_i K_ui = 0.
```

The SDK samples one signed CBD vector before conversion to RNS; both secret and
errors therefore lie in [-20,20], and the SAME E_u is mandatory in both bases.
Derivation centers Q0's residual, checks its small range, then requires Q1's exact
same error. It derives exact signed quotients only for witness production. Check
validates K in the symmetric range [-(2^19-1),2^19-1] and the exact integer equation;
it does not infer proof acceptance from successful decryption or a checksum.

The strict owner-only key reader accepts only SDK's canonical fixed packed sint64
field1: header0a8020 and4096 one-byte zigzag values0..40 (4099 bytes total). It
rejects unknown/repeated/trailing/noncanonical/oversized forms. Serialized bytes,
decoded S, W, E, K, secret transform and product scratch use Zeroizing. The SDK key
remains in the client fixture. No participant key is read or written; the explicit
example contains public rows and a fresh ephemeral random key. Stack/register
copies and upstream SDK scratch are not promised securely erased or constant-time.

## Actual Goldilocks FFT and integer lift

The field is p=2^64-2^32+1. Its fixed primitive8192-th root
psi=0x1544ef2335d17997 is checked by psi^4096=-1 and psi^8192=1. Forward transform
twists coefficient j by psi^j then runs a natural-order radix2 cyclic DFT with
omega=psi^2; inverse includes N^-1 and psi^-j. Every canonical multiplication is
performed in u128: (p-1)^2<2^128; sums use u128 before reduction; subtraction avoids
u64 overflow. The existing p<2^62 Montgomery module is deliberately not reused.

For canonical A<q and |S|<=20, an ordinary integer negacyclic product has absolute
coefficient at most20*N*(q-1)<2^47, far below p/2. Its centered Gold lift is exact.
With c0<q, W<=65536, |E|<=20 and bounded K, the entire residual has absolute value
below2^50, also below p/2. These bounds explain the arithmetic; no AIR/argument
constrains them in this source slice. A future proof must constrain the actual
FFT, full inputs/ranges, same-secret/error and commitments, not publish secret
frequencies/products or treat this native check as a proof verifier.

## Lifecycle, bounds and owning tests

All dimensions, canonical Q residues, plaintext ranges and fixed key length are
checked before FFT allocation. The explicit witness owns7*N i64 coefficients
(229376 bytes). Additional logical buffers, including that witness, two public
twist tables, W, secret transform, work and lifted product, are bounded by
14*N*8+4099=462851 bytes. This is a conservative logical-buffer estimate, not RSS:
Vec capacities/allocator/stack/SDK/Statement/fixture buffers are extra. The fixture
now retains the SAME two original guarded plaintext buffers for its client
lifetime (65536 additional bytes); producer/checker still receive only Statement.

The separate `--private-formation-fixture` mode builds/checks then drops the private
witness inside the fixture. It emits only counts, public phase durations and
false proof/security/Source/SQL/freshness/network flags. Its total includes the
reused genuine SDK product and client/witness cleanup; it does not produce/check
the public PIT certificate or claim completed SQL. The existing `--public-fixture`
mode and its certificate/profile/JSON protocol are unchanged.

Three owning tests cover dense and sparse full4096 integer negacyclic reference,
one genuine random-SDK-key fixture and all4096 independent SDK Poly coefficients
in both Q bases for both operands, and strict key-codec failures. That same SDK
fixture exercises a range-valid wrong key that no small error can absorb,
re-canonicalized wrong basis, coefficient4095 changes in c0/A/W, shared-error
inconsistency, quotient equation/range changes and exact request substitution.
Tests do not require every NEW ciphertext to reject: a coherently changed valid
encryption with a different small error can be valid. They reject changed data
against the retained witness, and reject basis-local error inconsistency even
when fresh quotients may be derived. No test logs the secret, E/K/FFT or products.

Strict all-target Clippy and all19 owning tests passed, including the three new
`gold_formation` cases and16 existing public arithmetic cases. The explicit
private fixture's witness construction/check took2.9332/1.5706ms; its local total
including the SDK product and cleanup was13.7364ms. Process RSS was not measured.
No network/FHE-proof/recovery gate or accepted DCS profile is implied. Actual
hiding Formation, authenticated Source/Key composition and the500ms complete
query remain unimplemented.
