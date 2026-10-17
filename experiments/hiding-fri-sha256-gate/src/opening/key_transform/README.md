# Full8192 private BFV-key transform prerequisite

Status: **release build, test compilation, strict Clippy and numeric gates PASS;
genuine proof/native oracle and all 189 serial tests PASS**. The
[validation record](../../../BFV-KEY-BASIS-VALIDATION.md) distinguishes these
stages. This private `bfv-key-transform` Kind remains a nonaccepting prerequisite
for future BFV formation, without an Owner key API, SQL acceptance, randomness or
production certification. Existing profiles and cases remain distinct.

## Contract and ownership

`statement.rs` holds only public data. Independently supplied `Expected` fixes
`SetupDescriptor` and `C_s` **before any query**. The descriptor is exactly database
16B, key-domain16B, public-setup digest32B and LE-u32 key epoch. It is an identity
label supplied by the verifier, not proof that a serialized BFV key/setup matches
it. `Statement` adds `C_Shat`. `verify` first compares the complete expected tuple,
then actually verifies the STARK. There is no trusted result flag, codec, cache,
network consumer, secret exporter or accepting production certificate type.

There are 33 public Goldilocks fields: profile8 + descriptor17 + C_s4 + C_Shat4.
No secret coefficient, transformed coefficient, salt, stage or query is public.
Digest inputs are typed canonical fields; no reducing untrusted u64 decoder exists.
`trace.rs::Witness` separately owns8192 signed coefficients and two independent
four-field salts, with no Clone/Serialize implementation. The CLI uses explicitly
PUBLIC NONSECRET coefficients. Future use still owes independent BFV-secret and
owner-decryption-key authority, actual setup/evaluation-key linkage and lifecycle.

The input relation proves ONLY coefficient support `s in [-20,20]`. This agrees
with the bounded support of the separately inspected CBD(variance10) generator;
it proves neither its distribution nor entropy, honest sampling or key generation.
The all-zero vector is within support. No shared error/noise, ciphertext, BFV
scaling, SelectedEncoding, AEAD key anchor or relinearization relation is claimed.

## Exact transform, encodings and schedule

N=8192, psi=`Goldilocks::two_adic_generator(14)` has order16384, phi=psi squared.
The input is natural-order `s`. One transition twists and bit-reverses to
`v[j] = psi^rev13(j) * s[rev13(j)]`. Thirteen ascending cyclic DIT stages produce
natural-order `Shat[k] = sum_j s[j] * psi^((2k+1)j)` without output normalization.
Indices/twiddles are fixed verifier-owned constants, not witness routing advice.
The independent native oracle is the existing p3-dft0.8 `coset_dft(s,psi)`, whose
SDK default materializes its bit-reversed view into logical natural order.
Tests also evaluate selected odd roots directly as polynomials.

Both roots absorb exactly8208 fields, with overwrite-rate8/capacity4 Poseidon2-12
and zero initial capacity: `contextSHA8 || private salt4 || zero4 || vector8192`.
C_s hashes natural `s+20`; C_Shat hashes natural canonical field evaluations.
The exact role domains are `DCS/BFV-SECRET-COEFFICIENTS/v1` and
`DCS/BFV-SECRET-ODD-EVALUATIONS/v1`. Each context SHA-256 preimage is
`DCS/BFV-KEY-TRANSFORM-CONTEXT/v1 || LE32(role-domain byte length) || role-domain
|| profileDigest32 || descriptor68`; ONLY the output context additionally appends
C_s as four canonical LE-u64s. It never includes its own output root. The profile
pins version, root/order, normalization, encodings, geometry and schedule. These
are experimental hash/commitment assumptions, not a new production crypto choice.

| Current rows | Action before next row |
| --- | --- |
|0..205|Hash C_s, hold entire vector; final row has ONLY gadget0 active|
|205->206|Hold original vector and last ACTIVE hash checkpoint|
|206|Twist+rev13 into row207|
|207..219|13 DIT butterfly transitions, complete output at row220|
|220..425|Hash C_Shat, hold entire vector; final row only gadget0 active|
|426..511|Hold vector, checkpoint and salts|

Five width248 native-equivalent P2 gadgets run per row. All permutation equations
remain unconditional, including padding/inactive gadgets. An inactive gadget has
all12 INPUT fields zero; its real permutation output need not be zero and never
replaces the checkpoint. Active gadgets chain capacity internally; first block
of each root resets capacity. Each root has1026 absorbs, and checkpoint/root use
the last ACTIVE gadget. All vector edges use the SDK transition selector directly.

Forty serial support lanes each contain six z bits and six slack bits. Whenever
an input-root payload field is consumed, `z=s+20`, `z+slack=40`. Prefix/inactive
lanes are allzero. Every8192 coefficient, including8191, is covered once; all
vectors hold across the full hash phases. This avoids8192 permanent bit banks.

## Computed geometry and validation

T512 retains q192, extension5, r5, blowup8 and TWO full-width openings. Its hiding
budget is404; shortening the trace to32 is invalid for this profile. W=9932:
8192 vector +5*248 P2 +12 checkpoint +8 salts +480 support bits.
Calculated dense arrays: trace40,681,472B, masked81,403,904B,
main LDE651,231,232B. Periodics512*512 fields add2,097,152B. These omit symbolic
DAGs, public twiddle tables (16383 fields plus Vec metadata), FFT reallocation, quotient/MMCS/proofs, witness
and allocator overhead and are NOT RSS/whole-process bounds. Only one vector bank
occurs per trace row; witness preparation/native oracle have their own temporaries.

The actual trace-free report gives degree3,10065 constraints,16 quotient chunks,
20044 batched functions and128/128 finite SDK bounds. The conservative declared
bound5 still controls quotient sizing. These per-proof model reports do not
establish composed128, empirical witness secrecy or production certification.
One observed genuine proof and the full8192 native oracle passed under the
separate process fuse. All 189 serial tests also passed. The report
records single-process timing/counters without claiming a benchmark or RAM bound.

Commands (security, one observed prove and the full suite executed):

```sh
hiding-fri-source-primitives security bfv-key-transform
hiding-fri-source-primitives prove bfv-key-transform
```

`tests.rs` contains full8192 native equivalence, genuine two-root verification,
independent descriptor/root replay, coherent alternate-key/support attacks,
rebuilt twist/stage/twiddle/order/normalization/hold violations, salt binding,
last-active checkpoint and inactive-P2 constraints. Malicious traces rebuild
through the actual SDK; they are not simulated proof acceptance. There is no
SDK fork, extra challenge phase, random projection or new dependency. Shared
arithmetic is only the existing [private P2 gadget](../poseidon.rs); the backend,
field/DFT and hash dependencies were already locked in the standalone experiment.

## Reusable owner boundary

The preceding validation describes the original experimental baseline. The current
module keeps its Kind/fixture and unchanged adversarial tests while delegating
mathematics to [bfv-key-transform](../../../../../crates/bfv-key-transform/README.md)
and shared mechanics to [bfv-hiding-stark](../../../../../crates/bfv-hiding-stark/README.md).
The distinct optional Core Owner API has a bounded codec and real key anchor;
[this validation](../../../../../crates/bfv-key-transform/OWNER-KEY-VALIDATION.md)
records its executed gates. The old profile/caps and this experiment's nonaccepting
SQL status remain unchanged.
