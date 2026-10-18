# Atomic public BFV arithmetic proofs

This library owns the fixed seventeen-relation public arithmetic proof: four
`Extend5To10`, ten tensors in Q0..Q4/P0..P4 order, then three `Scale10To5`.
Each relation covers all 8192 coefficients and every output component. Three
mandatory proof units cover `[0,4)`, `[4,14)` and `[14,17)`. Verification is
atomic across the complete ordered statement; no checked prefix is returned.

These are public ciphertext-residue relations. The backend is non-hiding; no
secret key, plaintext row or private predicate belongs in its main witness.
The library does not establish edges between independently supplied relations,
complete MulRelin, source provenance, same-secret evaluation-key provenance,
setup authority, freshness, SQL completeness or network admission.

## Dependencies and ownership

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-scale-circuit](../bfv-scale-circuit/README.md) | Fixed scaling equations, canonical public codecs and prover certificates |
| [bfv-tensor-circuit](../bfv-tensor-circuit/README.md) | Complete tensor equations and canonical public codecs |
| [limb-range-air](../limb-range-air/README.md) | Fixed supports and checked histogram union |
| [bfv-multilinear-stark](../bfv-multilinear-stark/README.md) | Fixed SHA512/WHIR configuration and actual SDK security assessment |
| [bounded-postcard](../bounded-postcard/README.md) | Nested sequence and shared aggregate decode budgets |

The private `statement`, `machine`, `backend`, `codec` and `proof` modules own
the frontend, AIR union, security policy and proof lifecycle. Deterministic
PUBLIC NONSECRET fixtures and hostile SDK programs are compiled only for tests.
The [CLI](../../experiments/bfv-arithmetic-batch-proof/README.md) owns its separate
public fixture and command-line/reporting policy. No library code depends on an
experiment, fixture generator or CLI.

The manifest directly selects the reviewed `vendor/p3-multi-stark` package,
version `=0.8.0`, with default features disabled and `streaming-lookups` enabled.
Each producer explicitly selects `LookupMaterialization::Streaming`; enabling
the feature does not change the SDK's resident default for other callers.
There is no package-level SDK patch.

## Public contract

The independent caller supplies nonzero `Context { query, setup }` and all
seventeen canonical requests and outputs to `Expected::new`, or reconstructs
them with `Expected::from_wires`. `instance_binding(context, index)` fixes each
position's role and basis, including distinct bindings for repeated scalers.
`Expected` validates canonical statement identity, not arithmetic. Accepting an
adversary-chosen expected statement establishes no external query or setup
authority.

`profile_digest(context)` exposes the unchanged full 64-byte protocol profile.
It binds the fixed roles, layouts, range domains, schedules, transcript and
resource policy. `analyze(&expected)` reconstructs verifier preprocessing and
the actual three SDK reports without evaluating an Aux or generating a main
trace. It uses the caller's exact public statement, not a fixture.

`prove(context, requests)` computes public arithmetic outputs and certificates,
assesses all three units before main-trace allocation, then proves and
self-verifies one unit at a time. The public `Generated` owns outputs, encoded
frame, diagnostic report and generation time. Phase AIR/PP/PK/VK/PCS and raw
proof storage are dropped between units. Aux values are never transmitted or
put into public preprocessing or public values.

`verify(&expected, frame)` rebuilds trusted verifier keys and all actual reports,
then checks all three genuine SDK proofs against the full outer statement.
`CheckedBatch::matches` compares the complete request/output envelopes and
profile. `CheckedBatch::security_report()` borrows the verifier-owned
`SecurityReport`; submitted report data and `Generated.report` are not accepted
as proof. Public report DTOs are `SecurityReport`, `ComponentReport`, `AirReport`,
`Schedule`, `ResourceBound` and `Term`.

## Security and bounded codec

The unchanged proof frame is `BFVABP02` with a 320-byte header and one canonical
Postcard `[Proof; 3]`. Full request/output envelopes, q/setup, the complete
profile and exact phase ranges bind all three Fiat-Shamir transcripts. The
maximum frame is 16 MiB. A single bounded decoder charges all three proofs with
limits of 16,384 elements per sequence and 8 Mi aggregate container elements;
these element limits are not RAM-byte measurements. Exact canonical boundaries,
EOF, mandatory preprocessing, current-only openings, sumcheck/GKR lengths,
WHIR topology and cap-zero Merkle frontiers remain required.

Actual per-unit assessments must be finite, have no unassessed component and
meet the existing floor. Whole acceptance requires
`min(actual component security bits) - ceil(log2(3)) >= 144`; the existing loss
is two bits. Setup labels do not prove their origin. No proof, profile, cap,
field, AIR equation or security policy changes as part of this extraction.

`generation_ms` starts after request-shape/binding validation and includes
public arithmetic, setup/assessment, traces, proofs, producer verification and
frame encoding. It excludes caller input construction and fresh verification.
The verification timer starts inside `verify`, after independent `Expected`
construction. These timers establish no whole-operation resource guarantee.

## Owning tests and validation status

The twelve existing owning tests move with the implementation. They retain
all-8192 upstream scaler/tensor oracles, prime provenance, genuine complete
three-phase verification, exact order/last-word/transcript binding, canonical
frame/topology/budget rejection and three genuine attacker programs. Each
altered program must pass its own actual SDK verifier before the honest
consumer rejects it; local constraint debugging is not lookup-proof evidence.

The
[historical standalone validation](../../experiments/bfv-arithmetic-batch-proof/VALIDATION.md)
records the previous package layout and measurements, not a fresh execution of
this extracted library. Complete-operation wire, latency and whole-process RAM
claims require separate measurements.

The [proof-library extraction validation](../../experiments/bfv-mul-relin-proof/LIBRARY-EXTRACTION-VALIDATION.md) records the current
relocation, owning native tests and preserved proof policy.
