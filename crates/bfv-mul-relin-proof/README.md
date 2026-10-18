# Complete fixed BFV product proof

This Core library proves and verifies the exact N8192/Q5/P5/t114689 two-input
BFV multiplication and relinearization graph. It owns proof composition and the
bounded verification session. Public encrypted polynomial residues are its
arithmetic statements; plaintext rows, predicate constants and private compiler
state are not accepted here.

## Ownership and direct dependencies

| Dependency | Responsibility |
| --- | --- |
| [bfv-mul-relin-circuit](../bfv-mul-relin-circuit/README.md) | Complete134-node claims, codecs, vector routing and exact ciphertext bridges |
| [bfv-relinearization-key-source](../bfv-relinearization-key-source/README.md) | Immutable public original-setup key preprocessing |
| [bfv-query-core](../bfv-query-core/README.md) | Independently supplied original PublicSetup and owner anchor |
| [registry200-proof](../registry200-proof/README.md) | Source and both complete coefficient-encoding proof statements |
| [bfv-key-transform](../bfv-key-transform/README.md), [bfv-basis-convolution](../bfv-basis-convolution/README.md), [bfv-ciphertext-formation](../bfv-ciphertext-formation/README.md) | Genuine Key, Basis and Formation input proof verification |
| [bfv-ntt-witness-proof](../bfv-ntt-witness-proof/README.md), [bfv-relinearization-multilinear-proof](../bfv-relinearization-multilinear-proof/README.md), [bfv-arithmetic-batch-proof](../bfv-arithmetic-batch-proof/README.md) | Actual child producers, bounded verifiers and their security reports |
| [bfv-ntt-circuit](../bfv-ntt-circuit/README.md), [bfv-scale-circuit](../bfv-scale-circuit/README.md), [bfv-tensor-circuit](../bfv-tensor-circuit/README.md), [bfv-relinearization-circuit](../bfv-relinearization-circuit/README.md) | Exact encrypted-residue arithmetic, request/output statements and prover certificates |
| [bfv-fixed-geometry](../bfv-fixed-geometry/README.md), [bfv-ciphertext-wire](../bfv-ciphertext-wire/README.md) | Shared parameters and bounded original SDK ciphertext grammar |

There are no dependencies on experiments, applications, fixtures or a network
manager. The QueryCore dependency supplies existing public contracts; QueryCore
must not depend back on this library. Client Pending ownership and network
completion belong above both libraries.

## Public lifecycle

`Provenance::new` retains independently pinned original setup/anchor, two full
encoding statements and two original ciphertexts. Its constructor checks their
association and grammar; it does not verify proofs. `Expected::new` associates
that provenance with the proposed exact output ciphertext. `PreparedGraph`
checks complete edges and headers while all numeric claims remain unverified.

`Prover` owns a prepared graph and emits one bounded record per `prove_next`.
`GraphClaims` and all claim codecs are owned by the circuit library and directly
re-exported. `profile_digest` retains the complete accepted protocol identity.

`Verifier` borrows the caller's `Expected` and `PreparedKey`. Submit complete
claims, then `InputEvidence` for the original15 individually bounded frames:
Key, two Source/Encoding pairs, ten Basis and two Formation. Both copies of
Source must be equal, yielding16 unique input proofs. Only then submit the118
ordered output records: one atomic arithmetic17 block and the remaining115 NTT
and two Relin records. No input proof buffer is copied or retained. Failed
attempts and bytes count toward the existing lifetime limits; cancellation and
exhaustion are terminal. Consuming `finish` returns `CheckedProduct` only after
all required proofs pass.

`CheckedProduct` exposes its exact output ciphertext, graph identity and the
output-only SDK union estimate. Output components retain a144-bit floor; input
proofs retain their original individual128 policies. This does not establish a
whole128/whole144 protocol, public evaluation-key same-secret theorem, full
noise analysis, authorization, a fresh agreed head or SQL admission. Callers
must independently derive expectations and prove those additional obligations
before consuming a client Pending or committing a mutation.

## Verification and consumers

Owning tests pin the published full64 profile, exact proof coverage and record
envelope rejection. The [input16/full134 integration](../../experiments/hiding-fri-sha256-gate/src/opening/coefficient_encoding/input_formation/full_product/README.md)
owns fresh verification after private/prover state is dropped, hostile proof
controls and the actual encrypted ciphertext result. It remains an experiment.
The [original full graph validation](../../experiments/bfv-mul-relin-proof/VALIDATION.md)
and [preceding circuit extraction](../../experiments/bfv-mul-relin-proof/CORE-EXTRACTION-VALIDATION.md)
retain their original source and measurement scope.

```text
cargo test --release --locked -p bfv-mul-relin-proof --lib -- --test-threads=1
```

The [proof-library extraction validation](../../experiments/bfv-mul-relin-proof/LIBRARY-EXTRACTION-VALIDATION.md) records the current
relocation, owning native tests and preserved proof policy.
