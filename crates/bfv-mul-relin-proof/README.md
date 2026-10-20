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

`Provenance::encode_claim` and `Provenance::decode_claim(setup, bytes)` provide a
bounded public prover-job metadata codec (`BFVMPV01`). The installed original
setup is supplied separately. The fixed header is 3372 bytes; two complete
canonical input ciphertexts follow, each bounded by the existing 512 KiB wire
contract. `MAX_PROVENANCE_CLAIM_BYTES` is 1,051,948 bytes. The namespace binds the
unchanged full graph profile64, full setup SHA256 identity and original SHA512,
public anchor claim, complete Source691/raw heads/packets, all Key33 fields and
both entire Encoding statements including Cw. Fixed roles and profiles are
reconstructed by their existing constructors; canonical Gold roots, exact
lengths and no trailing bytes are mandatory. No setup duplicate, output
ciphertext, proof, private mask, SQL, secret blind or opening is encoded.

A decoded claim is **untrusted mathematical metadata**. A server can use it to
construct a prover's Expected after actually computing the ciphertext product.
A client must construct its Expected from its own independently retained local
Provenance and the proposed output, never substitute the received anchor or
Source claims. `verify_inputs` performs all existing genuine input verifications
and returns no serialized receipt; successful verification alone does not
authenticate the sender's chosen anchor or grant SQL/freshness authority.

`INPUT_FRAMES`, `input_frame_limit`, `InputEvidence::frames` and `from_frames`
define exactly fifteen borrowed, individually bounded frames in order: Key,
Enc0, Enc1, Input0 Basis Q0..Q4, Input1 Basis Q0..Q4, Formation0, Formation1.
`from_frames` rejects empty or oversized frames before borrowing the collection;
it does not parse their proofs. `MAX_INPUT_BYTES` is the unchanged worst-case
sum, not a new aggregate message. The existing `byte_len` remains only a size
counter and retains its earlier empty-input behavior for direct callers.

Within each `Provenance::verify_inputs` call, the closed verifier itself freshly
checks the independently pinned setup/anchor Key proof and ALL33. It then retains
each operand's five actual scoped Basis results through that operand's genuine
Formation check. Formation checks their full statements and exact borrowed Key
scope instead of decoding the same Key and Basis proofs again. These public
mathematical results are local stack-owned values; the function takes no external
capability and returns no receipt. Five results are dropped before the next
operand, and every input proof buffer still dies before output118 processing.
The original two Source/Encoding verifications, output graph, standalone lower
verifiers, all proof languages/profiles/caps and individual security floors are
unchanged. Source/Query/Link reuse is not implemented.

The source call graph changes Key verification from13 to1 and Basis verification
from20 to10 per successful input collection. This is a static count, not a timing
claim. The new owning gate uses ONE actual Source, Key, two Encoding, ten Basis
and two Formation fixture; it checks genuine foreign CsHat, request/ciphertext,
ordered and independently created scopes, repaired setup/Expected headers,
malformed parameters/proofs and a second invocation after corruption. Its sole
new dependency is test-only `compact-store`, which generates actual AEAD Source
pages. The gate owns an explicit public canonical index suffix in `tests/fixtures/`;
it does not import another crate's test code or fixture generator. This path and
its two scope compile-fail examples passed the
[owning native validation](../../docs/joint-query-fast-path-validation.md).
The same record includes the successful seven-process network gate for this
revision, with its complete timing and resource qualifications.

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
envelope rejection. New claim-codec tests use actual Owner-generated public
setup/ciphertexts and explicitly unproved Source/Key/Encoding metadata to check
canonical reconstruction, full identity changes, source packet auditing,
namespace/setup/root/length rejection and all fifteen frame positions. These
four additions passed natively; they do not replace genuine proof integration.
The [actual peer stream](../../docs/private-where-peer.md) now verifies the complete
graph over TLS on a separate OS process. The [input16/full134 integration](../../experiments/hiding-fri-sha256-gate/src/opening/coefficient_encoding/input_formation/full_product/README.md)
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

## Immutable profile identity

`profile_digest()` returns the same complete public protocol identity through one
process-local `OnceLock<[u8; 64]>`. Its writer uses only fixed domains, limits,
public NTT tables, fixed arithmetic-profile labels and the two Relin roles. The
first caller computes the original writer; concurrent callers wait for that
identity and later calls copy its 64 bytes. No query, setup, secret, proof,
verification outcome, Journal state or authorization is cached. All proof,
binding, security and resource checks remain mandatory on their original paths.

The concurrent identity case passed in its own cold process, together with the
unchanged published-profile test and all eight owning runtime tests. Run the
identity case alone to exercise cold concurrent initialization; in a whole suite
another test may already have initialized the profile:

```text
cargo test --release --locked -p bfv-mul-relin-proof --lib profile::tests::concurrent_callers_retain_the_published_and_uncached_graph_identity -- --exact --test-threads=1
cargo test --release --locked -p bfv-mul-relin-proof --lib profile::tests::observe_uncached_and_warm_cached_profile_hashing -- --ignored --exact --nocapture --test-threads=1
```

Both compare against the independently retained pre-extraction profile64; the
concurrent case also runs the unchanged uncached writer. The observation reports
16 uncached calls and 65,536 warm cached calls, including equality checks, with no
timing assertion. The separate native observation measured 35.3611 ms for the
16 uncached calls and 0.0470 ms for the 65,536 warm calls. It measures identity
hashing only, not proof verification, SQL latency or whole-process idle CPU.
Operational improvement needs a separate measurement of the actual consumer.
