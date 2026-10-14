# Query-proof feasibility for compact TFHE queries

Research date: 2026-10-14. This evaluates requirements 11–13 against the active
[500 ms / 2x goal](optimization-goal.md), using the actual TFHE-rs 1.8.1 CPU
parameters. It does not implement a proof system or establish a production security
claim. [Index privacy](index-privacy.md) and the composed storage/query experiment
must retain their own acceptance checks.

## Decision

The best recent proof pipeline found for nonlinear TFHE is a specialized
ciphertext-execution argument, with HasteBoots the strongest concrete next
research candidate. No inspected implementation establishes a complete fresh
COUNT/SUM or overflow-safe UPDATE proof within 500 ms and 1–2 GiB RAM. This is a
finding about available evidence, not an impossibility theorem.

Authenticated index retrieval can be fast and useful immediately. Its evidence must
remain a different type from a proved computed result. An owner-maintained
materialized aggregate can authenticate a predefined answer at a snapshot, but
cannot count as fresh arbitrary SQL executed and proved by a peer.

## Published proof costs

These are authors' measurements, not measurements on this Windows host. MB units
are as printed in the papers; no conversion to MiB is assumed.

| Construction / scope | Prover | Verifier | Proof |
| --- | ---: | ---: | ---: |
| HasteBoots BabyBear + Brakedown, one PBS primitive | 3.51 s | 224.24 ms | 135.45 MB |
| HasteBoots BabyBear + Dory, one PBS primitive | 5.47 s | 109.35 ms | 0.24 MB |
| HasteBoots BabyBear + BaseFold, one PBS primitive | 45.53 s | 4.04 ms | 4.65 MB |
| HasteBoots BabyBear + Dory, batch of 16 | 60.90 s | 126.00 ms | 0.28 MB |

[HasteBoots, USENIX Security 2026, Tables 1–4](https://www.usenix.org/system/files/usenixsecurity26-liu-fengrun.pdf)
uses Apple M4, 14 cores, 24 GB installed RAM. BabyBear has n=728, N=1024,
B=2^8, ell=4, plaintext space 4, and estimated 128-bit LWE security; production
noise/failure re-tuning is outside that paper's scope. Its blind-rotation work is
O(ell*N*n). Installed RAM is not measured peak RSS. These figures already miss
500 ms for one primitive; batching reduces verification growth, not response
latency. The [ePrint version](https://eprint.iacr.org/2025/261) was last revised
2026-08-16.

The [official artifact README](https://github.com/f7ed/HasteBoots/blob/main/README.md)
and [archived artifact](https://doi.org/10.5281/zenodo.20275781) distinguish runnable
Brakedown examples from Dory/BaseFold experiments based on separate Jolt code.
The public workspace says only Brakedown is integrated. It implements its own
field-based TFHE and traces: it is not an adapter for arbitrary TFHE-rs ciphertexts.
A fast scalar XOR/comparison in our library therefore cannot simply attach one of
these proofs. At 100 Mbit/s, 135.45 decimal MB alone would require 10.84 seconds of
ideal one-way transmission, before RTT or ciphertexts. This is a bandwidth
calculation, not a network benchmark.

[Zama's CCS 2025 construction](https://eprint.iacr.org/2024/451), final revision
2025-10-13, reports under 20 minutes for a modified TFHE-like PBS on AWS Hpc7a,
about 200 kB proof and verification below 10 ms. Its
[academic prototype](https://github.com/zama-ai/verifiable-fhe-paper) uses plonky2
0.2 and a separate NTT implementation. Small N=8 tests do not establish secure
parameters. A general zkVM is useful as a reference semantics oracle; the available
PBS evidence does not make it a viable 500 ms backend.

A different semantic direction is [HELIOPOLIS, ASIACRYPT 2024](https://eprint.iacr.org/2023/1949),
revision 2024-08-15: HE-IOPs move checks into the plaintext space while the prover
works on ciphertexts. The reported HE-FRI commit phase for 4096 degree-2^11
codewords takes 5.4 s, 32 threads, less than 4 GB; verification is 12.3 ms, or
5.6 ms with another parameter choice. This is not a complete SQL benchmark or a
TFHE-rs proof adapter. It is a serious alternative for an exact packed-arithmetic
backend, with new conversion, resource and malicious-output checks required.

TFHE-rs's [native zk-pok](https://docs.zama.org/tfhe-rs/fhe-computation/advanced-features/zk-pok)
proves correct compact public-key **input encryption**. It does not prove the later
addition, predicate, SUM, UPDATE, or SQL completeness.

## What a complete statement must bind

A proof backend must commit to this statement, using a canonical bounded encoding:

- Database ID, current independently confirmed head/root and revision, schema,
  authorization domain, and minimum acceptable freshness.
- Canonical query/plan and arithmetic semantics, request nonce, selected input
  identities/multiplicities, exact ciphertext bytes, and input encoding version.
- FHE parameters, evaluation-key digest, randomness/re-randomization policy,
  permitted conversion algorithm, and exact output ciphertexts.
- A complete selection relation: unique-key membership/nonmembership, duplicate
  group boundaries, authenticated range boundaries, or a full scan over the
  committed row count. A Merkle opening for some returned pages cannot prove that
  all matching rows were selected.
- For UPDATE, the no-overflow decision, unchanged rows, new data/index roots,
  expected previous head, and the authorized atomic transition to the next head.

Proving a correct PBS on peer-chosen inputs proves the wrong statement if those
inputs are not authenticated. Likewise, independently valid PBS proofs need a
composition argument that connects all wires and the final result. A current
version number echoed by the peer provides no independently confirmed freshness.
The [malicious-vFHE model](https://arxiv.org/abs/2301.07041) explicitly separates
correctness, integrity and confidentiality in the presence of verification and
decryption oracles; that is the review boundary, not successful local decryption.

The following is a proposed acceptance contract, not an implemented verifier:

```rust
pub enum QueryEvidence {
    ProofUnavailable,
    AuthenticatedRetrieval(RetrievalProof),
    MaterializedViewOpening(ViewOpening),
    Computation(ComputationProof),
}

pub struct UnverifiedReply { /* bounded wire fields; no acceptance capability */ }
pub struct VerifiedRetrieval { /* exact committed data, not computed SQL */ }
pub struct VerifiedQueryResult { /* private fields; verifier constructs this */ }

pub enum RejectQuery {
    ProofUnavailable,
    UnsupportedProofSystem,
    InvalidProof,
    IncompleteSelection,
    WrongRequest,
    StaleHead,
    UnauthorizedTransition,
    ResourceLimit,
}

// Requires a trusted freshness/authorization context independent of the reply.
fn verify_query(
    context: &ConfirmedQueryContext,
    reply: UnverifiedReply,
) -> Result<VerifiedQueryResult, RejectQuery>;
```

`ProofUnavailable` is always a rejection for a computed result. Retrieval/view
openings may produce their own narrower capabilities, never `VerifiedQueryResult`
by conversion. The future computation variant must allowlist a concrete, validated
backend/version: opaque proof bytes or a boolean `proof_present` field are
insufficient. Verify a ciphertext-execution proof before decrypting hostile FHE
output. An experiment-only decryption API must not authorize durable publication.
Private-verification schemes that require decryption need their own proved
chosen-ciphertext/reaction security contract.

## Restricted linear authentication: useful primitive, unsafe shortcut

[Catalano–Fiore, EUROCRYPT 2013](https://iacr.org/archive/eurocrypt2013/78810334/78810334.pdf)
provides an established homomorphic MAC over a prime field. Its polynomial tag is
(y0=m, y1=(PRF_K(label)-m)/x). The verifier checks
f(PRF_K(labels)) = sum_j y_j*x^j. For a public linear SUM, degree remains one and
verification needs O(k) PRFs plus field arithmetic, without reading the k messages.
Its integrity model allows adaptive authentication and verification queries, and
requires unique authenticated labels. That is useful evidence for a restricted
linear design; the theorem does not by itself establish confidentiality for
FHE-encrypted tags under malicious TFHE evaluation.

Consider the proposed variant t_i=alpha*m_i+PRF_K(label_i), encrypted under the same
TFHE evaluation domain as m_i. Never sending Enc(alpha) is sensible but insufficient.
There is a concrete reaction attack on this composition:

1. A peer computes the honest encrypted sum S and tag T, and an encrypted secret
   predicate bit b from an available encrypted input.
2. It returns S and T' = T + (1-b), using FHE to implement that choice.
3. The owner's tag check accepts exactly when b=1. If acceptance, retry, payment,
   or an UPDATE publication is observable, that reaction reveals b.

This attack is an inference for the proposed composition, not a claimed attack on
the plaintext Catalano–Fiore theorem. It needs neither a tag forgery nor an
encrypted alpha, and fresh labels or a fresh alpha per query do not remove the
single-query leak. Restricting the honest API to SUM does not restrict what a
malicious holder of a full TFHE evaluation key can compute. Silence on explicit
error messages alone does not prove that subsequent application behavior hides
the verdict.

[Joo–Yun's homomorphic authenticated-encryption construction](https://eprint.iacr.org/2013/726)
addresses a chosen-ciphertext model with a bespoke error-free approximate-GCD
scheme. It is a formal reference, not a TFHE-rs compiler or a measured CPU solution
for this project. The later
[cryptanalysis of lightweight verifiable HE](https://arxiv.org/abs/2502.12628),
v3 dated 2025-10-13, also demonstrates that secret encodings cannot be assumed safe
against arbitrary FHE cheating circuits. Its REP/PE attacks concern those schemes;
they do not establish that every restricted homomorphic MAC is broken.

Additional implementation obstacles for this candidate remain:

- TFHE `FheUint128` arithmetic is modulo 2^128, whereas the cited MAC uses a prime
  field. Replacing that field by a wrapping ring invalidates the cited theorem.
  For unrestricted ring outputs, changing S by 2^127 and guessing the corresponding
  tag change needs only a parity guess for alpha; if alpha is constrained odd,
  adding 2^127 to both always passes. Range checks can exclude that particular
  large-output forgery but do not restore a prime-field theorem.
- Exact SUM needs an explicit bound, signedness and overflow policy. An encrypted
  predicate multiplied into an amount is not a public linear function with a
  verifier-known selection. Owner-trusted complete index selection can define the
  coefficients; an arbitrary encrypted WHERE cannot silently borrow that guarantee.
- Ephemeral tags avoid persistent row expansion but increase request bytes,
  owner input preparation, FHE arithmetic and decryption. Under our 2-bit radix
  parameters, one 128-bit value has 64 LWE blocks. With big-key dimension 2048,
  coefficient bytes alone are 64*(2048+1)*8 = 1,049,088 bytes per token, before
  serialization metadata. k input tags plus a returned tag therefore carry at
  least (k+1)*1,049,088 bytes, before data, keys or selection proofs. An exact
  serialized size is reported by the opt-in probe below.

Do not implement this algebra as an accepted production proof. A viable next
linear experiment needs an established encryption/authentication composition with
malicious verification-oracle confidentiality, a suitable prime-field backend,
complete selection and freshness, followed by full wire/CPU/RAM measurements.

## Fast authenticated reads and verified writes

An owner-built authenticated ordered index can authenticate exact key lookup,
nonmembership and complete duplicate/range boundaries at its committed snapshot.
The root must commit to index semantics and all updates must preserve them. A
Merkle proof authenticates committed bytes; it does not prove that an arbitrary
peer-built index correctly indexes hidden rows.

A stored COUNT or SUM, authenticated as a materialized view, moves work into writes.
Every accepted write then needs a proved transition that updates affected rows,
index and view atomically, or a trusted owner must perform that work. Authenticated
retrieval of that view can be fast, but it is a predefined view read. It neither
proves new ad-hoc FHE computation nor supplies arbitrary SQL latency. Enumerating
or materializing all possible SQL programs is not bounded storage.

An owner may directly authorize a new plaintext value and AEAD-encrypt it: that
is a valid authorized owner write. Decrypting an unverified peer UPDATE and
re-encrypting it does not prove that the requested predicate/delta was executed.
Checking its plaintext by recomputation would be a separate relaxation of
requirement 12. The trusted-head protocol, concurrent writes and owner availability
also remain unresolved, independently of the FHE proof mechanism.

## Interactive checks and audit soundness

A cryptographic proof normally offers a quantified negligible soundness error under
its stated assumptions; it is not a literal zero-probability guarantee. A valid
sum-check/IOP is also different from sampling a few rows. For example, sampling t
distinct rows from n rows containing one omission misses it with probability
1-t/n. At n=1,000,000 and t=100, that is 99.99%. Repeated peer voting does not turn
that audit into a proof of one peer's complete answer.

[The sum-check analysis](https://people.cs.georgetown.edu/jthaler/extensionsandsumcheck.pdf)
bounds soundness by v*d/|F| for a v-variable polynomial of per-variable degree d.
The terminal evaluation must be tied to an authentic oracle/commitment; merely
asking the peer for that value provides no guarantee. An interactive implementation
must count its rounds and RTT. A noninteractive Fiat–Shamir version needs an
applicable security argument and full transcript binding, including query, head,
inputs, output and session context. A batched proof must state its soundness across
all claims. These are candidates for a real protocol, not permission to label an
unquantified spot check as `ComputationProof`.

## Opt-in TFHE operation accounting

[proof_cost.rs](../crates/fhe-prototype/examples/proof_cost.rs) uses the native
`pbs-stats` counter with the same pinned parameters as the prototype. Enabling the
`proof-cost` feature only for this example leaves default workspace features
unchanged. It counts conversion, predicate, selected COUNT/SUM and overflow-safe
u16 UPDATE stages, plus full peer totals. Deliberately public fixed masks make
operation counts reproducible; they must never
be used for private storage. Three public fixtures cover a nonmatch
with local overflow, equality with rejected overflow and a valid update. Assertions
decrypt only locally generated results against those public fixtures. The final
128-bit addition/size control is not a MAC implementation.

```sh
cargo build --release --locked --offline -p fhe-prototype --example proof_cost --features proof-cost
cargo run --release --locked --offline -p fhe-prototype --example proof_cost --features proof-cost -- 2
cargo run --release --locked --offline -p fhe-prototype --example proof_cost --features proof-cost -- 8
cargo clippy --release --locked --offline -p fhe-prototype --example proof_cost --features proof-cost -- -D warnings
```

Counters are process-global: run this executable alone, with no overlapping FHE
work in its process. Its timings exclude owner preparation, authentication,
serialization, transport, proof generation/verification and compact writeback.
They are stage observations, not a 500 ms end-to-end claim. No data or key files
are written. Captured reports belong in ignored `.local/fhe-research/`.

Measured serially on 2026-10-14, Windows x86_64, AMD Ryzen 9 9950X3D2,
Rust 1.99.0 (b940084d7), TFHE-rs 1.8.1. Each thread budget starts a fresh process
and key set. Time ranges cover one observation for each of the three fixtures;
they are not latency percentiles. No other research CPU benchmark overlapped.

| Peer operation | PBS, 2 threads | PBS, 8 threads | Time, 2 threads | Time, 8 threads |
| --- | ---: | ---: | ---: | ---: |
| Scalar compact-to-FHE conversion | 12 | 12 | 65.14–73.61 ms | 32.89–66.56 ms |
| Encrypted u8 >= threshold | 5 | 5 | 32.29–34.04 ms | 24.55–26.57 ms |
| Selected COUNT/SUM after predicate | 16 | 16 | 86.69–88.19 ms | 31.70–35.35 ms |
| u16 UPDATE after predicate | 42 | 50 | 238.05–243.70 ms | 128.79–132.59 ms |
| Full point COUNT/SUM peer work | 33 | 33 | 183.34–188.75 ms | 89.93–93.34 ms |
| Full point UPDATE peer work | 59 | 67 | 334.13–341.73 ms | 177.32–200.69 ms |
| One u128 addition control | 128 | 205 | 709.04 ms | 428.66 ms |

The exact serialized `FheUint128` size is **1,053,720 bytes** for bincode 1.3 at
these parameters. Whole-process peak RSS is 247,341,056 bytes (235.88 MiB) with two
threads and 248,475,648 bytes (236.96 MiB) with eight. This includes both roles and
operation temporaries; it is not proof-prover RAM. Key generation takes
1031.08/710.42 ms respectively and is separate from the peer-stage table.

The different addition/UPDATE counts are from the same pinned scheme and
parameters. TFHE-rs's automatic carry-propagation strategy chooses parallel or
sequential propagation from block count and `rayon::current_num_threads()` in
`integer/server_key/radix_parallel/add.rs`. Increasing threads can reduce latency
while doing more PBS work. A future proof relation must identify the selected
algorithm/plan rather than assume a fixed circuit from the integer type alone.

Captured local reports are ignored files:
`.local/fhe-research/proof-cost-2threads-20261014-204158-171.jsonl` and
`.local/fhe-research/proof-cost-8threads-20261014-204216-450.jsonl`.
The optimized build, all three observable-behavior fixtures in each run, focused
Clippy with warnings denied, rustfmt, local documentation links and `git diff
--check` pass. These checks do not validate any proof backend.

A full point aggregate already has 33 PBS operations, and the overflow-safe
UPDATE 59/67. Do not multiply the published HasteBoots primitive timing by these
counts and call the product a benchmark: ciphertext formats, parameters, trace
machinery and batching differ. The published multi-second primitive proofs and
our unproved local peer times establish neither a measured end-to-end pipeline
nor the 500 ms goal.

## Next acceptance gate

1. Keep computed replies explicitly unverified in the compact-query experiment;
   reject missing proofs at any production acceptance/publication boundary.
2. Preserve the measured PBS counts and wide-integer size; reproduce them before
   changing implementation, security parameters or CPU concurrency assumptions.
3. Reproduce a secure-parameter HasteBoots primitive separately, including peak
   RSS and proof wire bytes; any TFHE-rs integration is a new cryptographic task.
4. Investigate exact linear HE/authentication as a separate bounded query contract,
   not a claimed solution for encrypted predicates or general SQL.
5. Only claim the full goal after complete selection, current-head confirmation,
   computation proof, verification, decryption and update publication are measured
   together under the actual peer RAM and network budget.

The subsequent [BFV-specific investigation](research-bfv-verification.md)
examines complete RNS/key-switch/rounding obligations for the byte-limb core,
published dCRT proof costs and why sparse NTT spot-checks are insufficient.
It adds no proof implementation or new end-to-end latency claim.
