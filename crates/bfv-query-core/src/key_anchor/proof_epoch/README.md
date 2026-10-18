# In-memory Owner proof epoch

`OwnerKeyAnchor::proof_epoch(original)` owns one genuine KeyTransform opening
and public Key frame across sequential operand jobs. The constructor checks the
complete original public setup/geometry before the secret copy. The existing
`formation-proofs` feature enables this capability; no dependency is added.

| Direct owner | Responsibility |
| --- | --- |
| [OwnerKeyAnchor](../../key_anchor.rs) | Borrowed actual Owner, independently pinned full setup/scope/Cs |
| [KeyMaterial](../key_material.rs) | One guarded Shat, CsHat salt, full Key33 statement and initial witness |
| [operand_proof](../operand_proof.rs) | Shared private canonical input/opening checks and actual Basis/Formation orchestration |
| [bfv-key-transform](../../../../bfv-key-transform/README.md) | Actual proof of the one fixed Key33 transform |
| [bfv-basis-convolution](../../../../bfv-basis-convolution/README.md) | Ordered five complete convolution proofs for each exact ciphertext/request |
| [bfv-ciphertext-formation](../../../../bfv-ciphertext-formation/README.md) | Actual prerequisites, common-noise formation and bounded evidence |

## Epoch and operand ownership

An epoch starts at `AwaitingKey`. `prove_key()` produces and self-verifies the
actual proof of its exact Key33/CsHat, clears the initial coefficient witness
and advances to `Ready`. It can run only once. `key_evidence()` borrows public
proof bytes; the epoch accepts no imported Key proof, serialized private state,
trusted marker or callback. Recreating an epoch chooses a fresh CsHat salt;
it cannot resume a discarded epoch from public Key bytes.

`begin_operand(request, OperandInput)` accepts one complete canonical ciphertext
and independently pinned public `EncodedCommitment`. A job exclusively borrows
`&mut epoch`, so another job or epoch cancellation cannot overlap it. Each job
has its own exact caller-supplied request32, public ciphertext, five fresh result
salts, fresh noise salt and optional owned `EncodedOpening`. Distinct requests
can therefore use the SAME full Key33/CsHat without a second secret copy or Key
proof. Request IDs are mathematical labels; this API supplies no global replay
ledger, SQL interpretation, origin association or freshness decision.

Job stages are `Basis(0..4)`, `AwaitingFormation`, `FormationReady` and
`Complete`/`Cancelled`. `prove_next_basis()` creates the next genuine proof.
`begin_formation(opening)` checks the whole producer/context/root commitment
before retaining W/salt. `prove_formation(expected, basis_frames)` checks ALL
Key33, this job's request, complete ciphertext/parameter bytes and exact encoding
metadata. Existing library verification of the actual retained Key and all five
borrowed Basis proofs precedes residual derivation, AIR and trace construction.
No earlier stage or public report replaces those proof bytes.

Failed calls do not advance. Success, job cancellation and Drop clear only that
job's W/salts/current input; the epoch retains its one Key opening for the next
job. Epoch `cancel()` is terminal and clears guarded Shat/CsHat, any initial
witness and retained public Key bytes. Epoch Drop erases the guarded fields.
Cancellation is between synchronous calls, not interruption of native proving.
SDK, polynomial, FFT, field, trace, allocator and PCS scratch are not promised
securely erased.

The API exposes no secret/salt/Shat getter, Clone, Debug, serialization, import
or callback. All generated evidence is public and caller-owned. Only one Key
frame is retained internally; jobs emit one component at a time. Current five
Basis frames are borrowed for Formation verification; there is no accumulated
proof bank, aggregate frame, raised cap or whole-process resource guarantee.

## Existing APIs and remaining composition

The old single-operand jobs and two-operand scope keep their existing semantics.
The latter still accepts exactly two operands with ONE request, clears its Key
opening after Input1 and cannot be reopened. Its private implementation shares
the same operand lifecycle and guard/proof code; all old tests remain unchanged.

This epoch is deliberately in-memory. There is no crash/restart recovery or
encrypted private-opening persistence. After losing it, callers must fail closed
or create a newly certified epoch; public evidence cannot reconstruct openings.
It does not make Source Copen query-independent, change the existing full-product
same-q provenance contract, certify a Source or SQL mask, or prove evaluation-key
same-secret consistency. A later Source-ingest/query composition requires its own
explicit origin/query statement. The Core API does not import that policy.

## Owning tests and current status

The new owning tests use explicitly PUBLIC NONSECRET generated messages and real
Owner encryption, one genuine Key and two sequential Basis5/Formation jobs with
different request IDs. An extra genuine partial Basis proves cancel/retry
isolation; a separately genuine same-anchor/different-CsHat Key is verified before
rejection. All 8192 coefficients of both ciphertext ring phases are checked with
the actual SDK. Public proof files are independently reverified after the jobs,
epoch, anchor and Owner are dropped. Negative cases cover full Key/q/CT including
last B word, producer/context/root, missing/reordered/stale proofs, cancellation,
terminal stages and foreign complete setup. Compile-fail examples cover private
ownership, trait restrictions, exclusive jobs and lifetime escape.

The [producer/epoch validation](../../../../../experiments/hiding-fri-sha256-gate/PRIVATE-INPUT-PRODUCER-EPOCH-VALIDATION.md)
records executed owning tests, 13 new compile-fail examples and input16.
Individual existing proof policies remain unchanged;
neither the epoch nor its tests establish composed128, live SQL acceptance,
agreed-head freshness or a RAM/latency bound.
