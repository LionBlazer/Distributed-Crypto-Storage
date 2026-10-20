# Registry200 lifecycle circuit and Source-first producer

This module owns the original Bootstrap and seven-operation Registry200 AIRs,
their private field builders and the single owner-side model/trace writer. The
implementation moved from the hiding-FRI experiment; domains, profiles, fields,
constraints and DCSLFPW1 limits keep their original meanings. It does not run a
Journal, choose q, sign a command, compile SQL or grant a lock.

| Direct dependency | Responsibility |
| --- | --- |
| [Source](../source/README.md) | Same canonical Source680 opening and complete reaudited Source691 claim |
| [Source verification](../source/verification.rs) | Actual bounded canonical Source proof verification; no retained proof/backend or success receipt |
| [wire](../wire/mod.rs) | Existing DCSLFPW1 grammar, fixed role/topology and byte/element budgets |
| [bfv-hiding-stark](../../../bfv-hiding-stark/README.md) | Original hiding backend, actual assessment, Poseidon expressions and canonical codec |
| p3-field/matrix and zeroize | Original field/trace storage and explicit byte/integer witness cleanup |

## Mathematical inputs and captured production input

`circuit::model` owns bounded N4/T2/D2 Registry, Transaction, Savepoint, Command
and Step construction. The seven native operations are **prover input builders**;
public verification never calls the model or compares its answer with a peer.
`circuit::commitment` owns the original enrollment64, registry200, command160 and
result144 private preimage builders. `circuit::Witness` is an explicit mutable,
caller-owned mathematical DTO, not a checked receipt or secret Owner getter. It
contains Source plaintext, controller labels, six salts, old Registry and command;
it contains no Source AEAD key or BFV secret key.

The DTO retains the existing field/row ABI for genuine hostile tests and the
legacy selected-originals encoding experiment. `trace` and `trace_step` check
safe vector/index geometry before allocation but intentionally allow well-shaped
false claims/Step images for actual AIR rejection. Neither trace construction nor
the native model establishes authorization or proof validity. There is one actual
writer, not an experiment copy. Generic row helpers are pure mathematical buffer
operations with the original circuit offset preconditions.

`PreparedWitness::new(&admission::Expected, circuit::Witness)` is a separate
consuming production boundary. It reaudits the complete sealed Source/Expected,
reconstructs exact C_open, C_enroll, C_old and C_cmd, derives the complete public
Statement, and privately retains that Expected and witness. It exposes no private
getter, configured factory, Clone, Debug or serialization API. Construction is
opening association, **not** Source verification, controller possession or an
application grant.

The captured producer banks use Zeroizing plaintext/controller bytes, canonical
u64 salts and native integer model/command fields. An internal trace method only
reconstructs transient mathematical inputs after actual Source verification and
child assessment. Drop clears the owned banks; the mathematical DTO also clears
its bytes/integer model and overwrites native salts. Caller clones/copies,
transient Gold fields, field traces and SDK scratch are outside the erasure claim.
The low-level mutable DTO is deliberately separate from the captured lifecycle.

## Genuine fixed producer and unchanged verifier

`prove(&admission::Expected, &PreparedWitness, source_bytes)` first matches the
complete captured Expected, including both full heads/packets, q, C_key/C_open,
genesis, exact parent, enrollment and phase/old/command commitments. A mismatch
fails before a Source backend is constructed. It then genuinely verifies the
bounded canonical Source proof and drops that decoded proof/backend before child
assessment or private trace allocation. The fixed child backend is locally
constructed, requires its individual target, proves and self-verifies. There is
no caller-supplied callback, proof configuration, VK, report or cached-success bit.

Opaque `Evidence` retains the complete public Statement and unchanged bounded
DCSLFPW1 pair bytes. It exposes read-only `statement`/`as_bytes` and consuming
`into_parts`. Persisted evidence is reverified through the existing byte verifier;
object identity never authorizes skipping Source or the lifecycle proof.

The existing Source20MiB/child12,578,091B and signed-Body reservation remain
unchanged, as do Source24Mi/child16Mi decoded-element budgets and sequence16384.
These element budgets are not byte/RSS bounds. The existing verifier keeps the
original mathematical relation and never runs the newly extracted native model.
Individual proof targets do not imply composed128 security.

## Consumers and validation status

The [experiment adapter](../../../../experiments/hiding-fri-sha256-gate/src/opening/registry_lifecycle/mod.rs)
now imports the actual Core model/trace/builders. Its normal lifecycle gate,
Journal producer, wire gate and legacy encoding fixture use the typed producer.
Only a test-local consumer decodes genuine produced pairs into raw proof objects
needed by existing coherent attacks. Its private adversarial trace callback stays
test-only; no such callback is exposed by this library. Old test assertions and
the separate private-predicate Link16 source remain unchanged.

The new owning tests exercise actual Source → Bootstrap/Begin byte verification
after dropping the prepared witness, complete Expected cross-use rejection,
canonical cryptographic Source tampering/resource bombs and bounded raw input
geometry. New ownership compile-fail cases cover cloning/private-field access.
All four new owning tests and both compile-fail cases passed. The existing 21
lifecycle tests, thirteen other Core tests and the actual eight-pair Journal
history/reopen regression also passed; all seven affected analytical CLI reports
matched the preserved baseline. The [native validation record](../../../../docs/lifecycle-producer.md)
contains source pins, scope and measured process observations.
The known-key test uses the independently published `compact-store::Owner::from_key`
constructor; it does not add a key getter or experiment fixture dependency.

Enrollment labels do not prove controller signatures or delegated client rights.
This producer does not read a current/finalized Journal, activate a work-weight
quorum, provide MVCC/writer fencing or accept SQL results. Hidden LockingSelect
compilation, one-Source joint input16/Lifecycle/Link orchestration, FHE-output
completion and agreed fresh-head admission remain separate work. No query-domain
rewrite, new old-operation allowlist or privacy relaxation is introduced here.

## Result144 opening without a Source/model copy

`circuit::commitment::ResultFieldsOpening` and `result_fields_opening` encode the
same existing transition context, old/command/next roots, opcode/outcome, two u32
transaction limbs, success-gated returned/skipped/visit flags, salt and padding.
The original `result_fields` writer delegates directly to this pure helper. This
allows owner completion to rehash its guarded original flags without reconstructing
a plaintext Source witness or executing the native query/model. It is preimage
encoding only: it proves no operation, key possession, authorization or freshness.

The new parity source case retains the exact pre-extraction builder as its oracle,
checks all seven opcodes/four outcomes and u64 limb boundaries, and asserts fixed
offsets/padding. No AIR expression, profile, commitment domain or proof limit changes.
Its native result is separate from the historical producer validation above.

## Enrollment and Registry opening without Source plaintext

`circuit::commitment::enrollment_fields_opening` accepts the existing Expected,
TableId, controller labels and salt. `registry_fields_opening` additionally takes
all four original RowIDs and a canonical bounded Registry. The original witness
builders delegate to these pure field encoders with the exact same ordering and
padding. They expose no owner getter, Source copy, model execution or verification
authority. The owner recovery path can rehash its captured enrollment64 and
Registry200 without reconstructing unrelated plaintext DATA.

Independent literal old-builder parity, all existing Core Lifecycle cases and
the 21 original experiment regressions passed; see the
[owner validation record](../../../../docs/joint-owner-preparation.md).
