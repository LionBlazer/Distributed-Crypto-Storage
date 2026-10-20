# Joint private locking input producer

This owner-side module composes actual canonical Source, private coefficient
Encoding/input16, Registry Lifecycle Acquire and PredicateAcquire Link producers.
It prepares separate public mathematical evidence. It does not execute Session
SQL admission, publish a Body, promote owner state, sign a request, or grant locks.

| Direct module dependency | Responsibility |
| --- | --- |
| [SourceOwner](../../source.rs) | Own AEAD authority; authenticate and open all four originals once |
| [sql-plan](../../../../../sql-plan/README.md) | Compile the private age-domain TRUE set with SQL three-valued logic |
| [registry200-journal](../../../../../registry200-journal/README.md) | Exact original application/Request and unchanged outer intent query |
| [version-journal](../../../../../version-journal/README.md) | Exact validated historical parent and shard association |
| [registry200-proof](../../../../../registry200-proof/README.md) | Source-first typed Source/Encoding/Lifecycle and genuine Link producers/verifiers |
| [BFV owner and epoch](../../../../../bfv-query-core/src/key_anchor/proof_epoch/README.md) | Actual encryption of all originals and hidden mask; one Key33 opening across two operand jobs |
| [Basis](../../../../../bfv-basis-convolution/README.md) and [Formation](../../../../../bfv-ciphertext-formation/README.md) | Ten ordered actual Basis proofs and two complete Formation proofs |
| [MulRelin proof](../../../../../bfv-mul-relin-proof/README.md) | Existing public provenance and fifteen input frames; output proving remains a later operation |

`CompiledLockingSelect::compile(sql, private_blind, public_nonce, query_id)` accepts
only `QueryPlan::LockingSelect` over one fixed records partition, with projection
age, amount, or age-then-amount. Strengths map to 1..4 and WAIT/NOWAIT/SKIP LOCKED
to 0..2. Offset is 0..4; omitted LIMIT means four; explicit LIMIT is 0..4.
Larger windows are rejected, not clamped. Reversed projection, ordering, aggregates,
mutations and multitable forms are rejected. The compiler reads no stored row.
Its 256 bits represent SQL TRUE after three-valued compilation, including NULL.
The caller supplies a private high-entropy blind distinct from the public nonce.
Neither SQL nor that blind is retained; the mask has guarded owner storage.

`LockingParent::new(&application, &journal, head)` rechecks the original application
against Genesis and obtains exact validated shards at the complete supplied
HeadRef. It requires Active control. This is a historical association, not an
agreed/finalized/latest-head token; a validated losing branch can still exist.
The owner supplies a Journal populated by the concrete Registry verifier/closed
adapter. The constructor does not certify an arbitrary generic verifier's history.
`LockingActor` and consuming `LockingControl` retain exact u64 actor/revision/sequence,
canonical Registry, both controller labels and enrollment/current-Registry salts.
They expose no private getters, Clone, Debug or serialization. Controller labels
do not prove signature possession or authorization.

`SourceOwner::prepare_locking(bfv, epoch, fetched, &compiled, &parent, control)`
first authenticates the complete fetched N4 object under its independent TableId,
object and both heads, and checks original application Source pins. The epoch must
be Ready. Its genuine Key proof is verified against the independently retained
Owner anchor/full setup. Enrollment64 and current Registry200 are reconstructed
and compared to actual parent roots before any new Source proof. The native model
only constructs a private witness; actual AIR/proof verification establishes the
mathematical transition.

The new inner nonce commits a privately blinded exact-SQL identity, public nonce,
QueryId, full setup id, stable KeyExpected29, object, both complete 112-byte heads,
Ckey, Genesis/application/network/database, complete parent HeadRef, enrollment,
current Registry and exact actor intent/controller label. It excludes Copen,
Cmask/Cw/Ccmd, next/result and all proof bytes. The outer q is **unchanged**
`registry200_journal::intent_query(application, G, parent.block, inner_nonce,
Cenroll, Transition)`; returned `Request.nonce` is exactly that inner nonce.
Fresh transformed Key fields are excluded from q29 only; all 33 fields still bind
both Encoding contexts and both Formations. Source q is set once, before Copen.

One genuine canonical Source proof and one private Source opening/Copen feed both
Encoding pairs and Lifecycle. A successful Acquire yields the same private 256-bit
mask in Cmd48 and Cmd160, and Result144 returned/skipped/visited flags bound by an
actual Link proof after both genuine prerequisite pairs have been reverified.
All four original rows are encrypted independently of mask, OFFSET and LIMIT.
The mask is encrypted as the second operand; no plaintext selected BFV answer is
created. Two exclusive epoch jobs produce and verify five Basis proofs plus one
Formation each under the same complete Key33.

Actual WAIT/NOWAIT outcomes return `LockingPreparation::NonAdmitted` with only the
explicit conflict and genuine Source/Lifecycle pair plus Request. There is no
success Link/input collection or append. SKIP with no available rows and LIMIT 0
are successful zero-return mathematical transitions and still require real proofs.
On success `PreparedLockingInputs` exposes immutable public input/proof/Request
references and consuming `into_parts`. Its private one-use `LockingCompletion`
contains only TableId, all four full RowIDs/original ordinals, Result144 flags,
result salt and projection. The existing BFV pending request binding stays in
`ProducedInputs`. No age, amount or mask is retained in the result. Caller-owned
`CompiledLockingSelect` is borrowed and must be dropped when no longer needed.

The result also owns a separate opaque `StagedLockingTransition`: the actual next
Registry, both controller labels, unchanged enrollment salt, new Registry salt and
exact old actor intent are guarded private banks. Its private constructor opens
the same Copen, rechecks enrollment and Cnext against the actual proved statement,
compares the exact canonical Request/complete parent/Source and full Key33 through
the genuine Link association, and checks both encrypted input bytes/pending labels.
It retains the existing canonical provenance claim, exact encrypted request and
full Link/Lifecycle context. The actual model's next Registry is moved into this
bank, not reconstructed from a public digest or fixture. The short-lived complete
Source copy and its salt are erased after those checks; no DATA/mask is retained.
`into_parts` returns this staged owner object as the sixth element. There is no
getter, Clone, Debug, serialization, import, promotion or completion method.
WAIT/NOWAIT creates no staged object. Merely holding it changes no current state.

This in-memory candidate preserves an otherwise lost next-root preimage; it does
not supply a durable pending transaction. A future owner-private store must retain
the old authoritative state and durably capture this exact candidate before any
network submission, then promote it only after the exact finalized joint decision.
Errors/restart cannot be handled by resampling its salts or trusting a peer's root.

There is deliberately no completion/admission API: it must eventually require the
actual complete FHE proof/output and exact finalized joint Acquire decision before
decrypting/projecting a result. Projection must then use actual FHE fields and the
proved returned ordinals, without applying OFFSET/LIMIT again. The old immutable
Registry application verifies only its original Source/Lifecycle contract and
does not admit this larger composite. A new closed application/resource profile,
durable full FHE evidence, fresh-head pin, retained signed-byte retry and pending
owner-state/keystore restoration are separate prerequisites. This module cannot
claim total restart, signature possession, SQL execution or composed security.

Every frame keeps its existing cap/profile; no combined Body/envelope is added.
The resident public collection, original setup and current heavy proof state need
whole-operation measurements. Guarded owned private copies are cleared on drop;
caller copies, native Gold vectors and backend/SDK scratch have no total erasure
guarantee. Proof production is synchronous and has no interruption/retry API.

## Owning tests

The eight new source tests use explicit public nonsecret fixtures and genuine
Source/Lifecycle/Encoding/Key/Basis/Formation/Link proofs. They cover strict compiler
and three-valued-mask behavior; a real signed Bootstrap→Begin1→Begin2→Acquire2
history; exact parent/actor/root preflight; SKIP/window, LIMIT 0, all-skipped and empty TRUE set;
WAIT/NOWAIT without a Link; stable q29 with genuine different full Key33; and
individually verified same-q foreign mask/parent/control mathematical pairs.
Foreign-parent standalone pairs are explicitly not claimed to satisfy the old
application's outer intent request. No accepting verifier or substituted SQL
answer is used. All eight passed in the owning native unit suite; the
[validation record](../../../../../../docs/private-locking-inputs.md) gives the
exact command, source pins, resource observations and separate integration failures.
The staged-opening case uses a genuinely prepared staged Acquire opening
to construct a conditional next End mathematical witness, checks its new Registry
salt/controller binding, and rejects altered openings. It does not submit, prove,
finalize or accept that End and does not claim client restart works.

## Distinct Joint application

The [Joint historical-parent adapter](joint/README.md) accepts only actual sealed
`VerifiedJointParent` plus independent installation/BFV pins. It reuses this
module's private producer under the new genesis and returns a fixed outer Acquire
request with guarded candidates. The old `LockingParent::new` factory and old
intent/profile behavior stay unchanged. Both new Joint owning tests and all twelve
client ownership compile-fail contracts passed; see the
[Joint validation record](../../../../../../docs/joint-locking-inputs.md).
The distinct Joint adapter now also owns one-shot completion of its exact
proof-and-QC-verified Acquire. Legacy preparation and generic SQL guards are
unchanged; no Vault installation or generic current-head/lease assertion is added.

## Separate Registry208 owner

The additive [Progress owner](joint/progress/README.md) uses the actual new
Control815/Predicate896 relation with WAIT/NOWAIT/SKIP in one bank. It retains the
original private statement and full Key33 across fresh attempts, opens only
QC-linked typed Result160, and fsyncs a private bank before freeing global flight.
Six fast tests and one real OS FHE/local-QC/recovery gate passed; see the
[validation record](../../../../../../docs/progress-owner-validation.md).
The old locking producer and SQL guards are unchanged.
