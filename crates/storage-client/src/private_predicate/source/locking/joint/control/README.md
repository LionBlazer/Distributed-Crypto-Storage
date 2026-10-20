# Typed Joint BEGIN and End

This owner-side module loads real fixed N4 Source and produces the existing
Source, Lifecycle and ControlKind proofs for BEGIN or End. It does not initialize
a Registry, execute FHE, apply encrypted SQL data, install owner state, or open the
generic Session SQL guard. Production RegistryBootstrap is a separate necessary
slice; WorkGenesis bootstrap is not Registry initialization.

| Direct owner | Responsibility |
| --- | --- |
| [SourceOwner](../../../../source.rs) | Real-object audit, owner AEAD decryption and actual Source witness |
| [Joint Acquire](../mod.rs) | Independent descriptor/setup/ALL33 pins and unchanged strict Acquire producer |
| [Lifecycle builders](../../../../../../../registry200-proof/src/lifecycle/circuit/commitment.rs) | Shared exact enrollment/Registry/Cmd160/Result144 preimages |
| [Core Lifecycle producer](../../../../../../../registry200-proof/src/lifecycle/prover.rs) | Genuine Source-first proof production |
| [ControlKind](../../../../../../../registry200-proof/src/control_kind/mod.rs) | Genuine private non-Acquire opcode membership |
| [Closed History](../../../../../../../registry200-finality/src/joint/history.rs) | Actual application/QC replay and exact own operation result |

`JointControlParent::from_verified` checks the complete independent binding and
descriptor, Active control, head, slot, semantic decision and next Context. These
are historical pins, not proof that no later network state exists.
`JointRegistryOpening::from_private_parts` consumes guarded Registry, controllers
and enrollment/current-Registry salts. It accepts canonical empty or failed
states but returns an **unverified private candidate**. It has no Clone, Debug,
public secret serialization, getter, installation or authority method.

Every `SourceOwner::prepare_joint_control` matches the complete parent/context
stamp, audits the actual fetched object and independently pinned heads, opens ALL
originals/index, and rehashes enrollment and old Registry before any proof trace.
The original table and ordinal IDs come from real Source. No fake DATA or Source
witness is constructed. Controllers are commitment labels; no new delegated
controller-possession or user-authorization proof is claimed.

The intent API is closed to `begin` and `end`. A fresh independent caller nonce
binds the unchanged inner intent query; existing OS randomness supplies fresh
Source-opening, command, next-Registry and result salts. SourceOwner's original
Ckey salt remains unchanged. The public intent is not an unsalted hash of a
private opcode. Query derivation precedes Copen/Ccmd/Cnext/Cresult.

BEGIN requires the actual allocator successor and sequence zero. End selects its
actor by stable transaction ID, including after another transaction is removed
and slots compact. Failed End is allowed only here: requested Close on a failed
transaction opens Result144 outcome3 and reports `AbortedRegistry`. Neither
`ClosedRegistry` nor `AbortedRegistry` commits or rolls back encrypted SQL data;
encrypted overlays and their atomic admission remain absent.

`PreparedJointControl::into_parts` yields actual outer Request, Source/Life pair,
ControlKind proof and a move-only candidate. Retain the two frames through the
same Joint depot, build the unchanged Control Manifest, then call the candidate's
`expectation`. `JointHistory::apply_control` checks the exact own expectation
before importing anything and genuinely replays Source/Life/Kind, QC and lineage.
A latest semantic retry performs the same actual replay. Only afterward can
`JointControlCandidate::complete` consume the sealed operation. It reopens
Cmd160, Result144 and the next Registry using the captured private table/all four
IDs without rerunning the state model. The output bank remains historical.

`CompletedJointAcquire::into_opening` is the sole Acquire handoff: it consumes an
actually completed operation and stamps the bank with its sealed next parent
and Context. Raw prepared StagedNext has no conversion. Every subsequent producer
must still reload real Source and rehash roots. `opening.for_acquire(parent,
txid, principal)` keeps the full stamp inside an opaque owned control; the owned
preparation route checks it again before calling the unchanged strict Acquire
constructor/producer. Failed and absent Acquire actors remain rejected.

Consuming errors clear the owned candidate. No clone, automatic retry, durable
pending intent, exact signed-byte lost-ACK recovery, Vault CAS, rollback protection,
current lease or fresh-network reconciliation is supplied. An old authentic
encrypted backup is not thereby current owner state.

The unchanged Source/Life and ControlKind frame caps apply separately; depot
references remain identities, not proof receipts. No wire, profile, AIR equation,
resource/deadline cap or security policy changes. The optional
`private-input-proofs` feature needs the existing local `work-finality` Context
dependency. No crypto library depends on this consumer.

The two owning tests passed on the native release build. They use real ingest
and proofs plus genuine local three-of-four signatures. Independent OS validators
are separate evidence; see the [owner validation record](../../../../../../../../docs/joint-owner-preparation.md). They cover empty BEGIN, two transactions, End compaction, an actually
admitted FailCurrent prefix then failed Close, private-root tampering, malformed
proof rejection, wrong own intent without history mutation, and latest semantic
revalidation. A future actual OS Acquire-to-End gate remains separate evidence.
No runtime, RAM, whole128 composition, BFV same-secret RK or full SQL claim is made.

## Owned recovery handoff

`SourceOwner::prepare_joint_locking_owned_recoverable` takes the same opaque
control and `JointOwnedRecovery` options. The complete parent/context stamp is
checked before any private-control extraction; the unchanged actual Acquire
producer captures the optional capsule. The owning recovery test uses this route.
No raw control getter, automatic retry or durable installation is added.

## Private phase payloads

The internal [state owner](state.rs) supplies fixed guarded payloads to the
adjacent Vault owner. It exposes no public secret getter or serialized proof
receipt. [Shared Registry grammar](../private_state_codec.rs) owns only the
existing two-transaction/two-savepoint field order, presence bits, absent zero
padding, compaction and canonical model checks. Its Registry/Transaction/Savepoint
widths are 274/129/37 bytes. The existing Acquire capsule uses this same grammar;
its 1242-byte envelope, private field order and errors remain unchanged.

The NEW Idle payload is 410 bytes: role/version8, Registry274, controllers64 and
enrollment/current Registry salts64. The NEW Control payload is 731 bytes:
role/version8, complete original Command88, command/result salts64, original
revision8, TableId32, all four RowIDs128, next Registry274, controllers64,
enrollment/next Registry salts64 and private outcome1. These widths describe this
new private grammar, not an older network frame or a resource/proof claim.

`require_idle_parent` checks the opening's original full parent/context stamp
before the owner captures Idle. `encode_idle` and `encode_control` return only
`Zeroizing` fixed arrays. The enclosing owner authenticates the independent full
binding/parent/context, phase, generation and preceding Idle digest; those pins
cannot be minted from the payload. `restore_idle` audits the real fetched Source
through SourceOwner and reopens Cenroll/Cold. `restore_control` also compares the
actual private table/all four IDs, controllers, predecessor revision and salts;
selects End by stable transaction ID; and reopens Cmd160, Result144 and Cnext.
Failed Close has the existing abort outcome3. Complete original Command fields
are decoded canonically, without `Registry::step`, proof production, re-encryption,
new nonces or regenerated salts. No ages, amounts or owner key are retained here.

The Control candidate contains only the next Registry and no original old bank
or salt. The enclosing owner must retain the preceding Idle and bind its exact
generation/hash. AEAD/grammar/private-root checks do not verify public proofs or
grant finality. Actual Source/Life/ControlKind, signed Header/Body, QC and exact
expectation checks through closed History remain mandatory before phase promotion
or completion. The existing unconditional completion checks are shared unchanged.
Wrapping-key custody, WAL/fsync, quota ownership and generation CAS belong to the
Vault, not this codec. Reopened state remains historical and has no current lease
or whole-vault rollback guarantee.

New owning source tests round-trip canonical full counters/savepoints, reject
nonbinary/absent-slot/command aliases, and restore actual Begin/End candidates
after their originals drop. The genuine local proof/QC case rejects changed
Source/key, old/private fields, final RowID, command salt, query and parent before
completing the exact original operation. Both tests passed on the native release
build. The same batch passed the five separate Control WAL file/recovery cases,
the previous Acquire capsule and private-grammar cases, and the previous Control
tests; see the [validation record](../../../../../../../../docs/joint-owner-control-vault.md).
The codec tests do not establish filesystem or network restart behavior.
