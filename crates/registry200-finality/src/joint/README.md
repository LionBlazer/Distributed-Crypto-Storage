# Closed keyless Joint history

This module checks historical checkpoints for the NEW fixed Registry200 Joint
application. Its four owning native cases and two ownership contracts passed.
The original Registry200 Binding, Follower, verifier, codecs and profiles remain
unchanged. No generic Journal, supplied verifier, callback or "already verified"
flag can construct this module's historical parent.

`JointBinding::new` takes independently authenticated public network, multi-slot
Rules, Work Genesis, NEW Journal Genesis, Joint descriptor and setup claim. It
requires the exact new algorithm identity and candidate bound. It checks the
new AppId/Genesis and exact original SourceSpec initial shards through the actual
Joint Application constructor. SourceSpec remains the original inner head/request
namespace; the old application's Genesis check is never relaxed. The binding ID
includes both Genesis IDs, RulesId, full descriptor and canonical SetupClaim.
Construction of metadata alone verifies no proof. Participant capacity is local
policy; selectable 10/20/30 GB is not placed in consensus RulesId.

`JointHistory::new(binding, depot)` owns an actual Journal, **concrete
JointVerifier**, Work Context and the latest checked checkpoint. Kernel startup
restores/hash-checks the bounded original setup from that same depot before SDK
decoding and rechecks its anchor. The full original setup/anchor/Key33/source
object remain independently pinned. Missing/corrupt setup fails construction.
Neither a peer status reply nor a catalog can supply different trusted pins.

`JointHistory::apply(checkpoint, original_block)` requires:

1. Exact candidate/header, binding, current slot, previous semantic decision,
   direct parent and height.
2. The real weighted Work quorum under the expected Context and its genuine
   deterministic successor. The inherited assumption remains less than one
   third Byzantine confirmed computational weight; signatures alone verify no
   computation.
3. Actual Header/PoW, canonical Body, owner authorization and complete fixed
   JointVerifier replay. Bootstrap needs the genuine Source/Lifecycle pair;
   Control needs its genuine non-Acquire Kind proof; Acquire needs the entire
   retained input16/output118 product and genuine Source/Lifecycle/Predicate Link.
4. Atomic Journal import and monotonic ancestry restriction before the new
   parent/context is published. An unexpected post-import invariant failure
   poisons this history; no new parent escapes and no later operation is allowed.

All invalid metadata, authorization, QC, math and ordinary resource failures are
checked before publication. A duplicate latest checkpoint with another genuine
quorum subset/round must retain the same semantic DecisionID/successor and still
reverify the actual application proof bytes. No proof-success cache is persisted.
The old work-finality engine and arithmetic are used directly, without a second
consensus implementation.

`JointCandidate` is an untrusted exact 272-byte value (`DCSJCV01`).
`JointCheckpoint` is an untrusted bounded candidate/round/QC envelope (`DCSJCQ01`)
with exact length, nonempty certificate, existing Work cap and strict EOF.
The existing `CandidateBlock` is reused only as bounded untrusted original
Header/Body bytes. None of these constructors marks a proposal accepted.

`VerifiedJointParent` has private fields and no generic constructor or conversion
from HeadRef/Journal/shards. Its read-only binding, descriptor, head, slot,
decision and Control metadata are published only after actual proof+QC checking.
There is no parent before a first checkpoint. An Empty checkpoint can retain
Pending Control; it creates no Active Registry or lock. Even an Active parent is
**historical**, not a current freshness barrier, durable signer floor or SQL grant.
Its immutable descriptor retains full setup and Key33 metadata; no secret or
private opening is exposed.

## Host lifecycle and limits

Before `apply`, the caller must fetch and durably retain **all** fixed catalog
references in the same typed depot, using the bounded CatalogClaim iterator and
JointEvidenceIngress. Every blob stays within its original role cap and 32 MiB
depot bound. Fetching must happen outside Journal/depot/state locks. This module
performs local I/O only. The host must hold its one actual native ProofGate during
construction/replay, including checks invoked by import; no second scheduling
gate is created here. Repeated verification can be expensive and remains subject
to host DoS/scheduling policy. No whole-process RAM or interactive latency claim
follows from these source bounds.

This keyless owner has no mutable Journal/store getter, signer key, outbound vote,
WAL or floor-log API. Fresh reconstruction must replay original blocks and QCs
with the original local evidence and independent binding. It is not a durable
JointFinality adapter. Durable floor-before-WAL-advance, network transport/prefetch,
owner Vault/staged-state promotion, exact signed-byte lost-ACK recovery, delegated
rights and fresh operation-specific Acquire completion remain separate required
integration work. Without quorum no lock/End permission may be returned.

No ordinary SELECT lane, plaintext query fallback, selected-answer fixture,
Source replacement, evidence GC/snapshot shortcut or SQL admission is added.
Finite participant quota and immutable history bounds still reject new work when
exhausted; safe retained-history compaction remains unresolved.

## Ownership and dependencies

| Dependency | Responsibility |
| --- | --- |
| [registry200-joint](../../../registry200-joint/README.md) | Fixed actual Bootstrap/Control/Acquire proof replay, descriptor and same-store setup/depot ownership. |
| [registry200-journal](../../../registry200-journal/README.md) | Original immutable SourceSpec and canonical Control metadata. |
| [version-journal](../../../version-journal/README.md) | Actual owner/header/Body validation, atomic import and bounded ancestry. |
| [work-finality](../../../work-finality/README.md) | Original weighted QC and semantic multi-slot Context rules. |
| [protocol-storage](../../../protocol-storage/README.md) | Existing explicit participant resource-profile identity and shared actual depot accounting. |

`binding.rs` owns independent pins, `wire.rs` owns the new bounded untrusted
envelopes, and `history.rs` owns closed application/QC checking and parent creation.
The parent crate's private bounded Reader and timestamp helper are reused.

Four runtime tests and two compile-fail examples passed. They cover new/old application and Rules separation,
bounded canonical wires, actual Work quorum/alternate semantic decision, atomic
invalid-QC handling, and actual signed Source/Bootstrap/Begin/Kind proofs with
re-signed wrong-q and invalid-owner rejection and fresh keyless proof replay.
After successful replay, actual corruption and deletion of the mandatory Kind
file both reject the same original QC/body without changing Context, parent,
floor, best head or Journal accounting. Deletion also poisons new shared-ledger
reservations; diagnostic usage remains readable. See the
[native validation record](../../../../docs/joint-admission.md).
Full Acquire retained evidence and independent-process/finality/SQL gates remain
pending; no expensive positive is replaced by a simulated success test.
