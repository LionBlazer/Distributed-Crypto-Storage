# Closed Joint history, exact Acquire operation and durable owner

This module checks historical checkpoints for the NEW fixed Registry200 Joint
application. Its four keyless owning cases and two ownership contracts passed,
alongside five durable owning cases and two durable ownership contracts.
The original Registry200 Binding, Follower, verifier, codecs and profiles remain
unchanged. Its private storage implementation is shared through the closed
`Pins::Original | Pins::Joint` choice, with byte-identical Original domains and
formats. No generic Journal, supplied verifier, callback or "already verified"
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

## Durable participant installation

`durable_profile_digest()` is a NEW fixed algorithm identity. Construct
`Rules::multi_slot(durable_profile_digest(), 272, ...)` before bootstrap work,
then `JointBinding::for_durable(...)`. The original `JointBinding::new` and
keyless `profile_digest()` keep their exact identities and reject these foreign
Rules. No caller-selected profile, accepting flag or automatic migration exists.
Keyless history can independently follow a correctly pinned durable binding.

`DurableJointFinality::{create_participant,open_participant}` take the ONE actual
`ParticipantQuota`, the independent binding and an owned signer key. Each opens
its concrete `JointDepot` from that quota's `depot_budget()` internally, so a
caller cannot substitute a store charged to another participant. Cold public
prefetch must close that store gate before construction. The owner returns only
`evidence_ingress()` for later bounded public bytes; it exposes no mutable
Journal/store, key, supplied successor or generic application verifier.

Creation is new-only: metadata absence is reserved before depot opening or setup
restoration, and the same actual permit is held through installation. Charged
Journal, floor and actual DurableVoter are created before metadata-last
publication. `DCSJFM01` metadata pins binding and signer. The SAME FloorLog has
fixed Joint domains `DCSJFL01`/`DCSJFR01`, a 168-byte header and unchanged bounded
record geometry. All control files are charged against the existing <=256-MiB
control budget, alongside the same participant's separate depot/global quota.
No legacy Body, transport, Journal, WAL, proof or blob cap is widened.

Import rechecks the exact current certified parent, owner-signed canonical Body
and all actual Joint proofs, even for a cached block; durable body sync precedes
voting. Every proposal, commit, recovery and signer advance calls the concrete
JointVerifier again. Bootstrap/Control/Acquire keep the kernel's exact mandatory
proof lanes. In particular no QC, manifest hash, catalog identity or previous
proof-success bit replaces all input16/output118 replay for Acquire.

Once the actual signer decision is durable, the owner rechecks application,
quorum/successor and terminal/history bounds BEFORE floor append. It syncs the
floor before restricting ancestry/installing historical parent state, then
unlocks State before the actual signer's no-argument `advance` rechecks the app
and syncs the successor WAL. A bounded slot-to-context-ID/parent map supports
old WAL proposal replay; only the latest complete Context is retained for
idempotent alternate-QC retry. The last allowed Header is admitted, not lost to
an off-by-one bound. Attempts beyond the terminal bound close this owner.

Within that single locked synchronization call, a private move-only
`PreparedFinalization` holds an exclusive borrow of the same State, the original
preflight Decision and its actually checked head/control/successor. The borrow
keeps that MutexGuard alive and prevents intervening State changes. After floor
fsync, its argument-free consuming `install()` performs only the mechanical
ancestry/state update; no second input or separately maintained snapshot exists.
Dropping the handoff installs nothing. Nothing is cached across calls or exposed
as a verification receipt. Floor replay on reopen still runs full preflight for
each already-durable record; floor-ahead reconciliation and the independent
actual verifier in `voter.advance` remain unchanged. This source optimization has
no measured latency or RAM claim. Its additional owning assertions prepare and
drop a genuine Source/Lifecycle/Kind decision without head, control-file size,
quota, WAL or outbound-action changes, then use ordinary successful finalization,
alternate QC and fresh full reopening. These assertions passed with all 19
registry200-finality runtime tests. This does not establish full Acquire latency.

Existing-only recovery restores the independently pinned setup, reopens the
actual Journal with full Joint verification, replays each floor's actual QC and
computation, then replays the signer WAL and synchronizes a durable decision/floor
gap. Missing/corrupt setup, computation premises, marker, Journal, floor or WAL
never recreate a file or authorize a signer. Torn tails are rejected without
truncation. Uncertain writes poison this owner and the shared actual-file ledger;
I/O/storage/floor/poison errors are preserved in `Error::Durable` rather than
reported as a malformed network encoding. Filesystem/directory-entry power-loss
guarantees, non-rollback honest signing and immutable evidence retention remain
host assumptions.

`import_candidate`, `propose`, `receive`, `receive_checkpoint`, `on_timeout` and
`checkpoint_after` use actual Work protocol types. Latest semantic duplicate QCs
recheck the complete application and retain the same successor without appending
another floor/WAL record. `finalized_parent()` publishes only the private-field
historical metadata after full synchronization. It is not a freshness barrier,
Vault promotion, completed FHE answer or live SQL grant; without quorum no lock
or End permission can be returned.

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

The keyless owner has no mutable Journal/store getter, signer key, outbound vote,
WAL or floor-log API. Fresh reconstruction must replay original blocks and QCs
with the original local evidence and independent binding. The separate durable
owner above adds signer/floor persistence. Owner Vault/staged-state promotion,
exact signed-byte lost-ACK recovery and
delegated rights remain separate required integration work. The distinct network
service and exact historical Acquire completion have since passed the full
[four-validator/FHE gate](../../../../docs/joint-participant-finality.md).
Without quorum no lock/End permission may be returned.

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
`adapter.rs` owns the concrete durable lifecycle and historical replay map.
The parent crate's private bounded Reader, timestamp helper, actual FloorLog and
participant metadata machinery are reused. Private `pins.rs` is the closed
Original/Joint namespace selector, not an application-verification interface.

Four runtime tests and two compile-fail examples passed. They cover new/old application and Rules separation,
bounded canonical wires, actual Work quorum/alternate semantic decision, atomic
invalid-QC handling, and actual signed Source/Bootstrap/Begin/Kind proofs with
re-signed wrong-q and invalid-owner rejection and fresh keyless proof replay.
After successful replay, actual corruption and deletion of the mandatory Kind
file both reject the same original QC/body without changing Context, parent,
floor, best head or Journal accounting. Deletion also poisons new shared-ledger
reservations; diagnostic usage remains readable. See the
[native validation record](../../../../docs/joint-admission.md).
Those initial cases gave no full Acquire process credit. The later retained
evidence/finality/completion gate passed as recorded below; general SQL remains
unavailable. No expensive positive is replaced by a simulated success test.

Five additional durable runtime cases and two ownership compile-fail examples
passed; see the [durable native record](../../../../docs/durable-joint-finality.md).
They use actual
signed Source/Bootstrap/Begin/Kind proofs and real Work QCs, fresh durable replay,
re-signed wrong-q rejection, semantic retry, missing/corrupt retained premises,
metadata-last/missing-WAL refusal, actual partial/lost-ACK floor writes,
post-floor shared-ledger refusal at actual WAL advance, corrupt closed-WAL tail,
shared poison and terminal-two-Header reopen. The test-only pre-advance point
marks the actual shared ledger failed; the real signer's grow must reject it.
Closed-WAL corruption uses actual file bytes after releasing its exclusive lock.
These do not claim arbitrary filesystem write-fault coverage or malicious rollback
protection; the unchanged work-finality writer owns its partial/sync fault tests.
Together with the original and keyless regressions, 19 distinct runtime cases
and seven compile-fail contracts passed. The later independent-process Joint
finality and full historical Acquire completion gates are recorded below.

## Exact own operation, with the fresh response

`AcquireExpectation::new(binding, sealed_parent, current_context, AcquireExpected)`
captures independently authenticated public input pins. It checks the complete
installation/descriptor, active parent and next slot/previous semantic decision.
The kernel expectation includes the exact own outer request, Provenance, complete
encrypted request and CatalogId. This constructor grants no verification authority.

`JointHistory::apply_acquire(checkpoint, original_block, expectation)` shares the
ordinary `apply` lifecycle and checks the genuine QC, exact Header/Body, direct
parent/height, Context, slot and deterministic successor. Its fixed kernel adapter
returns the same fresh input16/output118 result only after genuine Life/Link checks.
Ordinary Journal import still performs its full proof check; no previously streamed
product or cached parent replaces verification. No result escapes before successful
import and ancestry restriction. The same API can recheck only the latest identical
semantic decision, with another genuinely verified QC, while replaying all premises.

`VerifiedJointAcquire` owns the exact original Header/Body and QC bytes, before/after
heads, previous/actual semantic decisions, slot and before/after context IDs, plus
the kernel's exact request/manifest/catalog association and checked response. It
has private fields and no Clone, deserialization or raw-parent constructor. A
keyless client needs no validator signer to obtain it. Later End/reacquire cannot
turn this particular linearized operation into a generic current lock or permanent
lease. Current-network reconciliation, owner Vault/CAS, exact-byte lost-ACK retry
and generic SQL acceptance remain outside this value.

The new full owning source scenario in
[storage-client](../../../storage-client/src/private_predicate/source/locking/joint/tests/full_acquire.rs)
uses four independent OS validators for its QC and a separate actual OS FHE peer,
with one participant/depot per process and phased ownership of the SAME client
depot. A test-local supervisor is its only app-source include. Its first native
run completed input16/output118 with a clean stream end and uploaded all evidence
to the four validators, but reached its 30-minute observation deadline before an
Acquire QC was available. A later run on the corrected source passed the entire
scenario, including all four actual QCs, fresh client proof verification, exact
Result144 completion, stale-QC rejection, fresh latest retry, missing output117
and independently challenged corrupt Link. See the
[native record](../../../../docs/joint-participant-finality.md) for pinned source,
binary, timing and resources. The separate two-Acquire process gate also passed:
the first actual QC establishes the conflicting held row, and the second full
FHE/QC/client completion skips it before OFFSET/LIMIT. These establish fixed
historical operations; current lease, owner persistence and general SQL remain
separate.
No profile, frame cap, arithmetic relation or old ordinary-apply rejection
is changed by this return boundary.
