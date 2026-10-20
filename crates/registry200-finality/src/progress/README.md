# Closed Registry208 finality

This module owns independently pinned Work/Journal lineage for the new
[Registry208 application](../../../registry200-joint/src/progress/README.md).
It provides keyless historical verification and a durable participant owner.
A result identifies one actual operation; it does not install an owner bank,
open SQL execution, establish a current lease, or disclose Parked/Done status.

## Public contracts

- `Binding::new` and `Binding::for_durable` bind the complete new Descriptor and
  SetupClaim, Journal genesis, Work genesis and Rules selected before tickets.
  The new application commitment, candidate/checkpoint domains and RulesId are
  separate from the original and legacy Joint applications.
- `Candidate` and `Checkpoint` are bounded untrusted wire metadata. Decoding a
  value, a catalog ID or a signed Body is not application verification.
- `History` owns its Journal and the fixed `ProgressVerifier`.
  `bootstrap_parent` selects only genuine Pending lineage: initial genesis or
  an actually checked EmptyPending successor. No raw HeadRef constructor exists.
- `OperationExpectation::bootstrap/transition` retain independently supplied
  owner intent, full Context/parent and the exact canonical signed Body.
  `History::apply_operation` checks those pins before QC, proof work or import,
  then returns a move-only `VerifiedOperation` after full actual application
  verification, QC, successor and ancestry-floor publication.
- `History::apply` verifies generic authenticated Empty or Transition blocks.
  Empty never creates an own-operation receipt. A latest semantic retry uses
  its real historical before-context and full read-only replay below the floor;
  it cannot apply an old QC as a new invocation.
- `DurableFinality` owns the real Journal, floor and signer WAL. It exposes
  immutable evidence ingress from the same typed depot and ledger, not a guard,
  supplied verifier, unchecked successor or secret-key getter.

## Ownership and durability

The private [shared engine](../closed.rs) pairs each installed typed binding
with its actual verifier in a closed Joint/Progress enum. The old Joint owner
and new Progress owner use that same implementation. There is no public
polymorphic verifier, persisted success bit, or cross-drive proof cache.

The participant quota inventories the complete namespace before installation
or strict reopen. Metadata absence is checked first and its marker is published
last. Journal/floor/WAL writes use the same precharged control budget; proof
blobs use its typed depot budget. Blob/frame/control limits and Work algorithms,
timeouts and quorum rules are unchanged. Original and legacy Joint file/profile
bytes remain unchanged. Progress uses DCSPCV02/DCSPCQ02 and
DCSPFL02/DCSPFR02/DCSPFM02 with separate binding/file/hash domains; there is no
automatic adoption or migration.

A candidate import performs real application verification before its Journal
append fsync; this is not finality. A deciding command fsyncs its signer WAL,
then the exact prepared floor record is fsynced and installed, and only then
the next-slot signer WAL is advanced. Actions escape only after success.
The private same-drive handoff retains fixed public metadata only after the
cold full verifier ran. No frame survives a drive, error or unwind. Recovery
does not use that handoff and fully replays proofs, QCs and actual WAL output.
Uncertain owned I/O conservatively retains charges and poisons the owner/shared
namespace. Missing files, malformed tails and missing premises are not repaired.

The host owns one actual ProofGate across local verification/I/O operations.
Prefetch and network operations belong outside that gate and outside State
locks. This module does not construct a dummy server or a new ledger/store.
Windows directory-entry power-loss durability has the same qualified boundary
as [participant storage](../../README.md); file sync alone is not a universal
directory durability guarantee.

## Dependencies

| Library | Role |
| --- | --- |
| [registry200-joint](../../../registry200-joint/README.md) | Fixed new Source/Bootstrap803/Control815/Predicate896 composition, setup and same-store product replay |
| [version-journal](../../../version-journal/README.md) | Actual owner/PoW/Body/state validation, exclusive pending imports and durable append |
| [work-finality](../../../work-finality/README.md) | Actual weighted QC, Context, durable signer and unchanged bounded consensus |
| [protocol-storage](../../../protocol-storage/README.md) | One participant ledger, precharged control files and typed immutable depot |
| [registry200-journal](../../../registry200-journal/README.md) | Canonical SourceSpec and public Control CAS |

## Executed validation scope

All 26 library tests and 21 compile-fail examples passed in the owning native
gate. The new cases use explicitly public nonsecret fixtures, real
Source/Bootstrap803/Control815 proofs and genuine
three-key local QCs under an actual four-key Work roster. They check own Body,
parent/context/QC association, damaged Source with a genuine Control child,
latest retry, EmptyPending, strict cold replay, and real AfterSync/partial-floor
failures. Local signatures are not a real OS consensus test.

The bounded public setup/verified Key33 fixture is shared with legacy owning
tests; no live SDK Owner or private epoch is retained globally. Old durable
test assertions remain, with mechanical private-engine paths/test ownership
adjusted. The legacy module and original application stay separate.

The gate includes the affected original and legacy durability regressions.
Strict all-target consumer Clippy and six existing TLS actor tests passed after
boxing both private actor-owner variants; actor commands and deadlines are
unchanged. Those TLS cases exercise the existing Original application with Empty
blocks, not Progress or full FHE. See the
[validation record](../../../../docs/progress-finality-validation.md) for source
receipts, timing, failure coverage and scope.

A new-G full Predicate input16/output118 finality gate and actual multi-process
Progress runtime gate remain required before claiming those boundaries.
Owner State208/Result160 completion, durable Parked
calls, WAIT/deadlock/rollback continuation, mutable EPQ, Session integration and
permissionless roster activation are not implemented here.
