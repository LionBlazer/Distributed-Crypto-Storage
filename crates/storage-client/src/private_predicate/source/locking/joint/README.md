# Joint historical-parent input producer

This owner-side adapter produces the existing genuine Source/input16/Lifecycle/
PredicateAcquire relations under the distinct Joint application genesis. It
accepts only a sealed `VerifiedJointParent` plus independently pinned `JointBinding`,
BFV Owner/setup/anchor and actual Ready epoch. It never imports a generic Journal,
constructs a raw Joint parent, grants SQL/locks, completes a result or installs state.

| Direct owner | Responsibility |
| --- | --- |
| [Legacy locking](../mod.rs) and [producer](../produce.rs) | One private concrete parent route; unchanged shared mathematical producer and guarded candidates |
| [Joint descriptor/request](../../../../../../registry200-joint/src/lib.rs) | Full immutable application/setup/anchor/ALL33 pins and fixed outer Acquire envelope |
| [Joint history](../../../../../../registry200-finality/src/joint/history.rs) | Actual application proofs and weighted QC are the sole source of sealed parents |
| [Core Owner](../../../../../../bfv-query-core/src/lib.rs) | Read-only full original setup association before any FHE |

`JointLockingParent::from_verified(parent, independent_binding, bfv, ready_epoch)`
checks complete encoded descriptor, binding, new genesis/database, Active control,
actual Key proof and all33 values. Reconstructing `Descriptor::checked` uses the
caller's setup/anchor and the actual verified Key statement. Metadata supplied by
a peer cannot select these pins. Historical evidence does not show that no later
finalized state exists.

`SourceOwner::prepare_joint_locking` rejects a foreign object, re-audits/decrypts
the entire real N4 image/index, checks canonical actor/Registry/controllers and
rehashes both enrollment and current Registry with the NEW genesis before FHE.
It uses the same private producer as `prepare_locking`; the old public factory,
old intent hash domains, byte profiles and test bodies remain unchanged. Inner
SourceSpec intent/query remains the existing exact codec; the outer request is
`registry200_joint::Request` with `Lane::Acquire`, not an old-app Genesis relabel.

Success owns real Source/input16, Lifecycle and Link bytes, original prepared BFV
pending/request and guarded completion/StagedNext candidates. `into_parts` exposes
the public evidence/pending and a move-only opaque `JointLockingCandidates`; no
inner `LockingParent`/legacy prepared wrapper, secrets, install or completion API
escapes. WAIT/NOWAIT use the old early nonadmitted branch and have no Link/input16
or grant. Their Joint wrapper is mathematical evidence only, not an admitted lane.

The caller still has to execute actual peer FHE, record/replay ALL118 output
records, authenticate the exact signed Acquire body and obtain its genuine QC.
Client completion, durable owner Vault phases, exact-byte lost-ACK recovery,
fresh-network reconciliation and contention retries are separate work. The
input proofs retain individual128 policies; no whole128/144 or same-secret RK
guarantee is introduced. Existing frame, journal and participant caps stay fixed.

The two executed owning tests build sealed parents using actual Source, Bootstrap,
Begin, ControlKind and genuine3-of4 Work QCs. They release History/ingress/heavy
proof buffers before the full input16 preparation, and reverify public inputs
after private owners drop. There is no AcceptAll, forged sealed parent or fixture
FHE answer. New Joint contention after a competing held Acquire requires the later
full FHE+AcquireQC gate; this cut does not claim that test. Old genuine WAIT/NOWAIT
tests are preserved. Both new cases and twelve ownership compile-fail contracts
passed; see the [native record](../../../../../../../docs/joint-locking-inputs.md).

Optional direct `registry200-joint` and `registry200-finality` dependencies are
enabled under `private-input-proofs`; tests also use the existing
`protocol-storage` and `work-finality` owners. No Core-to-consumer dependency is
added. The first fullAcquire integration may phase ownership of the SAME typed
depot: clone sealed parent, drop History/all ingress, record via ProductStore,
drop it, reopen History and actually replay Bootstrap/Begin before Acquire QC.
No public MutexGuard/callback or second independent quota is needed for that gate.
