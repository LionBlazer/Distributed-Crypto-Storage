# Joint Acquire preparation and one-shot completion

This owner-side adapter produces the existing genuine Source/input16/Lifecycle/
PredicateAcquire relations under the distinct Joint application genesis. It
accepts only a sealed `VerifiedJointParent` plus independently pinned `JointBinding`,
BFV Owner/setup/anchor and actual Ready epoch. It never imports a generic Journal,
constructs a raw Joint parent, opens the generic SQL capability or installs state.

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
inner `LockingParent`/legacy prepared wrapper, secrets or install API
escapes. WAIT/NOWAIT use the old early nonadmitted branch and have no Link/input16
or grant. Their Joint wrapper is mathematical evidence only, not an admitted lane.

The caller still has to execute actual peer FHE, record/replay ALL118 output
records, authenticate the exact signed Acquire body and obtain its genuine QC.
Durable owner Vault phases, exact-byte lost-ACK recovery,
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

## Exact operation completion

`JointLockingCandidates::complete_acquire(owner, original_prepared, operation)`
consumes both original private banks, the original one-use BFV pending/request,
and a sealed `VerifiedJointAcquire` from the closed keyless History. That value
must contain the same fresh input16/output118 result that survived the full
Lifecycle/PredicateAcquire check and exact owner-signed Body/QC/context checks.
A prior streamed result, generic Active parent, catalog or boolean cannot replace it.

Before one actual decryption, completion compares the independent binding,
parent/slot/previous decision, exact inner and outer requests, Provenance, complete
BFV request, Body/Manifest and old/new Control roots. It rehashes Result144 from
the private actor transaction, returned/skipped/visit flags and original salt
using the same pure builder as the Lifecycle writer. No plaintext ages or
predicate are used for those checks. It decrypts the checked response once,
requires each returned original ordinal to be present, and projects the committed
returned flags once. WHERE, OFFSET, LIMIT and lock selection are never rerun.

`CompletedJointAcquire` returns owner-readable projected rows and may transfer
the still-guarded `StagedLockingTransition`. It cannot install that state or be
used as a generic current lock after a subsequent End/reacquire. The operation
was linearized in its exact QC slot; independently obtaining a current network
view and durable owner-state reconciliation remain the host's responsibilities.
The existing generic Session SQL guard stays closed.

The new opt-in owning source case under `tests/full_acquire.rs` requires a real
explicit `DCS_PEER_EXE`. It starts four OS validator daemons and a separate normal
OS FHE peer; no local fixture assembles the Acquire QC. It uses actual Store/Fetch,
the typed producer, all118 recorded components/END/EOF and fresh client replay.
The fixture returns ordinal3 for OFFSET1/LIMIT1 and checks that both offset-stepped
ordinal0 and returned ordinal3 are locked, consistent with
[PostgreSQL SELECT locking](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE).
It has no competing held row and makes no contention-branch claim. Repaired foreign
intent, stale genuine Begin QC, latest retry, missing output117 and corrupt retained
Link are explicit checks. With the same actual operation, the test changes and
restores each private Result144 flag bank, actor transaction and salt before the
one consuming completion. These malformed openings must fail before decryption.
This full gate passed with all four actual QCs, fresh keyless replay and exact
client completion; the [native record](../../../../../../../docs/joint-participant-finality.md)
pins its source, binary, timings and resource observations. The separate
two-Acquire test in `tests/full_acquire_contention.rs` also passed. Its first
actual Acquire holds ordinal0; the second skips that real conflict before OFFSET
consumes ordinal3. The second result is empty and its checked Registry locks
ordinal3. Both operations use real OS FHE streams, four-validator QCs and fresh
client replay. This remains a fixed-N4 historical operation; owner persistence,
current-network reconciliation and general SQL admission remain separate.
It imports only a cfg(test) shared OS supervisor; no production Core-to-app edge exists.

Native proposal from the repository root (PowerShell, using the default target
directory; use the actual isolated target path when `CARGO_TARGET_DIR` is set):

```powershell
cargo build --release --locked -p dcs-peer
$env:DCS_PEER_EXE = (Resolve-Path target/release/dcs-peer.exe).Path
cargo test --release --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::tests::full_acquire::four_os_quorum_and_fhe_peer_complete_only_the_exact_own_joint_acquire_after_fresh_replay -- --ignored --exact --nocapture --test-threads=1
```

Missing binary is a hard test failure. The old producer tests and their
historical validation record above remain separate evidence.
