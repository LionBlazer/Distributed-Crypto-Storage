# Private Registry200 lifecycle research candidate

Validated experimental relation. Release/Clippy, numerical gates, genuine proofs
and all 21 new owning tests passed; see the
[validation record](../../../PRIVATE-REGISTRY-LIFECYCLE-VALIDATION.md). It introduces
two distinct experimental kinds:
`registry-lifecycle-bootstrap` and `registry-lifecycle`. Neither kind is admitted
by the existing proof wire, private Journal, SQL acceptance path or BFV producers.
The validated Registry112, enrollment64, LockReturn168 and all older profiles keep
their existing meanings. A 32-byte root is not a conversion between these types.

The reusable production libraries do not depend on this experiment. Direct module
dependencies are the [canonical Source relation](../README.md), its private
[Poseidon gadget](../poseidon.rs), the fixed [backend](../../backend.rs), and the
SDK AIR/prover. It also uses [primitive contracts](../../primitive.rs) and the
shared [digest byte codec](../locking/statement.rs), without Registry112 conversion.
The `transaction-state` dependency is used only by the independent
owning-test oracle. That native state machine is never called by a verifier.

## Public boundary and authority

[Expected and Statement](statement.rs) pin the complete canonical Source statement,
its exact request, both full heads and packets, C_key, C_open, genesis, parent and
new principal enrollment. Transition Expected additionally pins C_old and C_cmd.
`verify` in [mod.rs](mod.rs) verifies the genuine canonical Source proof first,
compares the complete independently supplied Expected, then constructs the child
backend and verifies the lifecycle STARK. Missing, byte-only or foreign Source
proofs are rejected before constructing the child backend. No cache Boolean, native registry image, fixture
answer or unverified receipt is an accepting substitute.

The separate enrollment64 v2 binds two principal labels to two private nonzero
256-bit controller banks. A principal may own both live transaction IDs. The
relation does not prove controller signature possession, key validity or permission.
The application must independently owner-authorize the exact enrollment and command;
this module implements no authorization signature adapter. Its outputs are not live
lock grants, agreed fresh versions, MVCC snapshots or writer fences.

The empty bootstrap is post-genesis and proves revision 0, allocator 0 and no present
transactions under the new domain. It cannot relabel the old two-transaction
Registry112 bootstrap. Enrollment and Registry200 have independent fixed profiles,
not the current proof-kind profile, so enrollment persists across transitions and
there is no recursive profile hash. Source request identities are chosen before
C_open and C_cmd; the commitments are not inputs to their own request identity.

## Fixed image and command semantics

[model.rs](model.rs) is an owner-local prover input builder. It is not called by
verification. The new stable registry has exactly 200 Gold fields:

| Fields | Meaning |
| --- | --- |
| 0..79 | Domain/version/profile, genesis, DB/key domain, C_key, C_enroll, TableId, all four ordinal RowIds and N4/T2/D2 capacities |
| 80..83 | Revision and last allocated transaction ID, each two u32 limbs |
| 84..136,137..189 | Two complete 53-field transaction slots |
| 190..193,194..199 | Registry salt and six zero padding fields |

Each slot contains explicit presence, u64 ID and sequence limbs, enrolled principal
and its controller, failed flag, full 32-byte Begin snapshot, four lock modes, and
two savepoint records. Each savepoint has presence, all 32 name bytes and four saved
lock modes. Absent fields are zero; internal zero-mode one-hot selectors remain 1.
Present slots form a sorted compact prefix by transaction ID. End copies the entire
surviving 53-field record, including both names/snapshots, before clearing the tail.
The allocator never rewinds. Begin appends allocator + 1, starts sequence 1 and pins its
snapshot to the independently supplied actual parent. This is a control snapshot,
not a proof of data snapshot isolation.

All seven operations are constrained in the new AIR: Begin, Acquire, FailCurrent,
Savepoint, RollbackTo, Release and End. Acquire scans all four canonical source ages
against the full 256-bit mask and applies the four lock modes, WAIT/NOWAIT/SKIP,
OFFSET and LIMIT 0..4. OFFSET rows acquire locks; SKIP skips an actual conflicting
other transaction before counting the limit. Matching principals do not merge
transaction ownership. Conflicting WAIT/NOWAIT is atomic: C_new equals C_old with
the old salt and no counter change. All returned/skipped/visited result flags are
zero for that unsuccessful command. LIMIT 0 succeeds and advances counters.

Savepoint names compare as eight exact u32 equalities; zero names and duplicate
names are valid, and the newest live match wins. RollbackTo retains its target and
drops younger frames. Release removes its target and younger frames while keeping
current locks. FailCurrent explicitly restores the newest saved lock snapshot, or
zero with no frame, and marks failed. A failed transaction admits only RollbackTo
or End. Invalid APIs or lock conflicts do not implicitly become FailCurrent. End
removes the actor; failed Commit resolves to Abort and is a successful transition.
These controls follow the relevant PostgreSQL 18
[savepoint](https://www.postgresql.org/docs/18/sql-savepoint.html),
[rollback](https://www.postgresql.org/docs/18/sql-rollback-to.html),
[release](https://www.postgresql.org/docs/18/sql-release-savepoint.html) and
[locking](https://www.postgresql.org/docs/18/explicit-locking.html) behavior within
this explicit N4/T2/D2 abstraction. Saved modes summarize monotone lock upgrades;
they do not certify the native event history, its byte encoding or event-count cap.
There is no encrypted data rollback/commit relation here.

Revision increments on each successful command. Allocator increments only on
Begin. Existing actor sequence increments on each non-End command. End at sequence
u64::MAX remains admissible if the global revision can advance. Every increment is
two range-checked 32-bit limb equations with a Boolean low-limb carry; unsigned
ordering uses 64 explicit borrow steps. No full 64-bit value is recomposed in Gold.
Thus an ID equal to the Gold modulus is still positive, and a +Gold counter alias
cannot satisfy the increment relation. Cmd160 derives its claimed revision from
the committed old registry and its sequence/controller from the actual actor;
C_cmd still has to be independently pinned by the authorized caller.

## AIR and resource boundary

[layout.rs](layout.rs), [ranges.rs](ranges.rs), [control.rs](control.rs),
[acquire.rs](acquire.rs) and [air.rs](air.rs) define a calculated 6741-column,
512-row transition relation with 116 public values and 512 periodic columns. The
separate [bootstrap AIR](bootstrap.rs) has 1082 columns and 104 public values.
The actual bootstrap report has 4,996 constraints/degree 3; transition has
26,562 constraints/degree 5. Both have 16 quotient chunks and individual unique/list
floors of 128. The validation record separates array sizes, actual process
observations and the unresolved composed-security bound.

The transition opens six complete fixed streams, with a zero-capacity reset at
each start: Source680 at rows 0..84, principal Enrollment64 at 85..92, Old200 at 93..117,
Command160 at 118..137, New200 at 138..162 and Result144 at 163..180. Total 1448 fields
is 181 absorbs. Source680 retains the exact old 674 fields and six padding zeros.
Every last active hash is checked, all TableId/RowId words are captured from the
same C_open stream, and immutable banks/checkpoints remain constrained through
row 511. A genuine Poseidon gadget also constrains padding rows.

Result144 binds the full context and all three old/command/new roots, operation,
outcome, transaction ID and four returned/skipped/visited flags. It does not contain
the original-value tuples in legacy Return168 and is not a projected SQL result or
an authority/column-ACL grant. Outcome 0 means successful control/Acquire, 1 blocked,
2 NOWAIT, 3 successful End resolved to Abort. Result flags are zero except successful
Acquire. Global mutation success excludes outcomes 1 and 2; Abort 3 still removes the
actor and advances revision.

The old child wire limits are unchanged. The calculated unmasked trace is
27,611,136 bytes, masked main trace 55,263,232 bytes and main LDE 442,105,856 bytes
under the old backend formulas; these arrays are not process RSS. A future distinct
typed wire needs actual full Source+child serialization and a complete Journal body
bound under the existing 32 MiB limit. No emitter fit or composed 128-bit guarantee
is asserted. The required peer-only encrypted computation, compact storage,
decentralized agreement/freshness and fast complete SQL proof remain open.

## Validated owning examples and normal entry points

[tests.rs](tests.rs) and [tests/native.rs](tests/native.rs) contain 21 unignored
owning tests, all executed successfully. They cover independent native control parity, all seven
operations, duplicate/zero names, upgrades and rollback, complete compaction,
failed Commit, u64 boundaries, full flags, coherent raw-SDK attacks and repaired
positive controls. The genuine test code verifies Source, a new bootstrap, a
foreign enrollment child under its own Expected, and a ten-command chain through
the public composite verifier. A genuine Bytes proof is independently verified
before its prerequisite rejection. Actual discovery lists 296 cases; this stage
executed all 21 new and 27 prior controls. Old 275 test names/bodies remain unchanged except exhaustive
new-Kind rejection arms.

From the standalone leaf:

```powershell
cargo run --release --locked --offline -- security registry-lifecycle-bootstrap
cargo run --release --locked --offline -- security registry-lifecycle
cargo run --release --locked --offline -- prove registry-lifecycle-bootstrap
cargo run --release --locked --offline -- prove registry-lifecycle
```

Each security command emits exactly two analytical security objects, canonical
Source then child, without any trace, proof or Journal append. The lifecycle
`prove` path first proves/verifies the new empty bootstrap, then proves Begin with
C_old equal to that genuine output. It reports Source and child serialized bytes
using actual Postcard, without invoking a legacy wire decoder. Its proving timer
includes that bootstrap prerequisite; final verification timing covers only the
reported Source+child pair. Both fixtures are explicitly PUBLIC NONSECRET. The
validation record gives actual timings, component sizes and observed process RAM.
