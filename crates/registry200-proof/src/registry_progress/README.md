# Fixed-source Registry statement progress

This Core module owns separate Bootstrap803, Control815 and Predicate896
AIR/proof frontends. It changes no old Registry200/Lifecycle/Encoding profile,
opcode, wire, admission policy or cap. Its five model cases, nine actual
cryptographic cases and three ownership compile-fail examples passed the
[native validation](../../../../docs/registry-progress-validation.md).
This module does not enable SQL SKIP LOCKED/WAIT/NOWAIT, finality or a current lock.

## Actual proof boundary

BootstrapExpected/BootstrapStatement and BootstrapWitness own the empty role.
prove_bootstrap/verify_bootstrap genuinely verify canonical Source first, then
open the same Source680, original Enrollment64 and new empty Registry208.
Width1082/H512 has119 absorbs; all base state/progress/padding fields must be
zero. All TableId/ordinal RowId words come from the authenticated Source opening.

transition::Expected::{control,predicate}, Statement, Witness, Prerequisites,
prove and verify own the two step roles. Constructors capture independent public
claims and guarded private openings; hashes/construction authenticate nothing.
Witness::predicate consumes eight salts in order: Source, enrollment, old
Registry, Cmd160, new Registry, Result160, new Progress48, current Encoding Cmd48.
Statement96 retains its own original salt.

Every call freshly verifies prerequisites. Control requires actual canonical
Source. Predicate requires a full genuine PrivateMask Encoding772 pair with
byte-identical Source bytes in Prerequisites.source. The existing Encoding
verifier owns Source-first verification once on that path. After prerequisites
die, the fixed new backend assesses its actual AIR/security floor before trace
allocation, then proves/self-verifies or bounded-decodes/verifies. No success
cache, reusable receipt, accepting boolean or verifier callback exists.

| Role | Complete public values |
| --- | --- |
| Bootstrap803 | Profile8 + full Source691 + context100 + next root4 |
| Control815 | Profile8 + full Source691 + Transition116 |
| Predicate896 | Profile8 + full PrivateMask Encoding772 + Transition116 |

Transition116 = context100 + old4/Cmd1604/next4/Result1604. Context100 =
profile8/q8/raw heads56/Ckey4/Copen4/G8/parent8/enrollment4. No public phase,
cursor, holder, prefix masks, mode/wait/window/projection are added. All predicate
statuses have the same profile/width/wire. The new step tail is width 8266/H512;
its v2 profile includes private wait codes 0=WAIT, 1=NOWAIT, 2=SKIP LOCKED.
Statement96 now has a distinct v2 profile. Registry208/Progress48 layouts and
Bootstrap803 are unchanged. No old candidate or legacy profile is relabeled. VerifiedBootstrap/VerifiedStep expose
public mathematics only, never SQL/current-lock/finality permission.

Detached DCSPGB01/DCSPGR01 frames have header120: magic8, tag1/reserved7,
profile32, full claim identity64, length4/reserved4. Step tags1/2 distinguish
Control/Predicate only. Child bytes are nonempty and bounded16MiB, sequence16,384,
total decoded elements16Mi. Old Body/frame/Journal/WAL ceilings stay unchanged.
Actual individual suite security and quotient geometry must pass every time;
no composed128-bit, latency or whole-process RAM claim follows.

## Exact private preimages

| Preimage | Fixed layout |
| --- | --- |
| Registry208 | Base fields0..193 in old order with new domain/version/profile; two slot present/root5 banks194..203; zero4 |
| Statement96 | Header13, stable scope16, enrollment4, client8/call2/tx2/principal1/controller8, original invocation8/blinded SQL identity8/snapshot8, mask8, mode/wait/offset/limit/projection5, salt4/zero1 |
| Progress48 | Header13, Statement root4, tx2/principal1/call2/microstep2/cursor1, cumulative visited4/selected4, block-present1/ordinal1/holder2/mode1/revision2, salt4/zero4 |
| Result160 | Header5/context100, old/next/Statement roots12, action/status2, tx2/cursors2, visited/selected/blocked12, old/new progress roots8, holder2/mode1/call2/microstep2, salt4/zero6 |

The new AIR reuses unchanged Boolean Registry2052, ranges/control and pure
opening equations. It does not call legacy acquire::eval (atomic WAIT). The
new tail/equality scan/cumulative walker independently constrain every progress
step. The existing mathematical trace writer supplies only base-bank cells;
new hashes/scans/semantics are owned here. circuit DTOs/native State methods
are explicit caller-owned mathematics; a verifier never calls the model.

WAIT advances real revision/sequence and keeps acquired/upgraded prefix locks
before the first genuine conflict. Parked progress commits the exact original
Statement; cumulative selected flags are not a completed SQL result. Resume
reopens old Progress/Statement, proves old flags against the fixed Source/mask,
retains prefix held modes, increments microstep and continues the same
OFFSET/LIMIT/cursor. Cursor0 has a distinct private Resume bit. Done clears only
actor progress and keeps locks.

NOWAIT needs a real first conflict and derives exact FailCurrent: retain latest
saved outer scope, mark actor failed. It is not an unchanged nonadmission or an
empty successful answer. Control forbids generic Acquire/FailCurrent. A parked
actor may only explicitly End(abort); parked RollbackTo/cancel/failure causes
remain unsupported. Another actor's End carries all progress fields by stable
transaction ID through whole-slot compaction. This math does not finalize End
or release a lock without the future actual quorum/application path.

SKIP LOCKED is a complete Done walk in the same Registry208 bank. The private
walker derives skipped = attempted AND conflicting AND SKIP, while a blocking
conflict is attempted AND conflicting AND NOT SKIP. Skipped rows advance the
cursor without consuming OFFSET or acquiring a lock. An unlocked matching row
consumed by OFFSET is acquired; LIMIT stops before any additional row, including
LIMIT0 with no search at all. SKIP has no parked progress, failure or resume path.
The genuine AIR constrains these flags and exact held effects; a native model
answer is not its proof. WAIT prefix/cursor and NOWAIT failure semantics above
remain in this same fixed relation.

## Original statement versus fresh attempt

Start anchors original SQL identity to that attempt's full Encoding identity.
Resume keeps the original blinded identity private through the same Statement
root while allowing fresh public Encoding SQL identity/nonce and fresh Source
q/Copen. Current Cmd48 must still open the identical full256 mask. Original
options, actor/controller/snapshot, client/call/invocation and Statement salt
cannot change. No AIR hashes/parses SQL text.

Invocation is an owner-selected private nonzero logical identity; q does not
authenticate the logical caller or exact SQL custody. Host/application must do
that. Stable scope binds exactly G32, enrollment4, full raw heads/packets, Ckey4,
BfvBinding.full_setup SHA256/32 and allKey33. It excludes attempt q/Copen/Cmask/
Cw/proofs/current Encoding SQL identity/nonce. AppID, objectID, setup SHA512 and
graph role profiles are not explicit Core Expected fields. G is an opaque
independently supplied genesis label here, not a Core claim that it commits
those absent fields. Future closed admission must independently check the full
descriptor/object/setup/provenance/profile associations and genuine old-state
lineage. Carried opaque progress roots rely on that proved bootstrap/transition
history, not a sender's arbitrary old root.

## Owning tests and unfinished integration

The genuine math gate declares actual Source, Encoding, Bootstrap, Begin1/2,
Acquire1 SKIP holding row3, Acquire2 WAIT retaining row0 under OFFSET1/LIMIT1, proved
End/compaction, then fresh q/nonce/blind Encoding and Resume selecting only row3.
A cursor0 gate keeps the original statement across a fresh public blind.
Independently genuine foreign-mask Encoding cannot resume it. NOWAIT proves
actual conflict/savepoint scope. Test Key33/setup labels are explicit public
mathematical inputs: Key/Formation/FHE evaluation and setup custody are not
supplied by this Core gate.

Repaired-root attacks change real banks, recompute all intermediate roots,
Poseidon gadgets/checkpoints and Result commitments, then reach actual AIR
rejection: prefix loss, progress dropped during another End, unrelated parked
Savepoint, Start identity substitution, reset cursor, false NOWAIT cause and
outer saved-lock erasure. A genuine SKIP proof skips conflicting row0 before
OFFSET1, locks OFFSET-consumed row1 and returned row2, then stops before row3.
Its repaired-root attacks count the skipped conflict against OFFSET, omit an
unlocked matching row and add a lock after LIMIT. A second genuine LIMIT0 proof
retains existing locks without any search; its repaired-root attack tries to
skip a conflict and acquire an OFFSET-only row anyway. Comparison counters and
all cryptographic hash gadgets/roots are rebuilt before actual AIR rejection.
Bootstrap attacks remain separate. Five model tests are explicitly unproved
and cannot replace genuine gates. All 14 runtime cases and three ownership
examples passed the owning native gates. Their bounded public fixtures establish
this mathematical relation, not a complete encrypted SQL or finality operation.

Future SQL acceptance requires all original input16/all118 output FHE proofs,
new state/predicate relations and exact own completion. No owner-filtered rows,
dummy FHE, atomic retry substitute or QC-as-computation-proof is allowed.
Fixed Source only: mutable tuples/EPQ, deadlock/cancel proofs, parked owner WAL,
runtime/finality/new app admission, fresh linearization, retained-history quota
and full-operation resources remain open. Timing/repetition/access-pattern
leakage policy is unresolved. No generic SQL/GUI/Session guard is opened.

Owned byte/integer witnesses use zeroize. Native field traces, mathematical
temporary vectors, SDK buffers, caller copies and stack/move scratch have no
total erasure promise. No Source key getter is introduced.

## Direct dependencies

| Module | Reused responsibility |
| --- | --- |
| [source](../source/README.md) / admission | Canonical geometry, Source680 and fresh actual verification |
| [coefficient_encoding](../coefficient_encoding/README.md) | Full PrivateMask772/Cmd48 and Source-first genuine verifier |
| [lifecycle](../lifecycle/README.md) | Pure opening/Registry/range/control/equality equations and owner-side base-bank writer |
| [bfv-hiding-stark](../../../bfv-hiding-stark/README.md) | Actual hiding SDK assessment/proof/verification, Poseidon and bounded canonical codec |

Existing p3/SHA2/zeroize dependencies suffice. Test images use compact-store;
public mathematical key labels use bfv-key-transform. No reverse dependency on
experiments, storage-client, runtime, SQL planner or fixture generators is added.


## Executed native gates

Root owns sequential native execution. First compile the actual new relation,
then run the five short owner-model cases. The two new genuine SKIP cases share
the bounded public Source fixture in one test process and exercise the actual
security assessment, proof generation, self-verification, independent verifier
and four repaired-root malicious-witness attempts. They are the first gate for
the changed width. After they pass, run the seven existing cryptographic cases
once to retain WAIT/NOWAIT, bootstrap and hostile-state coverage. The unchanged
three compile-fail ownership examples must still reject compilation.

```sh
cargo test --release --offline --locked -p registry200-proof --lib --no-run
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::model_tests:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::transition::tests::genuine_skip_locked_ -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib registry_progress:: -- --test-threads=1 --skip registry_progress::model_tests:: --skip registry_progress::transition::tests::genuine_skip_locked_
cargo test --release --offline --locked -p registry200-proof --doc registry_progress:: -- --test-threads=1
```

The initial five model cases and two SKIP cases passed. Following mechanical
Clippy iterator fixes in the new AIR/trace writer, all nine cryptographic cases
were run together, including both affected SKIP cases. They passed in 135.03
seconds in the test body, 174.753 seconds including rebuild. The three ownership
examples and the old three-profile byte/geometry regression also passed. Strict
all-target release Clippy passed. See the validation record for exact source/log
pins, failed compile attempts, commands and resource observations. These gates
establish only this mathematical relation; complete FHE-result/application
composition later passed its own [application gate](../../../../docs/progress-application-validation.md).
Owner continuation, finality and real DCS admission remain separate required work.


### Private predicate Result160 opening

The typed opening assertions passed in all nine affected cryptographic cases;
five privacy examples and strict all-target Clippy also passed. See the
[opening validation](../../../../docs/result160-opening-validation.md) for the
exact tested revision, commands and limits. The earlier native record above
describes the preceding Core revision.

`result_opening::ResultOpening::open` consumes 160 canonical `u64` words and
requires the actual `transition::VerifiedStep`, the independently retained
original `StatementOpening`, and the exact optional previous/parked progress
openings. It checks every field's canonical range, the complete current proof
context, old/next/original-statement roots, the full Result160 commitment, fixed
padding, and typed cursor/status/flag/holder/call/progress associations. It
rejects the distinct Control result grammar. Typed getters expose only private
mathematical values; the backing 1,280-byte array is zeroized on drop and has no
raw getter, serialization, `Clone`, or `Debug` implementation.

`transition::Witness::result_opening_fields` returns the unverified private
preimage from the same internal builder used to set its proof claim. It is for
bounded encrypted owner custody; it performs no second predicate evaluation.
An opening does not grant SQL success, rows, a current lock, QC acceptance, or
bank installation. The actual owner must first bind its exact operation and
fresh agreed parent/finality receipt; only its separate completion boundary may
dispatch Done, Parked, or Error and install the next root-checked private bank.
This addition changes no relation, profile, wire format, proof cap, or old API.
