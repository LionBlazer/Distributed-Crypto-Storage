# Closed Progress network driver

## v3 same-call native result ownership

The new APPLICATION v3 digest intentionally creates new App/G/Rules/Binding IDs;
old v2 Descriptor/Manifest/Request G/QCs/private banks reject without migration.
Individual Core/math profiles, 02 wire grammar, all caps, IO180/op1800 and the
existing native gate policy stay exact. Historical v2 native records below do not
prove this new-G route. The full five-product v3 gate passed; see the
[validation record](../../../../../../../../../../docs/progress-driver-scoped-completion.md).
The earlier first-product and four-validator cold replay observations retain
their narrower scope.

A local RecordingScope starts inside one exclusive drive call. Work's SAME remote
stream genuinely verifies all input16/output118 and actual END/EOF before catalog
publication. Its move-only result survives only through that call's exact signed
proposal/Submit fsync and ordinary network QC round. The private phase pair keeps
both complete catalog=None BEFORE Attempt+Cursor and catalog=Some AFTER state,
full actual Context/parent and saved Header/Body; it is never a Driver/Owner field
or a WAL success flag. Native permits and store locks release before validator
upload/consensus waiting. Busy retries retain it only inside the bounded call;
Pending/error/cancellation/drop discards it without renewing a deadline.

After one independently valid full QC, private completion reacquires the SAME
gate and consumes the frame. SAME-Arc/all-original-byte rereads bind its already
completed native proof instance, then actual Source/query/Core896, current
Journal/Context/QC, Result160, whole private bank/book and fsync still run. These
rereads are not another native product verification. Public Owner.complete,
every validator/signer/floor/import/reopen and historical retry remain full cold
native paths. No cache/reconstruction/checked flag or accepting callback exists.

The SAME four-validator gate now has five genuine Work calls and eleven actual
network QCs: A acquire, B WAIT/Parked, full cold parked Owner/quota reopen, A SKIP
conflicts before OFFSET with actual Done EMPTY, ordinary End/resume, then NOWAIT.
All previous ingress handles drop before reopen. The diagnostic prefix remains
`progress_combined4` to identify four validators; it no longer means four jobs. No separate
one-product duplicate or reduced security check is added. Phase receipts must
separate original streaming, byte association, actual Core/QC/private completion
and cold recovery. This pass establishes no controlled full-query speedup.


This module owns concrete ordinary network orchestration around the SAME actual
Progress Owner. It does not activate Session/PGwire SQL or replace a computation
proof, fresh weighted QC, private opening or synced owner bank. The current
owning checks and the bounded v3 network workflow passed.

## Responsibility and dependencies

`Config` independently selects bounded distinct TLS peer endpoints, a FHE endpoint
and finite mining work. Binding, setup, clients, controllers, private bank, quota,
public evidence ingress and the ONE process ProofGate come from its actual Owner.
The module never opens another depot/quota or constructs another native gate.

`drive` calls the existing real custody/Source/input16/Core896 preparation and
actual RemotePeer FHE product118 recording route. `operation` owns resource-only
socket cancellation and a joined deadline watcher. `upload` schedules typed
ProgressFinalityClient RPCs, actual catalog references and independently checked
weighted QCs. It borrows no private bank/store lock during ordinary network waits.
The parent Owner alone opens QC-linked Result160, checks the full next bank,
fsyncs its existing AEAD WAL and installs Parked/Done/Error/Control outcomes.

Direct dependencies are parent closed Owner/Proposal APIs, peer-runtime typed
Progress clients/RemotePeer, peer-transport cancellation/TLS pins,
registry200-finality Binding/Candidate/History/OperationExpectation,
registry200-joint fixed Progress Request/Manifest/ingress, protocol-storage BlobId,
bfv-product-evidence CatalogClaim, actual work-finality Context signatures and
standard scoped threads. No application, fixture generator, callback verifier or
old Joint host is a production dependency. Private pure scheduling callbacks
exercise ordinary I/O only and cannot mint a proof/QC/SQL receipt.

## Public API

`Driver::attach(owner, signer, Config::new(...))` consumes the genuine owner and
checks the signing key against its own independently installed genesis. It
exports only Config, Driver and Run; no mutable owner/history/ingress/key getter
or unchecked result constructor is provided.

`execute(cursor, &Call, &Material, fetched, budget)` starts or continues the exact
logical client call. `resume(cursor, client_id, ...)` preserves the original
parked statement and accepts no replacement SQL. `continue_pending(cursor, ...)`
uses only the already durable global Prepared/Submitted/Terminal operation.
Caller authentication/authorization of logical clients remains the embedding
owner application's responsibility.

- `Run::Waiting { cursor }` is owned and holds no Owner/Reply borrow. The caller
  can execute another client's End immediately after destructuring it. It is the
  actual durable private Parked path, with no rows, ACK or lastCompleted advance.
- `Run::Pending { cursor, reason }` is resource/network incompletion, including
  Busy, missing quorum, interruption or deadline. It is never SQL WAIT/NOWAIT and
  cannot be mapped to SQL55P03 or an empty success.
- `Run::Terminal { cursor, outcome }` borrows only the actual typed durable
  Outcome. Done rows are already derived by the genuine Owner completion;
  NoWaitError and Control::Aborted keep their exact meaning. Explicit
  `acknowledge(cursor)` consumes only the existing prepaid terminal allowance.

`cursor()` supplies CAS metadata. Resource-only `request_control()` closes current
operation sockets without changing SQL locks, transaction state or pending bytes.
Consuming `into_owner()` transfers the same owner, including pending/parked or
poisoned state. Every operation has joined before any public return. No detached
worker remains behind a terminal borrow, error or panic.

## Exact original retries and Proposal boundary

A matching retry compares the retained client, sequence, kind and bound exact-SQL
call digest. It never derives a new transaction ID from a completed Begin's
allocator or an End's now-empty active slot. Prepared uses its saved original
input/proof frames; Submitted always first attempts its SAME saved Header/Body
per peer before missing-premise upload and exact retry. No parent/q/header/proof
rebase replaces an uncertain published operation.

The private shared Proposal path captures current Cursor, complete guarded
Attempt bytes, actual full Context/parent, checked product catalog and canonical
owner-signed Body. Unmined metadata or borrowed Computed grants nothing. Driver
retains its advancing Header nonce and mines in at most 4,096-attempt chunks,
checking deadline/cancellation between chunks. InvalidTimestamp waits for a
legitimate current timestamp; no future timestamp, easier target or changed
intent is invented. These objects exist only during this run.

Final publication checks the complete current Cursor/phase, exact Attempt bytes,
full Context and parent metadata, current genuine Computed identity, complete
Request/Manifest/Body/authorization, same-store catalog premises and actual
History-derived Header/target/PoW. It writes the unchanged Submit record and
syncs before installing Submitted. Public consuming Owner.submit delegates to
this same private path with its unchanged signature, wire/profile and WAL.
Catalog metadata is captured cheaply; the existing full retained-original check
runs once at final publication, avoiding a second whole proof-bank scan.

Cancellation/deadline before Body fsync keeps Prepared. Its operation-local
Computed/Proposal is dropped on return: there is no cross-call verified cache,
serialized success, catalog-to-proof shortcut or secret/key bank. Cold Prepared
restart therefore still requires actual Work/FHE verification again. After
Submit fsync, all retries keep its exact original Body. Synchronous native proof
work cannot be forcibly preempted; the driver waits for it and joins everything
before returning instead of claiming a hard deadline it cannot enforce.

## Bounded upload, QC and failures

The private plan contains metadata only from the SAME saved signed Body,
Attempt Request and Manifest, checked by actual OperationExpectation before I/O.
Control uses two Source/Core815 manifest roles. Predicate uses Catalog/Core896
plus every actual setup/input/output catalog reference. At most 142 references
are admitted. Each configured endpoint owns one scoped worker (at most16). Only
a read+PUT turn acquires a fair ordinary-I/O blob slot; at most three current
<=32-MiB public blobs are owned. Store and admission locks release before RPC.
All bounded configured endpoints share FIFO one-blob admission; no fixed first-three
subset or global all-upload barrier is selected. Upload success/import ACK/observed hints grant no authority.

Every candidate QC is independently compared using the WHOLE actual
Candidate::for_context encoding and Context.verify_commit. One valid exact QC
suffices: stop/cancel and join the remaining workers, then invoke actual
Owner completion for full proof/QC/Result160/root/WAL acceptance. Invalid peer
responses are disqualified without aborting healthy peers. Local original loss
or corrupt canonical metadata is a hard error. A genuine different current-slot
QC/new head without the saved matching bank yields RecoveryRequired; no foreign
bank is adopted or Prepared/Submitted rebased. This is no generic latest-head or
permanent-lock theorem.

Existing IO180s/op1800s budgets, proof/profile/wire/security/resource bounds and
old Joint behavior remain unchanged. An absent quorum returns only Pending;
locks are never granted through an unavailable peer or a metadata flag.

## Verification and remaining scope

The owning network filter passed 17 ordinary scheduling/configuration/call-guard
tests in 0.02 seconds (37.90 seconds including compilation); one expensive case
was initially ignored. Strict all-target storage-client Clippy passed. These
cheap tests use public nonsecret TLS identities and ordinary I/O observations;
they return no fake proof-positive result. The earlier Owner82 and compile-fail
execution records retain their exact source scope.

The one separate full gate then passed with four actual Progress validators and
an independent FHE peer. It includes A Acquire, B Parked, parked reopen, A SKIP
LOCKED Done EMPTY, A EndClosed, B fresh resume Done, then new A Begin, A NOWAIT as
product5 and A EndClose Aborted. Do not repeat another WAIT3 run without a new
failure or source concern. Session/PGwire/general SQL/MVCC/writers, parked
cancellation/RollbackTo, deadlock and EPQ remain unsupported; capability guards
stay closed.


## Executed five-product four-validator workflow

The separate test-only `process_tests`/`process_fixture` boundary adds one cheap
exact-SQL/options preflight and one ignored genuine network workflow. Its source
reuses the existing public non-secret custody construction and unchanged shared
five-child supervisor. The gate starts four actual Progress validators and one
independent FHE peer once, obtains an actual network Bootstrap QC, then exercises
public Driver BeginA/BeginB before doing FHE. No certificate is assembled by the
test. A valid full Candidate/context QC, fixed application replay, private result
opening and fsynced bank still precede every outcome.

The one staged workflow is A Acquire(row3), B WAIT with OFFSET1/LIMIT3 (locks the
consumed row0 and prefix1/2), one full parked Owner/quota cold replay, A SKIP LOCKED
with LIMIT2/OFFSET1 returning actual Done EMPTY, ordinary A EndClosed releasing
row3, B resume without SQL preserving the exact original
private statement while creating fresh q/Copen, then new A Begin/NOWAIT/Error and
A EndClose yielding Aborted. It has eleven actual QC slots, five Control815
children, one Bootstrap803, five Predicate896/remote output118 computations, and
exactly 40 owner WAL records. SKIP skips B's conflicts before OFFSET, while A keeps
its own row3 lock; the independent Core AIR cases also cover own-held rows not
being conflicts. B's exact private progress/client call remains unchanged through
SKIP and its ACK. The accepted catalog count and explicit Work_compute_start
markers must both be checked; unexpected retry/reproving is not hidden as five
jobs. Pending/timeout fails this connected acceptance gate without a fresh budget
or Work retry. No separate one-product or WAIT3 heavy run is required.

`drive.rs` and `upload.rs` diagnostics compile only under cfg(test). They use
monotonic Instant/eprintln and do not change production proof, gate, wire, quotas,
threads, scheduler or timeouts. Receipts separate preparation, Work.compute
(remote product plus local streaming verification/recording together), proposal/
Submit fsync, first/last actual PUT per peer, submit, checkpoint observation,
full actual QC verification/first selected valid QC, worker joins, private complete,
ACK and full cold replay. Successful private-completion markers distinguish
`original_native_scoped` (expected five) from `full_cold`; the original Work
starts/ends must each count five. QC-valid markers occur only AFTER the actual candidate
and weighted certificate checks. No private SQL, keys, values or proof bytes are
logged. These measurements must not be interpreted as pure cryptographic/network
cost when the interval includes multiple kinds of work.

The cheap preflight passed in the network filter, and the full acceptance passed
in exactly one ignored run. The earlier Driver9 and compile-fail results remain
separate historical evidence.
With an independently pinned absolute DCS_PEER_EXE:

```text
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::progress::host::network::process_tests::combined_public_fixture_sql_and_options_are_checked_before_any_crypto -- --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::progress::host::network::process_tests::actual_four_validators_wait_park_reopen_skip_locked_end_resume_then_nowait_abort -- --ignored --exact --nocapture --test-threads=1
```

The7200-second observer fuse applies to the COMPLETE MULTIOPERATION TEST only;
production1800-second operations and180-second I/O remain unchanged. Root observes
two Cargo jobs/Rayon2 and the existing1792MiB per-process fuse, actual disk usage,
individual/aggregate peaks and sampling gaps. The Rust test took 5845.27 seconds;
the external observer took 5845.625 seconds. Independent
commands between crypto phases would require extra full Owner/validator replay
and five-child restarts; this fixture uses one full parked recovery and meaningful
stage receipts instead. Children join before their owned temp root is removed.

This pass covers only the fixed Source/Progress Driver workflow.
It does not establish generic current-head/lock-lease policy or arbitrary SKIP semantics,
Session/PGwire, arbitrary schemas/SQL/writers/MVCC, parked RollbackTo/cancellation,
deadlocks or mutable-row EPQ. Existing capability guards remain closed.

## Optional public artifact custody (separate validation)

`process_capture.rs` (the private `process_tests::process_capture` child) is not
a library/export API. If `DCS_PROGRESS_PUBLIC_CAPTURE_DIR` is absent, the five-job
four-validator test performs no capture RPC, file IO or extra owner metadata
lookup. If enabled, it collects
only after product1 has genuinely completed its QC/private-bank/WAL fsync, before
its existing ACK. The full v3 gate above disabled capture. Enabling it requires
a separately pinned observer/runner that explicitly whitelists this path.

The opt-in absolute target must be a NEW direct child of a canonical existing
`.local` directory. Existing targets/files are refused. The helper fetches exact
historical slots1..4 using public checkpoint/candidate APIs, checks the original
Context/QC chain, real header-only Journal PoW/target/time validation, canonical
signed Body/owner authorization, root continuity and exact slot4 association to
the actual completed owner parent. It does not import bodies into a fake verifier
or treat these checks as Source/input16/output118/Core896 proof acceptance.

The same ingress supplies only explicit Manifest/Catalog references. Original
setup parts must match SetupClaim and both complete SHA256/SHA512 descriptor pins.
At most148 unique CAS blobs/162 files/1GiB TOTAL (including metadata) are allowed;
32MiB per blob,64MiB setup,64KiB Body,6416B catalog, the unchanged typed checkpoint
cap and a128KiB manifest further restrict them. The manifest explicitly records
the independently fixed public_network=[0x3a;32] fixture parameter; SourceSpec and
Work seed domain must match it before export. Every reference retains its actual
role cap. Rules parameters are in the manifest, not a163rd file. The roughly611MB
current fixture is an observation, not a new allowance or performance claim. One
blob buffer is read at a time; no second store/ParticipantQuota is opened.

All files use CreateNew and sync. `manifest.json` follows all payloads; `COMPLETE`
contains only its SHA256 plus newline and is written/synced last. Earlier failures
propagate to the owning test without a completion marker or omission fallback.
A final marker-write/sync failure is also an error; no returned success or durable
proof is inferred from an ambiguous directory/marker. Windows directory power-loss
durability is not established. Generated public output must never be committed.
The untrusted artifact excludes owner/private Source/BFV/Ready backups, statement
openings, rows, authority/wrapping keys, TLS keys, signer seeds and all mutable
WAL/journal/floor/lock files. Collection uses public DTOs and same-store raw bytes;
there is no arbitrary filesystem source path or serializable owner object.

The three cheap tests cover untrusted IO/caps/hash/CreateNew/error/marker behavior,
not a simulated crypto-positive. Capture and cold replay keep the separate scope
in the [validator profile](../../../../../../../../../../docs/progress-validator-profile.md);
the capture-disabled full v3 pass does not rerun or expand their assertions.
An opt-in capture uses this SAME genuine workflow, without an extra FHE fixture.
Four-validator replay independently pins the fixture and cold-verifies all
application proofs and prefix QCs. Target QC4 is reference-only and must not be
preseeded before target submit. An archive or COMPLETE grants no fresh SQL,
owner completion, current lease or benchmark result.

## Fair blob admission and independent metadata workers

On 2026-10-20, strict all-target storage-client Clippy and the owning network
filter passed. Its 17 cheap tests took 0.02 seconds; compilation and execution
took 37.90 seconds. The actual five-product/eleven-QC gate then passed; see the
[v3 validation record](../../../../../../../../../../docs/progress-driver-scoped-completion.md).
Historical first product1 private Done/QC/fsynced ACK and the separate four-peer
public-capture cold replay are their own evidence and do not measure this new
scheduler's performance. Root owns source integration and all native gates.

Each configured endpoint has one join-owned worker, bounded by MAX_PEERS16.
Only reading and PUTting its current public blob owns one of three FIFO slots;
the complete logical role cap, hash/length/EOF reread, exact owner-signed Body,
selector and BlobId checks remain unchanged. Original/Submit/checkpoint RPCs own
no blob slot, so three slow imports cannot prevent a fourth peer uploading.
Payload ownership is at most3*32MiB; whole-process RAM also includes bounded TLS,
control/certificate buffers and up to16 worker stacks and must still be measured.
No native ProofGate or owner/bank/store mutex spans these network waits.

SavedOriginal remains that peer's first exact Body RPC before any blob; no new
query, parent, signature, header or durable checked flag is created. FIFO admission
requeues each successful blob at the tail. BUSY/lost ACK retains the exact ordinal.
Cancellation wakes admission and all workers use the same absolute operation
checks. No production deadline or IO timeout is shortened, extended or renewed.

A normal remote disqualification ends only its own worker. Local original loss,
corrupt local metadata/store/admission state, genuine foreign-current QC and
worker panic remain hard failures. Any actually returned checkpoint is classified
by the concrete full candidate/weighted signature check even if cancellation
races its RPC; the cancellation tail can suppress success but cannot erase a
classified local error. The first valid expected QC cancels all local sockets,
then every started worker joins and its result is drained. A late local error or
panic still prevents Owner completion. Startup failure cancels/joins every worker
already started; no detached worker or token remains behind a returned result.

One slow peer creates no global upload barrier. Three indefinitely stalled PUTs
can still occupy all three bounded payload slots until cancellation/timeouts;
less than1/3 malicious weight does not bound the number of malicious routes.
This change does not claim arbitrary-many-stalled-route liveness. Stronger
preemption/streaming requires a separate transport/cancellation design. The180s
IO timeout is not asserted to be a hard180s total slow-drip RPC bound.

New ordinary-I/O tests call the same production admission and worker coordinator:
fourth PUT while three Submit latches are blocked, FIFO/max3 ownership, queued
cancellation, remote isolation, post-completion local error and panic joins, and
cancellation-tail error precedence. Unit completion tokens are (), not fake QCs,
proofs or SQL answers. Existing action/ordinal/exact-call/private-frame assertions
remain. Real cryptographic acceptance still comes only from require_checkpoint
and actual Owner completion. The full v3 record measures this scheduler, without
a controlled before/after full-query speedup claim.
