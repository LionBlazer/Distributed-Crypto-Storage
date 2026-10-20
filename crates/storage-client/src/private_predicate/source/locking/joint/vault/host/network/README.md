# Concrete owner Joint network runner

This addition drives the existing concrete `JointSqlHost`. Its owning rejection
and retry checks and the first complete real-network/FHE call passed.
It supplies a production library execution boundary; it does not provision an
application, load user keys, initialize Bootstrap, expose a mutable Vault, open
the legacy Session guards, or claim a general SQL implementation.

| Direct module dependency | Responsibility |
| --- | --- |
| [Host](../mod.rs) | Exact logical client/call identity, existing supported statement parser, shared bank and prepaid ACK |
| [Drive](drive.rs) | Original Compute/catalog/Body continuation and actual private completion |
| [Signing](sign.rs) | Owned database signer and bounded mining against the real historical Journal |
| [RPC scheduler](upload.rs) | Bounded fixed-role uploads, exact candidate submissions and independent QC checking |
| [Vault](../../durable.rs) | Existing exclusive phase/WAL/CAS/fsync, retained exact bytes and terminal quota |
| [Acquire continuation](../../durable_acquire.rs) | Genuine Source/BFV/Key33/Ready restoration and original pending/capsule |
| [Peer runtime](../../../../../../../../../peer-runtime/src/lib.rs) | Pinned TLS endpoints, cancellable real FHE recorder, Joint client and resource ProofGate |
| [Closed History](../../../../../../../../../registry200-finality/src/joint/history.rs) | Actual fixed proof/QC admission and read-only Journal mining metadata |

## Public ownership

`JointSqlNetworkConfig::new(connector, peers, fhe, mining_attempts)` requires one
through sixteen distinct configured validator endpoints, one configured FHE
endpoint, and an explicit nonzero mining-attempt limit. TLS pins authorize a
connection only. The already installed Host binding supplies the independently
authenticated fixed activated work roster and complete application/setup/Key33
pins; endpoints cannot nominate a replacement roster, target or application.

`JointSqlNetworkHost::attach(host, signer, config, gate)` consumes the actual Host
and database signing key. The signer must match its independently pinned Journal
owner. There is no private-key, bank, mutable Host or generic Journal getter.
The embedding owner authenticates its logical clients, configures endpoints and
obtains its real original data/material through its own authorized custody path.
This library neither invents nor persists those authorities.

`into_host(self)` consumes the runner and returns that exact owned Host. Every
execution has joined its operation workers and deadline owner before returning;
the transfer does not detach work, reset a pending/poisoned phase or manufacture
a reply. No mutable borrowed Host, private bank or Journal is exposed. The caller
keeps the original Host's checks and can explicitly transfer ownership again.

The process owner must allocate ONE actual `ProofGate` and give its clones to
all native proof services, producers and replay paths in that process. A supplied
gate is a resource owner, not a proof or freshness token; attaching a runner does
not enforce process-global ownership against unrelated independently made gates.
Opening the Host and its original materials is separately subject to that rule.

`execute(client_id, sequence, exact_sql, input, budget)` checks the existing Host's
entire supported SQL/intent grammar before network I/O. `input` borrows the actual
`SourceOwner`, independently fetched Source image and, for Acquire, original
`OwnerVaultAcquireMaterial`. Existing original Source/Owner/Anchor/Ready/setup,
ALL33 and recovery authorities remain mandatory. The budget must be nonzero and
at most the unchanged 1800-second Joint operation budget. No fixture data,
fixture target/timestamp, plaintext WHERE evaluator or in-process peer is used.

`resume_original` additionally requires a saved pending or latest historical
call. It never starts a new invocation if the original does not exist. Callers
must retain the exact original SQL bytes/client sequence themselves: Pending56
contains only the private intent identity, not recoverable SQL text.

## Actual order

For a new Control operation the Host produces genuine Source/Lifecycle/Kind.
For Acquire it first fsyncs the original Compute/capsule/input inventory, then
passes those original inputs to the real FHE peer using the SAME shared recorder
store. The existing RPC must complete genuine input16/output118, END and clean
EOF. Its heavy checked output and borrowed frames are dropped before the Host's
mandatory fresh catalog replay. A catalog-only restart uses `acquire_draft`;
it does not re-encrypt, re-prove, choose new salts or rerun FHE.

The runner signs the actual fixed request/manifest and deterministic control-shard
update. `JointHistory::candidate_header` uses that SAME closed Journal's real
branch target, next state and timestamp rules and checks owner permission. It
does not admit application proofs. Mining is bounded and checked for cancellation
between chunks. A same-second timestamp is retried against the real wall clock;
the runner never manufactures a future timestamp. The real Host then checks all
required proofs and fsyncs the complete signed candidate before network exposure.

For an already saved Body, the first RPC to each destination is an exact original
submission observation. Regardless of that observation, the fixed sequence then
stages only that SAME signed Body's typed public/encrypted references, resubmits
that SAME Body and requests a checkpoint. In particular, a first REJECT is never
interpreted as proof of missing evidence or permission to change a request. This
also permits recovery after Body fsync but before uploads. Every subsequent
server admission still performs its full independent checks.

At most three scoped workers share one round-robin queue over ALL configured
endpoints during an operation. They retain at most one existing bounded public
blob each. Busy is retryable; transport failure, rejection, malformed or foreign
QC disqualifies that endpoint for this operation. Such observations cannot stop
the other peers or count as quorum. Local canonical-body/depot/catalog corruption
is a hard failure. Exactly one independently valid, greater-than-two-thirds work
QC for the complete current context and exact candidate is sufficient. There is
no all-endpoints or matching-answer requirement.

After selection all outstanding sockets are cancelled and ALL workers join.
Actual private completion again verifies the complete retained proofs, QC,
association and private openings, then fsyncs the successor bank before returning
rows. The owner keeps its actual native permit across FHE streaming (which itself
verifies proofs), drops it before ordinary finality RPCs, and reacquires it for
private completion. No Host/state/store mutex spans RPC or native work. The shared
store locks remain limited to their existing individual storage operations.

## Failure, retry and remaining boundary

`Pending { cursor, reason }` contains no rows, no automatic lock release and no
SQL success. Offline peers, no quorum, cancellation or expiry retain the exact
original durable pending. A Control draft that never reached Body fsync is
discarded with its terminal lease; Compute, Body and Completed records are never
cleared by that cleanup. An unknown external successor with missing private
salts/bank remains `RecoveryRequired`, not an automatic rebase.

The deadline owner closes operation sockets and is joined before return. Existing
synchronous native work is not preemptible; it must finish and release its real
permit before return. If completion fsynced after cancellation/expiry, its reply
is dropped and `NeedsReopen` is returned. A full explicit acquire-aware reopen
may redeliver only the saved original historical response. A live consumed reply
is not silently regenerated. `acknowledge` remains a separate exact call/CAS
operation using the Host's prepaid ACK; it is not implicit in network success.

A new unpredictable invocation, independently bound full request and actual QC
can linearize that NEW operation under the fixed authenticated activated roster.
An old recovered invocation stays historical. This API supplies neither a
permanent current lease, rollback protection for restored owner backups, dynamic
roster activation, readonly freshness barrier, mutable-source/EvalPlanQual/MVCC,
WAIT/NOWAIT, nor full SQL COMMIT. Authentication, provisioning and application/UI
composition remain outside this owner library. Generic Session stays fail closed.

The owning native gates passed on 2026-10-20. The tests cover
actual Source/Life/Kind and local genuine QCs, exact Body retention through an
unavailable endpoint/reopen, signer/call/gate rejection, weighted-QC selection
against a fast genuine foreign QC and later valid QC, and the shared scheduler's
fourth destination. The new consuming-transfer assertions passed in two of the
five selected Host/Vault/grammar cases (144.76 seconds in the test body,202.009
seconds including compilation); strict all-target release Clippy also passed.
Local-QC/scheduler tests are not a four-validator network success test. The
separate [Host7OS gate](../../HOST-PROCESS.md) subsequently passed one actual
`execute` from Idle through real FHE, weighted QC and private completion, followed
by prepaid `acknowledge`, consuming transfer and the original second-call
recovery scenario. It used two genuine FHE evaluations, four real validators and
sequential owner processes; no simulated reply or local-QC substitute was used.
The first driver call took 1277.232 seconds and the full command 3345.196 seconds.
The [validation record](../../../../../../../../../../docs/joint-sql-network-validation.md)
pins the source, logs, resource observations and remaining boundaries. This is
not interactive latency, a comparable speedup, a whole-process RAM guarantee or
a complete SQL implementation.
