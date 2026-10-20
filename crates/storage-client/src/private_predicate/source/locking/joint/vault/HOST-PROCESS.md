# Host v3 same-principal contention and owner restart gate

Status: **PASSED** on 2026-10-20: the revised scenario completed both genuine
Acquires, owner restart and final strict reopen in 3345.196 seconds including
startup. The [native record](../../../../../../../../docs/joint-sql-network-validation.md)
pins this exact source and observations. The earlier manual-pipeline attempt
failed after 1592.9 seconds with a socket timeout after catalog-only recovery,
before the first Acquire completed; it remains a failure, not evidence for this
production-driver revision. The existing [Acquire v2 gate](ACQUIRE-PROCESS.md)
keeps its separate scope. The old Control/Acquire scenarios and assertions remain.

The gate uses seven distinct child PIDs over its lifetime: four real validator
processes, a separate FHE peer, and sequential owner A/B processes. The two SQL
clients are two independently configured logical Host bindings sharing principal
one. They are not two OS SQL-client processes, delegated rights or authenticated
SQL sockets. [The Host](host/README.md) remains owner orchestration; generic
Session/Database execution stays fail-closed.

| Direct test dependency | Role |
| --- | --- |
| [Supervisor](host_process_tests.rs) | Fixed public inventory, bounded reports, child ownership and cleanup |
| [Worker](host_process_worker.rs) | Actual Host calls, original material custody, QC/private completion and ACK |
| [Production network driver](host/network/mod.rs) | First actual Acquire from Idle through FHE, genuine QC, private completion and explicit prepaid ACK |
| [Shared process helpers](process_tests.rs) | Four actual validators, real owner-signed Header mining, uploads and exact network QC checks |
| [RPC observations](process_observation.rs) | Public per-peer timing and bounded retries of the exact original operation |
| [Acquire owner helpers](acquire_process_worker.rs) | Existing original Source/Owner/Anchor/Ready backups and strict independent restore |
| [Process launcher](../../../../../../../../apps/dcs-peer/tests/support/joint_process.rs) | Unchanged exact128 Control/exact160 Acquire authority frames and joined child readers |

## Owning sequence

1. A creates the real encrypted Source and BFV material once. It persists the
   original sixteen public/encrypted custody roles using the same quota and
   precharged creator. Keys travel only through the existing bounded private
   stdin frame, never argv, environment, reports or adjacent plaintext files.
   Public NONSECRET rows are initial ingest, never query answers.
2. Genuine Bootstrap obtains four network QCs. A creates a v3 Host with distinct
   client IDs A/B and principal one for both. `BEGIN(A)` and `BEGIN(B)` each run
   actual Source/Lifecycle/ControlKind, signed Body, four QCs, private completion
   and ACK, installing generations one and two. Host allocates stable transaction
   IDs; the test never constructs a held Registry or local QC.
3. Before the first Acquire, control quota pressure leaves less than five maximum
   record extents. Preparation must refuse without changing cursor or WAL
   extent. After pressure is dropped, A consumes that Idle Host into the actual
   `JointSqlNetworkHost`. `execute` must return its real `Completed`, never a
   Pending/NeedsReopen or transport ACK. It prepares the original invocation,
   records the real FHE input16/output118 with END and clean EOF in the SAME
   store, saves/replays the catalog, signs/seals, uploads, selects an independently
   valid QC and performs actual private completion. No second store, ledger or
   proof gate is opened.
4. The first result is ordinal zero, obtained solely by that completion/decrypt
   path. All remaining reservation slots are then occupied with zero-byte leases;
   driver `acknowledge` must consume the fifth prepaid record and install
   generation three. Pressure is released and `into_host` consumes the driver
   without copying or resetting its original Host. A fetches the actual signed
   first Body by RPC at the sealed finalized parent, retains the original
   ciphertext digest from its catalog metadata, and independently observes all
   four genuine QCs for that exact candidate/context. The driver itself requires
   one independently valid weighted QC; this owning scenario retains its stricter
   four-peer observations. Catalog metadata alone supplies no proof authority.
   Before catch-up, A makes exactly one checkpoint probe per peer. Only a genuine
   QC for the complete independently constructed candidate (binding, original
   Context and Header), with the driver's already completed semantic decision,
   skips that peer's redundant evidence upload and SUBMIT. Absence or a transient
   transport failure takes the original upload path; the nonempty subset of at
   most four missing peers is submitted concurrently and joined. Malformed,
   foreign or invalid QCs fail, rather than becoming missing-evidence hints.
   All four original QC and exact signed-Body observations still follow. This
   test-only probe revision passed in the full process gate. It establishes no
   isolated timing saving.
5. B's logical call now starts against that actual successor bank. Its encrypted
   predicate is the same age set with LIMIT one/OFFSET one/SKIP LOCKED. A second
   full FHE stream and catalog are required. Changed exact SQL or another logical
   client's End cannot replace this pending call. The second invocation and
   original encrypted-request digest must differ from the first actual ones.
6. After saving that second real catalog, A drops Host/ingress/quota and fully
   reopens with the independently pinned original material. This is a **local
   drop/reopen**, not an OS crash. The WAL genuinely replays the completed first
   operation and the second original catalog. The read-only `acquire_draft`
   returns byte-identical request/manifest metadata; stale pre-catalog cursor and
   other-client access fail. It does not produce a third FHE result, encryption,
   Source proof or nonce. A signs/seals its exact second Body,
   uploads all referenced public evidence, receives four submission ACKs and
   exits BEFORE second Acquire QC observation/private completion. The saved bank
   remains generation three. This is healthy seal/ACK followed by loss of the
   outcome, not injected lost-fsync-ACK.
7. The supervisor joins A and its report reader, then stops/joins the FHE peer,
   before B starts. B authenticates the complete setup, original anchor/ALL33,
   all original encrypted records and separately pinned completed QC chain.
   Only Bootstrap is external replay input; the WAL itself must fully reverify
   both Begin operations and the first Acquire. Restored parent includes the
   full HeadRef/state root, slot and semantic decision. B reconstructs the SAME
   logical call identity; its first network operation retries the saved signed
   second Body. No FHE prover remains alive for a recovery shortcut.
8. Four actual QCs precede the second completion. The genuine older first QC
   cannot advance it. The completed original B result is empty: conflicting
   ordinal zero is skipped before OFFSET consumes ordinal three. There is no
   second WHERE/window pass over decrypted results. Generation four is synced
   before the response; its completed record sequence is five after the first
   Acquire's. ACK again succeeds under reservation-slot pressure, then pressure
   is dropped. Stale completion cannot advance it again.
9. Full forward reopen also reconstructs A's distinct original response, consumed
   once for that open. `COMMIT(A)` and `ROLLBACK(B)` obtain actual Source/Life/Kind
   and four QCs, installing generations five and six. This exercises stable-ID
   routing after A's removal compacts B. A final acquire-aware exclusive reopen
   checks the exact Idle cursor/End head and original End response; lower calls
   cannot be relabelled as new operations.

The test observes empty rows and genuine linked proofs for the skipped-prefix
case; it adds no public private-bank getter. Existing owning Link/lifecycle tests
separately inspect their actual completed held masks. All native work shares one
actual caller-owned ProofGate. Network operations occur outside depot guards.
All proof/QC checks remain mandatory on replay, including known historical input.

Manual Control and second-Acquire signing use a cfg(test)-only forwarding seam
to that Host's SAME live closed History. Its `candidate_header` supplies the
actual branch target/state and validates the real wall-clock timestamp. A
same-second operation waits boundedly for a permitted real timestamp; neither
`1001 + height`, an invented future time nor a fixture target follows the driver.
The initial Bootstrap remains the original explicit genesis fixture operation.

## Running and scope

The Root-owned native command, after building the actual matching peer binary:

```powershell
$env:DCS_PEER_EXE = 'C:/absolute/path/to/dcs-peer.exe'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::host::seven_os_host_clients_skip_locked_recover_exact_second_call_and_prepaid_ack -- --ignored --exact --nocapture --test-threads=1
```

`owner_host_process_worker` is an opt-in subprocess entry, not an independent
positive gate. Reports/logs contain public pins, PIDs, phase timings, generations,
invocation/ciphertext identities and result counts, not WHERE text/constants,
keys, private bank/salt bytes or custody payloads. Children/readers are joined
before the supervisor's final assertion, including failure cleanup.

RPC observations identify operation kind, peer ordinal, reference ordinal, byte
count, attempts and elapsed time. Validator/FHE PID markers let the process
observer associate CPU and memory samples with those operations. Logs contain no
WHERE, constants or private custody bytes. Transient transport failures retry
the same borrowed request within the existing operation budget; rejected evidence
and interrupted calls fail immediately. A transport ACK is never a proof. The
helper checks its retry deadline before and after each synchronous RPC; it does
not cancel work already running remotely or detach an in-flight call.
The one-shot checkpoint observation uses that same transient-error classifier
without a retry loop or wait for an absent QC. Each RPC keeps its existing
transport budget. One fast real-TCP test covers a single attempt on absence/lost
ACK and hard rejection of malformed frames. A separate direct-error case checks
that rejection and cancellation never become missing evidence. Their public
fixtures supply no genuine QC or computation evidence. Both added tests passed
on 2026-10-20:0.05 seconds in the test body,38.093 seconds including compilation.
Strict release Clippy for all storage-client targets also passed. The1612-file
source inventory matched across both commands (source receipt
`0A2DCF29BD51C7BDBC58EBF38C411A234FD6FD488E27635E3FDC1C606F5674F5`,
after receipt `F0AD434DC6B404A1FCC3392D90484203D920AC28460AA6DB1DF47E13AAD793F4`).
The actual four-peer probe/catch-up path subsequently passed the full process gate.

The supervisor accepts a finite, ordered list of version-three phase reports
from the expected owner PID between its original inventory and final report.
Owner A reports exactly `BeginsCompleted`, `FirstCompleted`, `SecondFheRecorded`
and `SecondCatalogRestored`: initial report plus four phases plus final report
still fits the existing six-frame queue. `FirstCompleted` follows the genuine
driver completion and prepaid ACK; the four-peer observations then remain
mandatory before the second invocation. Owner B's phase list is unchanged.
Each report wait covers one fixed stage instead of spanning both FHE queries.
Wrong/reordered/extended reports fail. These public IPC markers
change no production timeout or final assertion, and are not network evidence.

The only added production API is consuming `into_host` ownership transfer. The
mining forwarding seam exists only under cfg(test). Proof/circuit/profile,
consensus timeout, 128/160 authority grammar, caps and original owning assertions
remain unchanged. The same v3 WAL
and control/depot ledger own all retained data; bounded external Ready backup is
outside the one-MiB record. There is no whole-vault antirollback, Windows directory
power-loss theorem, physically-once decrypt across crashes, production SQL
authentication, general WAIT/NOWAIT/deadlock behavior or data COMMIT claim.
Replies remain historical original invocations, never permanent/current leases.
The linked native record reports measured timing and per-PID memory for this
bounded scenario. It establishes neither a complete RAM guarantee nor full
PostgreSQL, mutable-data COMMIT or current-lease capability.
