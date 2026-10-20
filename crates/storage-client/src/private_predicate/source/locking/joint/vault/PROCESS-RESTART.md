# Owner Control process restart gate

Status: **PASSED native release validation**. This opt-in owning test ran four
actual validators and two sequential owner processes. The complete command took
103.208 seconds, including compilation; the test itself took 85.85 seconds. See
the [executed record](../../../../../../../../docs/shared-evidence-owner-restart.md)
for source/image identities and bounded resource observations.

The unchanged Control scenario also passed against OwnerVault v2 in 88.608
seconds including Cargo startup (88.10 seconds in the test), with a separately
pinned peer image. The [v2 record](../../../../../../../../docs/joint-owner-acquire-vault.md)
keeps that rerun separate from the original v1 measurements above.

`process_tests.rs` owns the bounded supervisor protocol, independently retained
public inventory and actual four `dcs-peer` startup. `process_worker.rs` owns the
two owner-only roles. The test-local [`OwnerProcess`](../../../../../../../../apps/dcs-peer/tests/support/joint_process.rs)
shares only child lifecycle ownership with the existing peer supervisor. It does
not change peer startup, Ready, TLS, wire roles, deadlines or production entry
points. The worker is an exact ignored unit-test entry, not an application
launcher. Calling it without the required bounded stdin fails.

The observable sequence is:

1. Owner A ingests four explicit public test rows, generates one actual BFV
   Owner/Anchor/Ready epoch and proves Key once. It produces a typed Bootstrap
   Source/Lifecycle pair. It saves the canonical original public setup, complete
   RawBundle including its original object nonce, full heads/Table identity,
   anchor, all 33 Key public values and exact Key proof. Source, Owner, Anchor and
   Ready backups use the existing authenticated encrypted codecs.
2. A sends a public hash/extent inventory to the supervisor. The supervisor
   starts four independent TLS validator processes with the same durable
   binding and setup chunks and returns four public endpoints. A uploads the
   genuine Bootstrap premise and obtains actual QCs. Every QC is independently
   authenticated against the same context and candidate; semantic decisions,
   rather than signature-subset bytes, must agree.
3. A completes that exact typed Bootstrap and constructs `OwnerVault` with its
   genuine prefix and private bank. It produces Begin, fsyncs the complete
   owner-signed Header/Body through `seal_body`, uploads its Source/Life/Kind
   premises and receives four actual submission ACKs. A exits before private
   completion. The supervisor joins A and its stdout reader before starting B.
4. B receives only external wrapping/signing authorities through bounded stdin,
   the independent public inventory and endpoint bytes. It opens the original
   files and restores Source then lexical BFV Owner, Anchor and Ready. It
   compares all 33 values and the exact original Key proof; it never calls a
   fresh Owner/Anchor/epoch factory, `prove_key`, or a Source salt factory.
5. B authenticates actual Begin QCs, reopens the WAL as `SubmittedUnknown` and
   compares the original cursor, Header and Body byte for byte. Actual proof/QC
   replay and private openings precede completion fsync. B then prepares End
   from the recovered bank, obtains four real QCs and durably closes the exact
   Registry transaction. A final exclusive quota/WAL reopen replays the saved
   completions and checks the exact final cursor and End parent. No local
   fixture assembles any QC.

The supervisor creates fresh high-entropy wrapping and database-signing keys.
They go only through a fixed 128-byte private stdin frame. The owner TLS identity
has its own bounded private frame. Neither secret argv/environment/report fields
nor an adjacent plaintext master-key file are used. Participant signer fixtures
are explicitly public nonsecret test keys sent through existing trusted daemon
bootstrap IPC. Public reports contain hashes, lengths, binding, generations and
PIDs, not private data or openings.

All saved custody files use fixed role-derived canonical `control/<id>.meta`
names under the same actual owner `ParticipantQuota`. `FilePermit` precharges
before `CreateNew`, each file is exclusively locked, registration precedes writes,
and complete contents are synced before the inventory entry is released. Failed
writes/syncs poison accounting without truncation or repair. The parent reads
closed public/ciphertext files directly against independent capped inventory
pins; it never opens a second EvidenceStore while A owns the quota. The original
History/ingress closes before `OwnerVault` opens its same scoped depot.

All owner/peer processes and stdout readers have kill/wait/join cleanup. The
normal scenario finishes all children before the final result assertion. Runtime
errors remain failures; no timeout, ACK, TLS connection or byte hash substitutes
for a proof or QC.

The owning command passed against the explicit peer executable:

```powershell
$env:DCS_PEER_EXE = 'C:/absolute/path/to/dcs-peer.exe'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::six_os_processes_restore_original_owner_epoch_and_complete_only_the_saved_control_intent -- --ignored --exact --nocapture --test-threads=1
```

Each worker owns one actual `ProofGate::new` resource owner. The constructor,
clone/unwind test and documentation example also passed. No dummy server or
proof-success cache is used to obtain the gate. A transient `WouldBlock` when
fetching the exact saved candidate is retried under the original 1800-second
deadline; QC, context and complete fetched-byte checks remain mandatory.

This is Control-only historical recovery. It does not retain Acquire's complete
input/output proof inventory, perform FHE evaluation after B restores Ready,
restore a current lock, enable Session/SQL, commit encrypted SQL data, or establish global
exactly-once/anti-rollback behavior. External authorities and independently pinned
public recovery files must still be available. This same-machine process test is
not a power-loss theorem: Windows directory sync remains qualified by the storage
contract. Only explicit owned secret buffers have zeroization guarantees; native
SDK scratch, compiler temporaries and caller copies have none.

The additive [durable Acquire process scenario](ACQUIRE-PROCESS.md) is a separate
SOURCE ONLY / UNEXECUTED gate. It uses a distinct exact 160-byte private bootstrap
and the same launcher; it does not change the validation status of this Control
case.
