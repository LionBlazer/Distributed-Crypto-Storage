# Durable Acquire process restart gate

Status: **PASSED native release validation**, 2026-10-20. The seven-process
scenario completed in 2,074.306 seconds, with a maximum observed individual
process OS peak of 1,516,175,360 bytes. The existing six-process Control scenario
also passed on this source. These are complete test measurements, not ordinary
SQL-query latency or general resource guarantees. Reproducible commands, source
and executable pins, memory observation and scope are recorded in
[the validation record](../../../../../../../../docs/joint-owner-acquire-process.md).
This gate extends [Control restart](PROCESS-RESTART.md); the original Control
scenario and its assertions remain intact.

`acquire_process_tests.rs` is a private child of `process_tests.rs`. It reuses the
same bounded supervisor, four-validator configuration, canonical custody writer,
exact candidate fetch and genuine network-QC checks. `acquire_process_worker.rs`
is a private child of `process_worker.rs` and reuses its real Source ingest,
independent binding and external-authority helpers. No production entry point,
proof, profile, resource cap, timeout or Session admission is changed.

The scenario requires seven distinct child PIDs over its lifetime: four actual
validators, one separate actual FHE peer and two sequential owner processes. The
supervisor joins A and its stdout reader before starting B. It also shuts down
the FHE peer before B starts; no pending Rust object, result or live evaluator can
survive from A into B. The existing process launcher remains shared. A distinct
`start_acquire` entry uses an exact 160-byte authority frame, while the original
Control entry remains 128 bytes. Both now reject a wrong authority-frame length
before launch; for malformed Control bootstrap this is an earlier failure than
the unchanged worker's own exact-length check.

The verified observable sequence is:

1. A creates real Source, BFV Owner, Anchor and Ready material and proves Key
   once. It persists the original sixteen Control-custody roles: complete setup,
   original encrypted bundle and heads, authentic anchor, ALL33 values, exact Key
   proof and existing authenticated Source/Owner/Anchor/Ready backups. Public
   test rows are initial ingest only, never a precomputed query answer.
2. Four actual validators accept the genuine Bootstrap Source/Lifecycle pair and
   produce network QCs. A completes that Bootstrap and creates the same durable
   owner Vault. Begin then obtains four real QCs and completes/fsyncs generation
   one. The original nineteen custody roles are preserved; a separately bounded
   three-role test inventory additionally pins Begin QC, pending Acquire Body and
   its exact cursor.
3. A calls `prepare_acquire` once. ComputePrepared is synced before its original
   invocation, request and input proofs escape. The separate FHE peer evaluates
   the encrypted operation and returns the actual input16/output118 stream with
   END and clean EOF. Its recorder uses the Vault's SAME `SharedProductStore`.
   `save_acquire_catalog` independently replays that catalog; `seal_acquire_body`
   checks the full original operation before syncing its owner-signed bytes.
4. A uploads all fixed manifest and catalog references and receives four actual
   submission ACKs. It exits with `SubmittedUnknown`, before querying Acquire QCs
   or completing/decrypting the pending result. This is a healthy seal/ACK followed
   by loss of the submission outcome. It is **not** an injected lost fsync ACK;
   the separate genuine local-QC OS test owns that fault case.
5. B receives the independent inventory and original external authorities. It
   checks complete setup hashes before SDK decode and compares authentic anchor,
   ALL33 and descriptor pins. `open_existing_acquire` restores the original
   encrypted materials and fully checks the saved log. The external history
   prefix is Bootstrap only; the separate genuine Begin QC must match B's restored
   historical parent. Its first network action repeats the exact saved signed
   Acquire, before requesting actual QCs. It never calls prepare, encryption,
   proof generation or a fresh-nonce factory for that recovered invocation.
6. B obtains and authenticates four Acquire QCs. The unchanged real completion
   checks all math, Link, pending association and QC, then decrypts/projects only
   the completed encrypted result. Generation two is synced before historical
   original-invocation rows escape. A genuine older QC and repeated completion
   cannot advance the bank.
7. After acknowledgement, a NEW End operation obtains four actual QCs and syncs
   generation three. A new exclusive quota/Vault opener uses the Acquire-aware
   path and the original materials to replay the completed log and check the
   exact final cursor and End parent.

All QCs come from actual validator processes; this module has no local consensus
certificate assembler. It uses the existing closed Source/Lifecycle/Kind,
input/output, Link and Journal verification paths without a test acceptance flag.
Each owner creates one actual `ProofGate` and clones only the already-open
store/ingress handles. No depot or state mutex is held across network RPC.

External wrapping/signing authorities travel only through bounded private stdin,
never argv, environment, reports or an adjacent key file. Original encrypted
Ready remains an externally bounded custody file, outside the 1-MiB WAL record.
The owner custody, WAL and depot files use one owner ParticipantQuota ledger and
existing precharge, exclusive file locking and fsync. Public reports/logs expose only PIDs, phase
timings, sizes, hashes, generations and result counts. No private bank, key,
predicate or constant is logged. Child cleanup and reader joins precede the
supervisor's final assertion, including error paths.

The Root-owned native command is:

```powershell
$env:DCS_PEER_EXE = 'C:/absolute/path/to/dcs-peer.exe'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::acquire::seven_os_processes_recover_original_durable_acquire_then_finalize_end -- --ignored --exact --nocapture --test-threads=1
```

Recovery returns the historical original invocation, never a new query or current
lease. This fixed public-fixture test does not enable generic Session SQL, prove
whole-Vault anti-rollback, promise power-loss portability, establish physically
once decryption across crashes, or implement data COMMIT. Independent original
material custody remains required. Windows directory durability and native SDK
scratch erasure retain the existing storage/owner qualifications.
