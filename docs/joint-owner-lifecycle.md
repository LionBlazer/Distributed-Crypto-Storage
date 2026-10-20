# Typed Joint owner lifecycle and fresh import validation

The fixed-N4 owner can now produce Bootstrap from closed Pending history,
complete its genuine proof/QC operation, pass that private opening through typed
Begin and recoverable Acquire, and close the exact Registry transaction with End.
The complete path passed on four independent validator processes and a separate
FHE peer. The previous full Acquire regression also passed on the same source.
This establishes historical operations and in-memory pending recovery. A durable
owner Vault, OS owner restart, general SQL admission and encrypted data COMMIT
remain unimplemented in this stage.

The [Bootstrap owner](../crates/storage-client/src/private_predicate/source/locking/joint/bootstrap/README.md)
and [closed Bootstrap boundary](../crates/registry200-finality/src/joint/bootstrap/README.md)
describe the new contracts. Prior [owner preparation](joint-owner-preparation.md)
and [participant process validation](joint-participant-finality.md) retain their
own source, failures and scope, including the separately executed two-Acquire
held-row SKIP LOCKED case. That contention case was not rerun in this batch.

## Publication and verification boundaries

`Journal::prepare_import` and `DurableJournal::prepare_append` return opaque,
exclusive pending borrows after a genuine fresh check, including known blocks.
Their argument-free commit publishes only the checked header/body/state; Drop
publishes nothing. The durable path reports an absolute checked next extent and
uses the existing position/write/sync/tail-repair mechanics. Its enclosing owner
retains charges and poisons on uncertain I/O. The old cached import/append APIs
retain their behavior; this adds no serialized verification receipt.

The Joint verifier returns this call's actual checked Acquire result with the
same pending import. The durable adapter holds its State guard through proof
checking, remaining semantics, charge and commit. Closed History uses a private
enum for the four own-operation modes and prepares a move-only receipt before
publication. Missing or unexpected Acquire payloads fail before commit. Only
successful import and ancestry restriction can mint the public sealed receipt.
The exact latest semantic retry separately rechecks the actual proofs under its
real previous Context and parent below the advanced floor. Voting, floor replay,
signer advance and reopening retain independent full checks. There is no cache
of prior proof success across calls and no supplied accepting callback.

The Bootstrap parent factory uses actual genesis or an actually checked
EmptyPending lineage. The owner loads and audits the pinned encrypted Source,
forms enrollment and the default Registry, and produces real Source/Lifecycle
evidence. Exact pair identity is checked before import; completion consumes the
sealed operation and reopens commitments with the real TableId and all four IDs.
Bootstrap needs neither dummy FHE nor a ControlKind or Result144 relation.

## Executed process behavior

The new opt-in case constructs each opening through its actual typed operation:

1. Bootstrap and Begin each obtain actual QCs from all four OS validators.
2. The owned producer forms Source/input16/Lifecycle/Link for hidden
   `WHERE age IN (0,255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED`.
3. The original pending/candidate handles are destroyed. Wrong wrapping key and
   identity fail; the authenticated capsule restores the identical original BFV
   request and actually rechecks its premises. Public typed inputs and required
   owner state remain in memory; this is not a process restart.
4. A separate OS FHE peer executes the encrypted operation. The same client depot
   records all118 components through clean END/EOF. After phased depot ownership,
   a new keyless History actually replays the prior Bootstrap and Begin.
5. All four validators return exact Acquire QCs. The client freshly verifies
   input16/output118/Lifecycle/Link and completes once, returning ordinal3 with
   age255 and amount65534. End consumes that private bank, obtains actual QCs,
   and removes the exact stable transaction ID under the correct new stamp.

The test joins all five children before its final assertions. It never builds
the Acquire QC locally or selects an FHE answer from fixture rows. The public
nonsecret ingest rows are the final test oracle only. This case has no competing
held row; its SKIP LOCKED path is uncontended.

The existing full Acquire gate independently checks false Result144 flag banks,
actor and salt against a genuine receipt before its one completion. Stale Begin
QC and foreign intent fail. A latest identical retry performs fresh replay;
physical absence of output117 and corruption of the retained Link reject without
publishing the challenged operation. The old test bodies and proof relations
were retained.

## Native measurements and commands

Windows x86_64 MSVC Rust1.99, release, offline locked dependencies,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs2 and Rayon2 were used. Every run had a
1792 MiB per-PID fuse. Ordinary commands had1800-second supervision and the full
process cases3600 seconds; production I/O/operation limits and consensus timeouts
were unchanged. Whole command times include compilation where needed.

| Receipt label suffix under `joint-owned-lifecycle-native-` | Scope | Result | Seconds |
| --- | --- | --- | ---: |
| `clippy-r2` | Six packages, all targets, strict warnings | passed | 1.325 |
| `bootstrap-r2` | Actual genesis and EmptyPending owner paths | 2 passed | 72.756 |
| `finality-r2` | Original and Joint finality, quota and corruption | 21 passed | 160.470 |
| `control-r3` | Existing Control intent and genuine Begin/End | 2 passed | 63.702 |
| `doc-r2` | Ownership compile-fail contracts | 43 passed | 11.910 |
| `fmt-check-r2` | Workspace formatting | passed | 1.851 |
| `peer-build-r2` | Explicit actual peer rebuild | passed | 10.162 |
| `process-r2` | Typed Bootstrap/Begin/recovered-Acquire/End, five OS children | 1 passed | 1502.548 |
| `acquire-regression-r2` | Original full Acquire, fresh retry and hostile premises | 1 passed | 1241.084 |

The43 doc cases are15 finality,1 Joint kernel,25 client and2 Journal contracts.
An earlier lower-core batch `joint-fresh-import-native-runtime-r2` passed
21 finality,7 Joint kernel and11 Journal cases in186.750 seconds. The separate
legacy journal command passed4 Registry journal,11 repeated Journal library and
18 integration cases in1.427 seconds; the repeated11 are not additional coverage.
All17 lower-core source/manifest files and the root lock were byte-identical when
Bootstrap was added. Finality and the affected owner paths were rerun on the
combined source rather than reusing their older upper-layer results.

| Full process run | Peak sampled working set | Peak private bytes | Maximum observed OS peak working set |
| --- | ---: | ---: | ---: |
| Typed lifecycle | 1497362432 | 1523896320 | 1497362432 |
| Acquire regression | 1410392064 | 1436262400 | 1490690048 |

These are per-process observations, not aggregate host memory or a general2GB
guarantee. The monitors recorded43975/35853 samples and maximum gaps of
494.499/573.536 ms respectively. The lifecycle's cumulative phase marks were
23.138 seconds for Bootstrap,47.454 for Begin,165.792 for restored preparation,
537.806 for FHE END/EOF,565.082 for upload,1350.249 for Acquire QC/client completion
and1497.421 for End completion. Neither whole case is a standalone query-latency
benchmark. There is no before/after speed claim from these different scenarios;
interactive performance remains unmet.

Reproduce the principal gates from the repository root:

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo build --release --offline --locked -p dcs-peer
$env:DCS_PEER_EXE = (Resolve-Path target/release/dcs-peer.exe).Path
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::tests::full_acquire::lifecycle::four_os_typed_lifecycle_restores_owned_acquire_and_closes_only_its_exact_registry_transaction -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::tests::full_acquire::four_os_quorum_and_fhe_peer_complete_only_the_exact_own_joint_acquire_after_fresh_replay -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-finality --lib -- --nocapture --test-threads=1
cargo test --release --offline --locked -p version-journal -p registry200-joint -p registry200-finality -p storage-client --features private-input-proofs --doc -- --test-threads=1
cargo clippy --release --offline --locked -p version-journal -p registry200-joint -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo fmt --all -- --check
```

Use the actual isolated target when `CARGO_TARGET_DIR` is set. The resource
observations above additionally used the pinned local process supervisors;
ordinary Cargo alone does not enforce their memory or wall-time fuses.

## Source, audit and retained failures

Parent: `b34e336c8fc79bfe411d8d4468ba1caaab95facc` on
`codex/feature/sql-latency`. The combined native inventory contains all1560
tracked/nonignored files. Its SHA256 is
`E1C60D44380C220578B0F4F7645BF3379E571F2AEC2AC0A38A096D2183CA77F3`;
the final after-receipt is
`CCF3A23D229157D98CC2DB398766EAE85CAC80ABD5BB9B6CD58DE8800962D4D1`.
The explicit rebuilt peer was21413888 bytes, SHA256
`C4E4E651253966BEDDB2A9A0516C6A14D3E86DF16E3D09D863AD16BA85B94C90`.
Every source, runner, binary and result/log hash was rechecked after both cases.
Publication changes documentation only after that audit, including the test's
introductory documentation comment; its executable body is unchanged.

Local receipts live under `.local/joint-owned-lifecycle-native-r2/` and
`.local/private-peer-native-r1/joint-owned-lifecycle-native-*/`. The preceding
Journal batch is pinned by source
`6FC2D115F1B1FEE6E569B6AAA4D5BCAE47FFEC1003E76B74688583D9DFBDA06E`
and after-receipt
`6D246AC4747D475BD02A7A5659B6F8E5EDB20C0F9A98E27BBA57E8852331F681`.
Generated evidence, participant data and binaries are not committed.

Three failed attempts remain retained. The first Journal finality run correctly
refused quota reopening while a local child budget still retained its exclusive
root lock; the test now drops that budget before reopening, without changing
production locking. Combined R1 Clippy rejected an unnecessary `drop` of a public
non-Drop test value; only that line was removed. The first combined Control run
failed at Windows temporary-directory canonicalization with OS5 under the
sandbox; the identical source passed after rerunning with access to that test
directory. No fuse, timeout, proof check or test expectation was loosened.

Durable owner phases/CAS, lost-ACK signed-byte persistence, owner process restart,
rollback protection, current-network reconciliation, permissionless weight
activation and general PostgreSQL admission remain separate work. The generic
Session guard remains closed. No current lease, whole128 composition theorem or
same-secret RK guarantee follows from these fixed-profile cases.
