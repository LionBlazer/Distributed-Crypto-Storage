# Progress peer transport validation

The distinct Registry208 Progress runtime passed its real four-process gate on
2026-10-20. The existing Joint four-process regression passed against the same
shared transport implementation. This establishes Source/Bootstrap803/Control815
network finality and strict restart, not a complete SQL query or live WAIT grant.

## Closed transport and installation

Typed Progress client/server/bootstrap entry points select `DCSPFN02` and a
distinct version-2 trusted-IPC kind. The paired installed Binding and evidence
ingress come from the actual owned durable application. Original and Joint wire
bytes, Work algorithms, profiles, public signatures, caps and timeouts are
unchanged. One private client/listener/prefetch/relay implementation serves Joint
and Progress; the Original service keeps its existing wire and handlers.

Before blob allocation, the server checks the actual owner-signed Body,
canonical request/manifest, parent and fixed role membership. Progress has two
manifest roles; a catalog names its complete bounded dependency graph and exact
independently pinned setup. Hash/length/EOF checks confer no computation
authority. Only the concrete durable owner verifies the actual application,
work, QC, current snapshot, Journal and signer/floor ordering. Prefetch occurs
outside the host-owned ProofGate. The same participant ledger/depot is shared
throughout; no RPC opens a replacement store or verifier.

Five bounded startup metadata frames bind config, Work Genesis, Journal Genesis,
Descriptor and SetupClaim before owned file I/O. New installation then consumes
one/two exact public setup chunks. Existing installation accepts no replacement
setup and fully replays retained files before Ready. Peers receive Work/TLS
signer material, never the owner's FHE, Source, controller or vault secrets.

The unchanged bounds are 32 MiB per Body/blob, 64 MiB setup, 16 MiB queued control
bytes, eight commands/connections, sixteen neighbors and three relay workers.
I/O and operation budgets remain 180 and 1800 seconds. One absolute expiry spans
prefetch and queue; synchronous native work already begun is joined. Client
import acknowledgment and observed-slot metadata are not proof or lock grants.
Own-operation acceptance still requires independent original intent and full
`History::apply_operation` verification of the actual network QC and application.

## Actual process and failure coverage

Each process case launches four actual `CARGO_BIN_EXE_dcs-peer` children, then
four healed existing installations, then four strict existing reopens. Ready
PIDs are checked against the real child handles. Setup/proof fixture authorities
are explicitly public and nonsecret. QCs come from actual process consensus;
the supervisor does not assemble local signatures as network evidence.

The new case checks two reachable equal-weight partitions without a QC, healing,
genuine Bootstrap803 and Control815, unauthorized upload, wrong request/parent,
missing/corrupt child, and a hash-valid damaged Source with the same genuine
Control child. It rejects a canonical checkpoint whose actual honest signature
was altered. A real dropped acknowledgment followed by original retries retains
one Begin decision. Each node obtains a valid Empty decision and, after restart,
replays its own exact selected certificate bytes; quorum subsets need not be
identical across nodes. The owner independently verifies its retained exact
operation expectation and complete proof/QC lineage.

The existing Joint case covers the corresponding real Source/Lifecycle/Kind
path and its three unchanged supervisor-report tests. Focused runtime cases
cover existing Original TLS actors, two partitions/healing/offline catch-up,
terminal framing, bounded leases/queues, expiry and relay scheduling, plus the
new Progress namespace, fixed manifest roles and startup parsing boundaries.

## Native observations

| Gate | Result | Test body | Complete command |
| --- | --- | ---: | ---: |
| Shared finality runtime | 19 passed | 26.44 s | 47.897 s |
| Progress bootstrap negatives | 2 passed | 0.00 s | 0.570 s |
| Progress privacy compile-fail examples | 3 passed | 2.55 s | 16.126 s |
| Existing Joint four-process target | 4 passed | 274.67 s | 351.095 s |
| New Progress four-process case | 1 passed | 328.90 s | 334.287 s |
| Runtime/daemon/client all-target Clippy | passed, warnings denied | n/a | 1.088 s |

The Joint command includes a 1m16s rebuild; the Progress command includes a
5.03s rebuild. These are different application/failure scenarios, not comparable
before/after query measurements. The gates use release/offline/locked Rust 1.99
MSVC, host-native code generation, two Cargo jobs and two requested Rayon threads;
each actual validator child also requests two Rayon threads. The unchanged
1792 MiB per-PID soft fuse and 1800-second whole-command budget did not fire.

Maximum OS-peak working set across the process gates was 925364224 bytes;
maximum sampled working set was 925347840 and private bytes 919568384. The largest
sample gap was 1563.947 ms. These are bounded fixture observations across sampled
native processes, not a complete-peer RAM guarantee or storage-growth bound.

The independent source review caught a missing foreign-family reject arm and
neighbor-validation ordering drift; both were corrected before native checks.
Clippy then found test-only placement/reuse issues. The new Progress supervisor
wrapper was moved before the unchanged existing test module, and the new target
has a targeted lint expectation for the separately tested legacy wrapper. No
production lint suppression was added. Failed Clippy attempts remain failures.

```sh
cargo clippy --release --offline --locked -p peer-runtime -p dcs-peer -p storage-client --all-targets -- -D warnings
cargo test --release --offline --locked -p peer-runtime --lib finality:: -- --test-threads=1
cargo test --release --offline --locked -p peer-runtime --lib participant_bootstrap::progress:: -- --test-threads=1
cargo test --release --offline --locked -p peer-runtime --doc progress -- --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test joint_finality -- --nocapture --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test progress_finality -- --ignored --exact four_os_progress_peers_prefetch_genuine_bootstrap_control_wait_for_quorum_and_reopen_exact_decisions --nocapture --test-threads=1
```

## Receipts and remaining work

The Clippy, focused and process batches have identical 1674-file source maps,
unchanged throughout every command. Only module documentation and this record
were updated afterwards. The process-batch source receipt SHA-256 is
`9F4476AA74A2662BE36FD80ED14CD975449DFE4A8A13483B1A771B50E8460C96`;
its unchanged after receipt is
`1DF0CD3CFCAE7D156F47BBE1F1423E0CB71B0537D76A391A763663A1F5973231`.
The complete reviewed result/log/CPU/memory profile is
`.local/progress-network-validation-r1/profile-reviewed.json`, SHA-256
`39730DAEDF18247C6BF48DD196C882E73A8A19FE9EC3147C9ABC02F5DF2C67E3`.
It aggregates both rustdoc summaries: zero ordinary examples and three actual
compile-fail examples. The earlier first-summary profile is preserved separately.

This gate does not execute new-G Predicate input16/output118 across validators,
open Result160 in a durable owner, resume a parked SQL call, or establish a
globally newest head during an unseen partition. The separate
[local application gate](progress-application-validation.md),
[finality library gate](progress-finality-validation.md) and
[Control opener gate](control-result160-validation.md) retain their exact scope.
Actual owner preparation/completion/WAL, Session integration, WAIT/NOWAIT/SKIP
queries through this new path, mutable EPQ, cancellation/deadlock policy,
permissionless roster activation and full PostgreSQL execution remain unfinished.
