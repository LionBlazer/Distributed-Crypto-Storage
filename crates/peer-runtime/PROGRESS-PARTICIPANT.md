# Progress participant transport

This module installs the distinct Registry208 progress application in an actual
durable peer process. It transports untrusted public evidence and consensus
messages; it does not expose a SQL result, a current lock lease or an owner bank.

| Direct library | Responsibility |
| --- | --- |
| [registry200-finality](../registry200-finality/README.md) | Fixed Progress durable owner, signer WAL, floor, QC and exact own-operation History |
| [registry200-joint](../registry200-joint/src/progress/README.md) | Closed Source/Bootstrap803/Control815/Predicate896 verification and typed evidence ingress |
| [protocol-storage](../protocol-storage/README.md) | One participant namespace, actual control/depot/custody ledger and strict reopen |
| [peer-transport](../peer-transport/README.md) | Authenticated TLS, bounded frames, cancellation and absolute connection deadlines |

## Public ownership

`ProgressFinalityClient`, `ProgressProofBlobSelector` and
`FinalityServer::bind_progress(config, owned, same_gate)` are distinct typed
entry points. The trusted host supplies an already-owned `DurableFinality`.
The private Original/Joint/Progress dispatch never accepts a caller verifier,
unchecked successor, serialized verified flag or proof-cache receipt.

Joint and Progress use the same private client, listener, prefetch and relay
implementations. The installed Binding and its actual ingress remain paired.
No second ProductStore or ledger is opened for an RPC. Public immutable bytes
are fetched before the native gate; only genuinely missing files are fetched.
Corruption and quota poison fail closed.

The new wire magic is `DCSPFN02`. Its profile binds the new Progress durable
profile and the existing caps/deadlines. Original and Joint wire bytes are
unchanged. Progress manifest selectors are exactly ordinal 0 or 1. Source,
Bootstrap803, Control815 and Predicate896 are not old Life/Kind/Link casts.
A product catalog expands to its full 139/140 references, including original
setup chunks, input16 and output118. Length/hash/EOF checks are storage checks;
the actual closed owner still performs all required mathematical checks.

`submit` success is only import acknowledgement. `observed_slot` is a hint;
decoded Checkpoints remain unverified. An owner independently pins the exact
original invocation/body and applies one genuinely valid weighted QC through
`registry200_finality::progress::History::apply_operation`. Its sealed receipt
adds real Header/Body/QC/before/next-context association to the kernel's
math-only operation. A historical retry does not become a current lease.

## Explicit process installation

`ProgressParticipantBootstrap::read` parses five bounded trusted-IPC metadata
frames: config64KiB, WorkGenesis, two-shard Journal716, Descriptor896 and
SetupClaim136. Config version 2 and kind
`registry208-progress-participant-finality-v2` select a distinct installation.
Independent Binding/G/setup/roster pins are checked before quota I/O.
Progress Rules/seed are selected before Work tickets; old tickets/G/QCs cannot
be relabelled.

`ProgressParticipantHost::bind` owns one ParticipantQuota and ProofGate.
New installation consumes exactly one/two pinned public setup chunks through
the same typed depot, closes the temporary handle and then constructs the
durable owner. Existing installation consumes no replacement setup and performs
strict cold replay before Ready. No FHE/Source/controller/vault secret enters
peer IPC. Work/TLS signer material stays in guarded bootstrap ownership.

`dcs-peer --participant-progress-finality new|existing PATH` prints only bounded
Ready metadata. Normal stdin EOF joins native work, actor, TLS and relay workers.
The gate is an explicit host-owned resource, not a claimed process-global
enforcement mechanism.

The old bounds remain: 32MiB per blob and Body, 64MiB setup, 16MiB queued control
bytes, 8 connections/commands, 16 neighbors and 3 relay workers. IO180s and
operation1800s are unchanged. One absolute expiry spans prefetch and queue;
enqueued synchronous work is joined, while an expired/cancelled client cannot
receive a late successful reply. Lost ACK requires exact original retry.

## Executed gates and exclusions

The new four-process case passed, alongside the existing Joint four-process
regression, 21 focused runtime cases, three privacy compile-fail examples and
strict all-target consumer Clippy. The opt-in owning case is:

```sh
cargo test --release --offline --locked -p dcs-peer --test progress_finality -- --ignored --exact four_os_progress_peers_prefetch_genuine_bootstrap_control_wait_for_quorum_and_reopen_exact_decisions --nocapture --test-threads=1
```

It launches four real validators, observes no QC in a real 2+2 partition, joins
them, heals/restarts and accepts genuine Bootstrap803/Control815 network QCs.
It checks unauthorized uploads, bad request/parent, missing/corrupt child and
a hash-valid damaged Source with a genuine child. Lost ACK/latest retry and a
second strict restart retain each node's actual selected certificate. All
fixture authorities are explicitly public and nonsecret; no local assembled QC
stands in for the OS network.

The new case took 328.90 seconds in tests, 334.287 seconds including its build.
The [native validation record](../../docs/progress-network-validation.md) gives
the complete scope, resource observations and source/log receipts.

This is not a new-G Predicate/FHE/Result160 owner gate. Real WAIT continuation
still needs the new owner producer and authenticated per-client Parked bank/call
WAL transition. Parked must not return rows or terminal ACK. Mutable EPQ,
deadlock/cancel/parked rollback semantics, roster activation, full SQL and durable
owner freshness are not established here. Runtime does not inspect private
Parked/Done status. The recorded fixture times and memory are observations;
no comparative latency improvement or complete-peer resource bound is claimed.
