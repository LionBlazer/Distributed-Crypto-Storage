# Peer runtime

Independent-process encrypted object custody, genuine BFV proving and durable
cumulative-work version propagation. No owner AEAD/FHE secret or plaintext row
type lives here. Applications own database creation, keys, complete selection and
client acceptance.

| Direct project dependency | Responsibility |
| --- | --- |
| [peer-transport](../peer-transport/README.md) | TLS signatures, endpoint pinning and bounded frames |
| [compact-store](../compact-store/README.md) | Exact-head encrypted page integrity |
| [bfv-query-core](../bfv-query-core/README.md) | Canonical public-only FHE operation adapters |
| [bfv-query-proof](../bfv-query-proof/README.md) | Actual STARK generation/verification for every BFV residue |
| [version-journal](../version-journal/README.md) | Pinned work/profile validation, ancestry, authorization and durable ordering |

`PeerServer::bind` owns its TCP endpoint and a caller-provided directory lock;
`run` serves it and `spawn` creates a supervised server. The process deployment is
[dcs-peer](../../apps/dcs-peer/README.md). `RemotePeer` issues typed RPCs and reports
actual application-frame bytes and elapsed time, excluding TLS/TCP overhead.
`RemotePeer::with_activity` additionally reports `RpcActivity` immediately after
an actual frame write or read, including request identity, operation and byte count.
It exposes no frame payload, keys or GUI clock. `ReplyReceived` is an I/O event,
not evidence that decoding, authorization or cryptographic verification succeeded.
Callbacks run synchronously and must return promptly. The separate `with_trace`
callback retains completed-RPC diagnostics and outcomes.

`RemotePeer::with_control` attaches the transport's `RequestControl` to cloned
owner RPC handles. An active scope interrupts local sockets, rejects further RPCs
and normalizes cancelled I/O to `Interrupted`; calls outside a scope are ordinary
authenticated RPCs. The application owns scope lifetime. Cancellation is not a
remote shutdown or rollback: an already submitted mutation can remain pending and
must use its existing exact-transition recovery contract. A peer may finish one
already admitted bounded proof job after the requester disconnects.

## Transport and custody

An empty `Bootstrap.authority` explicitly selects permissionless self-authentication:
`Identity` must contain a valid self-signed endpoint certificate and private key.
The transport verifies certificate/handshake signatures and exact endpoint pins;
this does not count identities as consensus weight or grant database write rights.
A nonempty authority retains the explicit CA-based deployment mode. Bootstrap
discovery, address reachability and NAT traversal remain deployment concerns.

The configured owner's TLS credential controls data/setup upload, neighbor and
quota configuration, journal initialization, collection and shutdown. Other
self-authenticated peers can fetch opaque bundles, execute/prove operations, mine
bounded candidates and publish independently validated signed transitions.

Objects are immutable, addressed by the complete bundle hash. `FetchVersion` uses
an exact data/index-head pair cache and still reads/authenticates the physical
bundle. Missing or modified data is rejected; cached names do not prove custody.
`Copy` transfers actual encrypted bytes directly between authenticated processes.
Custody does not assume a SQL row shape: byte-addressed typed images can exceed
one million encoded bytes. The geometry count is bounded by the unchanged 64 MiB
image cap, while page, transport-frame and participant disk-quota limits still
apply before allocation. This is a byte budget, not an unbounded SQL row limit.

## Computation and proof boundary

`InstallSetup` restores minimal `PublicUpdateEvaluator` parameters. Large legacy
rotation/relinearization evaluator objects are created lazily only by the explicit
diagnostic `Evaluate` route, whose response remains `UnverifiedCiphertext`.

`Prove` checks that the stored object matches both original request heads, converts
the actual ciphertext request to the canonical circuit and runs `bfv_query_proof`.
`ProofReply` contains the complete canonical encrypted output and serialized genuine
STARK. Supported proved operations are exact-index `SELECT`, `INSERT` and additive
`UPDATE`, plus schema-independent `ByteSelect` over bounded encrypted byte chunks;
aggregate proofs are explicitly unsupported here. `ByteSelect` carries its own
schema/query/table/page binding and uses the same full-residue public-mask product
proof. The caller authenticates complete page/row coverage and checks the exact
trusted request before completing the encrypted result. The service enforces the
stored object's original data/index heads for typed reads as for other operations.
Typed reads have no legacy unverified `Evaluate` route and cannot appear in a
mutation manifest. This service does not
decrypt, generate answers from fixtures or accept SQL for the client.

One atomic admission permit covers proving, public proof verification and mining
per process; concurrent heavy requests return `Busy` for bounded retry. Persistent
quota, frame and other capacity failures return `ResourceLimit` separately. Proof work
runs outside the shared status/object mutex. At most eight connections and two
public setups are admitted. These bounds do not establish a 1-2 GiB whole-process
RAM guarantee or a 50-100 ms request SLA; full operations must be measured.

`MutationManifest` signs an opaque query binding, operation, the full previous shard
set and every original job request. `MutationEvidence` contains the corresponding
canonical outputs and STARKs. Their manual codecs reject trailing bytes and bound
aggregate frames to 32 MiB, jobs to 32, and each request/output/proof to 2 MiB before
allocation. UPDATE must cover every shard, including empty ones; INSERT has exactly
one chosen shard. `JobVerifier` checks pinned crypto parameters, original contexts,
all job proofs, allowed changed shard IDs and head revision/schema/domain/count
constraints. The journal additionally checks parent state, work and owner signature.

`JobVerifier` keeps at most 128 successful arithmetic-proof digests in RAM, keyed
by its pinned application commitment and every byte/length of canonical input,
encrypted output and serialized proof. Entries are inserted only after genuine
STARK verification. Exact repeated proof validation during mining/publication can
reuse that evidence; authorization, complete manifest, all original contexts,
old/new head rules, ancestry and requested freshness are still checked separately.
No root or SQL answer becomes acceptable merely because an arithmetic cache hits.

This is public verification of exact FHE jobs and owner-finalized roots. It does not
publicly prove the private AEAD-root to FHE-input relation. The designated owner/client
must independently verify authenticated complete selection, exact saved FHE inputs,
decrypted completion and compact-store finalization before signing new roots.
An owner signature is authorization, not a substitute for these checks or STARKs.

## Journal RPCs and storage lifecycle

`InitJournal` pins the supplied genesis and application parameter commitment and
creates or reopens its durable log with the actual `JobVerifier`. `PublishBlock`
validates before `sync_all` and in-memory publication. Its acknowledgement identifies
the exact durably accepted submitted block, including an idempotent ancestor or a
valid nonwinning fork; it does not report a different current tip. `MineBlock` first checks all
candidate rules/proofs, then performs at most one million actual SHA256d attempts;
subsequent chunks retain their nonce cursor. No autonomous unbounded CPU miner is
started. A mined candidate is not a published or confirmed state.

`JournalBlocks { network, known }` returns zero or one previously unknown validated
block in topological order, keeping replies bounded even for larger logs. Configured
neighbors perform actual probes and pull one such block per heartbeat; every pulled
block passes the same validation/persistence path. Each peer owns its work and
validation; the GUI does not fabricate agreement. The generic journal's confirmation,
partition, eclipse and reorganization limits still apply.

Actual serialized journal and bundle file bytes share the participant's disk quota.
In-flight journal writes reserve quota while expensive verification runs outside the
status mutex; reservations release on every return path. Restart discovery charges
journal files before any network has been reopened. Status reports `journal_bytes`
separately; it does not hide them as free overhead.

`CollectJournal` is owner-authorized and removes only this journal's historical
bundles outside retained states: best validated, latest confirmed, and the confirmed
parent. Retained states of every other initialized network are also preserved;
collection refuses to run while a persisted network remains unopened. Unknown staged
objects are preserved so pending writes cannot be deleted. This bounds normal bundle
version retention; aborted staging garbage, journal pruning/checkpoints and automatic
crash-tail repair remain unimplemented. Arbitrary historical snapshots or deep-reorg
data can become unavailable and must fail or recover from another real holder.

Public-key setup material stays in RAM. Independent failure-domain repair, durable
owner-key recovery, automatic overlay discovery and production PoW security parameters
remain open work. No fixed roster, external chain or token is introduced here.

Verification:

```sh
cargo test --release --locked --offline -p peer-runtime -p version-journal -- --test-threads=1
cargo clippy --release --locked --offline -p peer-runtime -p version-journal --all-targets -- -D warnings
```

Owning process tests live in `dcs-peer`; they must exercise the complete client,
real encrypted proving, actual RPC journal agreement and resulting storage changes.
