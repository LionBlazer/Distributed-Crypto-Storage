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

The listener uses Mio socket readiness and a dedicated local stop waker instead
of periodically sleeping before accept. Local stop and authorized Shutdown wake
an idle listener without opening a dummy connection. Admission still reserves one
of eight connection slots before TLS/frame allocation; completed worker handles
are reaped even during a continuously readable burst. Shutdown and listener errors
join admitted workers and the heartbeat before releasing the directory lock.
Mio is a direct transport-scheduling dependency, not an async application runtime.

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

`PageBatchRequest::new` binds an immutable object ID, both independently trusted
compact-store heads, and 1–64 unique `PageAddress { image: PageImage, index }`
values. `RemotePeer::fetch_pages` returns Merkle-verified ciphertext pages in the
same requested order. The complete encoded runtime response is at most 1 MiB
(excluding the transport frame prefix and TLS), and its announced frame length is
checked before allocation. Both request and response payloads have distinct magic
values and an explicit version 1. Their manual codecs and bounded sequence
visitors check byte lengths, counts, head geometry and address-dependent proof
sizes before allocating pages. Unknown versions/kinds, duplicate, omitted, extra,
reordered or substituted pages fail closed. The client also rejects unrelated RPC
response variants before decoding their vectors.

The `FetchPages`/`Pages` enum tags are appended to the existing runtime boundary;
unsupported peers reject the new RPC rather than falling back to a whole-object
answer. The existing envelope version and every old tag stay unchanged. This
optional custody capability changes neither the FHE wire, application commitment,
proof profile nor cryptographic-kernel ABI. Authenticated nonowners keep the same
opaque ciphertext-read rights as `Fetch`; owner-only writes and configuration
remain owner-only.

For every page batch, `Store` reads and validates the **complete physical bundle**,
its immutable object hash and both encrypted snapshots, then derives real
`LookupResponse` membership proofs from those validated snapshots. Corruption in
an unrequested page or the other image rejects the batch, including after restart.
There is no stat/mtime/ObjectInfo admission shortcut, metadata custody cache or
persistent sidecar. This first stage still scans the whole bundle on disk; smaller
network replies do not establish sparse disk I/O or an SQL latency improvement.
Explicitly retained historical objects can be addressed as snapshots, never as an
assertion of the latest agreed version.

`PageBatch::verify` checks the exact original object/head/address binding and
returns compact-store `VerifiedPage` values. This proves ciphertext membership
only. The caller must independently obtain authorized agreed heads, authenticate
AEAD at the owner, establish complete selection, obtain the genuine computation
proof and enforce its required journal freshness. No SQL result or new state is
accepted by this RPC. Missing custody fails; application-owned replica choice may
retry another actual holder. The existing 64 MiB global frame, eight connections,
heavy-proof permit and disk quotas are unchanged.

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
STARK. Supported proved operations are exact-index `SELECT`, `INSERT`, additive
`UPDATE`, coefficient-packed `Aggregate`, and schema-independent `ByteSelect` over
bounded encrypted byte chunks. The proved aggregate accepts only the new
`BFVPAGQ1` coefficient layout and fixed 256-term public convolution; the historical
rotation-based aggregate remains an explicitly unverified diagnostic. Neither
read-only operation is permitted in a mutation manifest. `ByteSelect` carries its own
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
allocation. UPDATE must cover every shard, including empty ones; INSERT covers a
nonempty ordered set of existing shards with exactly matching jobs and updates.
Version-3 INSERT metadata binds each old row count and incoming batch count; each
new data head must grow by exactly that job's authorized count. `JobVerifier` checks pinned crypto parameters, original contexts,
all job proofs, allowed changed shard IDs and head revision/schema/domain/count
constraints. The journal additionally checks parent state, work and owner signature.
The application commitment uses domain version 2 for these batch-aware transition
rules, alongside the unchanged FHE/STARK profile identity. Old application anchors
reject during initialization; older INSERT wires and journals are not migrated.

`JobVerifier` keeps at most 128 successful arithmetic-proof digests in RAM, keyed
by its pinned application commitment and every byte/length of canonical input,
encrypted output and serialized proof. Entries are inserted only after genuine
STARK verification. `JobVerifier::check_job` independently derives the canonical
input from a caller's trusted original request, verifies its exact output/proof,
returns the checked arithmetic marker and inserts the same bounded digest. The
owner client uses this API before completion, so its later local journal import
can reuse the verification instead of performing the identical STARK check again.
No caller can populate the cache using a marker that omits proof-byte binding.
Exact repeated proof validation during mining/publication can reuse that evidence;
authorization, complete manifest, all original contexts,
old/new head rules, ancestry and requested freshness are still checked separately.
No root or SQL answer becomes acceptable merely because an arithmetic cache hits.

This is public verification of exact FHE jobs and owner-finalized roots. It does not
publicly prove the private AEAD-root to FHE-input relation. The designated owner/client
must independently verify authenticated complete selection, exact saved FHE inputs,
decrypted completion and compact-store finalization before signing new roots.
An owner signature is authorization, not a substitute for these checks or STARKs.

## Journal RPCs and storage lifecycle

`JobVerifier` commits its FHE parameter descriptor and the exact
`bfv_query_proof::PROOF_PROFILE_ID` under a separate application domain. A
setup-only or older proof-format application commitment is incompatible; it cannot
reuse a new verifier merely because the encryption parameters match.

`InitJournal` pins the supplied genesis and application parameter/proof commitment and
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

Collection selects obsolete object IDs from the head-pair index built by fully
validated Store and restart discovery. It excludes every ID referenced by any
retained pair and unlinks only canonical object filenames. Membership is removed
after successful unlink; an I/O failure retains that entry for retry. Collection
does not read retained/staged payloads or attest their integrity. Existing invalid
custody markers remain; Fetch, FetchVersion and Prove still audit complete physical
images before returning data or computation. A corrupt retained image cannot become
acceptable because collection succeeded. The same synchronous collection and
durability/retention rules apply; no cleanup work moves outside the query timer.

Public-key setup material stays in RAM. Independent failure-domain repair, durable
owner-key recovery, automatic overlay discovery and production PoW security parameters
remain open work. No fixed roster, external chain or token is introduced here.

Verification:

```sh
cargo test --release --locked --offline -p peer-runtime -p version-journal -- --test-threads=1
cargo clippy --release --locked --offline -p peer-runtime -p version-journal --all-targets -- -D warnings
```

Focused custody verification also runs actual TLS daemon I/O, replica failure,
restart, authorization, quota and unrequested-page disk corruption:

```sh
cargo test --release --locked --offline -p dcs-peer --test process_transport page_rpc -- --test-threads=1
```

Owning process tests live in `dcs-peer`; they must exercise the complete client,
real encrypted proving, actual RPC journal agreement and resulting storage changes.
