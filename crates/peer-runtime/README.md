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
| [proof-acceleration](../proof-acceleration/README.md) | Pure bounded CPU-worker policy, without enabling its loader |
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

Objects are immutable, addressed by randomized head-object profile 2. The selected
[prototype contract](../../docs/salted-custody-objects.md) defines its nonce,
complete admission and incompatible workspace/protocol boundary. RawBundle is an
untrusted envelope; TargetVersion binds metadata only, while CheckedObject audits
both complete images. `FetchVersion` uses
an exact data/index-head pair cache and still reads/authenticates the physical
bundle. Missing or modified data is rejected; cached names do not prove custody.
`Copy` transfers actual encrypted bytes directly between authenticated processes.

RawBundle's four byte-vector fields use a private `serialize_bytes` adapter.
With pinned bincode 1.3.3/fixed integers, this writes the same u64 length and
payload as ordinary Vec<u8>, in one byte write; the size-check pass also counts
the payload in one step. Raw, Store/Fetch and disk envelopes keep exact bytes.
The derived Deserialize implementation, bounded sequence decoders, version/nonce,
authorization, quotas and complete custody audits are unchanged. Codec contract
tests compare a plain-Vec shadow in both directions; the real million-row UPDATE
fixture also checks actual stored ciphertext after its proved result assertions.
This changes serialization work only; no complete-operation speed or RAM claim
follows without separate measurement.

Full-object disk reads, Store requests and successful RawBundle replies additionally
use a private borrowed serde view of the four byte fields. Every length must fit
the remaining immutable input, and trailing bytes reject before any payload Vec
is allocated. Only a completely parsed view is copied to the ordinary untrusted
RawBundle. Public generic Deserialize and the existing bounded sequence visitors
remain unchanged; this slice-only path is never used with an arbitrary IoReader.
The actual whole disk/RPC byte count is capped at 64 MiB, including its existing
40/14/18-byte envelope. This explicit cap is required because pinned bincode's
slice API replaces its configured size limit with Infinite.

The specialized wrappers retain the existing v2 namespace, profiles and enum tags;
all other RPC variants use the ordinary decoder. A malformed specialized body
rejects without trying another format. Inner raw version, nonce, head lengths and
image bytes remain untrusted data: parsing does not run custody checks before
owner authorization. Every physical read still performs both complete snapshot
root audits, and all quota, retry, Copy, proof and freshness guards remain in
place. Owned payloads and full disk/frame buffers still exist; no zero-copy
custody, process-RAM or complete-query latency guarantee follows.

`PageBatchRequest::new` binds an immutable object ID, both independently trusted
compact-store heads, and 1–64 unique `PageAddress { image: PageImage, index }`
values. `RemotePeer::fetch_pages` returns Merkle-verified ciphertext pages in the
same requested order. The complete encoded runtime response is at most 1 MiB
(excluding the transport frame prefix and TLS), and its announced frame length is
checked before allocation. Both request and response payloads have distinct magic
values and an explicit version 2. Their manual codecs and bounded sequence
visitors check byte lengths, counts, head geometry and address-dependent proof
sizes before allocating pages. Unknown versions/kinds, duplicate, omitted, extra,
reordered or substituted pages fail closed. The client also rejects unrelated RPC
response variants before decoding their vectors.

The custody enum tags retain their positions, but runtime RPC version 2 and each
custody payload version 2 are mandatory. Unsupported peers fail closed. The
application v4 anchor includes ObjectProfileID; BFV/STARK parameters and the
cryptographic-kernel ABI remain unchanged. Authenticated nonowners retain opaque
ciphertext-read rights; uploads and configuration remain owner-only.

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

`ReadImageRequest` / `FetchReadImage` is a separate static-footprint custody
operation: one complete canonical data image plus every index membership response
in `[0, prefix_pages)`, in order. It permits 0–512 prefix pages and at most 16 MiB
for the **complete encoded runtime response**, excluding frame-prefix/TLS bytes.
The exact data length, proof geometry and aggregate response length are checked
before allocating images/pages. The response keeps an actual authenticated full
`EncryptedSnapshot` for data and independent prefix proofs; it never represents
an incomplete index as a snapshot or table. `RemotePeer::fetch_read_image` checks
the exact original object, both heads, prefix count and all membership proofs.
Consumers must still authenticate their own table identity, AEAD, complete query
selection, computation proof and agreed freshness.

The new tags append after `FetchPages`/`Pages`, using explicit `DCSRIMQ2`/`DCSRIMR2`
magic and version 2. The response adds one fixed 32-byte nonce and verifies its
object/head binding before image use. Existing tags, the global 64 MiB frame,
eight connections, heavy-work permit and FHE/proof/ABI profiles are unchanged.
Every image reply uses **one complete physical custody audit**, including bytes
outside the returned prefix, then reuses those exact validated snapshots. No
stat/mtime/status shortcut or extra disk cache is introduced.

This generic RPC has no SQL schema dependency. Its public prefix length is visible.
A privacy-preserving fixed-footprint consumer must derive the same complete
prefix from public layout for every predicate, projection, LIMIT and empty result;
it must not select ranges by query content or fall back by cache/failure outcome.
This runtime does not choose an SQL privacy policy or claim sparse disk I/O.

## Padded ciphertext replacement

`StoreDeltaPlan::for_heads` computes an immutable advisory upload plan from public
data/index geometry alone. `padded_request_bytes` is present only when a fixed
worst-case delta is smaller than `full_request_bytes`. The delta reserves the
largest possible 257 page-membership responses across **both** images, including
their last-page lengths and Merkle heights. It does not inspect changed pages.
The complete encoded `WireRequest` is capped at 32 MiB; the unchanged global
64-MiB frame cap also covers Full Store. Transport prefix and TLS bytes are extra.

`StoreDeltaRequest::new` binds the exact old object/heads, an immutable binding-only
`TargetVersion` and 1-257 canonically ordered replacement proofs. Its target ID
is derived from nonce and both heads; no ignored raw target image is accepted.
Each image either keeps its exact head with no replacements or preserves geometry
and advances its revision once. Both unchanged is rejected. The explicit
`DCSDLTA2`/version-2 body has exact public-geometry length and zero padding.
Bounded serde first caps the frame allocation; header-derived exact length,
entry counts, address-specific proof sizes and all padding are then checked.
`Request::StoreDelta` appends tag 19 after the actual ReadImage request; its reply
reuses `Response::Stored` tag 2. Existing tags and cryptographic computation
profiles remain unchanged; the object/application profiles deliberately change. Unsupported peers fail rather than changing modes.

Only the configured TLS owner may upload a delta. On first write, the store
audits the **whole physical base**, including unrequested pages and its complete
immutable hash, verifies replacement membership against the new heads, applies
the checked pages to both audited snapshots and requires their complete new roots
and canonical bundle hash. Complete target validation, full-object quota,
file sync and atomic rename still apply. The original base stays intact until
normal journal GC. Lost-ACK replay fully audits an already stored exact target,
even after normal base collection; a corrupt target never receives a cached ACK.
No metadata-only custody proof, sidecar, FHE bypass or sparse disk-I/O claim is added.

The private store admission boundary uses three request-local, non-cloneable
capabilities. Only a complete physical read plus object-hash and both-root checks
constructs `CheckedObject`. It retains the original envelope version, nonce and
head buffers together with two `OwnedVerifiedSnapshotBytes` capabilities. Their
single canonical parser checks all packet revisions and both complete roots;
raw Fetch, Copy, startup and full candidate admission can move the exact buffers
without creating packet copies. PageBatch looks up both images directly;
ReadImage materializes its complete data image and looks up only the requested
index prefix. Delta keeps both canonical owned images throughout reconstruction.
No checked object is cached across physical reads or RPCs, and omitted/unrequested
bytes remain part of every complete audit. Checked trees still occupy memory,
and image materialization temporarily overlaps canonical bytes with packet copies.
These ownership boundaries do not establish a memory or latency improvement.

Complete custody audits resolve their CPU policy once from available parallelism
and `RAYON_NUM_THREADS`, using the same pure bounded worker policy as proof
acceleration. An effective budget of one keeps audits serial; any larger budget
opts into at most caller-plus-one leaf-hashing workers. Invalid/zero requests use
that existing bounded default. Compact-store's single shared nonblocking helper
permit covers concurrent Copy audits before the store mutex as well as ordinary
physical reads. Its public-geometry 4-MiB threshold and full serial fallback do not
skip packets, revisions, either root or the data-before-index check order.
A helper requests a 512-KiB stack and is joined before releasing the permit;
panics propagate after cleanup rather than accepting partially checked bytes.
This does not reuse the proof DLL's private Rayon pool or create a host-global
pool. The separate eight-connection admission and one-heavy-proof permit remain
unchanged; a proof and an audit can overlap, so this is not a total process CPU or
RAM bound. No full-operation speed or memory improvement is established.

Delta reconstruction consumes it and verified new pages into sealed
`ReconstructedDelta` after both complete new roots match. The shared core
transition/page validator checks every replacement. The owned-image adapter
preflights every exact byte range before updating the consumed private trees. Only matching complete target roots permit
copying replacement packets and manifests into those original allocations. No
partial capability escapes on error. The consumed in-memory base is lost, while
its durable file is unchanged; retry must reread and fully audit that file.
Private `Candidate` consumes that result, rechecks both exact heads and hashes
the exact target nonce and both heads. It privately retains the immutable checked
RawBundle and exact whole-file length/ObjectInfo, completing codec preflight before
quota admission or pending-file creation. The ID is the randomized nonce/head
commitment, conditional on full snapshot validation; it is not a hash of unvalidated
raw or disk bytes. The full-upload factory retains its ordinary raw-bundle audit.
Shared persistence accepts only this immutable candidate. The same disk writer
serves the test-only owned encoder and streams the unchanged serializer into the
pending file through a bounded 16-KiB buffer. Flush finishes before file sync and atomic rename;
only then are maps registered. Write/flush/sync/rename failure retains the existing
pending cleanup and never acknowledges storage. It does not reparse images already
fully authenticated by that construction. The candidate moves both canonical
image Vecs into RawBundle without packet materialization or snapshot encoding;
streaming also avoids a second complete disk Vec. Every required physical read
still audits both full images, every durable target write remains complete, and
no latency or process-memory gain is established. No validation flag, mutable
prevalidated Bundle or persistent custody cache is added. The existing custody profile 2, RPC v2 and application v4 namespaces
remain unchanged by this refactor. Existing-target replay still verifies requested
new pages and fully reads/authenticates the physical target.

The runtime does not choose recipient or privacy policy. A consumer must freeze
known holders and other candidates before query computation; mode may depend only
on public geometry and that committed placement class. A known holder's failed
Delta must never trigger Full Store to that same recipient. New replicas may have
a preplanned Full class. Delta addresses remain visible to the receiving holder;
fixed byte size does not hide timing, access patterns or differences between the
old/new ciphertexts it already stores. See the owning [writeback contract](../../docs/padded-update-delta.md).

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
`BFVPAGQ2` contiguous ten-band coefficient layout (2560 selected rows) and fixed
256-term public convolution; the historical
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
The application commitment uses domain version 3 for these batch-aware transition
rules and the length-delimited Q2/R2 aggregate semantics ID, alongside the unchanged
FHE/STARK profile identity. Version-2 application anchors reject during initialization;
older aggregate/INSERT wires and journals are not migrated.

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
`bfv_query_proof::PROOF_PROFILE_ID`, aggregate semantics ID and ObjectProfileID under
application domain v4. A
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
cargo test --release --locked --offline -p dcs-peer --test process_transport static_read_image -- --test-threads=1
```

Owning process tests live in `dcs-peer`; they must exercise the complete client,
real encrypted proving, actual RPC journal agreement and resulting storage changes.

Status::disk_bytes is advisory observed object/journal storage plus the fixed
40-byte root profile. It excludes pending writes, in-flight reservations and
RAM/setup material; only Store enforces quota admission. The serialized Status
fields are unchanged and carry no object nonce.

`ReadImage::index_page_for_reissue` delegates the existing membership verifier
and returns a sealed `compact-store::VerifiedPagePath` for a page already in the
fixed prefix. It exposes no raw siblings or mutable bytes. Owner reissue still
requires an independently supplied exact head, owner AEAD authentication and
format-specific bounds. This accessor grants no full-object custody, SQL
completeness, authorization or freshness.
