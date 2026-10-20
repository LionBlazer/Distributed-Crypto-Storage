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
| [bfv-mul-relin-proof](../bfv-mul-relin-proof/README.md) | Exact private-input BFV multiplication graph and complete proof verification |
| [bfv-product-evidence](../bfv-product-evidence/README.md) | Typed-depot public product retention and fresh actual proof replay |
| [bfv-relinearization-key-source](../bfv-relinearization-key-source/README.md) | Canonical public evaluation-key preparation for the pinned original setup |
| [proof-acceleration](../proof-acceleration/README.md) | Pure bounded CPU-worker policy, without enabling its loader |
| [version-journal](../version-journal/README.md) | Pinned work/profile validation, ancestry, authorization and durable ordering |
| [registry200-journal](../registry200-journal/README.md) | Fixed Registry200 application, canonical descriptor/request and genuine Source/Lifecycle admission |
| [registry200-finality](../registry200-finality/README.md) | Closed original/Joint durable proof admission, weighted QC, floor and WAL ownership |
| [registry200-joint](../registry200-joint/README.md) | Fixed Joint descriptors/manifests and same typed public evidence ingress |

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

## Private product stream

`RemotePeer::prove_private_product` sends one owner-authorized mathematical job
over an independent TLS connection. The peer audits the original custody object
and exact data/index heads, rebuilds bounded public provenance claims for its
installed setup, and verifies the fifteen mandatory input frames. Each encoding
pair retains its real Source-before-child verification. It then performs the
actual fixed BFV ciphertext product and emits claims and all 118 ordered proof
records for the 134-node graph. Plaintext SQL, predicate truth tables, rows and
owner keys never enter this service. The client uses its own independently pinned
provenance and verifies every input and output proof before returning
`CheckedPrivateProduct`; a received claim, ciphertext or prefix grants no result.

`DCSPRP01` frames bind the request identity, immutable job digest, random server
nonce, role and ordinal. The next proof is produced only after a bounded explicit
client demand. Each original input cap and the complete collection cap apply;
no aggregate proof blob or journal body is created. The peer retains at most the
fixed fifteen public input frames, drops them before output proof work, and
produces one output record at a time. The peer has no durable job/spool or implicit
retry identity. Complete application-frame reads/writes produce activity events;
partial transport reads are excluded from application-frame counters.

`RemotePeer::prove_private_product_recorded` uses that same closed verification
loop with a caller-owned `ProductStore`, whose only constructor requires typed
participant `DepotBudget`. It retains one Source and both Encoding children,
Key/ten Basis/two Formation, original setup/request/response/claims and the 118
verified output records as separate bounded immutable blobs. After actual END,
EOF, full verifier finish and a final live cancellation/deadline check it publishes
a small untrusted catalog last. Errors leave accounted public blobs without a
new completed catalog; no whole graph proof Vec or aggregate transport frame is
introduced. A subsequent reader must freshly verify every original proof against
independently pinned setup/Key33/Provenance/request/heads/query. A content identity,
prior QC or successful earlier read supplies no cached proof authority. See the
[retention contract](../bfv-product-evidence/README.md) and its
[actual OS-peer/replay gate](../../docs/retained-product-evidence.md).

The additive `RemotePeer::prove_private_product_recorded_shared` takes one
`SharedProductStore` cloned from the actual `JointEvidenceIngress::recording_store`
or obtained by moving an exclusive `ProductStore::into_shared`. Both recorded
methods use the SAME private transport/verification implementation. Only bounded
blob I/O holds the store's private lock; no network read/write, cancellation
check, SDK proof work or terminal END/EOF runs under it. Catalog publication
remains last, after actual verifier finish and the live budget fence. The new
shared OS-peer owning case and unchanged four-validator/FHE Acquire regression
passed [native validation](../../docs/shared-evidence-owner-restart.md); earlier
measurements above apply to the exclusive path. No new wire, timeout, proof policy or blob cap
is introduced.

One heavy permit spans the connection. Errors, EOF, cancellation and terminal
delivery drop its in-memory state and permit. I/O has a 180-second inactivity
budget and an absolute 1800-second socket deadline; these are service resource
bounds, not query-latency targets. An in-flight synchronous SDK call may still
finish after cancellation or deadline; later stages and delivery then stop.
TLS handshakes and initial request delivery also have absolute deadlines.

This service supplies mathematical FHE evidence. It does not authorize SQL,
establish a fresh agreed head, finalize locks, enforce writer ownership, prove
evaluation-key same-secret consistency, or claim composed security or a measured
whole-process resource bound. Current SQL entry points remain fail-closed while
their full composition is incomplete.

The [native private-WHERE record](../../docs/private-where-peer.md) reports one
actual full N4 operation on an independent daemon, all input/output proof bytes,
whole-operation timings, process memory observations and four real peer refusal/
cancellation cases. It does not establish interactive latency or SQL admission.

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

`RemotePeer::fetch_version(data_head, index_head)` additionally retains a complete
RawBundle reply in `ReceivedVersionBytes`: one original immutable received frame,
four checked field ranges and copied version/nonce scalars. The same borrowed
four-field parser completes all lengths and trailing-byte checks before this
non-cloneable value exists. `encoded_images()` lends both complete ciphertext
images; `target_version()` performs the existing metadata-only binding check.
Neither operation grants custody, owner authority, TableId binding, query proof
or freshness. Callers must still audit both full images and their trusted heads.
The original frame drops when its owner import finishes; it is not a custody cache.

The typed method uses the same private exchange as `call`: TLS pinning, request
identity, 64-MiB whole-frame cap (including the 18-byte response envelope), actual
Activity/Trace bytes, decoding inside Trace timing and final cancellation check
are retained. A completely decoded known unexpected successful variant returns
`Ok(None)` and remains a successful RPC. Remote errors, malformed/unknown variants
and request-binding failures remain errors; a malformed raw reply never tries a
second decoder. Ordinary `call`, public RawBundle Deserialize, server dispatch,
disk encoding and every physical two-image custody audit are unchanged. This
ownership path removes the four reply-payload copies for its consumer; it does
not establish complete-operation latency or process-RAM bounds.

The specialized wrappers retain the existing v2 namespace, profiles and enum tags;
all other RPC variants use the ordinary decoder. A malformed specialized body
rejects without trying another format. Inner raw version, nonce, head lengths and
image bytes remain untrusted data: parsing does not run custody checks before
owner authorization. Every physical read still performs both complete snapshot
root audits, and all quota, retry, Copy, proof and freshness guards remain in
place. Owned payloads and full disk/frame buffers still exist; no zero-copy
custody, process-RAM or complete-query latency guarantee follows.

Compute admission (`Prove` and the explicitly unverified legacy `Evaluate`) uses
the same fully parsed borrowed fields to audit both complete images directly in
the bounded disk buffer. It retains only `TargetVersion` after both audits and
the requested object-ID check; it does not allocate the four owned payload copies.
The private store read helper shares known-object lookup, physical read bounds
and invalid/status accounting with ordinary owned reads. Each compute RPC rereads
and reaudits the file, including unrequested tails in both images; exact repair
clears unavailability only after a successful full audit. Namespace, all four
lengths, trailing bytes, inner metadata, revisions and roots keep their existing
validation order. Setup lookup, heavy-work admission and Prove's exact two-head
request binding remain unchanged. TargetVersion is still metadata only, and this
path adds no source/completeness or freshness proof. The complete disk buffer and
Merkle hash/tree work remain; latency and process memory need separate measurement.

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
its randomized object binding and both encrypted image roots, then derives real
`LookupResponse` membership proofs from those validated images. Corruption in
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
outside the returned prefix, then reuses those exact validated images. No
stat/mtime/status shortcut or extra disk cache is introduced.

PageBatch and ReadImage construct their replies from private
`BorrowedCheckedImages` in the bounded immutable disk buffer. The same four-field
parser finishes all lengths/trailing checks before metadata validation; the same
canonical compact-store auditor checks the complete data image, then the complete
index image. Only after both succeed does Store compare the exact requested
object ID. PageBatch copies only its requested membership responses; ReadImage
materializes its complete data snapshot and copies the fixed index prefix. Both
replies own their bytes before the disk buffer drops. No partial snapshot, public
core API or alternate wire format is introduced.

The existing private read helper distinguishes physical custody from reply
construction through a nested Result. A failed physical read/audit/ID check marks
a known object unavailable. Successful physical repair clears that marker even
when a well-formed request supplies different heads and reply binding fails.
Malformed, duplicate or out-of-range wire requests reject before dispatch and
perform no audit or availability repair. Ordinary successful requests retain
their exact address order. This request-local path removes the four RawBundle
payload copies: 37,604,496 bytes for the documented million-row geometry. The
whole disk buffer, complete Merkle trees, owned reply payloads and encoding buffers
remain; this structural count is not measured RSS or a complete-operation speed
claim. Compute admission still drops each audit before starting the next image;
it does not retain both trees merely to return metadata.

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

The private store admission boundary uses request-local, non-cloneable
capabilities. Only a complete physical read plus object-hash and both-root checks
constructs `CheckedObject`. It retains the original envelope version, nonce and
head buffers together with two `OwnedVerifiedSnapshotBytes` capabilities. Their
single canonical parser checks all packet revisions and both complete roots;
raw Fetch, Copy, startup and full candidate admission can move the exact buffers
without creating packet copies. The separate borrowed reply path above serves
PageBatch/ReadImage. Delta keeps both canonical owned images throughout
reconstruction.
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
STARK. These operation names describe arithmetic RPCs, not admitted SQL queries
or a proved encrypted predicate/completeness relation. Supported raw operations
are owner-selected `SELECT`, `INSERT`, additive
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

`MutationManifest` and `MutationEvidence` retain their canonical bounded codecs:
32 MiB aggregate, 32 jobs and 2 MiB per request/output/proof. Wire tags, application
identity and disk namespace are unchanged. They are not an admitted SQL mutation
format: the shared `TransitionVerifier for JobVerifier` rejects every Jobs
transition with `RejectedComputationProof` before any arithmetic cache can admit
state. This applies to INSERT and UPDATE on Mine, Publish, relay and durable reopen.

Genuine Addition/Product proofs are insufficient for source-bound SQL predicate
and completeness, ciphertext input formation, and output-to-new-AEAD/index linkage.
An owner signature authenticates permission; it does not prove those relations.
The earlier designated-client finalization contract is therefore not accepted as
SQL mutation authority. Previously admitted Jobs mutation histories now fail
closed on replay; there is no fallback, migration or renamed replacement app.
Initial provisioning, Store/Copy/StoreDelta, raw Prove/Evaluate and separate
Registry200 control admission remain independent.

`JobVerifier::check_job` still derives the exact canonical input from the trusted
original request and genuinely verifies its complete encrypted output/proof. Its
checked marker is arithmetic-only. The bounded 128-entry digest cache remains
keyed to every input/output/proof byte; neither it nor a serialized marker grants
SQL result or root publication authority. Current SQL facades reject before I/O.
See [coverage and unfinished SQL scenarios](../storage-client/SQL-CAPABILITY-COVERAGE.md)
and the [native validation record](../storage-client/SQL-CAPABILITY-VALIDATION.md).
The refusal/raw-protocol gate passes; retained SQL-success cases remain unavailable
and the full SQL suite is not green. This does not establish complete SQL support.

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

## Opt-in chunk I/O feasibility fixture

The ignored owning test
`store::chunk_io_feasibility::million_row_chunk_io_reconstructs_and_audits_after_exact_delta_reuse_and_base_gc`
is a PUBLIC NONSECRET filesystem candidate, not a live storage backend. It uses
real CSTORE AEAD/Merkle images with the existing million-row custody geometry and
actual `Store::put_delta` reconstruction. Its generic encrypted index payload is
not a semantically valid compact-query Table, and it measures no SQL/FHE result.
The owner decrypts every final data page and checks the complete public byte vector.
No key/export API, production storage path, wire, Status or quota contract changes.

Run it explicitly with Rust 1.99 in an isolated target after coordinating other
heavy jobs. This command is a reproduction recipe, not an executed measurement:

```powershell
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:DCS_CHUNK_IO_FEASIBILITY = '1'
cargo test --release --locked --offline -p peer-runtime --lib store::chunk_io_feasibility::million_row_chunk_io_reconstructs_and_audits_after_exact_delta_reuse_and_base_gc -- --ignored --exact --nocapture --test-threads=1
```

The fixture creates a fresh `dcs-public-chunk-io-<pid>-<time>` directory in the OS
temporary directory and prints its path before input preparation. It retains all
nonsecret artifacts, including on failure; it never deletes another run directory.
Prepare at least 512 MiB free for its retained file contents, plus filesystem
allocation/metadata overhead. The bounded geometry is not a peak-RAM guarantee.

Both single-file and chunk writers call the unchanged `objects::write_disk`.
Their write intervals include serialization, actual writes and successful file
syncs. Read intervals include actual complete reads, both canonical image audits,
exact object/head checks and byte comparison with inputs prepared outside timing.
Final owner decryption is outside those intervals. OS caches are uncontrolled;
these are neither cold-disk timings nor complete accepted SQL latency samples.
`CHUNK_IO_SAMPLE` records every interval, including the expected corrupted-tail
rejection. Counters describe explicit Rust data/manifest file opens, read/write
calls and bytes, successful `sync_all`/unlink calls, and exact reused payload bytes;
they are not kernel syscall tracing or NTFS allocated-space measurements.

Source geometry predicts 574 raw 64-KiB chunks (last 52,474 bytes), 574 payload
opens plus one manifest open on a complete read, and 574 chunk syncs plus one
manifest sync for an initial Full/Copy. This particular real Delta changes chunks
0 and 48, so the candidate must create exactly two chunks and sync its new manifest.
These are source-derived counts, not measured speedups. No audit is cached across
rereads: only a freshly read and fully audited immutable base permits byte-for-byte
reuse during that one write.

The test-only manifest uses the pinned serializer and must match its owned expected
bytes exactly; it has no accepting persistent parser or production reopen contract.
Retirement writes only through the manifest's retained original creation handle
inside that fresh owned fixture. The ordering exercise syncs that handle before
unlinking the base manifest and its two unshared chunks, then rereads/audits and
owner-decrypts the complete surviving target. It does not establish hostile local
namespace/hardlink race protection, arbitrary power-loss recovery, production GC,
quota accounting, or feasibility of an unbounded file population.
The [single observed I/O report](../../experiments/storage-io/README.md) retains
all intervals, initial Full/Copy regressions and the limited fresh-directory scope.

## Opt-in packed-container I/O feasibility fixture

The child test module
[`chunk_io_feasibility/packed.rs`](src/store/chunk_io_feasibility/packed.rs)
reuses the same public million-row CSTORE fixture, actual Delta reconstruction,
canonical writer, complete custody auditor and owner checks. It compares the
single-file writer with a bounded append-only container of 64-KiB extents.
It is a test consumer, with no production backend, wire, accounting or acceptance
change. Its [separate record](../../experiments/storage-io/PACKED-CONTAINER.md)
describes exact measurement boundaries and validation status.

The ignored test requires `DCS_PACKED_IO_FEASIBILITY=1` and its exact name:

```powershell
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:DCS_PACKED_IO_FEASIBILITY = '1'
cargo test --release --locked --offline -p peer-runtime --lib store::chunk_io_feasibility::packed::million_row_container_reuses_delta_and_reclaims_retired_storage_after_full_audits -- --ignored --exact --nocapture --test-threads=1
```

Use an isolated Rust 1.99 target and coordinate heavy jobs. A fresh
`dcs-public-packed-io-<pid>-<time>` OS-temp directory retains public outputs, with
a 512-MiB file-content bound plus unmeasured filesystem metadata/allocation.
Only retained original creation handles perform append/retirement writes.
Every successful read physically reconstructs and audits both complete images;
contiguous extents can share a read without omitting bytes. A one-use fresh-base
token permits only exact positional reuse in the same container. Compaction
writes a fresh container, audits it before unlinking the old owned container,
and audits the survivor again. This is not a crash/reopen, namespace-race,
production GC, quota or SQL guarantee.


## Distinct Registry200 control admission

InitRegistryJournal is a new appended owner-only request, separate from the
unchanged BFV InitJournal/InstallSetup route. Its bounded canonical descriptor and
independently pinned Genesis construct the concrete
[registry200-journal](../registry200-journal/README.md) verifier before directory
registration. Network owns a closed Jobs/Registry verifier enum; unknown
descriptors cannot fall back to Jobs. Mining validates the actual signed proof
before work, publishing validates/syncs before state publication, neighbor relays
use the same publication path, and reopen re-verifies stored proofs. One existing
heavy-work permit and all transport/Body/history/quota policies remain unchanged.

This is private-control admission only. It does not execute private peer SQL
predicates, link data mutations to held RowIds or establish agreed global
freshness. Storage-client LockingSelect remains rejected. The
[validation record](../../experiments/hiding-fri-sha256-gate/REGISTRY200-PEER-CONTROL-VALIDATION.md)
records the actual two-process control flow and observation limits.

## Closed finality service

The distinct [Registry200 TLS actor](src/finality/README.md) consumes the concrete
durable adapter and shares the process-owned `ProofGate` with existing network
and private-product work. It verifies actual original application Bodies before
votes and provides sequential original-body/QC catch-up and a keyless independent
follower. `PeerServer::proof_gate` clones the existing resource gate before spawn;
`ProofGate::try_acquire` returns a move-only RAII permit shared with all existing
heavy work. A permit is resource ownership, never proof validity. The TLS owning
tests passed in one process; four existing OS-peer rejection/cancellation cases
also passed. These are not a four-OS-peer finality deployment result; see the
[native record](../../docs/network-finality.md).
Standalone hosts can now explicitly construct `ProofGate::new()` without a dummy
server, then pass clones to all their actual heavy consumers. Each construction
creates an independent resource; it does not enforce a process-global singleton.
The composition owner must create and share ONE gate. Construction supplies no
proof validity, authorization, finalized head or lock grant. The existing clone,
busy and unwind owning test remains unchanged and passed with the public
constructor's documentation example and the real shared-recorder OS case.
The participant-quota/bootstrap integration below has now passed its distinct
four-OS gate. System-lane admission, work roster activation/reconfiguration and
a hidden-SQL lock grant remain open. It adds no alternate Jobs application or
SQL capability enable flag.

## Explicit participant finality host

The new [`ParticipantBootstrap`, `ParticipantHost` and `RunningParticipant`
contract](PARTICIPANT-FINALITY.md) composes the original Registry finality service
with one actual participant ledger and one proof-scheduling gate. It activates no
legacy custody-v2/Jobs service in the new root. Its bounded local IPC bootstrap
and independently supervised daemon path passed the owning four-process
Source/Lifecycle finality test, including partition/reopen and offline catch-up.
The [separate native record](../../docs/participant-finality-host.md) gives exact
measurements and tests; earlier records retain their original scope. The host
does not enable encrypted SQL.

## One-record private-product lookahead (source candidate)

The private client output loop in
[`client/private_product.rs`](src/client/private_product.rs) sends the first
`NEXT(0)` only after its actual input16 check. After a complete bounded
`PROOF(i)` read and cancellation/deadline check, it sends `NEXT(i+1)` before the
SAME mandatory native `accept(i)` and evidence retention, except at the final
ordinal. This lets the remote process produce at most one following record while
the owner verifies the current one. `NEXT` carries only the existing session
binding, ordinal and empty payload; it is flow credit, never a verified grant.

The server, all wire/profile bytes, exact 118 role order, individual/aggregate
caps and original 180/1800-second budgets remain unchanged. Record0 is still the
fixed arithmetic17 proof and the remaining records are the same115 NTT plus2
Relin proofs. There is no 119th credit, reordering, proof cache or verifier skip.
Every actual input/output check, END, clean EOF, security union and catalog
publication gate remains required. A frame that was received successfully is
still unverified; the new private helper returns only bytes and cannot return
rows, CheckedProduct, a completed catalog or SQL authority.

No native worker, gate, producer queue, read-ahead heap buffer or detached task is
added. The server remains synchronous and starts only one credited stage at a
time. TCP backpressure bounds a completed following record while the owner is
busy; each payload retains the old16 MiB proof cap plus its fixed headers. The
owner still holds its ONE existing caller ProofPermit across the genuine RPC;
the server holds its existing permit until synchronous proving returns. Neither
native verification nor RPC retains the shared depot mutex. A rejected current
proof or cancellation can waste at most one already credited following stage;
in-flight native work is not preempted. Errors close the same scoped connection,
and existing deadline/connection workers retain their join/cleanup lifecycle.

Four added owning flow tests cover all118 credits with no terminal consumption,
malformed/truncated/foreign/out-of-order/extra roles, cancellation around credit,
and actual loopback delivery before the current bytes reach acceptance. Their
payloads are explicitly untrusted parser fixtures, not positive cryptographic
or SQL answers. The unchanged real verifier and genuine FHE stream gates own
proof acceptance and END/EOF success. All four flow tests passed on 2026-10-20
(0.00 seconds in the test body,18.363 seconds including compilation), as did
strict release Clippy for all package targets. The frozen1612-file inventory
matched after both commands. Two genuine input16/output118/END/EOF streams with
this scheduling subsequently passed in the seven-child-process Host scenario.
The first complete production-driver call took 1277.232 seconds; the entire
two-Acquire/restart/recovery command took 3345.196 seconds. Its 1612-file source
receipt was `A111D4BB49432A017207A04E8FC1FFE9203859870936A48243CD3B699E0A2CE6`;
the unchanged-source/log receipt was
`087A6687AB7227FDC828CA588AC47D543E27E99BC3008FDDA751A89635513C3F`.
The 1792-MiB per-process soft fuse did not fire. These are bounded measurements,
not a comparable before/after speedup or a complete RAM guarantee. The scheduling
change itself establishes no current lease or SQL admission.

## Distinct Progress participants

[Progress participant transport](PROGRESS-PARTICIPANT.md) adds typed
ProgressFinalityClient, bind_progress and explicit new/existing process startup.
One private transport/prefetch engine serves both active Joint and Progress
profiles, with the same ledger/gate ownership and unchanged old wire/deadlines.
The new four-OS Source/Bootstrap803/Control815 gate passed, as did the existing
Joint process regression and focused runtime/API checks; see the
[validation record](../../docs/progress-network-validation.md).
New-G Predicate/Result160 owner WAIT continuation remains a separate gate.
