# Closed Registry200 TLS actor

This module runs the original Source/Lifecycle application through the concrete
[registry200-finality](../../../registry200-finality/README.md) owner. It contains
no generic application verifier, SQL execution path or serialized accepting token.

| Direct dependency | Responsibility |
| --- | --- |
| `registry200-finality` | Actual candidate Body/owner/Source-first child checks, durable signer, floor and keyless follower |
| [work-finality](../../../work-finality/README.md) | Signed bounded consensus inputs and actual local timeout tokens |
| [peer-transport](../../../peer-transport/README.md) | Actual TLS endpoint pins, bounded frames, deadlines and socket cancellation |
| Parent `ProofGate` | The one process-owned resource permit shared with existing custody/FHE work |

`FinalityServer::bind` consumes an already-created/opened `RegistryFinality`,
trusted `ListenerConfig` and the process owner's actual proof gate before
spawning it. A legacy `PeerServer` supplies its existing gate; the explicit
[`ParticipantHost`](../../PARTICIPANT-FINALITY.md) allocates one actual gate and
keeps the participant root alive. No workspace, signer key or quota is created
by the listener. The legacy fixed-file adapter remains explicit under its real
256-MiB control budget. The participant constructor uses typed files and the
same control/global ledger; neither adopts custody-v2 paths.

One actor owns the signer. It never holds its application mutex across RPC. The
8-entry command channel has an aggregate 16-MiB control reservation ledger.
Inbound allocation is reserved before reading declared control lengths; its
lease follows the input through queueing and the response. The sequential relay
reserves control space for its pass. Exactly one service-wide Body lease spans
remote fetch, queued import or public export. Original Body bytes use a separate
bounded frame and are not recopied into a complete transport envelope. Connection
workers are bounded to eight, the pinned neighbor list to sixteen. Active TLS
operations have an absolute 180-second budget; the TLS handshake keeps its own
existing bound. Successful terminal replies require clean TLS EOF under that
same deadline; trailing bytes and truncated TLS streams reject. The intermediate
upload Ready reply keeps the connection open. These are protocol limits, not a
measured whole-process RAM or latency result.

Only the configured owner TLS identity can submit a local candidate proposal.
All admitted candidates still require the real Header work, parent, canonical
Body, owner signature and original application proofs. Other authenticated peers
can relay only signed consensus input and independently checked candidate bytes.
Remote timer/local proposal tags are rejected. Timers use monotonic `Instant`
and only the actual enabled timeout returned by the owned signer. Missing ANY
quorum disables its timer and waits; timeout or nil never unlocks. One pending
owner-submitted candidate can be proposed when this validator becomes the actual
elected proposer. The durable signed proposal/votes/POL are the source of outbound
replay; an unproposed candidate choice is in-memory and may need owner resubmission
after restart.

The relay reads status only as an untrusted fetch hint. It transfers one persisted
checkpoint and original block per slot, imports/rechecks the Body before passing
the real QC to the durable signer, and never skips directly to a remote context.
After Advance, the floor log supplies the previous durable QC even though current
outbound belongs to the next slot. Replayed current votes are no-ops in the WAL;
lost acknowledgements do not create another signature. Shutdown interrupts TLS,
stops new commands and joins actual in-flight proof work before releasing owners.
Checkpoint catch-up is pull-only: the lagging peer must reach an up-to-date
provider through its configured neighbors. Weak connectivity or an outgoing
connection from the ahead peer alone does not establish that reachability.
Avoiding a simultaneous push prevents both peers from retaining their sole Body
lease while each requests the other's unavailable lease.

`FinalityClient::follow_next` requires independent local `Follower` pins and the
actual process gate before allocating its remote Body. Its `VerifiedCheckpoint`
is in-memory application/QC evidence, not a durable validator floor, an epoch
activation, a freshness barrier or a SQL/row-lock grant. Status alone is never
accepted. Existing SQL capability rejections and original Jobs/wire/custody
profiles are unchanged.

The executed tests cover real TLS actors in one test process, 2+2 no-quorum,
restart/heal, three-of-four progress, offline catch-up, owner rejection, local
timer rejection and independent follower verification. An additional owning
regression forces an occupied Body lease and simultaneous relay passes, then
checks actual catch-up without owner resubmission. All 94 peer-runtime cases,
seven adapter cases and five ownership compile-fail examples passed; four
existing OS-peer rejection/cancellation cases passed too. See the
[native record](../../../../docs/network-finality.md) for exact source versions
and scope. A subsequent [participant-host gate](../../../../docs/participant-finality-host.md)
passed with four independent daemon processes, typed participant quota/bootstrap
and genuine Source/Lifecycle Bodies. It also tests clean, trailing and truncated
terminal TLS streams. Permissionless roster activation/reconfiguration, the
system lane, current SQL freshness and a hidden-predicate lock grant remain open.

## Distinct Joint participant service (source candidate)

`FinalityServer::bind_joint` consumes a real `DurableJointFinality` and the host's
same `ProofGate`. It returns `JointFinalityServer`; its supervisor and the old
service use the same private closed `Owner::Original|Joint` actor loop. A host
owns one signer, one timer, one participant ledger and one actual evidence depot.
The old `DCSRFN01` bytes and 180-second request behavior remain separate from new
`DCSJFN01`/`joint_profile_digest` and its explicit 1800-second operation budget.
This is a bounded protocol policy, not a latency or whole-process RAM measurement.

| Additional direct project dependency | Responsibility |
| --- | --- |
| [registry200-joint](../../../registry200-joint/README.md) | Independently pinned application/setup, canonical manifest roles and same-depot public ingress |
| [bfv-product-evidence](../../../bfv-product-evidence/README.md) | Canonical unverified catalog reference enumeration; genuine replay stays inside the fixed Joint verifier |
| [protocol-storage](../../../protocol-storage/README.md) | Typed depot/participant quota and unchanged 32-MiB public blob bound |
| [version-journal](../../../version-journal/README.md) | The existing exact owner authorization signature and canonical Header/Body |

`JointFinalityClient::put_proof_blob` presents the complete canonical owner-signed
Body plus a fixed role/ordinal and claimed byte identity in a bounded control
frame. The server requires the independently configured owner TLS identity and
the actual database-owner signature. It derives the allowed ID/cap from that
manifest and, for product parts, the same stored canonical catalog. It rejects a
foreign ID before allocating a blob payload. This grants only retention of public
bytes, never computation acceptance. Public GET rehashes exact local bytes and
returns one bounded blob. Exactly one download/receive and one export lease,
each at most 32 MiB, are shared across all workers and the bounded Joint relay.
Legacy Body and control reservations keep their separate unchanged bounds.

The private [relay scheduler](joint_server/README.md) owns at most three joined
workers over disjoint rotating neighbor lanes. One slow neighbor no longer
serializes all three neighbors of a four-validator deployment. Accepted inbound
workers remain bounded by eight; this is not a bound of eight total TCP sockets.
The owner, proof gate, participant ledger, body/blob leases, protocol and deadlines
are unchanged. An internal prefetch snapshot superseded by another genuine
decision returns Busy; the retry captures a new snapshot and repeats the actual
checks. Malformed data, owner/QC/proof failures remain hard rejections.

Every new candidate prefetches all fixed manifest references and every catalog
reference before entering the actor or taking the actual proof gate. No network
call runs under a journal/application mutex. Only missing files may be fetched;
corruption, poison and identity failures are not repaired as missing evidence.
The actor checks the exact current slot/context/parent again after acquiring the
gate and invokes real Joint admission. Empty is a no-blob operation with actual
Journal/QC verification. An exact latest-body/QC retry invokes the durable
last-context, semantic-successor and full-proof replay path; current-parent
prefetch is not misapplied to historical duplicates.

An absolute Joint expiry follows the operation through prefetch and queueing,
including the relay's local outbound and candidate-body metadata calls.
Expired queued work rejects before admission. Socket cancellation may end I/O
but cannot preempt an already-started synchronous proof, erase a lock, manufacture
a timeout or release the compute/signing owner in the background. The service
joins that work before releasing its gate/store. Clients must resolve a lost
acknowledgement through an actual independently verified checkpoint, not a status
observation. Owner resubmission may be necessary for an unproposed candidate.

The new owning `apps/dcs-peer/tests/joint_finality.rs` source builds genuine
Bootstrap/Begin/ControlKind evidence and launches four distinct OS validators.
It covers public evidence prefetch, a reachable 2+2 observation window without
QC, actual quorum after healing, new-PID reopen, owner/missing/tampered/foreign
request rejection, lost ACK and exact duplicate replay. This test passed in
292.03 seconds, followed by the original four-OS participant regression in
676.75 seconds. The [native record](../../../../docs/joint-participant-finality.md)
distinguishes that source from the subsequent certificate/queue corrections.
The full Acquire 16+118 process gate and exact FHE result/Result144 completion
also passed on four OS validators plus a separate FHE peer, with fresh client
replay and hostile-proof checks; see the same native record. The separate actual
two-Acquire gate also passed with a genuinely held row and SKIP LOCKED before
OFFSET/LIMIT. On the bounded relay source, both four-process protocol regressions
and all 110 peer-runtime library tests passed again. A fresh-head barrier, owner
Vault and delegated rights remain separate requirements. No ordinary SELECT lane,
SQL grant, plaintext fallback or quorum-as-computation shortcut is introduced here.
