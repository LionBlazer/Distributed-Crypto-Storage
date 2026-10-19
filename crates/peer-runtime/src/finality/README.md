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
trusted `ListenerConfig` and the gate cloned from `PeerServer::proof_gate` before
spawning it. No workspace, signer key or quota is created by the listener. The
existing legacy fixed-file adapter remains explicit: its caller owns all three
files under the same real 256-MiB control budget. The new participant namespace
and a production daemon bootstrap are separate integration work; do not place
those files silently into custody-v2 or an unaccounted subdirectory.

One actor owns the signer. It never holds its application mutex across RPC. The
8-entry command channel has an aggregate 16-MiB control reservation ledger.
Inbound allocation is reserved before reading declared control lengths; its
lease follows the input through queueing and the response. The sequential relay
reserves control space for its pass. Exactly one service-wide Body lease spans
remote fetch, queued import or public export. Original Body bytes use a separate
bounded frame and are not recopied into a complete transport envelope. Connection
workers are bounded to eight, the pinned neighbor list to sixteen. Active TLS
operations have an absolute 180-second budget; the TLS handshake keeps its own
existing bound. These are protocol limits, not a measured whole-process RAM or
latency result.

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
and scope. These do not establish four independent finality OS peers, permissionless
roster activation/reconfiguration, the system lane or a hidden-predicate lock
grant. The production four-OS gate must use actual participant quota/bootstrap
integration and original Source/Lifecycle proof-bearing Bodies; it remains open.
