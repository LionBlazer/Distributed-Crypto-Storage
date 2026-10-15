# Peer protocol experiment

A dependency-free state machine used by the [local playground](../../playground/README.md).
`ProtocolNode` owns connection and request lifecycle state. `Envelope`, `Message`,
`RequestToken` and `ProtocolEvent` form the transport boundary; the crate has no
project-module dependencies, GUI, storage or cryptographic keys.

A ping/pong/ack handshake binds both endpoints' live-node monotonic challenges.
Concurrent discovery chooses the lower node ID as initiator. Matching duplicate
handshake frames preserve the existing request/replay state. Each node retains at
most 32 neighbors, 64 outbound requests and 64 accepted inbound jobs; opaque request
payloads are bounded to 4096 bytes.

## Request lifecycle

1. `request(peer, id, payload)` reserves an outbound slot and returns a Send event.
   One logical ID may be outstanding to different peers. A duplicate active pair
   is rejected. General ID reuse after completion/cancellation gets a new token.
2. `receive(Request)` emits work once with its `RequestToken`. The caller retains
   that token with the job, then passes it to `respond(peer, id, token)`. A stale
   completion cannot consume a newer same-ID job; responding consumes the inbound
   slot. `discard_request` releases failed local work while keeping its token terminal.
3. Only a response matching the connected peer, current session, ID and outstanding
   token emits Response and releases the outbound slot. Unsolicited, duplicate,
   wrong-peer and cancelled-attempt responses are rejected. This correlation does
   not validate the answer's contents.
4. `cancel_request`/`cancel_requests` release local outbound slots and return Cancel
   frames. Deliver them, or disconnect: remote slots release only on actual Cancel
   delivery. A Cancel arriving before its Request prevents that attempt executing;
   accepted cancellations emit Cancelled so the work owner can stop the exact job.
5. `forget(peer)` releases that neighbor's session and both directions' active work.
   A fresh handshake has new challenges, so delayed frames/completions from an old
   live-node session cannot complete new work.

Incoming Request/Cancel sequences share a 128-attempt window per direction/session.
Duplicates and frames older than that window are rejected, even after work completes
or is cancelled. Reordering within the window is supported; arbitrarily delayed work
is not guaranteed delivery. Slot/payload rejection does not mark an attempt accepted.
A long-delayed active job may still respond or be cancelled using its exact token.
The caller owns delivery, retries, timeout policy, cancellation of running computation,
discovery hints, identity assignment and disconnect detection. Nothing executes twice
merely because an accepted Request is replayed; no cross-process exactly-once execution
or durable deduplication is provided.

Node IDs and public session/attempt tokens are transport correlation, not cryptographic
identity authentication or authorization. A peer holding a current token can lie about
its result. Recreating a `ProtocolNode` resets its counters: the transport must assign
a fresh incarnation or flush old frames before reusing that identity. This is not a
production P2P, consensus, replication or query-proof protocol.

The playground retains accepted tokens internally while its worker uses advancing
logical job IDs per client; the current ID may fan out once to each distinct peer
until responses begin. Cancellation, target removal/disconnection, or the first
response closes that logical job across every peer, including replacements and
previously unused peers. Only a strictly higher job ID opens new fanout. The adapter
retains one current-ID/closed flag and at most 16 current targets per client, for at
most eight clients; removing targets cannot clear retirement. Cancel frames use virtual
time and are visible control traffic; pause delays remote cleanup. A full packet
queue during cancellation explicitly revokes the pair's route instead of silently
losing cleanup. A failed discovery/handshake enqueue also revokes that pair and
schedules discovery again, so a full control queue cannot leave a reserved handshake
permanently pending. Removal/disconnection drops the corresponding local transport state.

Run API contract tests with `cargo test --release -p peer-protocol`. Playground
adapter tests also exercise delayed cancellation, quotas and ID-only worker routing.
