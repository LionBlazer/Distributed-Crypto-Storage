# Bounded Joint relay

[relay.rs](relay.rs) owns only transport scheduling and the lifetimes of at most
three Joint relay threads. The parent [joint_server.rs](../joint_server.rs) still
owns the typed TLS service, accepted connections and the original `synchronize`
implementation. The actual closed actor alone owns the durable signer, State,
Journal and the host's existing proof gate.

`Workers::spawn` starts `min(neighbors.len(), 3)` workers over the immutable list
of at most sixteen neighbors. Worker `i` visits `i, i+k, i+2k, ...`; these lanes
are balanced and disjoint. Each pass rotates the first neighbor within its own
lane. Only one endpoint attempt runs per worker. With three neighbors, each has
an independent worker; waiting for one remote application's real proof check
does not serialize the two other endpoint attempts behind it. There is no
per-RPC thread creation, all-neighbor completion barrier, message cache,
substitute acknowledgement or change to consensus/application verification.

The private `spawn_lanes` boundary owns actual thread creation and the rotating
lane loop. Production supplies only the fixed typed-client/`synchronize` call;
owning tests invoke that same spawner with controlled endpoint scheduling. This
private thread callback returns no cryptographic result and is not a public
verifier, backend or production configuration hook.

Every attempt invokes the same parent `synchronize`, byte for byte. The workers
share the same Handle, cancellation token, ingress/depot, BodyGate and BlobGate
through the original Service. No signer, proof gate, quota or ledger is minted.
The original protocol/wire and its 180-second budget are unchanged. Joint keeps
its existing 180-second I/O and 1800-second operation bounds; an enqueued actual
synchronous proof still must finish before the caller can release ownership.

## Resource and shutdown ownership

Each active synchronization pass reserves the existing `MAX_CONTROL` from the
same 16-MiB aggregate control ledger and releases it before idle parking. Three
full relay reservations use 6,291,675 bytes. Four full inbound reservations bring
that to 14,680,575 bytes, leaving 2,096,641 bytes for separately charged small
metadata/owner leases. Every additional request still uses that same ledger and
eight-entry command channel and can return Busy; neither bound is increased.
The single Body lease and one download/one export Blob leases retain their old
bounds. Eight accepted connection workers remain the limit; outbound relay dial
concurrency is now at most three. That inbound-worker limit is not a claim that
all inbound, relay and existing prefetch TCP sockets total at most eight.

The thread owner is created before the first spawn. If any subsequent spawn
fails, its Drop requests stop, cancels registered outgoing sockets, closes the
same registered inbound sockets, unparks and joins every thread already started.
Normal shutdown uses the same cleanup. A panic does not cause an early return
before the other workers are joined. No JoinHandle is detached and no timed join
pretends to cancel native work or unlock the actor. The parent TLS supervisor
then retains its existing actual owner-join behavior. A private worker-exit guard
sets the same host stop flag on an unexpected panic; the listener detects it and
performs normal cancel/close/join rather than silently losing one relay lane.

A stalled neighbor can still delay later neighbors in its lane until the actual
operation returns. Rotation changes visit priority, not proof policy or network
availability. This bounded scheduler alone establishes no interactive latency,
Byzantine-neighbor liveness, whole-process RAM result, fresh-head authority, lock
grant or SQL capability.

## Owning checks and native validation

Five unit scenarios cover all neighbor counts 1..16 and rotating priorities,
the actual shared spawner with a blocked first lane and two other active lanes,
early-startup-error Drop/join, actual peer EOF after Drop shuts down a registered
socket and joins its opposite endpoint's reader, and a worker panic that signals
host stop before parent shutdown and still joins all other workers. The concurrency
case would fail if the shared
production spawner serialized the three endpoints. Channels and socket timeouts
bound test handshakes. These test transport scheduling/lifecycle only and contain
no fake cryptographic verifier or SQL answer. All five passed in the peer-runtime
suite: 110 passed, two unrelated opt-in cases ignored. Strict all-target Clippy
and formatting passed. The original and Joint four-process protocol regressions
also passed, followed by the full two-Acquire contention gate with genuine FHE
input16/output118, QCs and fresh client completion. The
[native record](../../../../../docs/joint-participant-finality.md) pins the
1,539-file source inventory, binary, timing, resource observations and log hashes.
These tests establish no general SQL grant or quantified query speedup.

The first native candidate passed 109 tests but failed its different local-reader
check on Windows: an already pending local receive timed out despite shutdown on
a registered clone. That failure did not record the first shutdown syscall's
result, so its cause remains unresolved. The revised opposite-endpoint EOF check
does not establish prompt interruption of that local receive. Production shutdown
still joins actual work under the unchanged I/O/operation bounds; the earlier
failed candidate remains separate evidence.
