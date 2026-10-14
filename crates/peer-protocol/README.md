# Peer protocol experiment

A dependency-free message state machine used by the [local playground](../fhe-playground/README.md).
`ProtocolNode` owns bounded neighbor/handshake state; `Envelope`, `Message`, and
`ProtocolEvent` form the transport boundary. Ping, matching pong, and acknowledgment
must be delivered before a route is established. Requests and responses require
that route; forgetting a node revokes it.

The caller owns discovery hints, identity assignment, delivery, retry/timeout policy,
and disconnect detection. The library imports neither GUI nor virtual-time settings.
The playground transport supplies these policies and traces actual delivered messages.
Request payloads are bounded opaque bytes; storage and cryptographic keys remain
outside this crate. Transport IDs and handshake nonces are not cryptographic identity
authentication. This is not a production P2P, consensus, replication, or proof protocol.

Run contract tests with `cargo test --release -p peer-protocol`.
