# Peer transport

TLS 1.3 mutual authentication and bounded framing over TCP. `Connector` verifies
both the configured CA and the exact `Endpoint` certificate fingerprint;
`Acceptor` requires a client certificate. No verification bypass or plaintext
fallback exists. The implementation uses pinned rustls 0.23.45 with ring.

`Identity` owns one endpoint's TLS credential, wipes its private PKCS#8 bytes on
drop and has no Debug implementation. It is distinct from owner FHE/AEAD keys.
Authority provisioning and admission policy belong to the calling application.

`read_frame` and `write_frame` use versioned framing and a 64 MiB cap. The declared
length is checked before payload allocation. Connections have a two-second connect
timeout and 15-second read/write timeouts. These are transport bounds, not a
proof of a whole-process RAM or latency target. Windows accepted sockets are
explicitly returned to blocking mode before the TLS handshake.

There are no direct project dependencies, GUI, process supervision or database
operations. The [peer runtime](../peer-runtime/README.md) consumes this contract.
Run `cargo test --release --locked -p peer-transport` from the repository root.
