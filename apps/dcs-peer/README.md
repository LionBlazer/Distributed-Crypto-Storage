# DCS peer daemon

A standalone process hosting [peer-runtime](../../crates/peer-runtime/README.md)
through [peer-transport](../../crates/peer-transport/README.md). It has no playground,
GUI, local SQL simulator or owner FHE/AEAD secret dependency.

Build from the repository root:

```sh
cargo build --release --locked -p dcs-peer
```

Run `dcs-peer --state-dir PATH`. Before accepting connections, stdin must contain
one bounded JSON `peer_runtime::Bootstrap` frame encoded with the transport's
framing helper. Bootstrap supplies that peer's TLS identity, network CA, authorized
owner fingerprint, node ID, disk quota and listen address. Credentials belong in
private IPC or caller-managed secret storage, never CLI arguments, source control
or telemetry. Stdout emits one public JSON Endpoint after bind/lock succeeds;
subsequent operations use mutually authenticated TLS. Operator stderr reports
connection rejections without logging payloads or secret keys.

The [playground](../../playground/README.md) provisions a temporary local authority,
starts each daemon hidden, supplies bootstrap over its private stdin pipe and uses
loopback endpoints. Other deployments can supply their own authority, credentials,
listen addresses and persistent directories through the same contract. This
bootstrap is enrollment configuration, not a distributed membership protocol.

`tests/process_transport.rs` launches actual OS processes and tests distinct PIDs,
TLS authentication/pinning, real BFV outputs, direct peer copying, process loss,
restart from the same ciphertext directory, disk tampering, quotas and mandatory
proof rejection. Fixtures are explicitly public; credentials and owner keys are
fresh and stay in memory. Child handles own cleanup; no unrelated process is
inspected or stopped. Generated ciphertext stays under ignored `.local/`.
