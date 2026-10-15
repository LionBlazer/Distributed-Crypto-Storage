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
framing helper. Bootstrap supplies that peer's TLS identity, optional network CA, authorized
owner fingerprint, node ID, disk quota and listen address. Credentials belong in
private IPC or caller-managed secret storage, never CLI arguments, source control
or telemetry. Stdout emits one public JSON Endpoint after bind/lock succeeds;
subsequent operations use mutually authenticated TLS. Operator stderr reports
connection rejections without logging payloads or secret keys.

The [playground](../../playground/README.md) generates independent self-signed peer
identities, starts each daemon hidden, supplies bootstrap over its private stdin
pipe and uses loopback endpoints. Empty `authority` selects permissionless TLS with
real self-signature/handshake verification and endpoint pinning. Other deployments
can supply their own credentials or explicit CA,
listen addresses and persistent directories through the same contract. This
bootstrap is local administration, not a voting roster or production discovery
protocol. Valid work and authorized transitions are verified independently of the
number of connected identities.

`tests/process_transport.rs` launches actual OS processes and tests distinct PIDs,
TLS authentication/pinning, real BFV outputs, direct peer copying, process loss,
restart from the same ciphertext directory, disk tampering, quotas and mandatory
proof rejection for the historical diagnostic API. `tests/proved_sql.rs` uses the
new Session with real STARKs and durable journals to accept SELECT, apply INSERT
and UPDATE, reject global overflow, survive process loss and reopen persisted
metadata. `tests/proved_faults.rs` checks damaged/missing replicas and unauthorized
administration/invalid publication. Fixtures are explicitly public; credentials and owner keys are
fresh and stay in memory. Child handles own cleanup; no unrelated process is
inspected or stopped. Generated ciphertext stays under ignored `.local/`.
