# DCS peer daemon

A standalone process hosting [peer-runtime](../../crates/peer-runtime/README.md)
through [peer-transport](../../crates/peer-transport/README.md). It has no playground,
GUI, local SQL simulator or owner FHE/AEAD secret dependency.

Build from the repository root:

```sh
cargo build --release --locked -p dcs-peer
```

The [single launcher](../../tools/launcher/README.md) also packages portable peer
and GUI executables with trusted AVX2/AVX-512 proof kernels. After reading its
bootstrap and before serving requests, the daemon initializes
`bfv_query_proof::initialize_backend` from the `proof-kernels` directory beside its
executable and reports the selected backend on stderr. CPU/OS detection runs once;
proof operations use the retained implementation. Standalone builds without
optional kernels use the linked portable engine. A present incompatible or damaged
selected kernel stops startup. Every variant preserves the same proof parameters.

Run `dcs-peer --state-dir PATH`. Before accepting connections, stdin must contain
one bounded JSON `peer_runtime::Bootstrap` frame encoded with the transport's
framing helper. Bootstrap supplies that peer's TLS identity, optional network CA, authorized
owner fingerprint, node ID, disk quota and listen address. Credentials belong in
private IPC or caller-managed secret storage, never CLI arguments, source control
or telemetry. Stdout emits one public JSON Endpoint after bind/lock succeeds;
subsequent operations use mutually authenticated TLS. Operator stderr reports
connection rejections without logging payloads or secret keys.

Local supervisors may opt into `--exit-on-stdin-close`. After the bootstrap frame,
stdin becomes a lifetime-only pipe: the parent retains its write handle without
sending more bytes. EOF, pipe failure or unexpected data terminates the entire
daemon, including an in-flight job. OS handle closure also works when the parent
crashes or is forcibly terminated and cannot run destructors. This deployment
option is used by playground; an independent daemon without it keeps running after
bootstrap EOF or the loss of a network client. It is not a peer-protocol heartbeat.

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

For a separate full-UPDATE RPC cost observation, set `DCS_TEST_RPC_PROFILE=1`
when running the existing genuine process scenario:

```powershell
$env:RAYON_NUM_THREADS = '8'
$env:DCS_TEST_PEER_THREADS = '8'
$env:DCS_TEST_RPC_PROFILE = '1'
cargo test --release --locked -p dcs-peer --test proved_sql proved_select_insert_update_survive_a_process_loss_and_journal_restart -- --exact --nocapture --test-threads=1
```

The test-only recorder attaches the existing public `RpcActivity` and `Trace`
callbacks and records only the UPDATE envelope. It retains at most 4,096 metadata
events and reports an explicit `truncated` flag. `rpc_observation=` JSON lines
contain peer ordinals, request IDs, operation names, monotonic offsets, actual
application-frame byte counts, elapsed time and success/failure. They contain no
payload, row, SQL, proof or credential. Output is emitted after the UPDATE; the
fixture's existing public SQL timing labels and all correctness assertions remain
unchanged. Unset the flag for ordinary latency samples.

Completed RPC elapsed time begins before wire serialization. Subtracting it from
the callback offset reconstructs an approximate start. Request-sent and reply-read
markers divide the call into encode/connect/write, combined peer/wire/read, and
response-decoding tail. These combined phases do not isolate peer STARK or disk
sync time. Gaps without a client RPC include local proof verification, staging and
request construction. Concurrent RPC intervals must be merged before attributing
wall time; summed RPC elapsed time can exceed the critical path. This observation
adds no daemon or library instrumentation and no timing-based pass/fail threshold.
