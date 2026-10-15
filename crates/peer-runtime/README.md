# Peer runtime

A process-independent service owning encrypted object files and a public-only BFV
evaluator. It has no owner secret key, plaintext row type, GUI or virtual clock.

| Direct project dependency | Responsibility |
| --- | --- |
| [peer-transport](../peer-transport/README.md) | TLS identities, endpoint pinning and bounded frames |
| [compact-store](../compact-store/README.md) | Canonical encrypted pages and exact-head integrity checks |
| [bfv-query-core](../bfv-query-core/README.md) | Public setup restoration and actual encrypted aggregate/projection/insert/update circuits |

`PeerServer::bind` locks one caller-provided directory and binds a TCP endpoint;
`run` serves it, while `spawn` returns a supervised in-process server handle.
The standalone deployment is [dcs-peer](../../apps/dcs-peer/README.md).
`RemotePeer` sends typed RPCs and reports complete application-frame byte counts,
request identity, elapsed time and success/failure. Those counts exclude TLS/TCP
headers and are not a bandwidth benchmark.

Objects are immutable and addressed by a hash of their complete encrypted bundle.
Only the configured owner's TLS identity can upload data/public setup, change
quota, configure neighbor endpoints, request copies or stop the service. Other
admitted certificate holders can probe, read opaque bundles and evaluate ciphertext.
The service never treats TLS authentication as an SQL computation proof.

Disk quota charges actual serialized bundle file bytes, including record/head
metadata. Atomic staged publication, a live directory lock, bounded startup import,
trusted data-head checks and bundle hashes detect missing/truncated/modified files.
The owner independently authenticates both encrypted data and index on import.
Public setups are separately reported and kept in RAM, at most two per process.
At most eight connections are admitted before TLS/frame allocation; FHE work is
serialized per peer. Object and frame limits are additional to disk quota.

`Copy` fetches an existing object directly from another authenticated peer and
stores identical ciphertext locally. It is an explicit owner-authorized action,
not an autonomous placement/consensus protocol. Configured neighbors send actual
TLS probes on wall-clock schedules; reachability changes only after real replies
or failures. `Status` reports PID, objects, application-byte counters, recent RPCs
and observed neighbor reachability. Certificate and observation metadata are public.

No object-deletion RPC is implemented. Network-wide durable commit, signed policy
agreement, membership/revocation consensus, malicious computation proofs, automatic
independent-domain repair and Internet NAT traversal remain unresolved. This
bounded service is a working transport/runtime stage, not the completed requirements.

The target permits peers to join without invitations. Current CA provisioning is
an explicit local deployment restriction, not an implementation of open membership.
Counting admitted identities is not a Sybil-resistant consensus rule.

Owning process tests: `cargo test --release --locked -p dcs-peer --test process_transport -- --test-threads=1`.
