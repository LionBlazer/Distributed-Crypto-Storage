# Owner-authorized Registry200 Journal experiment

The historical local adapter passed 14 owning tests, 56 former controls and two
contracts; see its [validation record](../../../../PRIVATE-REGISTRY-LIFECYCLE-JOURNAL-VALIDATION.md).
This module now owns private preparation and PUBLIC NONSECRET scenarios for the
extracted [registry200-journal](../../../../../../crates/registry200-journal/README.md)
application and [registry200-proof](../../../../../../crates/registry200-proof/README.md)
verifier. The real-peer control route is covered by its
[validation record](../../../../REGISTRY200-PEER-CONTROL-VALIDATION.md).
It grants no live SQL, controller possession, global
freshness, MVCC, writer fencing or finality.

The owner-side builders consume the real
[version-journal](../../../../../../crates/version-journal/README.md) transition API.
The historical [Registry112 adapter](../../private_journal/README.md), profiles and
codec retain their separate meanings.

`RegistryVerifier` pins an `Application` and independently supplied genesis. Before
SDK verification it checks exactly two sorted source/control shards, unchanged
complete encrypted source heads, exactly one control compare-and-swap, the actual
parent, sticky enrollment and canonical Request200. It reconstructs the typed
Expected from that parent and verifies both original Source and child proofs
through the existing Source-first wire verifier. It never runs the plaintext
state machine. A verified unchanged registry root is evidence only: WAIT and
NOWAIT cannot append or manufacture a changed control head. Failed Commit resolved
as EndAbort is a successful mutation and remains appendable.

The ordinary Journal checks the owner Ed25519 signature over the complete request,
update and proof before calling this verifier. Calling the callback directly does
not establish authority. Every first accepted transition body verifies the real proof pair; every durable
reopen re-verifies all stored transition pairs. Exact already accepted block resubmission follows the
core idempotent path without another callback. Valid fork bodies remain evidence
under their original parent; client `Freshness` resolution is a separate policy.

## Stable application and request

The shared [control module](../../../../../../crates/registry200-journal/src/control.rs)
owns the application/Pending/Active domains. Application pins network,
database/key domain, both shard IDs, complete original source heads, C_key and the
actual wire contract fingerprint (both roles, output counts, profiles and resource
limits). It excludes genesis, query, C_open and C_cmd. Pending therefore exists
before genesis without a fixed point. Active depends only on application,
enrollment and Registry200 root; query, parent and nonce cannot disguise a no-op.

The shared [request module](../../../../../../crates/registry200-journal/src/request.rs)
owns the exact 2716-byte encoding: magic/tag/reserved bytes, eight
32-byte fields (genesis, parent, application, nonce, query, enrollment, C_open,
C_cmd), then the complete 60-byte and 2384-byte source packets. Bootstrap requires
zero C_cmd. Digest limbs are canonical. A domain-separated preproof intent fixes
query from application, genesis, parent, nonce, enrollment and phase before
C_open and C_cmd exist. The final owner signature binds their completed values.
This authorizes an opaque private command commitment; it does not prove that AIR
parses public SQL text or that an enrolled controller signed the request.

`owner.rs` is a prover-side builder. `ValidatedParent::read` is an exact known
validated protocol-parent context, not a confirmed or globally fresh client token.
`Inputs::transition` first matches the externally retained private Registry200
opening and salt to the actual parent C_old and enrollment, then computes C_cmd
and enters proof generation. It cannot replace C_old with a fixture-derived root.
The fixture encrypts source data once; each command changes only query/C_open,
retaining the same key, packets, plaintext witness and source heads. Private state
and salts remain owner inputs. Durable reopen restores public heads/proofs, not
those hidden openings; their secure persistence and recovery remain open work.

## Bounds and owning scenarios

The core `Body::encode` enforces the unchanged complete 32 MiB body limit, including
request, update and proof. The existing wire policy remains unchanged. A 2716-byte
request and one control update use exactly `117 + 2716 + 456 + proof_bytes` bytes.
No new partial proof-cap wrapper or larger Journal quota is introduced.

The public nonsecret fixture streams each proof pair into a signed Body, appends,
and drops temporary proof/encoding objects. The preserved local `prove private-lifecycle-journal` gate executes
Bootstrap plus seven transitions: Begin, Savepoint, Acquire, RollbackTo, Release,
FailCurrent and End with Commit intent resolved as Abort. It then appends one
empty confirmation block, drops the durable owner, and reopens/reverifies all
eight proof pairs. After the public fixture setup, the timer covers this entire local lineage and reopen;
it does not measure peer-only encrypted SQL execution. Printed body sizes are
actual full encoded Bodies, not estimates from proof-component sizes.

The prior local validation ran fourteen owning tests covering preserved lock upgrades, failed-frame
recovery, sparse-mask inter-owner SKIP with OFFSET, genuinely proved WAIT/NOWAIT
no-op rejection, full compaction and ID non-reuse, signed tampering, sticky source
and enrollment, stale CAS, detached branches, exact duplicate retry, canonical
body/request bounds and quota exhaustion. The quota case mines distinct valid
sibling headers for one genuine body under its original parent/genesis; every new
sibling re-verifies the proofs before resource rejection. It checks unchanged
validated state, accounting and disk after that rejection.

Only two public bootstrap/Begin bodies are cached for tests, not a long proof
history or verification authority. Longer scenarios are separate and streamed.
The unchanged Journal quota is 256 MiB and retains complete bodies: continuous
unbounded transaction history is not supported. Checkpoint/compaction protocols,
private-owner-state durability, controller delegation and integration with fresh
agreed live SQL remain required. Payload accounting, decoder slots and disk bytes
are distinct from observed process RAM; actual process observations and complete disk framing are recorded in the linked
validation report; they do not establish a whole-peer resource bound.

From the repository root:

```powershell
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security private-lifecycle-journal
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove private-lifecycle-journal
```

Security mode produces three analytical individual-proof reports (canonical Source,
new Bootstrap and Transition). It creates no trace, proof or durable append and
makes no composed 128-bit claim. The individual fixed assessment uses the shared
[proof library](../../../../../../crates/registry200-proof/README.md) and the
experiment Kind [backend](../../../../src/backend.rs); canonical storage commitments belong
to [compact-store](../../../../../../crates/compact-store/README.md).


## Registry200 original-row encoding

A test-only consumer now takes an actual accepted owner-signed Bootstrap/Begin/Acquire history through exact SQL binding, original proof-pair decode and fresh three-proof encoding evidence verification. Production Journal admission and Body/history quotas are unchanged. See the
[validation record](../../../../PRIVATE-REGISTRY-LIFECYCLE-ENCODING-VALIDATION.md).


## Two-process control consumer

The concrete verifier/control/request implementation now lives in
[registry200-journal](../../../../../../crates/registry200-journal/README.md).
This module owns only private preparation and PUBLIC NONSECRET scenarios.
peer_control.rs uses the shared OS-process supervisor without a dummy BFV object,
explicit 512 MiB participant quotas and unchanged 32 MiB Body/256 MiB Journal limits.
It generates four actual signed Source+Lifecycle bodies, transfers real mined
headers/bodies between two OS peers, observes durable persistence before losing an
ACK, retries exact retained bytes, reopens BOTH peers, fetches/re-verifies their actual histories, and exercises a valid
same-root sibling/reorganization. Successful proofs do not make a historical
Acquire current after End or a losing branch fresh.

After Root builds the real daemon, set DCS_PEER_EXE to its absolute path.
The new exact owning test is
opening::registry_lifecycle::journal::peer_control::tests::actual_two_os_peers_verify_sync_reopen_retry_and_reorganization.
The explicit CLI is:

~~~powershell
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry200-peer-control $env:DCS_PEER_EXE
~~~

The test is not skipped when the executable is missing. The CLI full timer includes
fixture generation, proof production, all RPC/sync/reopen/fork/EOF work.
owner_generation_ms covers the four actual outer transition producer calls;
transition_generation_calls counts those invocations, not primitive STARK proofs.
Application I/O counters are snapshots before Shutdown/EOF, excluding TLS/OS and
bootstrap framing; they are not total wire/process traffic. Public body sizes/PIDs
and process lifecycle are recorded in the
[two-peer validation report](../../../../REGISTRY200-PEER-CONTROL-VALIDATION.md),
which states their measurement scope. Private owner openings remain outside peers.
No SQL, writer, controller-possession, MVCC or global finality grant is made.
