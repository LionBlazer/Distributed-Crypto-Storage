# Concrete Registry200 finality over TLS

`peer-runtime::finality` now runs the existing concrete
[Registry200 finality owner](../crates/registry200-finality/README.md) through
actual bounded TLS. One actor owns its signer, Journal and floor; the relay uses
persisted signed inputs and sequential original-Body/QC catch-up. It invokes the
real owner/Source/Lifecycle verifier before votes, imports and recovery. No
endpoint status, decoded DTO, hash or TLS identity substitutes for those checks.

`FinalityServer::bind` consumes independently pinned, already-owned finality
state, trusted listener/neighbor configuration and the exact `ProofGate` cloned
from the owning `PeerServer`. This extracts the existing heavy-work permit into
one shared RAII implementation. No RPC can supply a timer, alternate verifier,
next context or accepting flag. Cancellation stops sockets and joins ongoing
proof work before releasing the signer. The [module contract](../crates/peer-runtime/src/finality/README.md)
records the fixed control, connection and Body bounds.

The client-side `Follower` has no validator signing key. It checks both the real
application and actual quorum under independent Binding, Genesis and Rules pins,
one slot at a time. Duplicate checkpoints still reverify their actual Body and
QC. `VerifiedCheckpoint` records this in-memory evidence; it neither establishes
the globally freshest head nor authorizes a SQL result or row lock.

## Catch-up collision found by independent review

The first implementation both pushed to a lagging neighbor and pulled from an
ahead neighbor. Each path held its own single Body lease across the RPC. Two
honest peers could hold both leases and receive Busy from each other repeatedly
on the same retry cadence. Native success in a larger topology did not disprove
that symmetric schedule.

Checkpoint transfer is now pull-only. The ahead relay returns without acquiring
a Body lease; the lagging relay fetches the exact original block and durable QC.
This requires directed reachability from a lagging peer to an up-to-date provider
through its configured neighbors. Weak connectivity or a one-way push link does
not provide that contract. Same-slot signed-input relay still transfers a missing
candidate when requested. No safety, proof or quorum condition was relaxed.

The regression starts two actual TLS actors at slots two and one, using a real
Empty Body and genuine three-of-four QC. It holds the exact ahead server's Body
lease and starts both relay passes behind a barrier. The ahead pass must succeed
without pushing; the lagging pass observes Busy. After release, the lagging peer
imports the actual Body/QC without owner resubmission, and a fresh independent
Follower verifies that exact header. The old push branch deterministically fails
the ahead-pass assertion. Only test-scoped private resource/handle accessors were
added; the production API was not widened.

## Executed validation

Windows/MSVC Rust 1.99.0, release/offline/locked, native CPU, Cargo/Rayon threads 2:

```text
cargo test --release --offline --locked -p peer-runtime -p registry200-finality -- --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test private_product -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p peer-runtime -- --test-threads=1
cargo clippy --release --offline --locked -p peer-runtime -p registry200-finality --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

Final coverage totals 94 peer-runtime cases, seven finality adapter cases, five
ownership compile-fail examples and four existing OS-peer rejection/cancellation
cases: **110 passed**. Two unrelated opt-in filesystem-I/O cases and the expensive
full private-product positive OS test remained ignored. That earlier
[full private-peer measurement](private-where-peer.md) was not repeated here.
Strict Clippy, Core default-member compilation, formatting, requirements mirror
and local documentation links passed. No package version or external dependency
was added: only seven direct `peer-runtime` edges to existing locked packages.

The four-actor TLS case uses one test process. It observes 2+2 no-quorum waiting,
joined restart/heal, three-of-four progress, offline catch-up, unauthorized-owner
rejection and remote-timer rejection. The genuine application case separately
rechecks owner-signed Source/Lifecycle Bootstrap/Begin/Acquire/End Bodies and
actual QCs with a fresh keyless follower after private inputs are dropped.
The four OS rejection cases launch four successive real daemon processes;
they are not a simultaneous four-process finality deployment.

The initial full suite took 171.640 s including 50.43 s compilation; peer runtime
was 25.76 s and adapter runtime 94.35 s. After the liveness correction, peer-runtime
and its ownership examples passed again in 67.710 s including compilation
(55.41 s runtime, 0.18 s doctests). The original adapter and OS-case code paths
were unchanged; only finality/client.rs, server.rs and tests.rs differ from the
initial full-suite snapshot. OS-negative validation took 48.760 s including
compilation, with 3.39 s actual test runtime. A failed test compilation initially
used private `Context::vote`; its fixture now uses the public `VoteContext` with
the exact public domain. No production visibility was widened. Failed receipts
are retained separately.

The ignored full-suite source manifest
`.local/network-finality-native-r1/source.json` (1448 files) has SHA256
`007DF623C3A80C9771E88C75BAAA7CE617C4EA53A61DF11E0EEF8F2F896D3917`;
final `.local/network-finality-native-r3/source.json` has SHA256
`BDFC412862267778A45800F7C0CB25F9D81C2884D506803DF2F4ADB3F3C7ED4A`.
All 1448 final raw files matched after tests and before these documentation
updates; all but the three named liveness files match the full-suite snapshot.
The source-only donor21 aggregate was
`6EBFA065AEC5B0B4DF077ADF9EFE3607CD6CE480E0E78BA80EDDE1707C9447A1`.
Root formatted it, updated deprecated AtomicUsize syntax for Rust 1.99, and added
the reviewed liveness correction and regression.

The nominal 100 ms observer captured 1122 samples across the full suite, maximum
gap 583.334 ms. Sampled and OS-reported peak WS were 1,030,930,432 B; maximum
private bytes 1,028,206,592 B. Final peer-only validation recorded 523 samples,
maximum gap 424.497 ms, WS 277,278,720 B, private 273,125,376 B and OS peak WS
277,299,200 B. OS-negative validation captured all four daemon PIDs over 228
samples, maximum gap 380.497 ms. No sampled 1792 MiB fuse or runner-budget abort
occurred. These observations are not a whole DCS/FHE memory or latency guarantee.

Full-suite stdout/stderr SHA256:
`A3248048A6AD2CA7D9277EA9A9E6DCD0F69FED3A27EAAC7FB814D252B636CED7` /
`64E66D3A91E229BE74252FE7E9FABD0485C65418AFF64113671108C0E1673FDB`.
Final peer-only stdout/stderr:
`B266EAA46184101E60905741F5D50DEB19272C4B104840FEEF8FD43E67246FBC` /
`EE279D2609E21F2E31BD55D97DD6BB90477DD38E914AB9BD7512AD44C666E727`.
OS-negative stdout/stderr:
`907ED4C6D781F8527FE808C2CD82694953BE687EA7BAAF1F4FC06B85474FB9AA` /
`14F671F7DB5ABBC9B0622BD855F2985A55282940B69236E1458124ADE1BFF801`.

## Remaining application integration

This record measures the explicit legacy original-app adapter. The subsequent
[participant-host stage](participant-finality-host.md) integrates typed participant
quota paths and daemon bootstrap and passes a four-independent-OS control gate.
Active custody ownership in that host remains separate work. The original
application cannot admit the larger hidden-predicate/FHE evidence graph;
a new closed JointApp, retained complete proof graph and actual fresh-head barrier
are required before enabling SQL locks. Permissionless work admission, safe roster
activation/epochs, owner key and pending-state recovery, complete SQL coverage and
composed cryptographic security also remain open. Existing SQL rejection guards
are unchanged.
