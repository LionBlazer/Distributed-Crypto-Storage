# FHE playground

The native egui client/manager supervises real [dcs-peer](../apps/dcs-peer/README.md)
processes. It does not execute peer queries or synthesize packet delivery. The
owner's keys and SQL preparation live in [storage-client](../crates/storage-client/README.md);
each child owns its disk directory and public-only FHE evaluator.

## Launch

Use Rust 1.99 or newer, from the repository root:

```sh
cargo run --release --locked -p dcs-launch -- playground
```

Zed's single **FHE: Open GUI playground** task runs the same launcher. It builds
portable applications and both x86-64 AVX2/AVX-512 proof libraries before opening
the GUI. Each process selects and validates its proof backend once at startup;
there is no CPU selector or feature detection on each query. Other architectures
use the SDK's compiled platform backend. See the
[launcher](../tools/launcher/README.md) for exact flags and artifact paths.

Add `--build-only` after `playground` to build and print artifact paths without
opening a window. The launcher uses `.local/target-playground/<host-triple>/release`
for both applications and its adjacent `proof-kernels/`. Zed keeps the launcher
itself in a separate `.local/target-launcher` to avoid nested build locks. A manually
launched GUI looks for `dcs-peer` beside its own executable; `DCS_PEER_BIN` can
select an explicit binary. If it is missing, startup reports an error and never
falls back to an in-process evaluator or simulated network. Tests and exporters
never open a native GUI window.

The packaged host remains portable. Acceleration changes no BFV or proof security
parameters, and a CPU without the optional x86 instructions uses the genuine
compiled baseline. The launcher does not use `target-cpu=native`. Packaging several
ISA variants does not establish a latency SLA.

## Network behavior and limits

Each peer starts as a separate hidden child process with a real PID, ephemeral TLS
identity, loopback listener and its own ciphertext directory under `.local/peer-processes/`.
Only that peer's TLS credential and public owner authorization metadata cross
bootstrap IPC. FHE/AEAD and journal authorization keys never enter peer processes.
Each participant and the owner generate independent self-signed TLS credentials;
bootstrap sets an empty authority and uses the transport's explicit permissionless
constructors. There is no manager-issued admission CA. Exact endpoint pins,
certificate self-signatures and TLS CertificateVerify signatures are still checked.

The live adapter uses `storage_client::Session` and explicitly pins a playground-only
work profile: initial target and work limit `[0x0f; 32]`, 1-second block spacing,
retarget interval 1024, 30-second future-time bound, one descendant confirmation,
4096 headers, 16 shards/updates, 32 MiB body/request/proof bounds and a 256 MiB
journal bound. The easy target and confirmation depth are **unvalidated test
parameters**, not a production security profile or a measured attacker budget.
Core libraries provide no easy-work default. Work weighting, ownership, proof and
freshness checks remain real under this explicitly selected test contract.

New live peer defaults use a 64 MiB disk quota so real proof/version journals fit;
explicit custom quotas and historical fixture defaults are preserved. The quota
covers physical encrypted objects and durable journal files. Node bars include
both, with the journal shown separately in the inspector. Public setup bytes are
reported separately as a serialized in-memory size; they are not disk usage or a
measurement of peak process RAM. The participant's disk quota can stop writes
before the contract's larger 256 MiB journal upper bound is reached.

Peer endpoints perform real mutual TLS probes. Graph/matrix links are recently
observed authenticated reachability, not a claim that a persistent socket is open.
The transport's `RpcActivity` callback supplies observed frame writes/reads while
SQL is still running, through a bounded UI queue independent of manager snapshots.
Failed connection attempts do not generate sent-frame markers. Peer-to-peer
observations come from peer status telemetry. Byte counters exclude TLS/TCP
overhead; receiving a frame does not establish proof validity.

**Trace speed** is a full-width 0–1 slider: zero freezes visual playback, one
animates an observation over 1.1 seconds. It never delays transport, FHE, proof
checks or results. Adjacent **Live** skips the pending visual tail and resumes at
100%; skipped snapshot IDs stay deduplicated. It does not replay SQL. Blue means
request, green means reply; optional amber health
checks include probes and status polling. Timelines are explanatory playback,
not measured packet travel. Deduplication prevents repeated snapshots from
restarting animation; the view retains at most 256 markers and reports visual
overflow. Data/FHE timing remains wall-clock timing.

Map defaults to selected-node connections and active observations; **All links**
is explicit. Filtering never changes the observed topology or protocol. Above
64 nodes, Auto/Map use at most 64 visual ID groups with search and virtualized
member lists. These are display groups, not consensus or storage clusters.
Matrix preserves all supplied connection pairs and paints only visible rows and
columns; it never allocates a dense N×N cell array. Headless rendering tests cover
10,000 public synthetic nodes, not a 10,000-process deployment. The live local
manager still caps owned peers at 16. The presentation follows the
[level-of-detail guidance](https://js.cytoscape.org/#performance) and
[display-only highlighting](https://v3.sigmajs.org/docs/advanced/data/) used by
established graph renderers; no JavaScript renderer is a dependency.

All managed peers run on one host and are therefore one failure domain. Arbitrary
domain labels cannot create independent failure tolerance. **Min copies** requests
physical copies through the owner's client; actual bytes travel directly from a
surviving peer to the target. This is explicit owner orchestration, not an autonomous
decentralized repair/consensus implementation. New peers start empty, and no lost
ciphertext is reconstructed from the editable owner fixture.

Normal manager teardown stops only children it owns. Stopping/restarting a peer
keeps its encrypted files and reloads public setup from the still-live owner. This
is not recovery after loss of the owner process. Owner keys are session memory;
complete owner/key recovery remains a separate unresolved requirement.

## Explore

- **SQL/Data** on the left, **Network/Settings/peer inspectors** on the right.
  Document tabs share one baseline; middle-click or their inset cross closes a
  peer inspector. Alt+Left/Right and mouse side buttons follow view history.
- Presets are ordered from SELECT through filters/aggregates to INSERT/UPDATE.
  They fill the editor; Run or Ctrl+Enter submits the actual encrypted operation.
- **Strict acceptance:** supported SELECT, INSERT and UPDATE operations use actual
  network FHE execution, computation/completeness verification and the validated
  confirmed version before returning results or publishing changes. Missing or
  invalid evidence is rejected; unsupported SQL reports an error. The live adapter
  never falls back to the historical `Database`, `LabEngine` or fixture answers.
  Live results have explicit verified/version metadata; historical renderer fixtures
  remain labeled unverified. TLS and decryption do not substitute for query proofs.
- Results start at half the window height, resize from their upper edge and scroll
  at the pane's right edge. Output records real elapsed operations and failures.
- **Data** edits an owner draft. Create/replace sends encrypted initial data to peer
  storage. One previous database and its owner keys are retained in the current
  session; previous remote objects are not deleted. The runtime currently permits
  two public setups, so a third owner state is rejected before replacement.
  The owner editor refreshes from authenticated encrypted network data through
  `Session::inspect_rows` after creation and mutations; it never supplies SQL answers.
  Disk counters include retained physical objects. Nothing implies durable owner
  recovery after the GUI/session ends.
- Right-click empty graph space to add peers or owner-client sessions; right-click
  a node to stop/remove it. Double-click opens the inspector, including the real
  PID, disk quota, actual serialized bytes and owner-only row inspection. Offline
  physical counters are explicitly labeled as last observed; they are never a
  fallback source for a query.
- Left/middle/right drag pans the camera, including its world-aligned grid.
  Dense networks can use the complete connection matrix; links are never removed
  merely to simplify the picture. See [layout research](../docs/graph-layout.md).

## Dependencies and verification

[peer-runtime](../crates/peer-runtime/README.md) owns real RPC/storage/FHE service;
[peer-transport](../crates/peer-transport/README.md) owns TLS/framing;
[storage-client](../crates/storage-client/README.md) owns the owner role;
[version-journal](../crates/version-journal/README.md) owns the explicit network
profile and confirmed-version reference types;
[bfv-query-proof](../crates/bfv-query-proof/README.md) owns computation proofs and
the process's one-time proof backend initialization;
[sql-plan](../crates/sql-plan/README.md) owns parsing. compact-query/compact-store,
replica-store and peer-protocol also remain dependencies of the historical local
`LabEngine`/`DemoNetwork` library and finite research examples. The live worker
imports neither local runtime, and core has no reverse playground dependency.
Those old experiments do not establish network guarantees. Historical measured
SQL integration is documented in the [integration report](../docs/experiment-bfv-gui-integration.md);
its timings are not measurements of the new network path.

```sh
cargo test --release --locked -p dcs-peer --test process_transport -- --test-threads=1
cargo test --release --locked -p fhe-playground -- --test-threads=1
cargo clippy --release --locked --workspace --all-targets -- -D warnings
```

The opt-in `process_backend::tests` require a built `dcs-peer` via DCS_PEER_BIN and
exercise actual GUI-backend child processes without a GUI window. The ignored
`export_ui_previews` writes explicitly public renderer fixtures, not query answers.
Production work/adversary calibration, independent failure-domain validation,
NAT/discovery deployment, complete SQL and target-scale/resource measurements remain
unfinished. Local process tests do not establish resistance to an eclipsed client
or a majority of adversarial work, nor globally newest data during a partition.
