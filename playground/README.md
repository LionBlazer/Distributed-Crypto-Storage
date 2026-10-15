# FHE playground

The native egui client/manager supervises real [dcs-peer](../apps/dcs-peer/README.md)
processes. It does not execute peer queries or synthesize packet delivery. The
owner's keys and SQL preparation live in [storage-client](../crates/storage-client/README.md);
each child owns its disk directory and public-only FHE evaluator.

## Launch

Use Rust 1.99 or newer, from the repository root:

```sh
cargo build --release --locked -p dcs-peer -p fhe-playground
cargo run --release --locked -p fhe-playground
```

Zed's **FHE: Open GUI playground** task builds both packages first. A manually
launched GUI looks for `dcs-peer` beside its own executable; `DCS_PEER_BIN` can
select an explicit binary. If it is missing, startup reports an error and never
falls back to an in-process evaluator or simulated network. Tests and exporters
never open a native GUI window.

## Network behavior and limits

Each peer starts as a separate hidden child process with a real PID, ephemeral TLS
identity, loopback listener and its own ciphertext directory under `.local/peer-processes/`.
Only that peer's TLS credential and public CA/owner authorization metadata cross
bootstrap IPC. FHE/AEAD owner keys never enter peer processes. The local certificate
authority is test deployment provisioning; it is not a live central relay.

Peer endpoints perform real mutual TLS probes. Graph/matrix links are recently
observed authenticated reachability, not a claim that a persistent socket is open.
Packet markers and logs represent actual complete RPC frames and peer observations;
failed connection attempts are not displayed as delivered packets. Byte counters
are application-frame payloads, excluding TLS/TCP overhead. Virtual Speed/Pause
and artificial link-delay controls are removed. Data/FHE time is wall-clock time.

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
- **Strict acceptance:** current peer output has no computation proof. A completed
  FHE query therefore reports a proof rejection, returns no accepted result and
  commits no SQL mutation. TLS, hashes and decryption are not substituted for
  requirements 11–13. Raw process tests validate ciphertext arithmetic separately.
- Results start at half the window height, resize from their upper edge and scroll
  at the pane's right edge. Output records real elapsed operations and failures.
- **Data** edits an owner draft. Create/replace sends encrypted initial data to peer
  storage. One previous database and its owner keys are retained in the current
  session; previous remote objects are not deleted. The runtime currently permits
  two public setups, so a third owner state is rejected before replacement.
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
Computation/completeness proofs, decentralized policy/head agreement, independent
failure-domain validation, NAT/discovery deployment and target-scale/resource
measurements remain unfinished.
