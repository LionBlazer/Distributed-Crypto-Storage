# FHE playground

A native **egui / eframe** client and manager for local FHE experiments. This crate
owns the test UI, a small SQL frontend, and an in-process transport adapter.
It composes [compact-query](../compact-query/README.md) for compact authenticated
storage, an owner-assisted encrypted age index, real FHE aggregation/updates and
compact writeback; [compact-store](../compact-store/README.md) supplies the page
limits, and [peer-protocol](../peer-protocol/README.md) owns connection/message
state. These libraries are independent of the GUI and simulation clock. This is an experiment, not a production distributed database.

## Launch

From the [workspace root](../../README.md), with Rust **1.99 or newer**:

```sh
cargo run --release --locked -p fhe-playground
```

An optimized build is required because FHE is expensive. The GUI uses the OpenGL
renderer and bundled fonts; no web server or browser is involved. The first build
compiles GUI dependencies. Opening the window starts a public four-row `demo`
database with three simulated peers; key generation runs in the background.

In **Zed**, run `task: spawn` from the command palette and choose
**FHE: Open GUI playground**, defined in [`.zed/tasks.json`](../../.zed/tasks.json).
This Windows task uses the built-in `powershell.exe` and `rustup which cargo` to
select the active Rust toolchain rather than a different `cargo` executable earlier
on PATH. The command runs directly in the task shell, without nested `-Command`
arguments, and preserves Cargo's exit code. PowerShell 7 is not required.
It runs at the workspace root with a local `.local/cargo-home` cache, saves buffers,
and allows one GUI task instance at a time.
After editing the task definition, select it again via `task: spawn`; rerunning an
old terminal task may reuse its previous command.

## Explore

The left pane switches between **SQL** and **Data**. The right pane always contains
the network or an opened node inspector. Drag their divider to resize. Buttons,
tabs, inputs and node cards have distinct hover, pressed, focus and disabled states.

- **SQL:** select a client, write a statement, then use **Run** or **Ctrl+Enter**.
  Presets only fill the editor. The shortcut applies to the SQL editor, never a
  focused peer setting. Results/history retain the originating client identity.
  With no clients, SQL submission is disabled.
- **Data:** edit typed draft cells, add/delete rows, or use CSV. Fixtures only fill
  the draft. **Create / replace** explicitly applies it with fresh keys; validation
  errors explain why creation is disabled. Unapplied edits survive queries.
- **Network:** right-click empty space to add a peer or client; right-click a node
  to delete it or change availability. Click a client to use it. Double-click a node
  to open its own inspector tab. The inspector edits a peer's name, storage quota
  and link delay; **Save settings** applies changes. Its shard rows come from the
  owner's fixture, while the peer evaluator holds ciphertexts.
- **Map / Matrix / Auto:** all modes use the same actual connection and packet
  snapshot. Auto uses a matrix for dense graphs; each undirected connection occupies
  two mirrored cells, while packet activity is directional (row sends to column).
  Hover a cell for endpoint names and in-flight messages. The map shares geometric
  lanes for dense links; selecting/hovering a node highlights its individual paths.
  These lanes are drawing conventions, not transport relays. No connection is
  removed to improve the picture. See [layout research](../../docs/graph-layout.md).
- **Camera / time:** pan and zoom the map; nodes, routes and background dots share
  world coordinates. Double-click empty space or use its **Fit view** menu item to
  fit the map. **Speed** and **Pause** control virtual message delivery independently
  of peer delay and FHE CPU computation. Pausing does not stop an already running
  cryptographic evaluation; its response still waits for transport to resume.

New nodes initially have no connections. Address discovery schedules actual
Ping/Pong/Ack deliveries, and a connection appears only when both endpoints finish
the handshake. The current adapter establishes all peer/peer and client/peer links;
clients do not connect to other clients. It does not choose a sparse overlay.
Requests must reach every required shard before evaluation starts, and responses
must arrive before committing an update. Deleting the requesting client or a
required peer revokes routes and cancels uncommitted work. A deletion racing an
already authorized commit is serialized by a commit permit.

Each request attempt is tied to its connection session. Duplicate requests and
unsolicited or repeated responses are rejected; cancellation packets follow virtual
delivery time and appear on the graph. Pausing can delay remote cleanup. The protocol
bounds outstanding requests and accepted jobs; transport IDs still have no
cryptographic authentication.

Peer IDs remain stable when a middle peer is removed. Adding/removing storage peers
explicitly repartitions rows under the local manager, preserving keys, revision and
surviving profiles. This is not automatic replication/recovery by the peer protocol.
Creation retains current topology and availability. Zero peers retains owner state
but cannot answer queries; failed repartition preserves the old encrypted data.

Quotas cover canonical encrypted data plus the complete encrypted index and its
headers (1 KiB..64 MiB), not
BFV working memory, shared keys or rebuildable in-memory Merkle hashes. The node
inspector shows data and index bytes separately. Creation, repartitioning, profile edits and
updates reject overruns without partial writes. Peer delay (0..1000 ms) belongs to
the virtual transport; it is not measured ping. Query wall time includes delivery,
index selection, fresh encrypted selected byte/COUNT weights, request/output serialization, FHE evaluation and owner decryption; per-shard query timing excludes virtual delay.
Offline required shards reject reads/updates, without silently omitting records.

The fixture editor is the owner's plaintext view. Peer evaluations receive only
opaque ciphertext inputs and evaluation material. The fixture is decrypted from actual staged compact ciphertexts after successful
updates for further editing; aggregate answers come from FHE evaluation, not a
plaintext SQL fallback. Unapplied draft edits are preserved when a live SQL update
finishes. A failed rebuild preserves the old database.

## SQL subset

The only table is `records(age u8, amount u16)`. Keywords are case-insensitive;
whitespace around operators and a trailing semicolon are optional. Supported forms are:

```sql
SELECT COUNT(*), SUM(amount) FROM records;
SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age = 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age < 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age <= 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age > 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 AND 42;
UPDATE records SET amount = amount + 5 WHERE age >= 18;
UPDATE records SET amount = amount + 1 WHERE age BETWEEN 18 AND 42;
UPDATE records SET amount = amount + 1;
```

Age literals must be in `0..=255`, deltas in `0..=65535`. BETWEEN includes both
endpoints; its AND is part of that one predicate, not general conjunction support.
The planner normalizes operators to inclusive age bounds without unsigned wrap.
Omitting WHERE selects all rows. Empty selections return `(0, 0)`; SQL NULL semantics
are not implemented.

`age < 0`, `age > 255` and reversed BETWEEN bounds are constant false for the public
u8 domain. The SQL planner folds these without inspecting any row: reads return
`(0, 0)` and updates succeed without changing either head, owner rows or revision.
`Updated.committed` reports a successful statement, not a changed-row count. Normal
database, peer availability and transport checks still apply. These folded cases do
not evaluate FHE and carry no FHE timing claim. Every potentially matching range,
including a valid range with no actual matches, follows authenticated exact-index BFV.
The entire statement is parsed, with a 4 KiB limit. Unsupported projections,
operators, clauses, aliases, comments, quoted identifiers, and multiple statements
are rejected. CREATE/INSERT/DELETE, CREATE INDEX, joins and transactions are not supported
as SQL; database creation and fixture replacement are GUI manager actions.

The BFV backend uses its owner-built authenticated encrypted age posting index for
complete exact equality/range selection and rejects every selected age mismatch.
The peer rotates/adds freshly encrypted byte/COUNT weights; it does not run a
redundant encrypted age comparator for this explicit exact-index operation. Peers observe selected addresses and cardinality. This
is an explicit experimental visible-access case; the final leakage policy is open.

Updates stage compact data/index copies for every shard. The owner decrypts and
locally checks selected FHE updates, reencrypts changed pages with fresh nonces,
and commits only after every shard passes. Overflow on any shard retains all
original shards. This is local atomic behavior under one manager, not a distributed
transaction or consensus guarantee. A committed update advances the local revision;
that number is not a network freshness certificate.

## Boundaries and verification

All peers, the owner, and keys live in **one process**. A network worker advances
virtual delivery while a separate compute worker serializes FHE jobs. BFV uses
one fixed Rows256 SIMD operation per shard, with no TFHE keys or row workers.
Evaluator clones share key allocation, so memory does not model
independent physical machines. Packets carry opaque references to local operations;
there is no TCP transport. The cryptographic backend actually serializes and decodes encrypted requests/results, but the virtual network does not yet model their byte-dependent transmission time.
Taking a peer offline preserves its local ciphertexts and does not model permanent
data loss, recovery, replication, or adversarial behavior.

The database, keys, drafts, and history are ephemeral and are never saved. Closing
the app loses the experiment. Results remain **unverified**: FHE confidentiality is
not proof of correct, complete, fresh execution by malicious peers. The cryptographic
limitations and measured costs of the underlying implementation remain as described
in [compact-query](../compact-query/README.md). Owner-side update checking repeats selected plaintext work and is not a succinct single-peer computation proof.

Library entry points include `parse_sql`, `Predicate::age_range`, `LabEngine::create`, `create_with_peer_ids`,
`repartition`, `execute`, `prepare_query`, `commit_prepared`, `discard_prepared`,
`snapshot`, SQL/fixture
helpers, and `DemoNetwork`'s node, delivery and snapshot operations. The binary owns
`worker` (composition/cancellation), `ui` (drafts, commands and views), and private
layout/routing/bundling modules. The reusable protocol owns handshake/message state;
it never imports the GUI, simulation speed or storage policy.

UI tests render egui in memory and observe its command channel. They exercise preset
selection without execution, focused SQL shortcuts, node context menus/inspectors,
client identity, independent topology/query completion, camera transforms, dense
connection preservation and discovery traffic. API/worker tests exercise real FHE,
quota/overflow rollback, stable peer removal, cancellation and transport commit gates.
They do not
open native windows, capture the desktop, or inject OS input. An opt-in CPU rasterizer
exports actual egui meshes and font textures as PPM images of public fixtures to
the ignored `.local/gui-previews` directory for offline visual review.

```sh
cargo test --release --locked -p fhe-playground --bin fhe-playground
cargo test --release --locked -p fhe-playground --bin fhe-playground export_ui_previews -- --ignored --nocapture
cargo test --workspace --release --locked -- --test-threads=1
cargo clippy --workspace --all-targets --release --locked -- -D warnings
cargo run --release --locked -p fhe-playground --example sql_workload -- 128 8 5
```

The sql_workload example exercises the actual SQL/manager boundary without opening a GUI: indexed point, duplicate-group and absent queries, then compact UPDATE. It emits public-fixture JSON timings and storage counters; network/proofs are excluded. Tiny tables may exceed 2x once fixed metadata and the encrypted index are counted.

The BFV owning library is [bfv-query-core](../bfv-query-core/README.md). Its inherited
profile is experimental and independently unvalidated for security/noise/CCA.
Initial BFV integration release/locked/offline validation passed all 80 headless GUI/SQL/worker tests (one
preview-export test remains ignored). The finite public 128-row workload runs all 16
cases three times on1/3/16peers plus three late-overflow controls:147 exact full
operations, zero observed >500ms, maximum 383.8544ms. This measures the visible local
LabEngine boundary with setup/virtual network/rendering/proofs excluded; it is not a
general SLA or privacy/security claim. These historical workload timings predate
the added strict/BETWEEN grammar. See the [integration report](../../docs/experiment-bfv-gui-integration.md)
for full timer scope, keys, native memory, canonical sizes and source/raw hashes.

```sh
cargo run --release --locked -p fhe-playground --example bfv_sql_workload -- 3
```

`LabEngine::backend_info_for_experiment` exposes public profile/setup counts and the
owner secret serialization COUNT only; `peer_heads_for_experiment` exposes opaque
commitment copies for failure-model checks. Neither returns secret key bytes.
