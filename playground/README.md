# FHE playground

A native **egui / eframe** client and manager for local FHE experiments. This crate
owns the test UI, presets/fixtures, a local owner/manager, and an in-process
transport adapter. [sql-plan](../crates/sql-plan/README.md) owns SQL parsing and
typed plans independently of the GUI and FHE backend.
It composes [compact-query](../crates/compact-query/README.md) for compact authenticated
storage, an owner-assisted encrypted age index, real FHE projection/aggregation/inserts/updates and
compact writeback; [compact-store](../crates/compact-store/README.md) supplies the page
limits, [replica-store](../crates/replica-store/README.md) places related ciphertext images
together, and [peer-protocol](../crates/peer-protocol/README.md) owns connection/message
state. These libraries are independent of the GUI and simulation clock. This is an experiment, not a production distributed database.

The dependency direction is playground → core libraries. `LabEngine` remains
here because it owns the complete local test deployment and owner-only inspector
rows. `fixtures.rs` and `presets.rs` own test data and editor shortcuts; they are
not imported by core. GUI/worker and deployment tests stay here; parser behavior
tests live with sql-plan. The architecture test rejects reverse dependencies.

## Launch

From the [workspace root](../README.md), with Rust **1.99 or newer**:

```sh
cargo run --release --locked -p fhe-playground
```

An optimized build is required because FHE is expensive. The GUI uses the OpenGL
renderer and bundled fonts; no web server or browser is involved. The first build
compiles GUI dependencies. Opening the window starts a public four-row `demo`
database with three simulated peers; key generation runs in the background.

In **Zed**, run `task: spawn` from the command palette and choose
**FHE: Open GUI playground**, defined in [`.zed/tasks.json`](../.zed/tasks.json).
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
the network, network settings or an opened node inspector. Drag their divider to resize. Buttons,
tabs, inputs and node cards have distinct hover, pressed, focus and disabled states.
Workspace, results and inspector tabs use adjoining flat surfaces on a shared
baseline, with the active tab joined to its content. Network and Settings stay
pinned while inspector tabs scroll horizontally; closing stays inside each tab.

- **SQL:** select a client, write a statement, then use **Run** or **Ctrl+Enter**.
  Presets are grouped as Read rows, Filter rows, Summarize, Insert and Update,
  starting with `SELECT *`. They only fill the editor. The shortcut applies to the SQL editor, never a
  focused peer setting. Results/history retain the originating client identity.
  With no clients, SQL submission is disabled.
- **Results:** start at half the window height. Drag the upper edge to
  grow or shrink the pane; the editor retains usable space. Results and output
  scroll across the full pane, with the vertical scrollbar at its right edge.
- **Data:** edit typed draft cells, add/delete rows, or use CSV. Fixtures only fill
  the draft. **Create / replace** explicitly applies it with fresh keys; validation
  errors explain why creation is disabled. Unapplied edits survive queries.
- **Network:** right-click empty space to add a peer or client; right-click a node
  to delete it or change availability. Click a client to use it. Double-click a node
  to open its own inspector tab. Tabs share one horizontal, scrollable strip with
  an inset close cross; middle-click also closes an inspector. Closing the active
  tab selects its neighbor, or Network when no inspectors remain. The inspector edits a peer's name, storage quota
  and link delay; **Save settings** applies changes. Its shard rows come from the
  owner's fixture, while the peer evaluator holds ciphertexts. Cards show charged
  physical storage against quota, plus useful payload and actual stored row count.
  Hover for separate data/index/replica-metadata bytes and current/stale copies;
  shared keys, Merkle caches and temporary RAM are outside this storage bar.
- **Settings:** the pinned tab beside Network contains **Min copies** and current
  replica health. It uses the existing serialized local-manager command; targets
  change only after worker confirmation. This is local prototype policy, not an
  implemented signed/agreed network contract. Speed and pause stay on the graph.
- **Back / Forward:** return between SQL/Data and opened network/inspector views
  using **Alt+Left / Alt+Right** or the mouse's back/forward
  buttons. New navigation after Back replaces the forward branch. Deleted nodes
  and closed inspectors are skipped; navigation preserves editor drafts and camera.
  Navigation fires on press, once per press; holding a side button cannot pan the
  graph. Moving through history does not change the selected SQL client or execute SQL.
- **Map / Matrix / Auto:** all modes use the same actual connection and packet
  snapshot. Auto uses a matrix for dense graphs; each undirected connection occupies
  two mirrored cells, while packet activity is directional (row sends to column).
  Hover a cell for endpoint names and in-flight messages. The map shares geometric
  lanes for dense links; selecting/hovering a node highlights its individual paths.
  These lanes are drawing conventions, not transport relays. No connection is
  removed to improve the picture. See [layout research](../docs/graph-layout.md).
- **Camera / time:** pan with left/right/middle drag and zoom the map; a right-click
  without dragging opens the context menu. Nodes, routes and background dots share
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

Peer IDs remain stable when a middle peer is removed. New databases start in fixed
logical-shard custody with a minimum of one copy; **Min copies** adjusts the target.
New peers start empty; removal drops their real ciphertext copies. The owner
fixture cannot recreate a lost shard. Lowering the minimum retains existing copies;
**Create / replace** explicitly creates a new database from the owner's draft with
fresh keys. Ordinary topology changes do not regenerate keys or encrypted data.

Replica reads select one current online executor per logical shard, using configured
link delay and stable IDs. INSERT/UPDATE stage new data/index images on all online current
holders; offline versions become stale and cannot answer current queries when they
return. Missing current shards reject the whole statement. **Failure domain** in
each inspector declares correlated placement; repeated labels count as one domain.
The inspector separates actual copy status from the current owner-fixture row view.

Automatic local repair runs once after relevant changes, while idle, unpaused and
after actual peer routes have formed. It copies authenticated ciphertext pairs from
survivors and reports completion or failure in history. **Repair replicas** in the
graph context menu retries manually. This local copy step does not model full wire
transfer or bandwidth, and does not invent packet animations. See the
[replicated SQL model](../docs/replicated-sql-prototype.md) for its failure limits.

Quotas cover canonical encrypted data plus the complete encrypted index and its
headers (1 KiB..64 MiB), plus 16 bytes of replica record metadata per physical
data/index pair. They exclude
BFV working memory, shared keys or rebuildable in-memory Merkle hashes. The node
inspector shows data and index bytes separately. Creation, repartitioning, profile edits and
inserts/updates reject overruns without partial writes. Peer delay (0..1000 ms) belongs to
the virtual transport; it is not measured ping. Query wall time includes delivery,
index selection, fresh encrypted selected byte/COUNT weights, request/output serialization, FHE evaluation and owner decryption; per-shard query timing excludes virtual delay.
Loss of every current online copy of a logical shard rejects reads/updates without
silently omitting records.

The fixture editor is the owner's plaintext view. Peer evaluations receive only
opaque ciphertext inputs and evaluation material. The fixture is decrypted from actual staged compact ciphertexts after successful
inserts/updates for further editing; query answers come from FHE evaluation, not a
plaintext SQL fallback. Unapplied draft edits are preserved when a live SQL update
finishes. A failed rebuild preserves the old database.

## SQL subset

The only table is `records(age u8, amount u16)`. Keywords are case-insensitive;
whitespace around operators and a trailing semicolon are optional. Supported forms are:

```sql
SELECT * FROM records;
SELECT age, amount FROM records WHERE age >= 18 LIMIT 20;
SELECT amount, age FROM records WHERE age BETWEEN 18 AND 42;
SELECT age FROM records LIMIT 10;
SELECT amount FROM records WHERE age = 18;
SELECT COUNT(*) FROM records;
SELECT SUM(amount) FROM records WHERE age >= 18;
SELECT COUNT(*), SUM(amount) FROM records;
SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age = 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age < 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age <= 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age > 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 AND 42;
INSERT INTO records (age, amount) VALUES (18, 10);
UPDATE records SET amount = amount + 5 WHERE age >= 18;
UPDATE records SET amount = amount + 1 WHERE age BETWEEN 18 AND 42;
UPDATE records SET amount = amount + 1;
```

Age literals must be in `0..=255`, deltas in `0..=65535`. BETWEEN includes both
endpoints; its AND is part of that one predicate, not general conjunction support.
The planner normalizes operators to inclusive age bounds without unsigned wrap.
Omitting WHERE selects all rows. Empty aggregates return zero for each requested
field; SQL NULL semantics are not implemented.

Row SELECT supports `*`, `age`, `amount`, `age, amount` and `amount, age`.
The existing owner-online input preparation authenticates the exact encrypted age
index and selected data pages, then freshly encrypts the original age/amount fields
and a projection/active mask. The peer performs BFV ciphertext-by-ciphertext masking
and relinearization, returning encrypted row values and presence markers. Only the
completed encrypted response supplies the client result table; the inspector fixture
is never a query source. This is genuine homomorphic projection under the explicit
exact-index contract, with no cryptographic computation proof. Returned plaintext
belongs to the client. Optional `LIMIT 0..=128` applies after
complete indexed selection and global ordering; it is an output limit, not a cap on
index work or a reason to omit unavailable shards. No ORDER BY is implemented.
Standalone COUNT and SUM use the existing genuine BFV aggregate operation and
return only the requested field; replicas never multiply rows.

`age < 0`, `age > 255` and reversed BETWEEN bounds are constant false for the public
u8 domain. The SQL planner folds these without inspecting any row: reads return
an empty row table or zero aggregate and updates succeed without changing either
head, owner rows or revision.
`Updated.committed` reports a successful statement, not a changed-row count. Normal
database, peer availability and transport checks still apply. These folded cases do
not evaluate FHE and carry no FHE timing claim. Every potentially matching range,
including a valid range with no actual matches, follows authenticated exact-index
selection and the appropriate BFV operation.
Single-row INSERT supports literal values in `(age, amount)` order, with that
column list optional. It chooses the smallest logical shard and sends
independently encrypted original rows and the new row to the public-only evaluator.
The peer rotates the encrypted incoming row into place and adds the relation.
The owner decodes that output, checks every old/new value and grows only that
shard's compact data/index under the same keys. Online current holders receive the
new images; offline holders remain stale. Quota failure or cancellation publishes
nothing. The whole laboratory database remains bounded to 128 rows.

The entire statement is parsed, with a 4 KiB limit. Unsupported projections,
operators, clauses, aliases, comments, quoted identifiers, and multiple statements
are rejected. CREATE/DELETE, CREATE INDEX, joins and transactions are not supported
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
Taking a peer offline preserves its local ciphertexts. Removing one drops its
copies; local repair can use only surviving current ciphertext.
This models declared crash/offline events, without proving malicious availability.

The database, keys, drafts, and history are ephemeral and are never saved. Closing
the app loses the experiment. Results remain **unverified**: FHE confidentiality is
not proof of correct, complete, fresh execution by malicious peers. The cryptographic
limitations and measured costs of the underlying implementation remain as described
in [compact-query](../crates/compact-query/README.md). Owner-side update checking repeats selected plaintext work and is not a succinct single-peer computation proof.

Library entry points include `parse_sql`, `Predicate::age_range`, `LabEngine::create`, `create_with_peer_ids`,
`repartition`, `set_replication`, `set_failure_domain`, `repair_replicas`,
`execute`, `prepare_query`, `commit_prepared`, `discard_prepared`,
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

The BFV owning library is [bfv-query-core](../crates/bfv-query-core/README.md). Its inherited
profile is experimental and independently unvalidated for security/noise/CCA.
Initial BFV integration release/locked/offline validation passed all 80 headless GUI/SQL/worker tests (one
preview-export test remains ignored). The finite public 128-row workload runs all 16
cases three times on1/3/16peers plus three late-overflow controls:147 exact full
operations, zero observed >500ms, maximum 383.8544ms. This measures the visible local
LabEngine boundary with setup/virtual network/rendering/proofs excluded; it is not a
general SLA or privacy/security claim. These historical workload timings predate
the added strict/BETWEEN grammar. See the [integration report](../docs/experiment-bfv-gui-integration.md)
for full timer scope, keys, native memory, canonical sizes and source/raw hashes.

```sh
cargo run --release --locked -p fhe-playground --example bfv_sql_workload -- 3
```

`LabEngine::backend_info_for_experiment` exposes public profile/setup counts and the
owner secret serialization COUNT only; `peer_heads_for_experiment` exposes opaque
commitment copies for failure-model checks. Neither returns secret key bytes.
