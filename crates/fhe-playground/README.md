# FHE playground

A native **egui / eframe** client and manager for local FHE experiments. This crate
owns the test UI, a deliberately small SQL frontend, and a logical peer simulation.
It depends directly on [fhe-prototype](../fhe-prototype/README.md) for encryption,
encrypted aggregation/updates, and compression. The core library does not depend on
the GUI. This tool is not a production client or a network protocol.

## Launch

From the [workspace root](../../README.md), with Rust **1.95 or newer**:

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

The SQL view follows the basic areas of
[DataGrip's query console](https://www.jetbrains.com/help/datagrip/query-consoles.html):
database tree on the left, editor on the right, and a resizable result/output pane
below. The Explorer includes object filtering, schema icons and type badges. The
editor has line numbers and SQL highlighting. A shared dark palette keeps these
views consistent with the data manager and network map.

- **SQL:** write a statement, then click **Run** or press **Ctrl+Enter**. The
  **Presets** menu only fills the editor; selecting a preset never submits a query.
  SELECT answers appear as a result row. Updates, errors, and history use **Output**.
- **Data:** edit typed cells in **Grid**, add/delete draft rows, or use **CSV** for
  bulk input. The settings sidebar contains the database name, schema and synthetic
  fixtures. **Create / replace** applies the draft with fresh keys; fixtures and cell
  edits never execute SQL or change the live database automatically.
- **Infrastructure:** select the client or a peer on the interactive map, pan/zoom,
  or use **Fit**. Direct client-to-shard routes highlight the worker's active peer.
  The directory and inspector show availability, compressed sizes and request times.
  The **Shard** inspector shows that peer's rows from the owner's fixture; peer
  evaluators still receive no plaintext. **Settings** edits name, compressed-storage
  quota and artificial request delay. **Add peer** opens a draft; **Add and repartition**
  applies it. The **Layout** menu adjusts the count in bulk, up to 16 peers.

Layout changes repartition live rows with existing keys, preserve the database
revision and existing peers' availability, and retain unapplied data drafts. New
peers start online. Layout slots determine peer IDs and round-robin placement;
shrinking a layout removes its last slots. Creation retains profiles from matching
slots but starts the replacement database's peers online. This is a local manager
operation, not peer discovery or data recovery over a network.

Per-peer quotas cover the compressed shard image, including its headers, with a
range of 1 KiB..64 MiB; they do not constrain TFHE working memory or key allocation.
Creation, repartitioning, profile edits and encrypted updates reject quota overruns
without partial changes. Artificial delay is 0..1000 ms per nonempty shard request.
It is applied on the worker and included in SELECT timings alongside FHE evaluation
and owner decryption; it is not measured ping. Offline required shards reject both
reads and updates; empty offline shards do not omit records.

Ctrl+Enter executes only on the SQL tab. Tab changes never submit operations. The
small status bar marks this as a local, unverified experiment; details are in tooltips.

The fixture editor is the owner's plaintext view. Peer evaluations receive only
opaque ciphertext inputs and evaluation material. The fixture mirrors successful
updates for further editing; aggregate answers come from FHE evaluation, not a
plaintext SQL fallback. Unapplied draft edits are preserved when a live SQL update
finishes. A failed rebuild preserves the old database.

## SQL subset

The only table is `records(age u8, amount u16)`. Keywords are case-insensitive;
whitespace and a trailing semicolon are optional. Supported forms are:

```sql
SELECT COUNT(*), SUM(amount) FROM records;
SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18;
SELECT COUNT(*), SUM(amount) FROM records WHERE age = 18;
UPDATE records SET amount = amount + 5 WHERE age >= 18;
UPDATE records SET amount = amount + 1;
```

Thresholds must be in `0..=255`, deltas in `0..=65535`. Omitting WHERE selects all
rows. Empty selections return `(0, 0)`; SQL NULL semantics are not implemented.
The entire statement is parsed, with a 4 KiB limit. Unsupported projections,
operators, clauses, aliases, comments, quoted identifiers, and multiple statements
are rejected. CREATE/INSERT/DELETE, joins, indexes, and transactions are not supported
as SQL; database creation and fixture replacement are GUI manager actions.

Updates stage copies of every shard and commit only after all encrypted overflow
checks and compression round trips succeed. Overflow on any shard retains all
original shards. This is local atomic behavior under one manager, not a distributed
transaction or consensus guarantee. A committed update advances the local revision;
that number is not a network freshness certificate.

## Boundaries and verification

All peers, the owner, and keys live in **one process**. The worker executes requests
serially away from the UI thread; TFHE uses two Rayon threads. Evaluator clones
share their key allocation, so memory does not model independent physical machines.
Taking a peer offline preserves its local ciphertexts and does not model permanent
data loss, recovery, replication, or adversarial behavior.

The database, keys, drafts, and history are ephemeral and are never saved. Closing
the app loses the experiment. Results remain **unverified**: FHE confidentiality is
not proof of correct, complete, fresh execution by malicious peers. The cryptographic
limitations and measured costs of the underlying implementation remain as described
in [fhe-prototype](../fhe-prototype/README.md).

Library entry points are `LabEngine::create`, `configure_peers`, `set_peer_config`,
`set_peer_online`, `execute`, `execute_with_progress`, `snapshot`, `parse_sql`, and
fixture helpers. `DatabaseDraft` carries explicit `PeerConfig` profiles; snapshots
include owner row indices, and `LabProgress` identifies the executing shard.
The private binary modules own the command worker and UI state; `ui/data`,
`ui/explorer`, `ui/infrastructure` and `ui/theme` own their views and shared styling.
API tests exercise real FHE, quota rollback, layout/data preservation, availability
rejection, overflow rollback, progress routes and SQL/fixture validation.

UI tests render egui in memory and observe its command channel. They exercise preset
selection without execution, explicit Run/Ctrl+Enter, map selection, peer settings
and addition, active routes, typed row layout, and draft preservation. They do not
open native windows, capture the desktop, or inject OS input. An opt-in CPU rasterizer
exports actual egui meshes and font textures as PPM images of public fixtures to
the ignored `.local/gui-previews` directory for offline visual review.

```sh
cargo test --release --locked -p fhe-playground --bin fhe-playground
cargo test --release --locked -p fhe-playground --bin fhe-playground export_ui_previews -- --ignored --nocapture
cargo test --workspace --release --locked -- --test-threads=1
cargo clippy --workspace --all-targets --release --locked -- -D warnings
```
