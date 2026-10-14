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
This Windows task uses PowerShell 7 (`pwsh`) and `rustup which cargo` to select the
active Rust toolchain rather than a different `cargo` executable earlier on PATH.
It runs at the workspace root with a local `.local/cargo-home` cache, saves buffers,
and allows one GUI task instance at a time.

## Explore

The SQL view follows the basic areas of
[DataGrip's query console](https://www.jetbrains.com/help/datagrip/query-consoles.html):
database tree on the left, editor on the right, and a resizable result/output pane
below. The editor has line numbers and SQL highlighting; decorative cards and the
topology diagram are removed.

- **SQL:** write a statement, then click **Run** or press **Ctrl+Enter**. The
  **Presets** menu only fills the editor; selecting a preset never submits a query.
  SELECT answers appear as a result row. Updates, errors, and history use **Output**.
- **Data:** name a database, edit `age,amount` lines, generate up to 128 synthetic
  rows, or choose an overflow/empty fixture. **Create / replace** applies these
  drafts and generates fresh keys using the peer count selected on Infrastructure.
- **Infrastructure:** choose **1–16 peers**, then **Apply** to rebuild round-robin
  shards from the live database. Unapplied data drafts are preserved. Toggle peer
  availability and inspect rows, compressed bytes, and last per-shard query times.
  A required offline shard makes reads/updates fail; empty offline peers do not
  omit data. Times include FHE and client decryption, not network ping.

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

Library entry points are `LabEngine::create`, `set_peer_online`, `execute`, `snapshot`,
`parse_sql`, and fixture helpers. UI composition and the bounded background command
channel are private binary modules. API tests exercise real FHE across shards,
availability rejection, cross-shard overflow rollback, invalid replacement, empty
databases, and strict SQL/fixture validation.

UI tests render egui in memory and observe its command channel. They exercise preset
selection without execution, explicit Run/Ctrl+Enter, tab separation, result/output
rendering, and draft preservation when applying a peer layout. They do not open
native windows, capture the desktop, or inject OS input.

```sh
cargo test --release --locked -p fhe-playground --bin fhe-playground
cargo test --workspace --release --locked -- --test-threads=1
cargo clippy --workspace --all-targets --release --locked -- -D warnings
```
