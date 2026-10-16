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

The compact **Speed** slider beside the view controls sets one display clock for
observed frame events, logs, topology/storage snapshots and completed SQL results.
Zero pauses this whole observed view. Actual transport, FHE, proofs and commits
continue in real time; their measured operation durations stay wall-clock values.
Live producers enqueue timestamped events through one ordered bus, so a displayed
result cannot overtake its earlier frame observations. **Run catches up before
submitting a new query and preserves the selected speed**, avoiding a wait behind
old background traffic. **Live** applies all waiting results/state and resumes at
100%; it never discards an accepted SQL result or repeats the statement.

Blue endpoint pulses mean a complete application frame was written; green pulses
mean a complete reply was read. They fade over half a display second rather than
pretending to measure one-way packet travel. Peer-reported observations mark the
receiving endpoint when status telemetry reaches the manager. Optional amber
health checks include probes and status polling. Marker deduplication and bounds
remain display-only. If the display backlog fills, old optional telemetry is
omitted with an explicit gap indication; a paused view stays paused and accepted
SQL/control results remain queued for display.

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
- Four presets cover SELECT, filtering, INSERT and UPDATE; operations whose
  computation proofs are not implemented are not offered as live presets.
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
- SQL uses square icon buttons: green play and red stop, with tooltips, keyboard
  accessibility and distinct hover/pressed/disabled states. Stop interrupts the
  actual owner's RPC scope without queuing behind SQL or stopping peer processes.
  Further steps stop; a peer can finish its currently admitted proof. The worker
  remains busy until the operation settles, then releases the scope before status
  refresh. Confirmed writes remain committed; ambiguous publication retains its
  exact pending mutation, so recovery cannot apply an UPDATE twice.
- Data import fits the actual Open SQL button before allocating the path field.
  Its scroll viewport contains wide content instead of changing the SQL/network
  splitter; the splitter still resizes when explicitly dragged.
- Startup opens **SQL** with `CREATE TABLE IF NOT EXISTS records (...)` followed
  by `SELECT * FROM records`. No sample rows or database are created until Run.
  Run works before a table exists; missing tables and unsupported SQL report in
  Output. The first CREATE starts three real local peers if none were configured,
  initializes an empty encrypted Session, then SELECT requires the ordinary proof.
  An existing table is retained by IF NOT EXISTS. Scripts are preflighted as a
  whole, then executed sequentially; a runtime failure reports earlier commits
  without claiming rollback. `SELECT FOR UPDATE` is rejected because row locking
  and transactions are not implemented.
- **Data** shows authenticated current rows. Import SQL, sources and preview are
  collapsible; the optional **Manual data draft** is closed by default. Its explicit
  Create/replace action sends encrypted initial data to peers. One previous database
  and its owner keys are retained in the current
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
  Every map card, glyph, indicator, border and storage bar shares one world-space
  transform. Zoom never switches card contents or fixes label sizes in screen pixels.
  Dense networks can use the complete connection matrix; links are never removed
  merely to simplify the picture. See [layout research](../docs/graph-layout.md).

## SQL dump import

The Data panel downloads public SQL scripts on demand to client memory or reads a
local `.sql` file. It does not ship datasets, launch another database engine, or
execute script text on the host. Downloads and file reads are capped at 8 MiB;
preview text is capped at 64 KiB. Network loading runs off the UI thread, with
HTTPS, redirect and timeout bounds. `samples::prepare_import` uses the reusable
[typed importer](../crates/relational-types/README.md) to validate the entire
schema and all literal rows, including PK/FK/UNIQUE/CHECK constraints. Unsupported
input returns no partial database. Loading or previewing a file does not create
data. There is no 128-row cap; byte/table/column resource budgets remain explicit.

**Import** explicitly initializes a new encrypted RelationalSession and its agreed genesis
from all validated owner-supplied input rows. It creates actual ciphertext copies
on the managed peers and never replaces an existing database. Initial owner-input
encryption is not a substitute query answer: subsequent SELECT requires actual
peer BFV projection, genuine STARK evidence, complete authenticated private-index
selection and confirmed-version checks. Typed imported catalogs are currently
immutable: unsupported mutations, joins and aggregates report an error rather
than executing on plaintext or falling back to the two-column engine.

The catalog contains [Northwind and pubs from Microsoft](https://github.com/microsoft/sql-server-samples/tree/master/samples/databases/northwind-pubs)
and [Chinook](https://github.com/lerocha/chinook-database/releases/tag/v1.4.5),
approximately 1 MiB, 123 KiB and 597 KiB of SQL respectively. The complete official
Northwind script imports 13 base tables and 3,308 rows without relabeling or
discarding columns, including dates, money, NULLs, Unicode and binary images.
Other catalog scripts still undergo the entire typed grammar/constraint preflight;
their presence in the download catalog is not a promise of every dialect feature.
[AdventureWorks backups](https://learn.microsoft.com/en-us/sql/samples/adventureworks-install-configure)
use SQL Server `.bak` restoration and are not SQL text for this importer.

The Data view lists actual imported table schemas/counts. Browse prepares a query;
the user still presses Run. The SQL table selector and presets use the current
catalog. Text, exact decimals, NULLs and dates display as typed cells; binary
fields show their length instead of flooding the result grid with hex. No local
plaintext imported table is used to answer a query.

```sql
SELECT CustomerID, CompanyName
FROM Customers WHERE Country = 'Germany' ORDER BY CustomerID;
SELECT * FROM [Order Details];
SELECT ProductID, ProductName, UnitPrice
FROM Products WHERE UnitPrice >= 50 ORDER BY UnitPrice DESC;
```

Rows/cells stream through 8,191-byte BFV blocks; neither 128 rows nor one BFV block
limits a table. Current client budgets are 8 MiB encoded data and 8 MiB private
index per table, the explicit network profile's table count, one million result
cells and 32 MiB projected output. Oversized operations reject without silent
truncation. The [Northwind verification report](../docs/northwind-typed-import.md)
records the actual separate-process test and its current performance limits.

## Dependencies and verification

[peer-runtime](../crates/peer-runtime/README.md) owns real RPC/storage/FHE service;
[peer-transport](../crates/peer-transport/README.md) owns TLS/framing;
[storage-client](../crates/storage-client/README.md) owns the owner role;
[version-journal](../crates/version-journal/README.md) owns the explicit network
profile and confirmed-version reference types;
[bfv-query-proof](../crates/bfv-query-proof/README.md) owns computation proofs and
the process's one-time proof backend initialization;
[sql-plan](../crates/sql-plan/README.md) owns the earlier two-column statement parser;
[relational-types](../crates/relational-types/README.md) owns typed catalogs, dump
preflight and schema-bound SELECT planning. compact-query/compact-store,
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
