# Distributed Crypto Storage

Rust prototype and research for encrypted SQL storage on participant-owned
computers. [REQUIREMENTS.md](REQUIREMENTS.md) defines the intended distributed
system; networking, consensus, recovery and verifiable malicious-peer execution
remain unfinished. The current implementation is a local experiment.

Use Rust 1.99 or newer, from the repository root:

```sh
cargo run --release --locked -p fhe-playground
cargo test --workspace --release --locked -- --test-threads=1
```

In Zed, spawn **FHE: Open GUI playground** from [.zed/tasks.json](.zed/tasks.json).
The [egui playground](crates/fhe-playground/README.md) has SQL/data on the left and
network/node inspectors on the right, up to 16 simulated peers and 8 clients.
Presets fill the editor; Run or Ctrl+Enter executes them. Graph and connection
matrix reflect the same protocol links/events. Virtual delivery is in one process.

The SQL frontend supports its documented COUNT/SUM and amount-addition subset on
`age: u8, amount: u16`; it is not an arbitrary-SQL database. The GUI uses the BFV
exact-index backend, shared public evaluation keys and compact encrypted pages.
Complete authenticated index selection precedes fresh FHE; unsupported budgets
reject rather than truncate. Owner secret keys stay outside peer role objects.

| Module | Responsibility |
| --- | --- |
| [fhe-playground](crates/fhe-playground/README.md) | Test client/manager, SQL frontend, worker and virtual network visualization |
| [compact-query](crates/compact-query/README.md) | Complete index selection, fresh FHE aggregates and checked compact updates; explicit BFV backend plus retained legacy TFHE module |
| [bfv-query-core](crates/bfv-query-core/README.md) | Reusable owner/public-peer BFV arithmetic and wire contracts; no storage or GUI dependency |
| [compact-store](crates/compact-store/README.md) | Owner-only symmetric keys, opaque authenticated pages, independently trusted version roots and constant-size replacements |
| [peer-protocol](crates/peer-protocol/README.md) | Bounded transport-independent handshake/message state machine |
| [fhe-prototype](crates/fhe-prototype/README.md) | Original standalone TFHE experiment and historical baseline |

The [measurement ledger](docs/optimization-goal.md) preserves successful and failed
experiments. Private retrieval and process recovery currently live in standalone
experimental compositors; the GUI uses visible access. Generated public fixtures,
ciphertext datasets and reports stay in ignored `.local/`; no real secrets or
participant data are committed.

| Measured configuration | Maximum complete local operation | Files plus reported native peak / logical payload |
| --- | ---: | ---: |
| [Actual GUI SQL, 128 rows, 1/3/16 peers, 147 operations](docs/experiment-bfv-gui-integration.md) | 383.854 ms | Tiny-table metadata/key cost; no 2x claim |
| [Original-owner process restart, 1,000 tables / 3 GB](docs/experiment-private-bfv-restart-disk-scale.md) | ExactIndex: visible 37.288 ms / PIR 320.674 ms; one FullPredicate control 520.214 ms | 1.814826x including both sealed checkpoints and observed parent/serial-child peak bound |
| [Two-posting/two-data-page selection, 1,000 tables / 3 GB](docs/experiment-private-bfv-multipage-disk-scale1000.md) | PIR cached-header 436.036 ms; five uncached Fixed256 misses exceed 500 ms, max 522.106 ms | 1.813729x; all 480 answers exact |
| [Bulk full snapshots, 256 matches across 256 pages, one 3 MB table](docs/experiment-private-bfv-bulk-disk.md) | 31.541 ms, all 18 exact | 94.909507x; fixed keys are not amortized in this tiny fixture |
| [Compact BFV UPDATE, 1,000 tables / 3 GB](docs/experiment-private-bfv-update-disk.md) | 100 point cycles through commit/invalidation: 316.162 ms | 1.814285x; 126 positive commits preserve file sizes |

These are different measured workloads, not interchangeable performance claims.
Setup is separate; OS file cache is allowed; network, replication and arithmetic
proofs are excluded. Bulk uses 5,736,091 bytes/query: its ideal 100 Mbps/10 ms RTT
model exceeds 500 ms. All outliers and complete accounting remain in the reports.
The [visible/concealed access comparison](docs/index-privacy.md) keeps both policies
open. Private reads hide selected pages within their declared table/plan, while
identity, heads, sizes, timing and allowed failure patterns remain public.

The [sealed recovery candidate](experiments/owner-recovery-candidate/README.md)
and [process-restart compositor](experiments/private-bfv-restart-disk/README.md)
restore original compact/BFV/PIR owners and public setups. The latter waits for
actual writer exit before launching its reader; its live broker holds the external
wrapping key. Full-machine key custody, current-anchor authority and durable
multi-file publication remain open. Results remain explicitly Unverified; retrieval
authentication is not a proof of SQL arithmetic or malicious-peer correctness.

The integration branch is `master`. [AGENTS.md](AGENTS.md) defines task branches,
automatic publication, incoming master synchronization and explicit promotion.
Shared project skills live in [.agents/skills](.agents/skills).
