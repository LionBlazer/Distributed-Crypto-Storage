# Distributed Crypto Storage

Rust prototype and research for encrypted SQL storage on participant-owned
computers. [REQUIREMENTS.md](REQUIREMENTS.md) defines the intended distributed
system. Peers now run in separate processes over mutually authenticated TCP/TLS.
The live owner client verifies full-residue FHE STARKs and confirmed journal heads
before accepting SELECT or publishing INSERT/UPDATE. Missing or invalid evidence
rejects. Self-signed TLS identities need no invitation CA; identity count supplies
no consensus weight. Production discovery, security parameters and scale remain open.
The [selected consensus direction](docs/consensus-model.md) is an internally
operated cumulative-work version journal. Bounded work/fork validation, durable
peer metadata and client freshness are implemented; external consensus networks
and identity-count voting are excluded. Easy playground work is not a production
adversarial security budget.

The repository has two dependency layers: the [reusable core](crates/README.md),
and deployment/test consumers: [peer daemon](apps/dcs-peer/README.md),
[playground](playground/README.md) and
[experiments](experiments/README.md). `crates/` contains libraries only; GUI, virtual time,
fixtures, presets and executable measurements live outside it. A default Cargo
build selects core libraries; the GUI is an explicit package target.

Use Rust 1.99 or newer, from the repository root:

```sh
cargo run --release --locked -p dcs-launch -- playground
cargo test --workspace --release --locked -- --test-threads=1
```

In Zed, spawn **FHE: Open GUI playground** from [.zed/tasks.json](.zed/tasks.json).
The single launcher builds portable GUI/peer executables and AVX2/AVX-512 proof
kernels. Each process selects the fastest supported installed kernel once at
startup, including OS register-state support; the linked portable engine is the
fallback. All variants use the same cryptographic parameters and proof format.
`playground --build-only` packages the applications without opening a window.
The [egui playground](playground/README.md) has SQL/data on the left and
network/node inspectors on the right, up to 16 real managed peer processes and
8 owner-client sessions. Presets fill the editor; Run or Ctrl+Enter sends genuine
encrypted FHE operations. Graph/matrix reflect authenticated reachability and
actual RPC observations. Virtual delivery is not used by the live GUI.
Alt+Left/Right and mouse side buttons navigate between views; middle-click closes
inspector tabs.

The SQL frontend supports row SELECT/projections with age filters and LIMIT,
single-row INSERT and amount addition on `age: u8, amount: u16`; it is not an arbitrary-SQL
database. Row projection uses actual BFV encrypted masking. The client authenticates
complete private index selection, verifies exact peer arithmetic, then rechecks the
confirmed version. INSERT/UPDATE publish actual compact ciphertext only after all
proof/overflow checks and durable journal confirmation. Parsed COUNT/SUM remain
unsupported by the verified path and reject explicitly.
The GUI uses the BFV
exact-index backend, shared public evaluation keys and compact encrypted pages.
Complete authenticated index selection precedes fresh FHE; unsupported budgets
reject rather than truncate. Owner secret keys stay outside peer role objects.

| Module | Responsibility |
| --- | --- |
| [fhe-playground](playground/README.md) | GUI, process supervision, owner-client views and actual network observations |
| [dcs-peer](apps/dcs-peer/README.md) | Independent peer daemon with no GUI or owner keys |
| [peer-transport](crates/peer-transport/README.md) | TLS 1.3 mutual authentication, endpoint pinning and bounded TCP frames |
| [peer-runtime](crates/peer-runtime/README.md) | Peer-owned disk objects, public FHE evaluator, neighbor probes and real copies |
| [storage-client](crates/storage-client/README.md) | Owner preparation, proof-first SELECT/mutations and confirmed version checks |
| [sql-plan](crates/sql-plan/README.md) | Backend-independent SQL parser, typed statement inputs and plans |
| [compact-query](crates/compact-query/README.md) | Complete index selection, fresh FHE projections/aggregates and checked compact updates; explicit BFV backend plus retained legacy TFHE module |
| [bfv-query-core](crates/bfv-query-core/README.md) | Reusable owner/public-peer BFV arithmetic and wire contracts; no storage or GUI dependency |
| [bfv-linear-circuit](crates/bfv-linear-circuit/README.md) | Canonical full-residue BFV addition statement for proof consumers |
| [bfv-product-circuit](crates/bfv-product-circuit/README.md) | Canonical full-residue BFV public-polynomial product |
| [bfv-query-proof](crates/bfv-query-proof/README.md) | Genuine bounded STARK generation and independent arithmetic verification |
| [proof-acceleration](crates/proof-acceleration/README.md) | Startup CPU/OS dispatch and bounded ABI for trusted proof kernels |
| [dcs-proof-kernel](apps/proof-kernel/README.md) | Fixed-profile SIMD build of the same arithmetic proof engine |
| [dcs-launch](tools/launcher/README.md) | Single build/package/launch command for portable hosts and SIMD kernels |
| [version-journal](crates/version-journal/README.md) | Signed state transitions, cumulative work, confirmed ancestry and durable metadata |
| [compact-store](crates/compact-store/README.md) | Owner-only symmetric keys, opaque authenticated pages, independently trusted version roots and constant-size replacements |
| [replica-store](crates/replica-store/README.md) | Bounded ciphertext replicas, fault-domain placement and atomic local repair batches |
| [peer-protocol](crates/peer-protocol/README.md) | Bounded transport-independent handshake/message state machine |
| [fhe-prototype](experiments/fhe-prototype/README.md) | Original standalone TFHE experiment and historical baseline |

The live GUI stores encrypted shards in child processes and requests physical
copies directly between peers. Process stop/restart and holder failover use actual
network/disk state. All locally managed processes share one host failure domain;
multiple local copies do not establish independent failure tolerance. Existing
objects and one previous owner state are retained during a session replacement.
No remote object-deletion RPC is exposed. The earlier [replicated SQL model](docs/replicated-sql-prototype.md)
describes the historical local LabEngine, not the new transport's consensus or
availability guarantees.

The [requirements/code audit](docs/requirements-code-audit.md) records the checked
FHE/plaintext boundaries, repaired bypasses and requirements that remain unfinished.

The reusable [BFV proof engine](crates/bfv-query-proof/README.md) covers all 81,920
ciphertext residues for addition and public-polynomial projection with Plonky3.
Its proof-first client composition is described in [proved network SQL](docs/proved-sql-network.md).
Private AEAD/index authentication remains owner-side; this is not an independently
public proof of SQL/AEAD linkage. Full network queries still exceed the 50–100 ms
target. The original [addition experiment](experiments/bfv-addition-proof/README.md)
and its [measurements](docs/experiment-bfv-addition-proof.md) remain historical evidence.

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
| [Bulk full snapshots, 1,000 tables / 3 GB, 256 matches across 256 pages](docs/experiment-private-bfv-bulk-scale.md) | 30.329 ms, all 54 exact | 1.782226x; one DB owner, all keys/native allocations retained |
| [Compact BFV UPDATE, 1,000 tables / 3 GB](docs/experiment-private-bfv-update-disk.md) | 100 point cycles through commit/invalidation: 316.162 ms | 1.814285x; 126 positive commits preserve file sizes |

These are different measured workloads, not interchangeable performance claims.
Setup is separate; OS file cache is allowed; network, replication and arithmetic
proofs are excluded. Bulk uses 5,736,091 bytes/query: its ideal 100 Mbps/10 ms RTT
model exceeds 500 ms. All outliers and complete accounting remain in the reports.
The 2x results require the stated large datasets; fixed setup costs still dominate
tiny tables, as the [one-table control](docs/experiment-private-bfv-bulk-disk.md) shows.
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
