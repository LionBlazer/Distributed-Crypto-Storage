# Replicated SQL prototype

This composes the [playground](../crates/fhe-playground/README.md),
[compact-query](../crates/compact-query/README.md) and
[replica-store](../crates/replica-store/README.md) in one process. It advances the
local crash/freshness parts of requirements 1, 6–9 and 13. It does not establish a
decentralized consensus or malicious-peer query-proof protocol.

## State and operations

Database creation establishes fixed logical shard identities, trusted data/index
heads and actual physical ciphertext holders, initially with a minimum of one copy.
`LabEngine::set_replication(1..=16)` changes that minimum; `repair_replicas` performs
copying separately. Adding a peer starts it empty and removing one drops its real
copies. Neither topology changes nor repair reseal rows from the inspector fixture.

Each usable copy contains BOTH canonical data and its matching encrypted index.
Reads select one current online holder per logical shard; replicas do not multiply
COUNT/SUM. Selection uses configured delay, then peer ID. Index authentication,
fresh BFV evaluation and owner result decryption still run. Aggregate results remain
explicitly unverified for malicious arithmetic or completeness.
Equal-delay selection can concentrate work on the lowest-ID holder. Shards execute
sequentially in this local engine; queue-aware scheduling and parallel distributed
execution remain open parts of requirement 7.

UPDATE evaluates once per logical shard and stages ciphertext replacements on all
online current holders. Overflow, quota failure or cancelled preparation publishes
no partial update. Offline copies retain older heads and are excluded after return.
Single-row INSERT chooses the smallest logical shard, homomorphically appends to
its encrypted relation and checks the decoded response before growing its compact
data/index. It stages every online current holder, leaves offline copies stale and
shares the same quota/cancellation/commit gate. The laboratory database is capped
at 128 rows; INSERT neither creates fresh keys nor reconstructs lost ciphertext.
Repair validates survivor ciphertext and publishes the complete data/index batch;
it does not read the owner fixture as a recovery source. Removing every copy leaves
an unavailable shard even if the fixture is visible and empty peers are later added.

The GUI serializes these operations. Automatic repair starts after actual peer
discovery, with an idle worker and unpaused simulation; failed repair is reported,
without retrying every tick. Manual context-menu repair retries. Copying itself is
local CPU/memory work, not a byte-accurate virtual or WAN transfer. Pause defers new
repair starts, as distinct from stopping already running work.

## Failure and resource limits

If EVERY shard has at least r current complete copies in r genuinely independent
failure domains, at least one survives any r−1 of those domains failing. Merely
requesting r copies does not establish that condition. Labels and availability are
caller-supplied facts; they provide no independence, Sybil or proof-of-storage test.
Repair also needs current survivors, capacity, eligible domains and established
routes. A lost final copy, unavailable owner/key, or malicious withholding has no
unconditional recovery guarantee.

Per-peer quota includes every physical canonical data/index image and 16 bytes of
record metadata per pair. Offline/stale copies remain charged; lowering the minimum
does not garbage-collect extras. Owner keys, shared evaluation keys, Merkle caches,
temporary images and allocator overhead are additional RAM. All state remains
ephemeral; durable publication and process restart are separate experimental work.
Peer-card occupancy uses these actual physical bytes. Its separate useful-payload
count comes from each held data image's row geometry, including stale copies;
it is not the current global fixture size.

## Reproduction

With Rust 1.99, release mode, public synthetic rows and no native window:

```sh
cargo test --release --locked -p replica-store -p fhe-playground -- --test-threads=1
cargo run --release --locked -p fhe-playground --example replicated_sql_workload -- 3
cargo run --release --locked -p fhe-playground --example replicated_sql_workload -- 16
```

The finite workload reports setup/repair separately from local SQL. It checks reads
before/after peer loss, UPDATE with a peer offline, exclusion of the returned stale
copy and a read after repair. Native Windows process memory and physical data/index
bytes are reported explicitly. Network, consensus and computation proofs are outside
those timers; no general latency, 2x-storage or whole-process resource SLA follows.

## Local measurements

Measured on 2026-10-15, Windows, AMD Ryzen 9 9950X3D2, Rust 1.99 release,
`CARGO_BUILD_JOBS=2`, `RAYON_NUM_THREADS=8`. Each column is one finite run with
128 public rows (384 logical bytes), minimum two copies, zero configured peer delay,
five full-table COUNT/SUM statements and one range UPDATE. Shard count initially
equals peer count and stays fixed through the offline/return steps. These are
observed operation times, not latency percentiles or an indexed point-query result.

| Measurement | 3 peers / shards | 16 peers / shards |
| --- | ---: | ---: |
| Create, including keys | 335.9 ms | 335.9 ms |
| Five reads, observed range | 67.2–69.1 ms | 353.9–362.1 ms |
| UPDATE with peer 1 offline | 35.0 ms | 178.7 ms |
| Initial local repair | 0.128 ms | 0.382 ms |
| Refresh returned stale copies | 0.107 ms | 0.393 ms |
| Physical canonical data, all copies | 1,728 B | 5,888 B |
| Physical encrypted index, all copies | 14,456 B | 74,880 B |
| Total charged storage, including record metadata | 16,280 B | 81,280 B |
| Peak private process commit | 244,867,072 B | 244,498,432 B |
| Peak resident working set | 239,865,856 B | 239,157,248 B |

All reads returned 128 rows and the expected sum (3,200 before UPDATE; 3,520 after).
The six SQL operations include actual ciphertext preparation, BFV evaluation and
owner completion. Setup/repair are separate. Copy timers measure local in-memory
copying and validation, not network recovery. Keys are shared within one process;
these figures do not measure independent peer processes or a large database.
More shards add sequential cryptographic work here, so the 16-shard run misses the
50–100 ms target. Small-table index/header costs also prevent a whole-store 2x claim.
