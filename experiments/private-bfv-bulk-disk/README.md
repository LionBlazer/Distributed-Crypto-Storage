# Whole-table bulk retrieval → exact BFV aggregate

The separate [bulk-scale package](../private-bfv-bulk-scale/README.md) adds actual
1,000-table disk-only dispatch under one DB owner. Its measured files plus native
peak are 1.782226215x of 3 GB; all 54 complete local operations are below 31 ms.
This package retains the original one-table Disk/Resident comparison unchanged.

Validated isolated alternative, **not PIR**: all18 full operations on one fresh
1,000,000-row public table returned exact COUNT/SUM. Local time was27.0733–31.5408ms;
every operation transferred5,736,091B across two sequential RPCs. The100Mbps serial
network MODEL is485.9606–490.4281ms at zero RTT and505.9606–510.4281ms at10ms RTT.
No network or GUI was run. See the [measured report](../../docs/experiment-private-bfv-bulk-disk.md)
for every cell, actual byte/memory ledger, reproduction and limits.

## Ownership and dependencies

| Module/dependency | Responsibility |
| --- | --- |
| bulk_wire.rs | Exact bounded270B framing: magic/version, tableID, requestID, two independently trusted112B heads and lengths. No selected addresses, predicate or count. Reject shape/nonce/head/length errors before canonical decoding;8MiB maximum per image. |
| roles.rs | OwnerTable owns compact/BFV authority and trusted descriptor. DiskPeer owns only ciphertext files/optional serialized ciphertext cache and Arc-backed public BFV Evaluator. No owner response/plaintext/FHE cache. |
| compact-query, BFV-only | Existing full canonical/root restoration, complete padded-index counts/postings/duplicate/256-row preflight, all selected age checks and selected-page AEAD; owning prepare/complete lifecycle. Supports selected rows across arbitrary data pages. |
| bfv-query-core, transitively | Unchanged full N8192/Q218/t114689/CBD variance10/native/level0 keyset. Genuine fresh byte/COUNT weights,8 encrypted rotations/adds, Unverified output. |
| Spiral owner-state + pinned SDK | Original owner image/client/public wire/full expanded public matrices retained solely for fair accounting; UNUSED for retrieval. No database NTT cache. |
| fixture.rs/main.rs/tests.rs/resources.rs | Explicit public sparse fixture, finite driver/post-timer oracle, six owning tests and decimal2GB current/OS-peak RSS/commit guards. |

Disk mode exact-reads both held files each operation, with OS file cache allowed.
Resident mode retains the same5,065,148B canonical ciphertext at the peer; its1.1571ms
prefetch is separately timed. Both rebuild a fresh full response. The owner bounded-
decodes and recomputes BOTH full roots, authenticates index binding and complete
selected postings/data, then freshly encrypts exact fields. All selected ages must
match. An empty query still sends both full snapshots and performs real encrypted
zero-weight COUNT/SUM. Query buffers/Table are dropped before the outer timer ends.
The timer includes a diagnostic full-body SHA256; the public oracle is constructed
only afterwards. Expected-page counts are fixture properties, not internal I/O counters.

The bulk request exposes tableID, heads, lengths, timing and failure pattern, but
contains no selected-page address or predicate/cardinality field. Both snapshots
are always transferred. This is a concealed-selected-address access plan, not a
formal traffic-analysis/privacy proof. Failure shapes are not padded.

## Reproduction

Rust1.99. The standalone Cargo.lock is frozen; no registry downloads or version changes
were made to the owning workspace. prepare.ps1 verifies source-basis hashes and pinned
public SDK fdb7206517c249603b0c91b65f1f29f95272107c, materializes a NEW ignored package,
changes only dependency paths and records them. It does not execute Cargo or keys.
The six release tests, authored strict Clippy, fmt and build passed on their first attempt.
No benchmark repetition or discarded outlier occurred.

```powershell
./prepare.ps1 -SourceRepository /path/to/reviewed/checkout
# In the returned isolated directory, under an exclusive CPU lease:
$env:CARGO_HOME='/path/to/reviewed/checkout/.local/cargo-home'
$env:CARGO_TARGET_DIR='/path/to/reviewed/checkout/target/private-bfv-bulk-disk'
$env:RAYON_NUM_THREADS='8'
cargo test --release --locked --offline --jobs 2 -- --test-threads=1
cargo clippy --release --locked --offline --jobs 2 --all-targets --no-deps -- -D warnings
cargo fmt -- --check
cargo build --release --locked --offline --jobs 2
# Freeze executable/sources first; output directory must be a NEW .local child.
& "$env:CARGO_TARGET_DIR/release/private-bfv-bulk-disk.exe" /new/ignored/.local/data-bulk 3
```

prepare.ps1 now copies the reviewed Cargo.lock. The pre-run source archive records
the original generated manifest/README; only documentation and lock-copy preparation
changed afterwards. The measured Rust runtime remains byte-identical.

One table is a functional/latency scope, not a pooled1000-table measurement. Fixed
BFV/PIR keys remain counted: actual files plus observed native peak private total
284,728,520B for3MB logical (94.909507x). Thus no combined2x claim. The full parameter
security/noise/CCA and malicious arithmetic-proof gates remain open; heads/authentication
do not verify peer arithmetic. No general SQL, hidden writes, restart, consensus,
replication, WAN guarantee or same-fixture measured PIR speedup is established.
