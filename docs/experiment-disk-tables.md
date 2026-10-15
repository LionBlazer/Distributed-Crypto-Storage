# Bounded disk-backed table experiment

Measured: 1800 independent million-row tables, 5.4 GB logical data, with only
one encrypted Table loaded at a time. Complete counted canonical material is
9,298,369,256 bytes, **1.721920x** logical data. Whole-process native peak RSS
is 370,515,968 bytes. Nine exact indexed point queries, including actual file
read/decode/authentication and genuine FHE, take 61.130–117.962 ms.

This extends the [retained-table experiment](experiment-key-amortization.md)
using the unchanged current classic TFHE kernel. It does not measure global SQL
routing, hidden access, multirow queries/updates, transport or arithmetic proofs.
The separate [byte-limb BFV experiment](experiment-bfv-byte-limbs.md) is not the
backend used in these disk measurements.

## Storage and lifecycle

The new [disk_tables example](../experiments/core-workloads/examples/disk_tables.rs)
generates varied explicitly public rows, seals one table, writes both actual
encrypted canonical images, calls sync_all and drops that table before creating
the next. Every table has a distinct root and a table-specific rare age250 row.
No plaintext, secret key or expanded FHE row cache is persisted.

Each .cq file contains an eight-byte version marker, two u64 lengths and the
canonical data/index encodings. It is created with create_new in a unique child
directory under the explicitly supplied existing experiment directory. Header,
file size and 8 MiB per-image bounds are checked before allocating image buffers.
Independent trusted data/index heads remain with the live owner. Loading one
table reconstructs and authenticates both images against those heads.

| Counted material | Actual bytes |
| --- | ---: |
| Logical rows, 1800 x 1,000,000 x 3 bytes | 5,400,000,000 |
| Canonical encrypted data | 5,442,451,200 |
| Canonical encrypted PaddedV2 indexes | 3,674,815,200 |
| Disk framing, 24 bytes/table | 43,200 |
| Actual sum of file lengths | 9,117,309,600 |
| Trusted catalog payload, two heads and u64 table ID/table | 417,600 |
| Complete shared public evaluation-key wire | 180,610,708 |
| Owner FHE key serialized byte count | 31,268 |
| Owner symmetric key/domain state | 80 |
| Joint counted material | **9,298,369,256** |
| Joint / logical data | **1.721920233x** |

File lengths are real filesystem metadata, not projected allocations. The total
also counts complete serialized keys and catalog payload even though these are
kept in the live process rather than persisted. Directory entries, filesystem
allocation rounding/journaling, application binaries and future SQL routing
structures are not included. There is one replica. Rebuildable hash payload
would total 113,414,400 bytes if every table were loaded; it is not persisted,
and only the current table's hashes are live during queries.

This is image restore using the same live keys, not process restart or durable
key/catalog recovery. File sync_all does not establish a crash-consistent
catalog transaction or directory durability. The benchmark removes only files
it created, without recursive deletion, and confirms its own run directory is
gone before emitting successful completion.

## Actual queries and resources

All three samples for each supplied table ID execute full age-index selection,
authenticated retrieval, fresh encrypted mask/input preparation, genuine TFHE
predicate/COUNT/SUM, request/output serialization, and owner decryption. The
public fixture oracle runs after timing. Each answer has COUNT1 and the expected
table-specific SUM; the table ID is supplied explicitly.

| Supplied table ID | Complete query ms, samples 0 / 1 / 2 |
| --- | --- |
| 0 | 117.962 / 76.954 / 67.676 |
| 900 | 62.175 / 61.130 / 68.151 |
| 1799 | 74.617 / 64.167 / 63.299 |

File read/decode/verification alone takes 4.029–5.211 ms. OS file caching is
allowed; this is not a cold physical-I/O measurement. Each full counted query
flow is 434,054 bytes: request263,669, output148,497 and separate authenticated
page-response payloads21,888. No actual network latency is measured.

Setup/key generation and complete public-key serialization take 719.657 ms.
Creating and syncing all files takes 62,085.412 ms; whole experiment wall time
is 64,894.437 ms. Eight shared Rayon workers and the existing scoped row-worker
budget8 are configured. One-row queries do not start extra row initiators.
The CPU lease excludes simultaneous heavy agent benchmarks.

Whole-process native peak RSS/commit is 370,515,968/366,690,304 bytes, including
owner, peer, key setup and serialization buffers. Windows native high-water
counters and the existing guard check 2 GB RSS/1.85 GB private commit at bounded
allocation/phase boundaries. This is not an OS hard allocation cap. System-wide
file cache is outside process counters; no cache flush or global OS setting is
changed. Rejected real ciphertext tampering, truncation, u64::MAX frame length
and a different table's trusted head are checked after the queries. Restoring
the original file succeeds. All own generated image files are then removed.

## Reproduction and provenance

From repository root on Windows, use a dedicated target for this experiment:

~~~powershell
$env:CARGO_TARGET_DIR = Join-Path $PWD 'target/disk-tables'
cargo build --release --locked --offline -p core-workloads --example disk_tables --jobs 2
cargo clippy --release --locked --offline -p core-workloads --example disk_tables --no-deps -- -D warnings
$output = Join-Path $PWD '.local/fhe-research/disk-tables'
New-Item -ItemType Directory -Force -Path $output | Out-Null
& "$env:CARGO_TARGET_DIR/release/examples/disk_tables.exe" $output 2
# Inspect the successful dry run and available disk space before the larger case.
& "$env:CARGO_TARGET_DIR/release/examples/disk_tables.exe" $output 1800
~~~

The actual run used the existing explicit Cargo executable/shared local cache and
target, with more than 1.2 TB disk free. An initial dry run exposed a stale
grouping4 compact-query artifact in that shared target. Its output is retained
as dry2.jsonl and is excluded from classic results. The source then gained a
runtime gate for the expected classic evaluator/owner-key sizes, the classic
library was forced to rebuild, and dry2-classic plus actual1800 passed. Dedicated
targets avoid reusing same-named local-workspace artifacts. No core API or
cryptographic parameter was changed.

Focused release build, strict Clippy and Rust2024 formatting pass. The actual
dry and larger runs cover the owning file/restore/query/failure boundary; the
unchanged core unit suite is not claimed as rerun. Source SHA-256:
1EC189B7A427BA7231DA67DAD29F03BA487F6F8A7D79E1B2DCCE5833EA3079B6.
Archived classic executable SHA-256:
DB272A3646634F6A559CFCEEA6EDA3A9F2C2EF5A37A0A7BDC6778BC88AD8E15C.

Ignored raw files are in the compact-playground worktree's
.local/fhe-research/disk-tables directory: dry2-classic.jsonl and stderr,
actual1800-20261014-222555-797.jsonl, .stderr.txt and .process.json, plus the
archived disk-tables-classic.exe. Actual run exit0, empty stderr, completed
2026-10-14T22:27:00.7214449Z. Actual JSONL SHA-256:
0211ae59e90654bedfa186293bc71bc72514228cd3cdf75b2b99821ad6a1d454.
Generated data, keys, executables and raw reports
are not publication inputs. Owner availability, global freshness and malicious
query verification retain the existing compact-query limitations.
