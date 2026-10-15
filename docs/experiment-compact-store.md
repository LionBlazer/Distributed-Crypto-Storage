# Compact encrypted page experiment

On 2026-10-14, one million public synthetic 3-byte rows occupied 3,187,648 canonical
encrypted bytes: 1.062549333x the 3,000,000 logical bytes. After 1,000 owner-driven
fixed-page replacements, the canonical image still occupied exactly 3,187,648 bytes.
This validates a compact encrypted page lifecycle and authenticated address lookup.
The measured lookup performs owner decryption; it does not perform FHE or prove SQL
computation, so its latency does not establish the encrypted indexed-query target.

The implementation is the independent [compact-store](../crates/compact-store/README.md)
crate. Its owner uses RustCrypto XChaCha20Poly1305; peers hold opaque encrypted pages
and a rebuildable SHA-256 Merkle tree. Secret keys remain with the owner.

## Run conditions

Measured at 2026-10-14T20:15:26.4583011Z on Microsoft Windows 10.0.26200 x64,
AMD Ryzen 9 9950X3D2 16-Core Processor, 16 physical cores and 32 logical processors.
Rust was 1.99.0 (b940084d7, 2026-09-28), release profile, with the checked-in lockfile:
chacha20poly1305 0.10.1, sha2 0.10.9 and zeroize 1.9.1.
This crate's workload is synchronous, with no Rayon workers or GUI.
Other task benchmarks were stopped during this measurement.

Source was the task's compact-store implementation on base commit 95ed312; the
implementation and report had not yet been committed when measured. The public
fixture uses varied age:u8 and amount:u16 values packed into exactly three bytes
per row. There is no compression, zero padding, persistent HE cache, or historical
ciphertext overlay. Keys are generated in memory and never serialized. One replica
is counted.

## Exact storage accounting

The canonical image consists of a 112-byte manifest plus exact plaintext-length
encrypted payload and 48 bytes per page: 8-byte page revision, 24-byte nonce and
16-byte authentication tag. Geometry is fixed at 256 rows/page in this experiment;
the final page contains only its actual rows.

| Rows | Logical bytes | Pages | Canonical encrypted bytes | Expansion | Rebuildable index hash bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 0 | 112 | Undefined | 0 |
| 1 | 3 | 1 | 163 | 54.333333x | 32 |
| 16 | 48 | 1 | 208 | 4.333333x | 32 |
| 64 | 192 | 1 | 352 | 1.833333x | 32 |
| 1,024 | 3,072 | 4 | 3,376 | 1.098958x | 224 |
| 65,536 | 196,608 | 256 | 209,008 | 1.063070x | 16,352 |
| 1,000,000 | 3,000,000 | 3,907 | 3,187,648 | 1.062549x | 250,208 |

For one million rows, adding all index hash payload produces 3,437,856 bytes,
or 1.145952x logical data. The current index is reconstructed in memory. Persisting
it would add those bytes to disk; it cannot be excluded from a total-storage claim
if a later implementation persists it. Vector/allocator overhead is not included
in the hash-payload counter, but it is included in whole-process peak memory.
The owner's secret-key payload is 32 additional bytes and is not part of the
peer image. Replication multiplies the stored copies separately.

The small-table rows deliberately expose fixed metadata overhead. This format does
not provide at most 2x expansion for every table size.

## Authenticated lookup and replacement

The owner/application chooses a known logical row ordinal, computes its direct
page address, and requests that page. The peer returns its full encrypted packet
plus an exact-address Merkle proof. The requester verifies against its independently
known head and then decrypts at the owner. Every returned row is compared with the
public fixture.

The measured warm operation includes address calculation, proof construction,
response encoding/decoding, root verification and owner decryption. It excludes
fixture comparison after the timer, network IO, consensus, FHE conversion/evaluation,
and computation-proof construction/verification.

| Measurement | Observed value |
| --- | ---: |
| Warm lookup samples | 1,000 |
| Warm p50 | 4.0 microseconds |
| Warm p95 | 4.5 microseconds |
| Warm p99 | 9.8 microseconds |
| One cold in-memory image reconstruction + index rebuild + lookup | 3,156.1 microseconds |
| Last response bytes | 1,216 |
| Owner page replacements, each checked against its prior head | 1,000 |
| Total replacements + proof verification + owner plaintext checks | 8.5944 milliseconds |
| Final snapshot revision | 1,000 |
| Canonical image before / after replacements | 3,187,648 / 3,187,648 bytes |
| Final rebuildable index hash bytes | 250,208 |
| Old proof against final current root | Rejected |
| Whole benchmark child-process wall time | 91.7178 milliseconds |

The cold case starts from an existing image byte buffer; it is not cold disk IO.
The wall time includes the storage sweep, setup, queries, replacements and final
decode; it is not the latency of a single query. The replacement total also includes
live-size assertions; it is not an isolated encryption primitive.

These percentiles describe 1,000 local samples in one standalone process, with
pages and the Merkle index already resident for warm reads. They are not independent
trials, a network SLA, a distribution under load, or evidence of concealed access.
A full-page response here is 768 payload + 48 page metadata/tag + 16 response header
+ 12 * 32 sibling bytes = 1,216 bytes. The short final page has less payload.

## Whole-process memory

The separate benchmark child process peaked at 18,673,664 bytes of resident working
set, or 17.80859375 MiB. Peak process commit charge was 14,725,120 bytes. This includes
the owner key, public fixture, encrypted snapshots, encoded images, tree, temporary
responses and runtime in that process. It measures a combined owner/peer experiment,
not an isolated peer or an FHE process. No TFHE key or server key is loaded here.

An external hidden/no-shell .NET process wrapper redirected stdout/stderr and
retained the child's process handle. After exit it successfully queried
GetProcessMemoryInfo, recording the kernel PeakWorkingSetSize and PeakPagefileUsage
without polling during timed operations. The PowerShell/.NET wrapper's own memory
is outside the child-process measurement. Windows defines these as peak resident
working-set size and peak commit charge, respectively.
[Microsoft memory counter definitions](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters),
[GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo).

## Validation and security boundary

The focused release suite passed all 19 tests: two independent AEAD tests and
17 public API contract tests. Strict Clippy passed for all compact-store targets.
Coverage includes modified nonce/ciphertext/tag/proof, wrong page, altered schema
or geometry, omitted/extra path nodes, old changed/unchanged-page proofs against a
new head, foreign owner, malformed/truncated headers, excessive sizes/counts,
overflowing layouts, corrupt roots, future page revisions and unchanged live
storage after 1,000 replacements.

Page AEAD binds database, key domain, schema, complete geometry, exact page index
and page revision. The Merkle version root additionally binds the manifest,
snapshot revision, row/page shape and encrypted packets. Independent current-head
selection rejects stale proofs. Parsing a head from the responding peer does not
make it trusted or fresh; head authentication, consensus and conflict resolution
remain external.

A valid page proof demonstrates membership and all exact bytes of that fixed page.
The direct row address does not implement encrypted predicate search, arbitrary-key
absence, duplicate-key groups, SQL result completeness, FHE computation proofs,
transactions, network replication or crash-atomic durable writes. Fixed-page
replacement is not an insert/delete/compaction or full restart/key-recovery test.
The next composition with real FHE must measure conversion, evaluation, verification
and any owner-assisted compact rewrite as part of its complete operation.

## Privacy and remaining comparison

This experiment reveals public database/schema identity, geometry, page lengths
and revisions, requested page addresses, repetition, timing and response sizes.
The owner keeps all secret keys; the peer has no plaintext decryption API.
These observable addresses are an experimental condition, not selection of the
project's permitted leakage.

Concealed access is not implemented or measured here. ORAM/PIR comparison still
needs an explicit peer-collusion model and measurements of bandwidth, server work,
client state, rebuilds and freshness. Fast address retrieval alone cannot establish
the combined storage, FHE, malicious-peer, freshness and privacy requirements.

## Reproduction

From the workspace root:

~~~sh
cargo fmt -p compact-store --check
cargo test --release --locked -p compact-store
cargo clippy --release --locked -p compact-store --all-targets -- -D warnings
cargo run --release --locked -p core-workloads --example compact_lookup -- 1000000 1000 1000
~~~

The example writes JSON lines only; no data or key files. The measured run's raw
results, stderr, native memory metadata and wrapper are retained in the task's ignored
.local/fhe-research/compact-store/ directory as results.jsonl, stderr.txt,
process.json and measure.ps1. Generated reports are not repository source.