# Compressed authenticated age postings

This change compresses the actual encrypted posting index owned by
[compact-query](../crates/compact-query/README.md). It keeps the same trusted-owner
index policy, selective FHE execution, 256-row materialization limit and
unverified-result boundary. No evaluator or owner UPDATE semantics change.
It does not add general SQL, private peer-side index traversal or a computation
proof. See [query-proof feasibility](experiment-query-proofs.md).

## Exact V2 format

The index uses compact-store's normal AEAD pages, Merkle retrieval proofs and
112-byte outer manifest. Its row width is one byte and page capacity is 4096 bytes.
The schema identifier is `CQAGEINDEX000002`; the older fixed-u32 format is rejected,
without a compatibility layer or migration.

| Plaintext offset | Field | Bytes |
| --- | --- | ---: |
| 0 | Exact current data commitment | 112 |
| 112 | 256 little-endian u32 posting counts | 1024 |
| 1136 | 257 little-endian u32 payload byte offsets | 1028 |
| 2164 | Real age buckets followed by encrypted zero padding | B(N) |

Offsets are relative to byte 2164. An empty bucket has count zero and equal adjacent
offsets. Within each bucket, encode the first logical row ordinal as an absolute
unsigned LEB128 integer; encode each later ordinal as its strictly positive gap
from the previous one. Reset the previous ordinal at each age boundary. A zero
first ordinal is valid. Groups are increasing and every row belongs to one group.
The final offset marks the real posting end. Pad the remaining capacity B(N) with
zero plaintext bytes before AEAD encryption; padding is not a posting bucket.

The owner builds this index from the same rows it seals. The index's independently
trusted commitment authenticates its complete intended bytes and AEAD domain;
the encrypted binding authenticates the exact data head to which they belong.
Counts/offsets alone cannot validate a peer-built index's hidden SQL semantics.

Default fixed-per-N encrypted padding makes total index length/page count depend
only on the public table row count and format, not on gap compressibility. Without
that padding, single-age and uniform inputs would expose different index sizes.
This hides that particular additional length leak; candidate cardinality, selected
pages/addresses, repetition and timing remain visible. It is not concealed access.

## Bounded selection and rejection

Before reading posting pages or encrypting FHE inputs, authenticate/decrypt page
zero and require:

- The V2 schema and exact one-byte/4096-byte layout; plaintext length exactly
  header + B(data_rows), with data_rows <=1,000,000 and B(0)=0.
- Exact equality of the embedded 112-byte data commitment and the requested head.
- Count sum exactly equal to the data row count, first offset zero, final real
  posting offset no greater than B(data_rows), and monotonic offsets.
- Empty counts exactly matching empty byte spans. For nonempty groups, count <=
  encoded byte length <=5*count, with checked arithmetic.

Sum counts for the complete candidate age range. Reject above the lower of caller
budget and hard MAX_ROWS=256; never return a truncated group. This requires only
the first index page, including for a million-row single-age group.

For accepted selections, read only pages intersecting the chosen bucket byte
spans. Cache page zero rather than fetching it twice. Authenticate each page
against the current index head before decrypting/consuming its bytes. The decoder
can cross page boundaries but cannot consume a byte beyond the current bucket.
Reject truncation, more than five groups, a fifth group beyond u32, noncanonical
leading zero groups, zero later gaps, ordinal addition overflow, out-of-table
addresses, extra real-bucket bytes after the count, and duplicate ordinals across
selected groups. No allocation follows an untrusted posting count before preflight.
The decoder
never consumes the encrypted padding as a posting; padding-only pages are not
queried. AEAD/Merkle authentication still binds their stored ciphertext bytes.

These checks validate selected encoding and trusted-head consistency. Unselected
postings are not scanned; their meaning remains tied to the trusted owner-built
snapshot. This preserves selective access rather than claiming a new SQL proof.
With at most 256 selected rows and five bytes per posting, their contiguous bucket
span is at most 1280 bytes, so it intersects at most two posting pages in addition
to the header page. Some boundary pages also contain unselected bytes.

## Amount updates and restart

Amount-only changes do not alter ages or ordinal positions. The existing owner
checks/stages its UPDATE, then `index::rebound` verifies the old binding, retains
all metadata/postings and replaces only the first encrypted page with the new
112-byte commitment. The first page may contain posting bytes after the header;
that suffix is retained exactly. All later encrypted page packets remain byte
identical. The new index root/revision changes, old bindings are rejected against
the new data head, and no historical overlay is retained in the live snapshots.

Canonical encode/decode rebuilds Merkle hashes and requires independently supplied
expected heads at the Owner restore boundary. This is restart with the same live
key authority, not durable secret-key recovery or distributed head consensus.

## Storage bounds and actual experiment

For N<=1,000,000, every encoded ordinal/gap is below 2^20 and needs at most three
bytes. For each age, the sum of its first absolute ordinal and later gaps equals
its last ordinal, at most N-1. Across 256 ages that sum is at most 256*(N-1).
Consequently the posting payload is bounded by

`B(N) = N + min(N, floor(256*(N-1)/128)) + min(N, floor(256*(N-1)/16384))`, with B(0)=0.

This is an encoding bound derived from the format, not a performance measurement.
At one million rows it is at most 2,015,624 payload bytes. Including the header,
493 AEAD index pages and outer manifest gives exactly 2,041,564 bytes for
the default padded canonical encrypted index for every age distribution. With
256 data rows/page, the actual data geometry
is 3,187,648 bytes. Thus data plus the padded index is 5,229,212 / 3,000,000 =
1.743071x for that geometry, before keys, independent owner state, rebuildable
hash caches and replicas. Small tables have proportionally larger fixed overhead.

[index_storage.rs](../crates/compact-query/examples/index_storage.rs) generates a
real shared key pair, seals actual public million-row fixtures with uniform,
90%-skewed, deterministic pseudorandom and single-age distributions, then encodes
and restores both encrypted images against their exact trusted heads. It reports
actual canonical data/index bytes, rebuildable hash payload, complete serialized
owner/evaluator FHE key sizes, owner symmetric/domain state, trusted heads and the
combined total including keys. No FHE result, pad or expanded row table is retained.
It does not write keys or database images. Timings printed during setup are not
query latency measurements.

Measured on 2026-10-14 at 21:04 UTC (2026-10-15 in Moscow), Windows x86_64,
AMD Ryzen 9 9950X3D2, Rust 1.99.0, pinned TFHE-rs 1.8.1. The uniform, skewed,
pseudorandom and single-age cases all produce exactly the following actual sizes;
each canonical data/index encode-and-restore check passed against its exact heads.
This is a size experiment; no FHE query was evaluated.

| Component / combined total | Actual bytes | / 3,000,000 logical bytes |
| --- | ---: | ---: |
| Canonical encrypted data | 3,187,648 | 1.062549x |
| Canonical encrypted padded index | 2,041,564 | 0.680521x |
| Data + index | 5,229,212 | 1.743071x |
| Rebuildable hash payload | 281,824 | 0.093941x |
| Data + index + hash payload | 5,511,036 | 1.837012x |
| Serialized owner FHE key | 31,268 | Separate fixed key material |
| Serialized peer evaluation key | 180,610,708 | Separate fixed key material |
| Owner symmetric key, database/domains | 80 | Separate owner state |
| Independently retained data/index heads | 224 | Separate owner state |
| Data + index + keys + owner state | 185,871,492 | **61.957164x** |
| Previous total + hash payload | 186,153,316 | 62.051105x |

The complete key set is shared by the Owner/Evaluator pair, so multiple tables
could amortize it, but this one-table measurement does not establish <=2x after
including keys. The table's fixed million-row cap is unchanged. Do not describe
its 1.743071x data/index ratio as a complete system footprint. Hash payload excludes
allocator/container overhead; no peak-process RAM or replicas are inferred from
these serialized counts.

The generated metrics report is ignored local output:
`.local/fhe-research/index-storage-1000000-padded-20261014-210436-153.jsonl`.
No keys, database images or participant data were saved.

## Validation and reproduction

The index-owned contract tests cover complete equality/range groups for all four
distributions, absent buckets, exact budget preflight, one/two/three/four/five-byte
integer encodings, a two-byte integer straddling pages, selective page traffic,
malformed header/postings, selected duplicates, empty tables, restarted images,
fixed-capacity padding, authenticated padding bytes, and unchanged later ciphertext
packets after repeated amount-only data updates.
All 11 index-owned tests passed, including nine repeated amount replacements and
canonical restarts. Strict Clippy for every compact-query target, rustfmt, local
documentation links and diff checks pass. The existing public Owner/Evaluator
tests remain necessary after integration to validate genuine
FHE and owner-checked compact writeback after integration.

```sh
cargo test --release --locked --offline -p compact-query index::tests -- --test-threads=1
cargo clippy --release --locked --offline -p compact-query --all-targets -- -D warnings
cargo run --release --locked --offline -p compact-query --example index_storage -- 1000000
```

Run CPU-heavy checks serially with the other FHE research. Generated local metric
reports belong in ignored `.local/fhe-research/`. All fixtures here are deliberately
public and synthetic. The full 500 ms requirement still needs a measured complete
proof/transport/freshness pipeline; this format change addresses index storage.