# Compact query composition experiment

This report preserves the initial implementation and successive integration
measurements. The current padded V2 index is described in the
[index format report](experiment-index-compression.md); the latest narrowed
encrypted predicate/output kernel and its independently validated SQL boundary
are in the [query wire report](experiment-query-wire.md).

This experiment composes the existing compact-store authenticated XChaCha20Poly1305
pages with selective genuine TFHE evaluation and compact owner-assisted update
writeback. It is implemented by the independent
[compact-query](../crates/compact-query/README.md) crate. It does not establish
arbitrary SQL, a distributed query SLA, concealed index access or query proofs.

The peer retains only canonical compact-store encrypted table pages and a
rebuildable Merkle tree. The owner supplies freshly encrypted stream masks for the
selected rows; no secret key, plaintext row or plaintext pad crosses to the peer.
The mask is derived at the owner by authenticated AEAD decryption XORed with the
public ciphertext, rather than by an invented stream cipher or key export.
The evaluator XORs those masks with public stored bytes, then executes encrypted
age equality/range predicates, COUNT, SUM and AddAmount. COUNT/SUM outputs are u32;
all matching amount updates are globally rejected if any u16 addition overflows.

## Actual index and update lifecycle

The owner builds an encrypted complete age posting index when sealing the table.
Its canonical plaintext layout, entirely AEAD encrypted, is the exact 112-byte
table commitment, 257 u64 group boundaries and one u32 row ordinal per row.
Owner-side boundary lookup plus authenticated posting-page retrieval returns every
candidate for an equality or inclusive age range. No row-ordinal request is labeled
as a SQL index. A caller-provided candidate range must contain the whole predicate
range, and the peer still evaluates the encrypted predicate on all candidates.

The owner-issued trusted index head authenticates this owner-built policy; an
exact encrypted table-head binding prevents mixing a current table with a stale
index. Successful AddAmount updates keep age/posting order constant, reencrypt
changed data pages with fresh nonces and a single new table revision, and reencrypt
the index binding page. The owner verifies the decrypted update by repeating the
selected plaintext calculation locally. Both encrypted images are staged before
either live image changes, and retain fixed geometry with no historical overlay.
This is an explicitly trusted local experiment, not succinct query verification or
durable crash-atomic storage.

MAX_TABLE_ROWS is 1,000,000, but MAX_ROWS is 256 selected/materialized rows per
request. The latter is checked before FHE mask allocation. Larger complete groups
or full scans return SelectionBudget with their actual count. They are never
silently capped to obtain a latency result. Wire objects have a 128 MiB limit;
hostile FHE parameter/allocation hardening is not implemented. An honest 256-row
mask request is about 50 MiB, with key/evaluation/output transients additional.

## Measurement scope and reproduction

The standalone example uses one million public synthetic age:u8/amount:u16 rows,
256 rows per table page and 4096 bytes per encrypted index page. Rare complete age
groups contain exactly 1, 4 and 16 rows; one absent age produces zero candidates.
A range query returns all 21 rare rows. Each query freshly authenticates the index
and data, encrypts masks/predicate, round trips request/output encodings, converts
the selected compact bytes, evaluates real FHE and decrypts at the owner.

The repeated update case performs at least 100 fresh encrypted point AddAmount
queries and owner-local verification/writeback operations. Every iteration then
encodes and freshly decodes both full encrypted images and checks old-output
rejection and constant live size. A genuine four-row AddAmount case is included.
First key restore and complete image reconstruction are reported as cold in-memory
work, not cold disk IO. Setup, key sizes, data/index sizes, request/output/proof
traffic and all measured stage times are reported separately.

Run serially with other benchmarks stopped:

~~~sh
cargo test --release --locked --offline -p compact-query -p compact-store
cargo clippy --release --locked --offline -p compact-query -p compact-store --all-targets -- -D warnings
cargo run --release --locked --offline -p core-workloads --example compact_query -- 1000000 5 100 8
~~~

On the Windows research host, use E:/Users/white/.cargo/bin/cargo.exe, with
CARGO_HOME pointing to the main checkout's .local/cargo-home and CARGO_TARGET_DIR
to its target. The experiment worktree starts at 9b95d21. Generated JSON belongs
in ignored .local/fhe-research; no generated data, key or report is repository source.

Timings exclude transport, disk IO, consensus, latest-head agreement and query
proof generation/verification. Candidate count/addresses, equality/range shape,
geometry, revisions, repetition and timing leak. The private index policy remains
owner-assisted; it is not a concealed peer index. Reconstructing images with the
same live owner tests encrypted snapshot restart, not durable secret-key recovery.
Aggregate decryption does not establish correct computation. Update verification
repeats work at the owner and does not satisfy the project's proof requirements.

## Serial composition measurements

Measured serially at 2026-10-14T20:47:19.5372924Z on Windows 10.0.26200 x64,
AMD Ryzen 9 9950X3D2, 16 physical/32 logical processors, Rust 1.99.0, release
profile and the checked-in lockfile. The standalone process used eight Rayon
workers, one initiating query thread and fresh ephemeral keys. Other CPU research
benchmarks were stopped. This is the initial serial evaluator, before optional
row-initiator or compressed-index experiments.

| Full local operation | Samples | p50 | p95 | p99 / maximum |
| --- | ---: | ---: | ---: | ---: |
| Indexed aggregate, 1 selected row | 5 | 72.34 ms | 83.37 ms | 83.37 ms |
| Indexed aggregate, 4 selected rows | 5 | 479.60 ms | 499.70 ms | 499.70 ms |
| Indexed aggregate, 16 selected rows | 5 | 1671.49 ms | 2052.57 ms | 2052.57 ms |
| Indexed aggregate, absent age / 0 rows | 5 | 0.69 ms | 0.94 ms | 0.94 ms |
| Point UPDATE, owner verification/writeback and fresh complete image decode | 100 | 207.28 ms | 278.21 ms | 306.38 / 316.07 ms |

The 21-row inclusive range aggregate took 2510.20 ms. An actual four-row UPDATE,
including owner verification and compact writeback, took 867.52 ms; that single
case did not include the extra full-image decode. The first cold in-memory
key/image restoration plus one-row query took 186.04 ms, of which key restoration
was 46.49 ms, image encode/decode/rebuild 7.00 ms and the query round trip 126.34 ms.
Key generation (604.10 ms), key serialization (43.74 ms) and initial table/index
construction (25.52 ms) are separate setup costs.

The one-row update case meets the local 500 ms budget in these samples. Sixteen-row
aggregates and four-row updates do not. Four-row aggregate samples approach 500 ms
before transport or computation proofs, so they do not establish an end-to-end
500 ms guarantee. Five aggregate samples make nearest-rank p95/p99 equal their
maximum; they are descriptive observations, not production tail estimates.

### Exact bytes and memory

| Component | Measured bytes |
| --- | ---: |
| Packed logical plaintext, 1,000,000 rows | 3,000,000 |
| Canonical compact encrypted table | 3,187,648 |
| Encrypted complete u32 age index | 4,049,224 |
| Data plus index, initial and after every update | 7,236,872 |
| Additional rebuildable data/index hash payload | 312,896 |
| Serialized owner TFHE key | 31,268 |
| Serialized evaluator key and public domain | 180,610,708 |
| Owner symmetric key/database/domain metadata | 80 |
| Two independent trusted owner head encodings | 224 |
| Joint persistent accounting above, excluding rebuildable hashes | 187,879,152 |

The data image is 1.062549333x logical data. Data plus this index are 2.412290667x;
including all listed fixed keys/state is 62.626384x for this three-megabyte table.
Thus the experiment does not establish a combined 2x storage bound. The hash tree
is reconstructed in RAM; persisting it would add its bytes. One table replica is
counted. No persistent FHE row, plaintext/pad cache, historical overlay or query
proof bytes are present. The four-megabyte public Rust fixture is measured and
dropped before queries; its three-byte packed row denominator is not struct padding.

Aggregate request sizes are 131,922 / 329,546 / 922,418 / 3,293,906 bytes for
0 / 1 / 4 / 16 candidates, respectively. Every serial aggregate response is
527,161 bytes. A nonempty indexed query additionally reads 5,240 encoded index
page/proof bytes, 1,216 owner-side data-page/proof bytes and 1,216 evaluator-side
data-page/proof bytes. The empty case reads 4,480 index bytes and no data pages.
The four-row UPDATE request/response are 1,054,154 / 1,070,617 bytes. These are
actual serialization and proof bytes, not a transport latency measurement.

Kernel high-water working set was 398,618,624 bytes (380.15 MiB), and peak process
commit charge was 395,550,720 bytes. The complete child process took 37.41 seconds.
This includes both roles, key wire buffers, source setup and all transient query
objects; it does not isolate peer RAM. A hidden/no-shell .NET process wrapper kept
the process handle and called GetProcessMemoryInfo after exit, without polling
within measured operations. Its own memory is outside the child measurement.

All 100 point updates passed exact expected-value checks, kept the same encoded
data/index lengths, reconstructed both images from fresh bytes and rejected each
old output against the updated head. The final table revision is 101 after the
additional four-row update. The focused release suite passed nine compact-query
and 21 compact-store tests, and strict release Clippy passed all their targets.
The run's ignored files are .local/fhe-research/compact-query/serial-8t.jsonl,
serial-8t.stderr.txt, serial-8t.process.json and measure.ps1. The measured executable
SHA-256 is 8DA7CE65E398264509313EDBE121512F87E8442E8795BEA42410D2780F2BCA73.

## Bounded scoped row initiators

An opt-in evaluator policy preserves the same public API, exact TFHE security
parameters, masks, predicate semantics and compact writeback. It creates up to
eight scoped OS initiating threads outside the global Rayon pool, installing a
server-key context on each thread. They share the public server-key allocation
and the same eight internal Rayon workers; owner keys/plaintext are not supplied.
One-row and empty phases do not spawn workers. Default and restored evaluators
retain serial policy; with_row_workers_for_experiment explicitly selects 1..8.

Two serial process runs on 2026-10-14T20:59:21.7970114Z and
2026-10-14T20:59:45.3092397Z compare policies 1 and 8 using the same release
executable, host, million-row fixture, parameters and old u32 posting index. Each
process creates fresh keys and fresh request masks. This is a configuration
comparison, not a statistical paired-input or production-load study. Each aggregate
has five samples; each point UPDATE has 30 fresh queries and complete image decode.

| Full local operation | Serial policy 1 | Scoped policy 8 |
| --- | ---: | ---: |
| 1-row aggregate p50 / p95 | 93.59 / 98.70 ms | 98.88 / 103.11 ms |
| 4-row aggregate p50 / p95 | 532.36 / 572.24 ms | 426.31 / 445.14 ms |
| 16-row aggregate p50 / p95 | 1879.35 / 1973.23 ms | 1320.99 / 1345.11 ms |
| Empty aggregate p50 / p95 | 0.69 / 0.90 ms | 0.81 / 1.14 ms |
| 21-row range aggregate, one sample | 3227.41 ms | 1880.93 ms |
| Point UPDATE + fresh decode p50 / p95 / maximum | 253.77 / 271.92 / 275.91 ms | 242.44 / 283.56 / 300.52 ms |
| 4-row UPDATE + fresh decode, one sample | 1072.81 ms | 896.88 ms |
| 16-row UPDATE + fresh decode, one sample | 4079.88 ms | 3083.89 ms |
| Empty UPDATE + fresh decode, one sample | 7.25 ms | 6.98 ms |
| Kernel whole-process peak resident bytes | 399,310,848 | 398,692,352 |
| Complete child-process wall time | 29.37 s | 23.47 s |

The four-row aggregate p50 improves by about 20%, and the sixteen-row aggregate by
about 30%. One-row aggregate timing is slightly higher, and point-update p95/max
also vary upward; the option does not establish a one-row improvement. Sixteen-row
aggregates, range aggregation and multi-row updates remain above 500 ms. The
option supplies a measured scheduling improvement, not a 500 ms arbitrary-SQL SLA.
Both processes retain exactly 7,236,872 canonical data/index bytes and pass all
value, fresh-decode and stale-output assertions. Final revision is 32
after 30 point updates plus the 4/16-row updates; the empty UPDATE retains its head.

The focused release suite now passes ten compact-query and 21 compact-store tests,
including serial/scoped range results, global overflow rejection, successful
multi-row writeback and invalid initiating-thread budgets. Strict release Clippy
passes all targets. Ignored records are paired-serial-8t-r1 and
paired-parallel-8t-r8 .jsonl/.stderr.txt/.process.json under the same report folder.
Their shared executable SHA-256 is
4CF86A701B72CF4B9AFA6A966DE16FE7F3765F37037D733ED71D256AFB960AC6,
archived as paired-scoped.exe. No keys or data files are saved.

## Integrated padded index and scoped evaluator

On 2026-10-14 at 21:11 UTC, the combined V2
[padded index](experiment-index-compression.md) and scoped evaluator passed a fresh
run on the same million-row fixture. It used eight Rayon workers and up to eight
additional scoped row initiators, unchanged cryptographic parameters and no other
research benchmark running. The GUI adapter explicitly selects this scheduling
budget; the reusable evaluator's default remains one initiator.

| Full local operation | Samples | p50 | p95 | p99 / maximum |
| --- | ---: | ---: | ---: | ---: |
| Indexed aggregate, 1 row | 5 | 96.24 ms | 100.98 ms | 100.98 ms |
| Indexed aggregate, 4 rows | 5 | 434.58 ms | 477.71 ms | 477.71 ms |
| Indexed aggregate, 16 rows | 5 | 1154.98 ms | 1240.72 ms | 1240.72 ms |
| Indexed aggregate, absent age | 5 | 0.79 ms | 1.05 ms | 1.05 ms |
| Point UPDATE, writeback and fresh complete image reconstruction | 100 | 202.38 ms | 264.27 ms | 267.90 / 273.18 ms |

The 21-row range aggregate took 1565.69 ms. Complete 4/16-row UPDATEs including
writeback and fresh image reconstruction took 776.08/2765.27 ms; the empty UPDATE
took 6.66 ms without changing its head. A cold in-memory key/image reconstruction
and first point query took 158.46 ms, with key generation excluded as setup.
These remain local observations, with transport, durable IO, consensus and
computation proofs excluded. Five-read nearest-rank p95/p99 are descriptive maxima.

Actual canonical data and encrypted index were 3,187,648 and 2,041,564 bytes,
1.743071x combined. Both remained exactly 5,229,212 bytes after all 100 point and
two multi-row updates. Every point iteration reconstructed both images, checked
its exact value and rejected its old output against the new head. Final revision
was 102. Rebuildable hash payload was 281,824 bytes, bringing data/index/hashes to
1.837012x. Full fixed keys and independent owner state still bring this tiny
three-megabyte fixture to 61.957164x; see the index report's complete byte ledger.

Kernel peak resident set was 391,970,816 bytes (373.81 MiB), and peak process
commit was 389,091,328 bytes. The same external retained-handle measurement includes
both roles and setup/query transients. Total child runtime was 35.62 seconds.
Ignored records are combined-padded-r8.jsonl/.process.json/.stderr.txt in the same
report directory. The measured executable SHA-256 is
6270031806379DB785AE278AC2762D5D1E70FFDBA2743762DF03DB5CF0C142FE.

The integrated source passed 21 compact-query, 21 compact-store and 72 GUI/API/
worker tests (114 total), strict release Clippy and rustfmt. An independent source
review found no actionable integration defect; this is not a cryptographic audit.
The normal Cargo integration-test command could not replace an already open GUI
executable on Windows. Its newly built integration test was identified by fresh
timestamp and executed directly; all 13 workflow cases passed. No native window
was opened or closed, and the user's running GUI was left alone.

The actual 128-row SQL/manager boundary control, with the same 8+8 budget, measured
five point reads at 86.71–133.57 ms, four-row reads at 417.00–466.59 ms and a point
UPDATE at 257.79 ms. Data/index were 544/2581 bytes for 384 logical bytes;
fixed metadata dominates this tiny example. Its ignored JSON is
.local/fhe-research/gui-compact-padded-r8.jsonl.

The combined version improves storage and multi-row scheduling. It still does
not establish a 500 ms budget for 16-row queries, multi-row updates or complete
adversarial/network execution, nor concealed SQL index navigation.
