# Compact query composition experiment

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
cargo run --release --locked --offline -p compact-query --example compact_query -- 1000000 5 100 8
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
