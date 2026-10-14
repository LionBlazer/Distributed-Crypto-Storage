# FHE prototype

This local experiment tests whether basic relational operations can run on encrypted
values and survive repeated compression and reloads. It uses real TFHE-rs CPU
operations, with a fixed schema `age: u8, amount: u16`. The library exposes typed
operations; the binary supplies public synthetic fixtures and measures them.

The opt-in [transciphering example](../../docs/transciphering-probe.md) separately
tests compact AES/PRF input converted to FHE for one addressed COUNT/SUM query.
It compares four conversion modes and explicit CPU budgets, with complete local
wire/key accounting. It does not change library storage, supply an SQL index or
implement compact updates. Its format is separate from compact-store.

The opt-in [proof-cost probe](../../docs/experiment-query-proofs.md) counts native
PBS operations for the scalar conversion, selected COUNT/SUM and overflow-safe
u16 UPDATE, and measures a serialized 128-bit ciphertext. Enable only the
`proof-cost` feature for that example. It generates no computation proof and does
not change production acceptance or the library's Owner/Evaluator APIs.

There are no direct dependencies on other project modules. The binary and API tests
and [GUI playground](../fhe-playground/README.md) are the library's consumers.
TFHE-rs 1.8.1 is pinned as an experimental dependency;
the production cryptographic stack remains undecided. Consult its
[license and patent terms](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/LICENSE)
before adopting it in a product.

## Implemented operations

- Encrypt rows, a comparison threshold, and an update delta at the owner.
- Full-scan filtering by encrypted `age == threshold` or `age >= threshold`.
- Return encrypted COUNT and SUM with TFHE's specialized multiple-input sums.
  COUNT uses a private 12-bit accumulator before returning the existing `u32`
  result; SUM masks stored `u16` values before widening them to `u32`.
  An empty selection returns zero for both; SQL NULL semantics are not implemented.
- Add an encrypted delta to matching amounts. If any matching amount would overflow
  `u16`, an encrypted condition retains every original amount. The evaluator never
  decrypts or branches on whether an individual row matches or an overflow occurred.
  The overflowing adder supplies both the candidate amount and its encrypted carry.
- Compress the table with TFHE's `CompressedCiphertextList`, including after updates,
  and restore it with the same evaluation key.

The API bounds tables at 1,024 rows and images at 64 MiB. The row bound also prevents
overflow of the aggregate accumulators, with compile-time checks for their widths.
These are experiment guards, not a validated
peer RAM budget. Equality, range boundaries, empty results, wide sums, update overflow,
and repeated compression are tested at the public API boundary.

## Ownership and public API

| Entry point | Responsibility |
| --- | --- |
| `Owner::generate` | Generate an owner with a secret key and an evaluator with only evaluation material. |
| `Owner::encrypt_table`, `encrypt_predicate`, `encrypt_delta` | Create opaque ciphertext inputs. |
| `Evaluator::aggregate` | Compute `UnverifiedAggregate` without the secret key. |
| `Evaluator::add_amount` | Modify an owned table and return encrypted `UnverifiedUpdate` status. |
| `Evaluator::compress_table`, `restore_trusted_image` | Encode/decode a local experiment image. |
| `Owner::decrypt_*_for_experiment` | Read locally trusted results without checking a query proof. |

Ciphertexts and keys stay behind crate-owned types. Dropping these types releases
their allocations; an evaluator clone shares the underlying server key. The evaluator
sets and restores TFHE's thread-local evaluation context around each operation. A
random public domain identifier catches accidental mixing of different key sets; it
does not authenticate a table, predicate, or result.

Secret keys are neither exposed nor serialized. Disk images contain encrypted rows,
their count, and the public domain identifier. This experimental format is not a
durable database format: the CLI generates fresh ephemeral keys on each invocation,
so old images cannot be queried by a later invocation. Save/load cycles happen within
one run. Writes are not crash-safe transactions.

## Run and measure

Run from the [workspace root](../../README.md), using a release build. The manifest
requires Rust 1.91.1 or newer; measurements should record the actual compiler and host.

```sh
cargo run --release --locked -p fhe-prototype -- --rows 4 --cycles 2 --threads 2
cargo test --workspace --release --locked -- --test-threads=1
cargo clippy --workspace --all-targets --release --locked -- -D warnings
```

On Windows, Rust's MSVC toolchain needs the C++ linker/build tools. The first build
compiles TFHE and can take several minutes. `--help` lists options for row count,
update cycles, age threshold, delta, Rayon threads, and output directory. Defaults
are four rows, two cycles, threshold 18, delta 5, and two threads. The initial result
is COUNT=2, SUM=50; successive successful updates produce SUM=60 and SUM=70.

Each run creates a unique ignored `.local/fhe-runs/run-.../` directory, stores the
current `table.fhe`, and prints/writes `report.json`. It checks decrypted results
against the public fixture solely to test local behavior. That comparison is not a
cryptographic proof suitable for accepting an untrusted peer's answer.

The report includes key generation, encryption, query plus decryption, update plus
status decryption, and compression/write/read/decompression timings. Disk timings
include normal buffered filesystem I/O; they do not measure a forced durable flush.
It also records compressed image bytes, serialized evaluation-key bytes, and process
high-water resident memory on Windows/Linux/macOS. The memory measurement includes
owner and evaluator, keys, fixtures, and temporary operation buffers in one process;
it is not a measurement of an isolated peer. Evaluation-key serialized size is not
its RAM footprint. Other platforms report memory as `null`.

Storage expansion divides compressed image bytes by `rows * 3` logical plaintext
bytes, excluding Rust padding, replicas, and keys. Small fixtures include substantial
fixed ciphertext overhead; they do not establish expansion or latency for realistic
databases. The experiment uses TFHE's
`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` and matching compression preset.

### Initial measurements

These measurements predate the [scan kernel optimization](../../docs/experiment-fast-scan.md).

Observed on 2026-10-14 with rustc 1.99.0, Windows 11 Pro x86_64, AMD Ryzen 9
9950X3D2 (16 cores / 32 logical processors), approximately 94 GiB visible RAM,
and **two Rayon threads**. Both runs use the default threshold 18 and delta 5;
the second run changed to `--rows 16 --cycles 1`.

| Measurement | 4 rows, 2 cycles | 16 rows, 1 cycle |
| --- | ---: | ---: |
| Logical plaintext | 12 B | 48 B |
| Compressed table, before and after updates | 2,167 B | 3,055 B |
| Table expansion | 180.6x | 63.6x |
| Query plus decryption, across the run | 2.638–2.874 s | 10.598–11.008 s |
| Update plus status decryption | 1.879–2.195 s | 7.677 s |
| Compression / disk round trip | 0.312–0.329 s | 1.228–1.266 s |
| Whole-process peak resident memory | 489.0 MiB | 488.2 MiB |
| Whole experiment | 15.083 s | 33.716 s |

The serialized evaluation key was 310,667,319 B (296.3 MiB) in both runs;
key generation took 1.79–1.87 s. COUNT/SUM were `(2, 50) -> (2, 60) -> (2, 70)`
and `(8, 200) -> (8, 240)`. Images retained the same size through updates.
These two small runs show substantial storage expansion and expensive full scans.
They do not meet the 1–2x storage target or establish interactive query latency;
the roughly constant memory measurement reflects this tiny workload, not scaling
to a peer's full storage quota. Larger workloads and alternative FHE execution
strategies need separate measurements.

### Storage and indexed query optimization

[Optimization research](../../docs/fhe-optimization.md) records the current
compression preset's structural overhead, larger storage probes, a measured
aggregation variant and two index privacy models. The active acceptance goal is
canonical encrypted storage at most 2x logical plaintext size and 500 ms indexed
queries; the earlier research target was 100 ms, preferably 50 ms. The current
evaluator does not establish either indexed-query target or compact storage.

The `storage_size` example measures image growth through 1024 rows without scanning
the table. `query_layout` compares the previous serial scan/update kernels, the
current narrower COUNT/specialized SUM/overflowing-adder kernels, and an experimental
scan with parallel initiating threads. It verifies decrypted answers and updated
amounts and reports latency and process peak memory. They use the same TFHE parameters.
The parallel experiment adds initiating threads to the declared Rayon worker count;
the library retains serial row traversal. See [methods and limits](../../docs/experiment-fast-scan.md).

```sh
cargo run --release --locked -p fhe-prototype --example storage_size
cargo run --release --locked -p fhe-prototype --example query_layout -- 2 3
cargo run --release --locked -p fhe-prototype --example query_layout -- 8 3
```

## Boundaries and unresolved requirements

The evaluator learns the schema, row count/order, comparison operator, operation
sequence, and timings. The threshold, delta, row values, and match conditions are
encrypted. This leakage model needs approval before designing indexes or networking.
The benchmark executable contains both roles and a public plaintext reference; it
demonstrates the API boundary, not process isolation.

FHE provides computation on encrypted values; it does not prove that a malicious
evaluator used the requested query or complete, fresh data. Results remain explicitly
unverified. The image loader is for locally generated, trusted images: size, format,
type, and domain checks do not authenticate ciphertexts or make malicious payloads
safe. No peer authorization, agreed version, freshness, or tamper-proof storage
protocol is implemented.

Open work against [REQUIREMENTS.md](../../REQUIREMENTS.md) includes query proofs;
SQL types, NULLs, joins and ordering; privacy-preserving indexes and batching;
bounded streaming execution; durable key/data lifecycle; and distributed replication,
recovery and failure handling. The 1–2x storage, 1–2 GB RAM, and interactive latency
targets must be evaluated on representative workloads before broader implementation.
