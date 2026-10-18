# Fixed BFV ciphertext wire

This library checks the borrowed canonical protobuf wire before an SDK decoder can
allocate polynomials or perform NTT work. Its only dependency is
[bfv-fixed-geometry](../bfv-fixed-geometry/README.md); it has no SDK, proof backend,
protobuf decoder, key, fixture or network dependency.

`validate(&[u8])` allocates no heap storage and retains no input. It first applies a
512 KiB byte limit, then accepts exactly the fixed level-zero N8192/five-Q grammar:
two unseeded NTT polynomials, or one NTT polynomial plus seed32. Each polynomial
contains 223232 packed power-basis bytes. Every residue is checked against its own
ordered modulus. Proto3 omitted-false and explicit-true variable-time metadata are
both valid. Explicit defaults, unknown/duplicate/reordered fields, nonminimal or
overflowing varints, other degrees/representations/levels, extra components and
trailing bytes reject. `WireError` distinguishes the outer byte limit from invalid
encoding. Geometry and byte limits cannot be selected by a submitted message.

The algorithm is extracted from the existing Basis decoder. Basis and Core map its
errors into their own APIs, then retain the actual SDK decoding and semantic checks.
Passing this gate is not an encryption, key-ownership, computation, freshness or SQL
proof. It does not replace SDK deserialization or its canonical roundtrip.

Synthetic wire tests are explicitly public and non-secret. Actual SDK interoperability
belongs to the Basis/Core consumers, and the dcs-peer test exercises malformed input
under real stored heads and an installed setup.

Owning commands for the orchestrator:

```sh
cargo test --release --locked --offline -p bfv-ciphertext-wire
cargo test --release --locked --offline -p bfv-query-core ciphertext_preflight_tests
cargo test --release --locked --offline -p bfv-basis-convolution borrowed_preflight
cargo test --release --locked --offline -p dcs-peer --test process_transport ciphertext_preflight
```


## Executed validation

Release/offline/locked validation on Rust 1.99.0, Windows MSVC and native CPU flags
passed 115 runtime tests: all 5 wire tests, all 5 Basis tests, 103 Core unit and
integration tests, and 2 actual process/TLS tests. All 8 newly declared cases were
discovered in the newly built binaries and executed. Fifteen Core doctests, the
requirements mirror and the core dependency/target contract also passed. The default
Core build and strict Clippy for the affected libraries, peer runtime, peer app and
research consumer passed. Existing AIRs, proof profiles and old test bodies are
unchanged; unrelated historical cryptographic suites were not all rerun.

The hostile TLS case installs an actual setup and stored object with matching
heads, verifies genuine public-product proofs before and after the malformed
request, and decrypts the final encrypted response with the original Owner. The
2299 tiny degree8/NttShoup records occupy 524172 bytes, below the 512 KiB cap; the
peer returns the Core InvalidShape error and remains usable. This is arithmetic
admission coverage, not SQL selection or key-authority evidence.

The test harness and its independent daemon were sampled separately and at aligned
instants. In this hostile case, the daemon's sampled OS peak working set was
169160704 bytes and the maximum sampled concurrent working set was 213913600 bytes.
Across the selected runtime suite, the maximum sampled working set was 1325486080
bytes, sampled private bytes 1327448064, and sampled OS peak working set 1326907392.
The observer recorded 1414 per-process samples from 14 owned PIDs. Its nominal
100 ms delay is not the actual interval: the largest aligned gap was 1139.4924 ms.
No sampled 1792 MiB per-process or 1200 s per-command soft fuse fired. These are
observations of these tests, not a hard memory bound or live SQL latency result.
