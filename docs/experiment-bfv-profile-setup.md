# Construct only the selected BFV parameter profile

Status 2026-10-15: the reusable BFV core now constructs only its existing
N8192/Q218/t114689 profile. Three fresh processes per variant and geometry
show a reduction in complete cold setup from 1492–1504 to 308–310 ms for
Rows16, and from 1561–1592 to 385–417 ms for Rows256. Whole-process peak RSS
falls from 592/601 MB to 199/241 MB. Warm GE timings do not establish a
speedup; all 36 actual encrypted queries return exact unsigned COUNT/SUM.

## Cause and unchanged cryptography

The locked fhe 0.1.1 implementation of `default_parameters_128(17)` eagerly
constructs every supported degree into a Vec before returning its iterator.
Selecting N8192 with `find` therefore also constructs unused N1024, N2048,
N4096 and N16384 contexts. The old core repeated this during owner generation,
public wire decoding and peer restoration.

The replacement uses the public BfvParametersBuilder with the existing degree,
plaintext modulus, five exact coefficient moduli and variance10. A new owning
test compares its complete serialized parameter wire to the original upstream
catalog entry. Existing profile, ciphertext-level, geometry and wire guards
remain. Secret and error sampling remain CBD(20), variance10; native/unfused
level0 arithmetic and the kernel source are unchanged. Independent security
estimates, worst-case noise bounds and malicious-evaluator proofs remain open.

## Paired process measurements

Windows x86_64, Rust 1.99/MSVC, release/locked/offline, isolated target directory.
No other research build or FHE benchmark ran concurrently. Each row covers three
fresh processes, each generating a fresh owner and performing three actual GE18
queries over a public fixture. The owner and public-only peer are in one process.
Numbers are ranges of observations, not p95/p99 or a universal latency guarantee.

| Geometry / constructor | Complete setup ms | Setup + first GE ms | Nine warm GE ms | Peak RSS bytes | Peak commit bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rows16 / catalog | 1491.83–1504.17 | 1604.48–1617.69 | 111.53–114.58 | 592474112 | 603377664 |
| Rows16 / direct | 308.48–309.68 | 419.81–423.13 | 108.81–114.40 | 199446528 | 203923456 |
| Rows256 / catalog | 1561.02–1592.14 | 1678.94–1710.93 | 115.31–118.73 | 601137152 | 615481344 |
| Rows256 / direct | 384.98–417.23 | 506.73–540.53 | 115.13–132.14 | 240820224 | 252338176 |

Complete setup includes owner/key generation, public serialization and byte
counts, bounded PublicSetup decoding, peer key restoration and dropping temporary
wire/setup handles. Setup + first GE additionally includes the intervening
report output, public-fixture creation, fresh request encryption/serialization,
public peer decode/evaluation/serialization and owner answer decode/decryption.
The after-timing oracle verifies COUNT12/SUM264184 or COUNT192/SUM4226944.
No plaintext enters PeerEvaluator. ProofStatus remains Unavailable.

Rows16/Rows256 public setup remains exactly 8930306/13395426 bytes; owner secret
serialized byte COUNT is 8195. Every query is 670134 bytes and every response
446764 bytes. No generated key or fixture image is persisted. The native memory
guard uses current and OS-maintained peak process counters; it is an admission
check, not an allocator sandbox. All observed peaks are below its 2 GB RSS and
1.85 GB private-commit limits.

These are BFV setup/core measurements. They exclude index/PIR caches, storage
reads, networking, consensus, SQL planning and arithmetic proof generation or
verification. Rows256 cold setup plus first query still exceeds 500 ms. The
previous private-index result is a separately frozen experiment, not retroactively
retimed by this change.

## Reproduction and source identity

Use a dedicated CARGO_TARGET_DIR and the repository's cached CARGO_HOME:

```powershell
cargo test --release --locked --offline --manifest-path experiments/bfv-byte-limb-core/Cargo.toml --jobs 2 -- --test-threads=1
cargo clippy --release --locked --offline --manifest-path experiments/bfv-byte-limb-core/Cargo.toml --all-targets --no-deps --jobs 2 -- -D warnings
cargo build --release --locked --offline --manifest-path experiments/bfv-byte-limb-core/Cargo.toml --example profile_setup --jobs 2
# The label is descriptive; the compiled source selects the constructor.
profile_setup.exe direct 16
profile_setup.exe direct 256
```

The catalog control uses the exact preceding lib.rs from cd3d23d, plus the same
new example/helper and dev dependency. The candidate changes only parameter
construction and its equivalence test. All existing Cargo.lock package versions
and checksums remain equal; only serde_json and its three transitive packages are
added for the example. Resolved fhe/fhe-math features remain native (no optional
optimized-ntt). Four core unit tests and seven public role tests pass; authored
strict Clippy passes across all targets.

| Artifact | SHA256 |
| --- | --- |
| Catalog lib.rs | 6576adf2f81f886d3c6ca0480566e920c8dcadb9f6cf3d4aa0418d5ae9e7dd12 |
| Direct lib.rs | 83d3e4e23803f96544617e88aa6ef2b17dfec274dcb962c168bdafd7dba82c7a |
| Unchanged kernel.rs | 1d719aa6193470c6f3b8c7d28fbc56a87a90d4d14e152a9ce63e5ff47400ae54 |
| profile_setup.rs | 3e21e4437b08b466fa476993bd24758b094be2d453713b7182f46e37cc906b6f |
| profile_memory.rs | f7b1a0310bc96b4498bb4c57eb833ce71f0b53006b80782847993c84d3e3a50f |
| Catalog executable | 3f809c308b7017828361d3697e32ccbd19a192bb9992d13b40de6e4761708d4e |
| Direct executable | 5c6a254234b4570fa58e592d5b1e5d8e6739696d9c972fddc6c6662338e76150 |

Ignored raw logs and frozen executables are retained in the compact-playground
worktree under `.local/fhe-research/profile-setup-20261014-225737-135/`, with
`catalog-{16,256}-{0,1,2}.jsonl` and matching `direct-*` files. Generated outputs
are not committed. The command label does not implement an alternate backend.
