# Indexed private-access/FHE experiment

This separate headless probe composes a real PaddedV2 age-index read, native
single-server Spiral reads of index/data pages, authenticated owner decryption,
fresh TFHE selected-field encryption, peer equality/COUNT/SUM, and owner result
decryption. It exists to measure the entire indexed operation and both privacy
profiles against the same visible-address control.

The online owner owns compact-store and TFHE secret keys, trusted heads and
version-bound cached header metadata. The storage/PIR peer owns canonical
encrypted snapshots, native NTT caches and public PIR parameters. The FHE peer
accepts only fresh ciphertext inputs and public querywide metadata. It receives
no original storage ciphertext, nonce, page address or row ordinal.

| Entry point | Owned responsibility |
| --- | --- |
| [run-spiral-index-fhe.ps1](run-spiral-index-fhe.ps1) | Exact SDK checkout/cleanliness check, standalone package preparation, build, run, ignored JSONL output. |
| [spiral_index_fhe_probe.rs](spiral_index_fhe_probe.rs) | Public 1M-row fixture, real transport composition, encrypted evaluator, resource/timing report and actual canonical update/freshness check. |
| [padded_index_codec.rs](padded_index_codec.rs) | PaddedV2 encoding and authenticated callback-based complete posting decoding. |
| [padded_index_codec_tests.rs](padded_index_codec_tests.rs) | Adapted original codec contracts and callback/budget checks. |
| [SpiralIndexFhe.Cargo.lock](SpiralIndexFhe.Cargo.lock) | Exact standalone dependency graph. |

The direct project dependency is
[compact-store](../../crates/compact-store/README.md), responsible for compact
encrypted page snapshots, independent commitments, membership verification and
owner AEAD decryption. The native pinned Spiral SDK is downloaded to ignored
.local/private-access/sdk; it is not vendored or modified. TFHE 1.8.1, Rayon,
serde/bincode, getrandom and zeroize supply the standalone supporting runtime.

From the repository root:

    ./experiments/private-access/run-spiral-index-fhe.ps1 -Rows 1000000 -Rounds 8 -Threads 8

-PrepareOnly installs the ignored standalone package without building or running.
-Offline requires the pinned SDK and locked dependencies to be cached.
CargoHome and TargetDirectory can point to existing project-local caches.
The script restores its process environment on exit.

After preparation, focused checks are:

    cargo test --release --locked --offline --manifest-path .local/private-access/spiral-index-fhe-probe/Cargo.toml
    cargo clippy --release --locked --offline --no-deps --manifest-path .local/private-access/spiral-index-fhe-probe/Cargo.toml -- -D warnings

Read the [complete measured report](../../docs/experiment-private-index-fhe-pipeline.md)
for per-age visible/private results, exact byte/RAM/key accounting, public-length
audit, source adaptation, failure coverage and reproducible assumptions.

The accepted workload is complete age groups of at most 16 rows, fitting one
posting page and one data page. AddressOnly exposes candidate count and RPC
schedule; Fixed16 pads the accepted cases with real dummy PIR reads and encrypted
validity bits. It does not implement arbitrary SQL, hidden writes, offline-owner
execution, malicious-server feedback security or verifiable COUNT/SUM computation.
