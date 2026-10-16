# Native BFV original-input formation oracle

Validated on 2026-10-16: native release build, seven serial tests, strict
all-targets Clippy and the three-layout CLI passed. This standalone PUBLIC
NONSECRET research consumer checks the exact upstream secret-key encryption
equation. It produces no cryptographic proof or SQL answer.

The private binary has no public library/API or input-file mode.

The fixture uses pinned fhe/fhe-math/fhe-traits/fhe-util 0.1.1, Rand 0.9.2,
rand_chacha 0.9.0 (ChaCha8Rng) and zeroize 1.9.1. N8192, the unchanged five
43/44-bit moduli (Q218), t114689 and variance10 match
[bfv-query-core](../../crates/bfv-query-core/README.md). No project library
depends on this experiment; the root manifest/default members remain unchanged.

| Module | Owned responsibility |
| --- | --- |
| packing.rs | Original exact SELECT age/amount/presence, UPDATE amount limbs, and Q2 aggregate coefficient lanes; all unused slots zero |
| ntt.rs | Separate canonical u128 butterflies, exact public root and SIMD conventions; no lazy/Shoup implementation |
| oracle.rs | Real upstream key/encryption, caller-RNG replay, signed support, independent scaling/NTTs and every public b residue |
| tests.rs | Observable native parity and rejection controls, not proof-security tests |
| main.rs | Runs only the three fixed known nonsecret source fixtures; emits counts, never key/noise/slot values or timings |

Key and error fixtures use explicitly known fixed nonsecret RNG seeds. A clone
immediately before each real upstream call reproduces its CBD(20) vector:
8192 times (20 add bits minus 20 subtract bits), exactly 5120 next_u64 calls.
RNG positions are checked. The upstream ciphertext's a seed comes from INTERNAL
rand::rng(), not this supplied RNG. The oracle reads a from the actual ciphertext;
it neither controls/replays that internal source nor proves entropy.

For SIMD, reproduce matrix_reps_index_map and the plaintext-modulus inverse NTT.
For coefficient packing, use original coefficients directly. Then compute
w=(M*(Q modt)) modt (Q modt=78307), and per qi use delta=inverse(-t modqi).
The oracle scales in coefficient space, transforms s/e/delta*w, then checks
b=NTT(e)-a*NTT(s)+NTT(delta*w) modulo EVERY qi. Scaling commutes with this NTT.
All 40,960 b residues must match. Real upstream decryption is an extra positive
control, not the formation check. Public fresh ciphertexts may use seed compression;
the check concerns canonical residues, not equality of rebuilt serialized bytes.

This is native recomputation of a public research fixture. It is NOT a fast
verifier, a private formation proof, an input-completeness proof, a source/key
anchor, a valid-query marker, an Owner key exporter/importer or a production API.
It does not connect C_open to BFV secrets/evaluation keys or certify noise
randomness, RLWE security, zeroization, private data secrecy, RAM or latency.
A future proof must constrain all original source values, selection/plan,
SIMD encoding, cross-modulus common small s/e, integer-safe products/ranges,
NTT routing, independently authorized key anchors and exact public requests.
Successful native parity supplies none of those accepting capabilities.

Reproduce from the repository root with the pinned dependencies already cached
and a fresh isolated target. The checked-in standalone lock needs no regeneration:

```powershell
$env:RUSTUP_TOOLCHAIN='1.99.0-x86_64-pc-windows-msvc'
$env:CARGO_HOME='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR='.local/target-bfv-formation-oracle-repro'
$env:CARGO_BUILD_JOBS='2'; $env:RAYON_NUM_THREADS='2'
$env:RUSTFLAGS='-C target-cpu=native'
Remove-Item Env:CARGO_BUILD_TARGET,Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
cargo build --release --offline --locked --manifest-path experiments/bfv-formation-oracle/Cargo.toml
cargo test --release --offline --locked --manifest-path experiments/bfv-formation-oracle/Cargo.toml -- --test-threads=1
cargo clippy --release --offline --locked --all-targets --manifest-path experiments/bfv-formation-oracle/Cargo.toml -- -D warnings
& (Join-Path $env:CARGO_TARGET_DIR 'release/bfv-formation-oracle.exe')
```

Source contracts are [exact SELECT](../../crates/bfv-query-core/src/indexed_select.rs),
[indexed UPDATE](../../crates/bfv-query-core/src/indexed_update.rs), and
[Q2 aggregate](../../crates/bfv-query-core/src/polynomial_aggregate.rs). The cached
fhe 0.1.1 source VCS is fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a:
secret_key.rs owns the actual key/encryption sampling, plaintext.rs owns scaling,
parameters.rs owns the SIMD map, and fhe-math ntt/native.rs owns the twiddle convention.

Actual validation used Rust 1.99.0 (b940084d7), x86_64-pc-windows-msvc,
`-C target-cpu=native`, jobs2/Rayon2, parent
5a4eba146a85119ee2e1fe8b27d0e270247e6ea7 and the separate
MAIN/.local/target-bfv-formation-oracle target. Its standalone lock SHA256 is
DAA240A1D9EE211E9773AEED31B0FF05AE49C98CD2422B1BE8B89C0BB5690F40:
72 packages, including 71 registry identities/checksums exactly present in the
root lock and this local binary. Root manifests/lock and core sources are unchanged.

Retained ignored records are MAIN/.local/bfv-formation-oracle-runs/
20261016-183503-963-lock and 20261016-184453-339-native-r5. The latter records
all four actual commands/exit0, seven passed/zero ignored tests, three CLI JSON
results, original profile/counts, toolchain and artifact identities.
CLI output contains no witness values or timings; Cargo build/test durations are
not operation measurements. Its success.json SHA256 is
DB069CE57E9317FBBC1E038468AD922AA837BA0EE5B6597A50B72DC66BD8A76F.
Compiled source freeze: 9458A8C538E6D8F4CDBA96C47A7C7B50A54421D30DBB088160B75DC240949C3A.
CLI: 0A0149B7F49929BED6F28DE8FCA2AFB81E3109387A415158F8CA04324273BC91.
Test: C77C3479671FBECE7DB4F00EEAD0E7EA5D001066745BA26C764A0802DFFB5824.
Only documentation changed after those compiled source hashes were frozen.

Four earlier build-only attempts stopped on generic trait inference
(E0277/E0282); their logs and oracle sources remain in the same run parent:
183907-010-native, 184122-183-native-r2, 184242-746-native-r3 and
184356-447-native-r4 (all prefixed 20261016-). The only repairs made Plaintext
references explicit and selected the existing BFV encryption/u64 decoding traits;
no sampling, arithmetic, packing or rejection check changed. No tests ran in those
failed attempts. No performance, resource or proof-security conclusion follows
from these native parity results. Do not use production keys, participant data or
secret witness logs.
