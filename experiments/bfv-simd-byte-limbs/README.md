# Exact byte-limb BFV probe

Status: built and measured;52 exact real-FHE successes, one preserved failed
AND-range control. The final additive-range matrix passes30/30 checks with
local whole-operation79.65–220.74 ms for16/256 rows. Independent security,
worst-case noise, network/index/PIR integration and arithmetic proofs remain open.
See the [complete report](../../docs/experiment-bfv-byte-limbs.md) for samples,
negative output, keys/wire/RAM, exact parameters and artifact hashes.

This independent package uses fhe=0.1.1 official default_parameters_128(17),
N8192/Q218/t114689, unchanged CBD variance10 secret/error. It owns its lock;
no main workspace feature/backend is changed. No persistent FHE record copy
is retained. Dependencies are fhe/fhe-traits for BFV, compact-store for actual
authenticated compact fixture pages, serde/bincode for bounded wire and the
platform memory-counter dependency. src/main.rs owns CLI, owner/peer roles,
fixtures, exactness gate and measurement; src/metrics.rs owns process counters.

The owner freshly encrypts low/high amount bytes and eight age/threshold planes.
Four repeated predicate groups yield low SUM at0, high SUM atN/2 and COUNT at8r,
with16r<=N/2. All unused weights are zero. Unsigned limbs each<=65280 and
<=255*COUNT; COUNT<=k. Reconstruct exactu32 SUM=low+256*high<=16,776,960.
Only k16/256 geometries were FHE-tested. Peer has public keys and ciphertexts;
owner holds secrets and performs compact-page authentication/decryption.

From the repository root, set CARGO_TARGET_DIR to the root target directory
before using the executable paths below (PowerShell: `$env:CARGO_TARGET_DIR = Join-Path $PWD 'target'`).
Otherwise this standalone package uses experiments/bfv-simd-byte-limbs/target.
Build default features:

    cargo build --release --locked --offline --manifest-path experiments/bfv-simd-byte-limbs/Cargo.toml --jobs 2
    target/release/compact-bfv-simd-byte-limbs --rows 16 --predicate ge --lower 18 --upper 128 --samples 5 --additive-range
    target/release/compact-bfv-simd-byte-limbs --rows 256 --predicate range --lower 18 --upper 128 --samples 5 --additive-range
    target/release/compact-bfv-simd-byte-limbs --rows 256 --predicate range --lower 0 --upper 255 --fixture allmax --samples 1 --additive-range --noise-diagnostic

Use --additive-range for successful measured closed ranges. It evaluates
GE(age,lo)+GE(hi,age)-1 after owner rejection of lo>hi. The default AND range
remains a reproducible incorrect depth6 control; its timing is not accepted.
Default EQ/GE and additive range have depth5. No plaintext answer substitutes
for FHE; the public-fixture oracle executes after timing. Output is unverified.

The optional optimized-ntt feature and runtime --fused-ge/--output-level flags
are inherited experimental controls; they were not needed or timed in this
byte-limb stage. Native whole-process peak remains below2GB. All-feature authored
Clippy passes, which is distinct from FHE-running every feature combination.
Source/executable/raw archives are ignored and remain separate from tracked code.
