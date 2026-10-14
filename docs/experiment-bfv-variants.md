# BFV SIMD NTT, GE and final-output variants

Status 2026-10-15: separate measured research, no core-backend promotion.
N=16384 output-level 8 passes tested exactness and reduces output bytes, but GE
and range remain above500 ms locally. Independent security validation and
malicious-peer arithmetic proofs remain absent.

The [new package](../experiments/bfv-simd-variants/README.md) preserves the
[original baseline](experiment-bfv-simd.md). Its six original WT files remain
unchanged. Original executable8d5603d2d62365367b975a7ae228f2610b5499b005b0a5315a2a0777f3582502
and those files were copied without replacement under ignored
.local/fhe-research/bfv-baseline-8d5603d2d6236536/.

## Source changes and invariants

The official fhe 0.1.1 feature tfhe-ntt forwards to fhe-math/tfhe-ntt. It selects
a wrapper around tfhe_ntt 0.6.1 prime64 Plan, with native fallback. The wrapper
retains the native operator as well, so a memory increase is plausible.
[Feature forwarding](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/Cargo.toml),
[NTT wrapper](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe-math/src/ntt/tfhe.rs).

The fused GE uses G_H+E_H*(G_L+E_L) at the final four-bit merge.
It saves one product and rotation per GE with unchanged depth. Observed
counts are EQ 5 products/7 or11 rotations, GE 7/9 or13, range 14/14 or18 for
16/256 rows. No plaintext predicate or precomputed aggregate replaces FHE.

Final-output switching uses the official Ciphertext::switch_to_level(8),
after all query arithmetic/reductions. The output retains q0=281474976546817.
All input encryption and public keys still use the full original
N=16384/Q=438/t=33292289 profile, with unchanged CBD variance 10 for secret/error.
[Ciphertext levels](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/ciphertext.rs).
The official leveled relinearization and evaluation-key APIs were inspected;
no multi-level execution schedule was implemented in this bounded stage.

The owner/peer boundaries, fresh input encryption, exact head/request ID,
unsigned u32 aggregate contract, three/four input ciphertexts and complete
local serialization/decryption timing remain as in the baseline. Full
security-estimator/distribution validation is still open; a plaintext
exactness oracle or residual diagnostic does not close it.

## Measurements

Same Ryzen 9950X3D2/Windows 11/Rust 1.99 host as the baseline, release build,
unchanged Q/N/distributions, no global RUSTFLAGS/target-cpu override, no added
worker threads. Measured 2026-10-14 22:05–22:11 UTC. Cases use lower18, and
range upper128. Each process generates fresh keys; every query freshly
encrypts inputs.

Native and NTT-only controls each use5 total samples for EQ/GE and3 for range.
The fused-only series uses the same counts. Output-level 8 uses 3 total samples
for each case, with sample0 cold. Entries below are warm median/max of ALL
samples in milliseconds:

| Operation | Native control | NTT-only | NTT+fused | NTT+fused+output level 8 |
| --- | ---: | ---: | ---: | ---: |
| EQ16 | 597.44 /647.81 | 492.29 /525.13 | 453.10 /463.43 | 419.70 /424.46 |
| EQ256 | 660.47 /686.59 | 570.19 /595.48 | 489.95 /506.11 | 472.05 /483.34 |
| GE16 | 841.81 /874.30 | 731.43 /764.34 | 787.26 /894.30 | 537.88 /540.51 |
| GE256 | 942.86 /1006.86 | 776.29 /828.85 | 1222.55 /1494.64 | 604.09 /629.01 |
| Range256 | 1572.38 /1600.78 | 1391.15 /1404.77 | 2151.09 /2346.69 | 1061.27 /1099.31 |

These are sequential short series, not simultaneous or randomized comparisons.
The fused-only GE/range series regressed despite lower operation counts.
EQ does not use the fused GE path yet also varied. Retain this drift/regression;
do not assign a uniform speedup or attribute the entire final-column timing
difference to output switching. Native NTT remains a lower-memory option.
No tested mode establishes the full500 ms goal: actual transport and proofs
are additional, and GE/range already exceed500 ms.

All94 real-FHE queries passed exact oracles:23 native controls,23 NTT
controls,23 fused controls,10 output-level 8 boundaries and15 output-level 8
matrix queries. The ten boundaries cover EQ0/255/miss 19, GE 0/255, full/empty
ranges, EQ256, range256 and all 256 amounts 65535 with GE0. The latter returns
COUNT 256 and SUM 16,776,960. No negative exactness/resource result was discarded.

## Exact accounting

Public key bytes are unchanged in all tested modes:
relinearization 8,073,399 B; rotation 56,513,847 B at 16 rows or88,807,479 B at 256;
combined 64,587,246/96,880,878 B. These are extra to data/index/owner state.

| Wire item | Level0 output | Final level 8 output |
| --- | ---: | ---: |
| Complete packed response | 1,794,232 B | 196,794 B |
| Full EQ/GE query,16 rows | 4,485,747 B | 2,888,309 B |
| Full EQ/GE query,256 rows | 4,486,467 B | 2,889,029 B |
| Full range query,256 rows | 5,383,549 B | 3,786,111 B |

Requests remain 2,691,403 B for EQ/GE or3,588,485 B for range; page responses
remain 112/832 B. Keys must be added on first transfer. No index/PIR cost or
actual network latency was measured.

Native control maximum RSS/commit was 1,199,681,536/1,298,829,312 B. Across all
NTT/fused/output tests, maxima were 1,624,104,960/1,721,724,928 B, below the
2 GB completion gate. Thus the official NTT option costs approximately424 MB
additional process peak here. Native counters include owner+peer, setup and
temporary key serialization/restoration; they are not separate peer memory.

Output-level 8 correct boundary residuals were9–10 bits versus nominal
log2(Q_output/(2t))22.01. This is an optional diagnostic on the ciphertext's
own decoded plaintext, not a worst-case noise margin, failure bound or
explanation of a wrong answer. All acceptance checks use the independent
public-fixture oracle.

## Reproduction and provenance

Both feature builds succeeded, and authored Clippy --release --locked
--offline --all-targets --all-features --no-deps -- -D warnings passed.
Rustfmt and standalone lock/metadata checks are recorded with the source.
The source package is independent; the root Cargo.lock and baseline package
were not modified.

Archived executables (SHA-256), under ignored .local/fhe-research/:

| Artifact | SHA-256 |
| --- | --- |
| Native variant | 6cc842f04b9c78c74d66d2db0864c62fb0e55e9d39ee3e2af724bc16690c92b6 |
| NTT variant, shared by control/fused/output-level flags | 0df35e30d206a8f24f562f5b3e8e5f33f08ae1a2dc56ad1c1135c1035e274383 |
| Measured Cargo.toml | a4424539d3e3e570fb9eddfa777854c2c72383f1a36e9b5f0554e6ccd24b085e |
| Published Cargo.toml, trailing blank line removed only | 00a41ec6a9a392f0243022619ddba1b95bb3fac3f66fdd5feffc4bd8076e578d |
| Cargo.lock | f17439e9fd21ad4e91225982bbe11ecec96a3a7c696054757d3a18cbcbb42349 |
| src/main.rs | 613b1304d1741a3ae9167f2e2e2ee79fdc3e638ce957c9419da895f108ddee40 |
| src/metrics.rs | a8e60c2e43e73b098a19be91f7a062b1089b25c9d7c5597d8e5f1d0282f12f88 |

Raw JSONL prefixes: bfv-native-control-*-20261014-220508-150;
bfv-ntt-control-*-20261014-220621-505; bfv-ntt-fused-*-20261014-220740-025;
bfv-ntt-fused-level8-boundary-20261014-220917-027-{1..10};
bfv-ntt-fused-level8-*-20261014-221047-027. Raw files and executable archives
remain ignored, with no keys or database images committed.

The subsequent [byte-limb experiment](experiment-bfv-byte-limbs.md) uses the
complete official17-bit plaintext N=8192 profile. It separately measures exact
low/high byte SUMs and an additive closed-range identity; those later results
do not alter these retained N=16384 measurements.
