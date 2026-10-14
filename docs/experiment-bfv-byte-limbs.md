# Exact BFV byte-limb COUNT/SUM

Status 2026-10-15: an isolated owner-online experiment passes 52 real-FHE
queries, including all 30 queries in the final bounded timing matrix. Final
local owner-to-owner times are 79.65–220.74 ms for EQ/GE/closed range over
16/256 rows. This establishes this exact tested kernel locally, not the full
500 ms storage goal: actual index/PIR/network, arithmetic proofs, UPDATE,
arbitrary SQL and independent security validation remain outside this probe.
The main TFHE backend is unchanged.

The [standalone package](../experiments/bfv-simd-byte-limbs/README.md) preserves
both the [25-bit original](experiment-bfv-simd.md) and the separate
[N=16384 implementation variants](experiment-bfv-variants.md). No existing
measured package, root manifest or root lock is modified by this experiment.

## Unchanged security profile, exact representation

Use the published fhe=0.1.1 release's complete
BfvParameters::default_parameters_128(17) N=8192 entry, obtained at runtime:

| Item | Actual value |
| --- | --- |
| N | 8192 |
| Plaintext t | 114689; t mod16384=1 |
| Coefficient q_i | 8796092858369, 8796092792833, 17592186028033, 17592185438209, 17592184717313 |
| Prime bit counts | 43,43,44,44,44; total218 |
| Secret/error | Release's unchanged centered binomial variance10, i.e. CBD(20) |
| Initial/output level | 0/0 in every final measurement |
| Implementation switches | Native NTT, unfused GE; no RUSTFLAGS override |

Only application plaintext width changes from25 to17 bits; N, complete Q,
secret/error distributions and public-key construction remain the official
8192 profile. The release labels it ABOUT128 classical bits. This does not
supply independent >=128-bit evidence. The pinned security/distribution and
key-exposure investigation remains in
[the security report](experiment-bfv-security.md); numerical independent
estimates are still unexecuted. Do not substitute SEAL's ternary-secret
assumptions for this library's CBD(20).
[Official parameter source](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/parameters.rs),
[secret-key sampling](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/secret_key.rs).

For amount:u16, encrypt low=amount&255 and high=amount>>8 separately. Each
selected limb sum is at most256*255=65280<t. COUNT<=256. The owner reconstructs
low_sum+256*high_sum in u32, bounded by256*65535=16,776,960. No modulo wrap or
approximation is accepted; all limbs are unsigned because65280>t/2.
This reconstructs two genuinely evaluated FHE aggregates; it is not an
owner-computed plaintext aggregate substituted for peer evaluation.

For k in{16,256}, r=next_power_of_two(k), M=N/2, require16*r<=M. Eight MSB-first
age/threshold bit planes are repeated in four groups at0,8r,M,M+8r. Only
row0/group0 has low-byte values, row1/group0 high-byte values, and row0/group1
COUNT weights1 for real rows. All other weights are zero. Rotations1,2,...,r/2
aggregate within the consumed base blocks. Read low at0, high atM, COUNT at8r.
No8r rotation or row-swap key is needed. Age and threshold bits remain encrypted.
Only geometries16/256 are tested; arbitrary or non-power-of-two k is not claimed.

EQ uses XNOR=1-a-b+2ab and three balanced AND levels. GE combines old E/G
states from MSB to LSB. Both have total depth5 including the final
predicate-times-values multiplication. Closed range uses
GE(age,lo)+GE(hi,age)-1, exactly its bit when lo<=hi. Reversed bounds are
rejected by the owner before any key setup/input encryption. Both comparison
results cannot be false for valid bounds. This linear combination retains
depth5. It is invalid as a range identity for lo>hi.

Actual operation counts including values/reduction:

| Predicate | Ciphertext products | Rotations16/256 | Depth |
| --- | ---: | ---: | ---: |
| EQ | 5 | 7/11 | 5 |
| GE | 8 | 10/14 | 5 |
| Additive closed range | 15 | 16/20 | 5 |

## Preserved negative control and exact boundaries

The initial17-bit level0/unfused range used an AND between the two GE outputs,
adding a product and depth6. Its range256 mixed fixture returned COUNT96631,
low78291/high102414 and SUM26,296,275 instead of the exact result. It failed
unsigned contract bounds and the public-fixture oracle. Its223.72 ms is an
invalid operation, not a successful latency measurement. The cause is not
established. Its executable5aa82700... and exact source3d429323... are archived
with all raw output; the failed AND mode remains default and reproducible.
Successful timings below explicitly require --additive-range.

The final arithmetic-preserving identity removes that range product. All11
actual range boundaries pass:16/256 rows, full0..255, singleton0/255,
empty singleton19, mixed18..128, allmax256 giving COUNT256/SUM16,776,960 and
allzero256 giving COUNT256/SUM0. Separate EQ/GE tests pass for0/255, absent19,
byte edges and maximum sum. Across both executables:52 exact successes,
one preserved failed AND range,29 raw reports. Reversed255..0 is explicitly
rejected before setup. Public fixture values include0,1,255,256,257,65280,
65534,65535 and all-zero/all255/all256/all65280/all65535 columns.

Optional owner-local residual diagnostics on correct queries ranged178–185
bits versus nominal log2(Q/(2t))200.19. The failed query's201-bit diagnostic
subtracts the embedding of its OWN decoded plaintext. It cannot establish or
exclude an intended-result noise failure. Neither correct outputs nor these
diagnostics prove a worst-case failure/noise bound. Exact independent public
fixture oracles are the acceptance authority. Diagnostics run after timing.

## Final bounded measurements

Same Ryzen9 9950X3D2/Windows11/Rust1.99 host as the original report. Native
NTT, one application thread, no added worker pool. Final series measured
2026-10-14 22:22 UTC. Each case has5 total samples, sample0 cold and4 warm;
each process generates fresh keys, and every query freshly encrypts inputs.
All cases use mixed values, encrypted lower18 and range upper128.

| Operation | Cold ms | Warm median ms | Max all5 ms |
| --- | ---: | ---: | ---: |
| EQ16 | 80.81 | 81.01 | 87.25 |
| GE16 | 116.40 | 114.19 | 116.40 |
| Range16 | 204.54 | 212.95 | 214.27 |
| EQ256 | 93.22 | 90.31 | 93.22 |
| GE256 | 125.31 | 122.35 | 125.31 |
| Range256 | 220.74 | 205.44 | 220.74 |

The timed operation includes authenticated compact-page lookup wire,
Merkle verification/owner AEAD decryption, packing/fresh encryption of all
3/4 request ciphertexts, serialization, public peer request restoration,
FHE evaluation/relinearization/rotation, output serialization, owner
binding checks/restoration/decryption/unsigned bounds and reconstruction.
The public-fixture correctness oracle and optional residual diagnostic run
after timing. Setup/key generation is separate,586.06–707.36 ms in the matrix.
No actual network transport, concealed index/PIR, SQL proof or update is timed.
These short sequential samples do not establish an arbitrary-input p99 bound.

## Complete material accounting

| Item | 16 rows | 256 rows |
| --- | ---: | ---: |
| Canonical compact fixture bytes | 208 | 928 |
| Rebuildable hash payload | 32 | 32 |
| Relin key | 1,116,273 | 1,116,273 |
| Rotation keys | 7,813,957 | 12,279,077 |
| Combined public evaluation keys | 8,930,230 | 13,395,350 |
| EQ/GE request,3 ciphertexts | 670,024 | 670,024 |
| Range request,4 ciphertexts | 893,313 | 893,313 |
| Complete output,1 ciphertext | 446,646 | 446,646 |
| Authenticated data response | 112 | 832 |
| Whole EQ/GE query wire | 1,116,782 | 1,117,502 |
| Whole range query wire | 1,340,071 | 1,340,791 |

Additional state: public parameters46 B, owner BFV secret serialized8195 B,
compact owner key/domain64 B, trusted data head112 B. First-transfer public
keys are additional to query wire. Rotation steps are1,2,4,8,16,32,64 for16
rows;256 rows adds128,256,512,1024. Keys/RAM are not hidden in the three-byte
record denominator. This tiny-table probe establishes no <=2x combined
storage claim and does not retain a persistent expanded FHE table.

Across all measured runs, native whole-process peak RSS521,437,184 B and peak
commit519,749,632 B. This includes owner+peer, key setup and transient
serialized/restored keys; it is not isolated peer RAM. The probe checks reported
peaks against2,000,000,000 B after setup and completed queries, rather than
installing an OS allocation cap. No resource failure was observed.

The owner is online and sees decrypted selected records. The peer contains
only public parameters/evaluation keys/encrypted snapshot and encrypted query
inputs; it has no owner SecretKey or AEAD key. Request ID and current data head
are matched at the owner. This is binding plus authenticated retrieval, not
malicious-peer arithmetic verification. Every output remains proof unavailable.

## Reproduction and frozen provenance

Set CARGO_TARGET_DIR to the repository's target directory as described in the
package README. Build default features, then use the required additive-range flag:

    cargo build --release --locked --offline --manifest-path experiments/bfv-simd-byte-limbs/Cargo.toml --jobs 2
    target/release/compact-bfv-simd-byte-limbs --rows 16 --predicate eq --lower 18 --upper 128 --fixture mixed --samples 5 --additive-range
    target/release/compact-bfv-simd-byte-limbs --rows 256 --predicate range --lower 18 --upper 128 --fixture mixed --samples 5 --additive-range
    target/release/compact-bfv-simd-byte-limbs --rows 256 --predicate range --lower 0 --upper 255 --fixture allmax --samples 1 --additive-range --noise-diagnostic

Build, rustfmt and authored strict Clippy --release --locked --offline
--all-targets --all-features --no-deps -- -D warnings pass. All-features Clippy
does not mean the optimized-ntt feature was timed in this byte-limb stage.
The default feature/native level0/unfused executable is the measured artifact.
No fused/output-level variants were needed or measured in this stage.

| Frozen item | SHA-256 |
| --- | --- |
| AND baseline executable | 5aa82700c533d7c701e990c2d309797af2732865c55b564c5a5d829cdc96dd4f |
| AND baseline main.rs | 3d429323bf2d031992d7ee844c57fa5dd8c25aaafb534478bc5dd68b19d5ff9a |
| Final additive-capable executable | 65c0472659340586f1a8bbbe6470f0f041349a93c55280ed5a6fc5d81d9fb9db |
| Measured Cargo.toml | 0cd851fe59dde8794f4ec5e6e84126e412e6410c3eca87775ffdbca3d13b8a47 |
| Published Cargo.toml, trailing blank line removed only | 55877f32afc9dfdc8a667383280e640c44f52db26c3022b419cce6c031e86b9d |
| Cargo.lock | 704bb046f218ae9478d7989d25211191da631786663286dfd5df023c38ac8b01 |
| src/main.rs | b1bea65631457cd3f3c5b7538cbc99cc25a392c832f64baca175f1eb22728563 |
| src/metrics.rs | a8e60c2e43e73b098a19be91f7a062b1089b25c9d7c5597d8e5f1d0282f12f88 |

Ignored archive prefixes: bfv-byte17-baseline-5aa82700...exe;
bfv-byte17-and-baseline-3d429323bf2d0319/ (source/manifest/lock/README copy);
bfv-byte17-additive-65c04726...exe. Raw JSONL prefixes under
.local/fhe-research/: bfv-byte17-first-20261014-221851-746-{1..3};
bfv-byte17-boundary-20261014-221942-857-{1..9};
bfv-byte17-add-range-boundary-20261014-222158-393-{1..11};
bfv-byte17-add-matrix-{16,256}-{eq,ge,range}-20261014-222228-281.
Generated raw output/executables/keys/database images are never committed.

The subsequent [experimental core](../experiments/bfv-byte-limb-core/README.md)
exposes owner preparation, public-only evaluation and owner decrypt_unverified
with context binding to both trusted data/index heads. Ten boundary tests pass,
including an explicit in-bounds forged answer that remains UnverifiedAggregate.
Its extraction adds no latency claim. Index completeness, PIR access privacy
and malicious-peer arithmetic proofs remain separate contracts.
