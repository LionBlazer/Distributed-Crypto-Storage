# Actual Owner ciphertext formation validation

The reusable fixed `bfv-ciphertext-formation` relation and optional Core
`formation-proofs` continuation connect independently supplied encoded words to an
actual Owner ciphertext. The Registry200 research consumer additionally checks
the complete independently retained Encoding136 statement, Source, packets and
original request. This is input formation, not admission of a live SQL answer.

## Ownership, equation and admission boundaries

The public Owner API accepts exactly 8192 caller-owned scaled polynomial words W
below 114689, validates the complete original setup before SDK work, recovers
m=W*(78307^-1 mod114689), and uses the actual SDK poly level0 encryption with
OS-backed ThreadRng. It does not export a secret key, private getter or callback.
The opaque completed Basis job consumes an independently committed opening and
retains guarded W/Shat/salts until formation completes, cancels or drops.
Cancellation is between synchronous calls; native field/FFT/trace/LDE/SDK buffers
are not promised securely erased. No private persistence or recovery is added.

Actual Key verification and every one of five ordered Basis proofs precede
residual derivation and AIR/trace creation. ALL Key33 values including CsHat,
original complete setup/parameter/ciphertext bytes, q, five full Basis claims and
the original producer identity/context/Cenc stay bound. The library proves for
each coefficient and each basis:

```text
B_i + R_i - e - DELTA_i*W = q_i*k_i
```

One shared e is in [-20,20], W in [0,114688], R signed 63 and k signed 20. The complete
residual is strictly inside the Goldilocks modulus, so field equality is integer
equality. Noise is derived from the original ciphertext and supplied W after
encryption, without RNG capture, re-encryption comparison or decryption-derived
W. This proves bounded-noise existence, not CBD distribution, uniformity or
evaluation-key consistency. The independently assessed actual symbolic degree is
3, distinct from the unchanged degree hint 5. Quotient chunks
are 16, batched functions 25684;
both individual analytical security floors remain at least 128 bits.

The Registry200 adapter verifies the actual Source/Lifecycle/Encoding frame and
compares all 136 public values including Cenc, the independently compiled
projection byte, plus complete heads and packets,
before entering the Owner factory. SQL/Command160 is bound before any signed
Journal append; the decoded full 116 Lifecycle claim is then checked before
append. A genuine alternate same-parent/W Encoding with fresh Cenc independently
verifies but fails the original retained pins. Source AEAD C_key and BFV Cs stay
different domains. Local validated lineage is not agreed finality or freshness.

The normal prove path really admits signed Bootstrap, Begin and Acquire. Its
returned Encoding frame contains only the current Source/Lifecycle/Encoding
proofs; it does not contain the preceding history. Private Owner/handle/jobs are
dropped before the public-only product is returned. Fresh verification decodes
PublicSetup and checks all ten current components against retained public pins.

## Executed checks

Rust 1.99.0/MSVC, release, locked/offline, native CPU, Cargo jobs 2 and Rayon threads 2
were used on AMD Ryzen 9 9950X3D2 16-Core Processor (16 cores,
32 logical processors), Microsoft Windows 11 Pro
build 26200. The OS reports 100,547,211,264B
of physical memory. This hardware context is separate from the observed process
limits. Formatting, default-core check and strict
selected-library/experiment Clippy passed. All 460 actual compiler-discovered
runtime scenarios passed: 112 old Core/library/integration, 337 old experiment,
and 11 new owning scenarios (Formation 5/Core 2/Registry200 4). All 15 compile-fail
examples including four new opaque-job fences and both requirements/architecture
contracts passed. All 33 old security commands retained their complete ordered
JSON report lists, and the new analytical command passed before genuine proving.

Tests check every coefficient of all five bases against independent native
SDK/prime arithmetic, common bounded residuals, coherent B mutations, repaired
controls, last coefficient 8191 and biased quotient-bit attacks. They include real
Key/CsHat and Encoding/Cenc swaps, valid differing W/root rejection against the
original ciphertext, every missing/reordered component, header/canonical/nested
proof/budget corruption, incomplete/repeated/cancelled jobs, real signed LIMIT0,
conditional all-skipped old roots and WAIT/NOWAIT/failed-End non-answer rejection.
Existing legacy tests, contexts, profiles and arithmetic remain preserved. The
old Chacha helper adds only one exhaustive Kind arm; old test bodies stay intact.
Earlier compilation attempts exposed a missing public digest export and test
helper build/style errors. A real native regression then exposed missing projection
metadata in the new formation producer identity. The correction binds that byte
while retaining the attack and adding an explicit same-PV136/context but different
formation-commitment assertion. Old equations, profiles, AIR and wire formats stay
unchanged. Failed attempts and artifacts remain retained in local audit evidence.
The final build used a new exclusive target to preserve every earlier test/CLI
executable at its original path; no cached test or proof result was accepted.

## Reproduction

Set `CARGO_BUILD_JOBS=2`, `RAYON_NUM_THREADS=2` and
`RUSTFLAGS=-C target-cpu=native`. The new owning tests should be invoked separately
with `--exact` when applying per-process observation time limits.

```sh
cargo test --release --offline --locked -p bfv-hiding-stark -p bfv-key-transform -p bfv-basis-convolution -p bfv-ciphertext-formation -p bfv-query-core --features bfv-query-core/formation-proofs --all-targets -- --test-threads=1 --nocapture
cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p bfv-query-core --features formation-proofs --doc
cargo run --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security registry-lifecycle-formation
cargo run --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry-lifecycle-formation
```

The security alias uses an explicitly nonsecret mathematical shape fixture; it
does not generate a proof or establish an operational Owner association.

## Observed operations and resources

One Core invocation measured Owner generation 175.2329ms,
public encryption 11.5503ms, Key production/self-verification/
serialization and public frame copy 3473.9814ms, formation production including
mandatory prerequisite verification 9448.0853ms, and
fresh setup decoding plus Key/five Basis/formation verification
6700.6771ms. Public setup/ciphertext bytes were
8,930,306/223,281; Key frame 16,734,431B
and formation frame 21,289,627B.

Each Basis phase also includes mandatory Key verification and complete ciphertext
preparation.

| Basis | Complete frame bytes | Prerequisite checks, generation, self-verification and serialization ms |
| --- | ---: | ---: |
| 0 | 15,960,547 | 5415.8651 |
| 1 | 15,958,499 | 4710.3447 |
| 2 | 15,957,123 | 5208.7917 |
| 3 | 15,956,803 | 5129.5763 |
| 4 | 15,953,443 | 5153.1986 |

The separate actual signed-history CLI measured complete generation
82649.3501ms and fresh setup/current-ten-proof verification
10274.2369ms. Generation includes real Journal
history, encoding, Owner setup/encryption, Key/five Basis, formation and all
mandatory checks/serialization. Verification includes setup decoding and all ten
actual current checks; public frames are already resident. Both exclude file I/O.
These are same-process observations with public parameter caches warm during
verification, not cold application SQL benchmarks or a latency guarantee.

Across 151 owned CLI/test processes, 42725
samples and 42574 actual intervals, maximum sampled working set was
1,379,143,680B, private usage 1,374,810,112B
and sampled OS peak working set 1,379,143,680B. Maximum observed
interval was 544.9028ms (nominal 100 ms). No sampled 1792 MiB soft
fuse or 1200 s per-process validation timeout fired. Compilers and child processes
were not observed; these are not hard RAM bounds, whole-peer guarantees or global
concurrency enforcement. The fixed trace/masked/LDE array estimates total
992,780,288B before other costs and are not RSS measurements.

## Component and remaining system limits

The genuine DCSFMP01 component fits its 140-byte header and 24 MiB payload bound;
sequence 16384/nested 32 Mi element budgets and canonical topology are enforced before
SDK verification. Prerequisites remain fixed borrowed public frames and are
decoded/dropped one at a time. There is no ten-proof aggregate serialization,
transport registration or raised quota. Key+five Basis mandatory main openings
alone exceed 64 MiB; the ten current main openings total 141,748,224 B. Existing
64 MiB transport messages, 32 MiB Journal Body and 256 MiB history quotas remain.

Ten individual 128-bit floors give only a 124.678-bit union floor before any extra
history proof. No composed 128-bit claim is made. Live peer-side private SQL
predicate/program/completeness, bounded prerequisite streaming/checkpointing,
evaluation-key same-secret consistency, controller authorization, MVCC/writer
fencing and fresh decentralized agreement remain required. FOR UPDATE and
SKIP LOCKED are not enabled by this mathematical input relation. No fixed
query-latency cutoff applies; reasonable full-operation performance remains a goal.
