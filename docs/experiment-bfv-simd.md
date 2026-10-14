# Exact BFV SIMD candidate for selected COUNT/SUM

Status on 2026-10-15: the standalone package builds and has bounded real-FHE
measurements. The complete official 8192 profile fails exactness; 16384 passes
the tested boundaries but misses the 500 ms maximum before actual transport/proofs.
Independent >=128-bit validation remains open. This is research only, not
eligible for core-backend promotion or a claim that requirements 11–13 are met.

## Choice that can actually be attempted here

Use the published pure-Rust **fhe 0.1.1** release, not its changing Git main, for
the first separate probe. The archive was read directly without installing it:
[official archive](https://static.crates.io/crates/fhe/fhe-0.1.1.crate), SHA-256
`929ff5c547926375361c75c126198d886b77b6ee952fdaea4c26002cbe0359cf`.
Its VCS record points to
[`fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a`](https://github.com/tlepoint/fhe.rs/tree/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a).
The normalized release manifest says `build=false`; generated protobuf is
included. This release needs no CMake, native C++ or protoc. Current Git main
has a different protobuf build process and is not the selected dependency.

The release provides HPS-RNS BFV, `Encoding::simd`, symmetric encryption,
relinearization, selected column rotations and parameterized serialization.
BFV arithmetic is exact modulo its plaintext modulus. The author explicitly
reports no independent security audit. [Library documentation](https://docs.rs/fhe/latest/fhe/),
[release example](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/examples/bfv_ops.rs).

At inspection time, the project's lock/cache contained no BFV, SEAL, OpenFHE,
prost or native-binding package. CMake exists at
`E:/Program Files/CMake/bin/cmake.exe`; clang, ninja and protoc were not found on
PATH. The initial separate probe lock resolved 91 packages before compilation.
The subsequent successful Windows build and actual measurements are recorded below.

Sunscreen's `seal_fhe` native build script targets bundled SEAL 4.0 and bindgen.
Current SEAL warns that versions before 4.4 need critical untrusted-input fixes.
That wrapper is not the shortcut selected here.
[Wrapper source](https://github.com/Sunscreen-tech/Sunscreen/blob/main/seal_fhe/build.rs),
[SEAL notice](https://github.com/microsoft/SEAL).
The joint OpenFHE Rust wrapper requires a separately installed C++ library; its
published instructions use Linux linking, while OpenFHE's Windows instructions
prefer MinGW and no longer support VC++. This is a larger toolchain/integration
task and no such installation was performed.
[OpenFHE-rs](https://github.com/fairmath/openfhe-rs),
[Windows instructions](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/windows.html).

## Parameters, security and exactness gates

The probe selects the release's unmodified
`BfvParameters::default_parameters_128(25)` entry for N=8192, then N=16384 if
the smaller official profile cannot evaluate the full circuit exactly. Keep
every prescribed coefficient modulus and the default distributions. The
upstream description is **about 128 bits**, not a validated lower bound.
[Parameter implementation](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/parameters.rs).

| N | Coefficient-prime bit counts | Sum of bit counts | 25-bit batching prime candidate |
| --- | --- | ---: | ---: |
| 8192 | 43,43,44,44,44 | 218 | 33,538,049 |
| 16384 | 48,48,48,49,49,49,49,49,49 | 438 | 33,292,289 |

The prime candidates were independently checked by trial division and satisfy
t mod 2N = 1. The program obtains t from the official generator and prints the
actual t and every q_i; it refuses t <= 16,776,960 or incompatible batching.
It never substitutes the table candidate for a failed official profile.

For comparison, SEAL's explicit `sec_level_type::tc128` validator limits total
coefficient-modulus bits to 218 at N=8192 and 438 at N=16384. That table assumes
a **ternary secret and error standard deviation 3.2**, and its 128-bit category
is classical. The fhe release samples **both secret and error with centered
binomial variance 10**. Equal N/Q budgets do not prove equal security across
these distributions. [SEAL security table](https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/hestdparms.h),
[fhe secret sampling](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/secret_key.rs).

Before calling this candidate independently >=128-bit secure, record an
estimator version/commit, complete N/Q/t, actual secret/error distributions
and variance, key-switch modulus/decomposition exposure, classical reduction
cost model, attacks checked and minimum resulting work factor. Cross-check the
implementation against those assumptions. No such estimator result exists
for this probe. A library's profile name or successful decryption is not that
evidence. The broader implementation guidance is
[Security Guidelines for Implementing Homomorphic Encryption, 2024/463](https://eprint.iacr.org/2024/463).

The subsequent [exact security-input mapping](experiment-bfv-security.md) identifies
the variance-ten sampler as estimator CBD(20), pins the complete modulus and
official estimator, and supplies a reproduction script. Sage is unavailable in
the inspected Windows runtimes; no numerical estimate has run and this gate
remains open.

For exact unsigned SUM, 256*65535 = 16,776,960 < t, and COUNT <=256.
Decode as unsigned u64, check these bounds, then use u32. A signed centered
decoder can return a negative value near this maximum because t/2 is smaller
than the maximum SUM. For a genuinely signed SUM bound S, require t>2S or an
explicit CRT/sign convention. More than 256 rows needs a new aggregate bound.

Multiplicative circuit depth does not equal the number of explicit modulus
switches. The initial probe stays at level zero and relinearizes every product.
Its failure policy is exact-output rejection and retry with the next complete
official profile. A noise safety margin/probability bound for all allowed inputs
remains missing; checking representative public fixtures cannot establish it.
Increasing t also consumes noise capacity, so a 20-bit demonstration does not
establish this 25-bit circuit. [SEAL BFV explanation](https://github.com/microsoft/SEAL/blob/main/native/examples/1_bfv_basics.cpp).

## Packed circuit and reproducible cost counts

The following is our circuit construction using standard BFV operations, not a
claimed new cryptographic primitive. Let k<=256, r=next_power_of_two(k), and
M=N/2. Lay out age bit 7-i in block i of width r, i=0..7; copy these blocks into
both SIMD rows. Encrypt threshold bit blocks the same way. Eight blocks fit
because 8r<=M for both proposed profiles. At selected positions in block zero,
encrypt amounts in row zero and ones in row one; every other value position
is zero. Only final block-zero positions are consumed.

For secret bits a,b, compute z=ab, E=1-a-b+2z and G=a-z. E is equality and G
is strict unsigned greater. Combining adjacent high/low bit groups uses
E'=E_H*E_L and G'=G_H+E_H*G_L. Keep both old E/G until both products are formed.
Positive column rotations read block i+shift into block i; the release's
rotation test explicitly checks that direction.
[Rotation implementation and test](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/evaluation_key.rs).

EQ reduces E with shifts r,2r,4r. GE combines (E,G) at those shifts and returns
G+E. A closed range computes GE(age,lower)*GE(upper,age). Multiply the predicate
by encrypted values; log2(r) rotate-add steps sum both SIMD rows simultaneously.
The owner decodes SUM from slot 0 and COUNT from slot M. Padded COUNT positions
and non-value blocks are zero, including predicates matching age zero.

| Operation | Input ciphertexts | ct*ct products including values | Depth | Rotations k=16 / k=256 |
| --- | ---: | ---: | ---: | ---: |
| EQ COUNT+SUM | 3 | 5 | 5 | 7 / 11 |
| GE COUNT+SUM | 3 | 8 | 5 | 10 / 14 |
| Closed range COUNT+SUM | 4 | 16 | 6 | 16 / 20 |

Each product requires relinearization. Rotation keys cover only
{1,2,...,r/2,r,2r,4r} with powers of two: 7 keys at k16 or 11 at k256,
plus one relinearization key. No row swap or full-slot inner-sum key set is
needed. The alternative eight-ciphertext bit-plane layout consumes 17/25
input ciphertexts for encrypted predicates; the packed layout avoids that
request cost without replacing the predicate with plaintext.

Arithmetic source-level coefficient payload estimates, **not measurements**:

| Profile | One 2-polynomial ciphertext, u64 RNS words | Raw 3-input+1-output payload |
| --- | ---: | ---: |
| N8192, L5 | 655,360 B | 2,621,440 B |
| N16384, L9 | 2,359,296 B | 9,437,184 B |

For this release's level-zero switching key, two arrays each contain L
polynomials with L residues per coefficient: at least 2*N*L^2*8 coefficient
bytes per rotation/relinearization key. This gives 25/37.5 MiB for 8/12 keys
at N8192, or 162/243 MiB at N16384. Shoup tables, contexts, scratch buffers,
vectors, owner state and serialization copies are additional. Fresh symmetric
ciphertexts and switching keys serialize a random-polynomial seed, so actual
wire differs from uncompressed RNS words. Measure `to_bytes().len()` and RSS;
do not use these estimates as complete RAM/wire numbers.
[Key structure](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/key_switching_key.rs),
[Ciphertext serialization](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/ciphertext.rs).

## What the first benchmark must include

The [standalone probe](../experiments/bfv-simd/README.md) uses real random owner
keys and public fixtures. The peer type has no BFV secret key or compact-store
owner. Every measured query includes compact page response encoding, exact-head
Merkle verification, owner AEAD decryption, packing, fresh symmetric BFV input
encryption, all 3/4 input ciphertexts, request encode/decode, peer evaluation,
output encode/decode and owner decryption. The direct byte roundtrip is local;
there is no network latency measurement. JSONL reports those stage times,
all query wire, public evaluation-key wire, setup, cold sample and whole-process
high-water RSS separately. Key setup/transfer is excluded from warm queries and
reported explicitly; first-use session cost must add it.

Run the same predicate/fixtures for k16 and k256 with official N8192 then N16384
only when required by exactness. The measured series below uses one cold plus four
warm queries for EQ/GE and one cold plus two warm for range; it is a bounded
comparison with scalar TFHE. Check age/threshold 0 and 255, equality
misses, mixed predicates, range endpoints, zero matches, and all256 amounts
65535 with GE0. A wrong answer invalidates the timing. Record the exact build,
CPU, thread setting, t/q_i, fixture, wire and RSS before claiming an improvement.
Index/PIR candidate selection and actual transport must then be composed and
remeasured; this small full-selected-table probe does not measure those costs.

BGV supports the same modular SIMD circuit but has distinct correction/noise
management. No BGV Rust backend was found already pinned or cached here, and
switching schemes without measuring the complete operation is not evidence.
[Official BGV example](https://github.com/microsoft/SEAL/blob/main/native/examples/4_bgv_basics.cpp).

## Measured Windows results

Measured 2026-10-14 21:39–21:44 UTC (2026-10-15 in Moscow): AMD Ryzen 9
9950X3D2, 16 cores/32 logical processors, Windows 11 Pro 10.0.26200,
Rust 1.99.0 (b940084d7eb6a299eb4bfeb8e34901bc051e7ac4),
x86_64-pc-windows-msvc, LLVM 23.1.1. The OS reports 98,190,636 KiB visible RAM.
Release build, no RUSTFLAGS or RAYON_NUM_THREADS override, no concurrent heavy
agent workload. The probe adds no worker threads.

The complete official N8192 profile **failed** the exact oracle for EQ16,
GE16 and range256. Two initial failures stopped at the unsigned bound; reruns
retained invalid decoded values and explicit failed-oracle records. These
84–124 ms invalid reruns are not performance results. The failure cause is
**unknown**. Independent source review found no concrete algebra, rotation,
packing or relinearization defect; this is not a proof for all inputs.

The official N16384 profile passed nine boundary invocations: EQ at 0/255 and
miss 19; GE at 0/255; ranges [0,255], [18,128], [19,19]; and all 256 amounts 65535
with GE0, returning COUNT 256 and SUM 16,776,960. Two initial smoke queries,
23 sampled queries and a final maximum-SUM confirmation also passed: **35
successful FHE queries total**. The timed matrix uses **five total samples**
for EQ/GE and **three** for range, not the earlier proposed 20. Sample 0 is cold;
the remaining four/two are warm.

| Official N16384 operation | Total samples | Cold whole local ms | Warm median ms | Maximum of all samples ms |
| --- | ---: | ---: | ---: | ---: |
| EQ,16 rows | 5 | 490.65 | 492.21 | 508.16 |
| EQ,256 rows | 5 | 573.49 | 560.41 | 573.49 |
| GE,16 rows | 5 | 716.90 | 711.20 | 718.00 |
| GE,256 rows | 5 | 807.00 | 772.47 | 807.00 |
| Range[18,128],256 rows | 3 | 1399.03 | 1399.77 | 1406.92 |

These are owner-to-owner local wall times, including owner work and serialized
request/output roundtrips. The matrix excludes public-key setup and actual
transport. Setup took 1.432–1.960 seconds in these five processes. Even EQ16
exceeded 500 ms once before actual transport or proofs: **bounded negative SLA**.

Actual serialized accounting:

| Item | 16 rows | 256 rows |
| --- | ---: | ---: |
| Public parameters | 76 B | 76 B |
| Public relinearization key | 8,073,399 B | 8,073,399 B |
| Public rotation keys | 56,513,847 B | 88,807,479 B |
| Both public evaluation-key objects | 64,587,246 B | 96,880,878 B |
| Owner BFV secret-key serialized byte count only | 16,388 B | 16,388 B |
| Owner compact key/database/domain state | 64 B | 64 B |
| Independently retained current head | 112 B | 112 B |
| Canonical compact input table | 208 B | 928 B |
| Rebuildable input-table hash payload | 32 B | 32 B |
| Encoded compact-page response | 112 B | 832 B |
| Complete EQ/GE request,3 ciphertexts | 2,691,403 B | 2,691,403 B |
| Complete range request,4 ciphertexts | 3,588,485 B | 3,588,485 B |
| Complete packed COUNT/SUM output | 1,794,232 B | 1,794,232 B |

Total measured query wire is 4,485,747 B for 16-row EQ/GE, 4,486,467 B for 256-row
EQ/GE and 5,383,549 B for 256-row range. Add keys on initial transfer. No encrypted
posting index or PIR selection was included in this small selected-input
table; these numbers are not a complete storage ratio.

Native Windows counters include owner, peer, setup, temporary key serialization/
restoration and allocator retention. Across the timed matrix, maximum
PeakWorkingSetSize was 1,199,165,440 B and maximum PeakPagefileUsage (commit
high-water) was 1,299,353,600 B. These are not separate peer-memory estimates.
PrivateUsage is retained in each raw record. The post-Clippy max-SUM confirmation
had RSS 1,198,460,928 B and peak commit 1,296,113,664 B.

Optional --noise-diagnostic runs only at the owner on public fixtures, outside
query timing. It reports library residual bits and nominal log2(Q/(2t)).
**SecretKey::measure_noise subtracts an embedding of its own decoded plaintext,
not the independently intended answer.** Thus the 8192 residual 193 versus
nominal 192.00 cannot diagnose the cause of a wrong answer. Correct N16384
boundaries showed residual 221–264 versus nominal 412.01. These observed residuals
are not a worst-case noise margin or failure-probability bound. Exact oracles
remain authoritative. No independent security-estimator gate was closed.

Validation: optimized locked build succeeded (first build 29.83s); authored
Clippy --release --locked --offline --all-targets --no-deps -- -D warnings
passes. Rustfmt, metadata, lock/archive checksum and local doc links pass.
Clippy requested the typed equivalent as_chunks::<3>().0 for compact-row
parsing. After this syntax-only change the package rebuilt and the
all 256 maximum-SUM FHE check passed again. The measured predicate kernel did
not change.

Raw JSONL remains ignored under .local/fhe-research/:
bfv-boundary-20261014-214211-245-{1..11}.jsonl (1/2 fail 8192);
bfv-16384-{16,256}-{eq,ge}-samples-20261014-214304-396.jsonl;
bfv-16384-256-range-samples-20261014-214304-396.jsonl; initial-smoke logs;
bfv-16384-256-allmax-confirm-20261014-214420-361.jsonl.

SHA-256 provenance:

| Artifact | SHA-256 |
| --- | --- |
| Timed-matrix executable | ac612e17ee53a849f89fa1e00e8f853e129375d58cf944317556c405606c9340 |
| Final executable, typed-chunk fix and max-SUM confirmation | 8d5603d2d62365367b975a7ae228f2610b5499b005b0a5315a2a0777f3582502 |
| Measured Cargo.toml before trailing blank-line cleanup | 761ab4493c341045230832de56cf0703647d7f36466117c9a056facdc3e9d04e |
| Published Cargo.toml, same dependencies/profile | 911420751b304503aebbd49196709d7075fa30cada6e0a6c700f3928db39435c |
| Cargo.lock | 8518e09f21dee5612a70818947e37e904b573260b083416b2374fe366f27de08 |
| Final src/main.rs | d4bfcf0a7eff009952a895a11e531d91588726d22ce3e79855cee084e14eec14 |
| Final src/metrics.rs | a8e60c2e43e73b098a19be91f7a062b1089b25c9d7c5597d8e5f1d0282f12f88 |
| EQ16 sampled JSONL | abbf741cc2578daa66c28f60b5b48fc0f74b51172215358bbb5004704c80ffd3 |
| EQ256 sampled JSONL | 5aa8f6e87b791d36f2b05cceb606ee98ae1c365ff2bdedef7565580b3e395243 |
| GE16 sampled JSONL | 2aab5f1c7e7762a3117a06d9f7a94290c3f5fdf5d37cfaad8a80629b371596e7 |
| GE256 sampled JSONL | 31ae3496d378657b59d8073695f7ac956d98e489d2cd081385c85e463d3eddd3 |
| Range256 sampled JSONL | 5241674cbee24b3b122f059f7b32e86977193d569f8d75370be3f166a0e57185 |

An unimplemented follow-up can replace the final GE merge with
G_H+E_H*rotate(G+E,4r), saving one ciphertext product and one rotation per GE
with the same Boolean polynomial/depth. It was not changed during this series.
No latency gain, noise safety or 8192 correctness is claimed for it.

## Limits that remain after a fast aggregate

UPDATE needs separate exact u16 overflow logic. Addition modulo t does not
detect overflow modulo 65536. An encrypted overflow bit per matching row and
an all-row/all-shard rejection decision must preserve atomicity. A 16-bit
comparator and a product-based global Boolean reduction add circuit depth and
rotations; the COUNT/SUM depth table is not an UPDATE estimate. No UPDATE
source or performance claim is included here.

This online-owner experiment handles plaintext input rows at the owner; that
availability assumption is not a new approved requirement. No plaintext
predicate/aggregate answer is supplied to the peer and no owner-precomputed
answer replaces evaluation. Only the compact AEAD selected-input table is
implemented here; a large-table index still needs composition. FHE inputs are
ephemeral and public keys must still be counted. BFV supplies no cryptographic
arithmetic-correctness or completeness proof. The probe labels its output
`proof: unavailable`; no production verification or acceptance API is implemented,
even when its local exactness tests pass. The existing
[query-proof analysis](experiment-query-proofs.md) still applies.
