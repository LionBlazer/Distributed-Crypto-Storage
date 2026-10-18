# Complete arithmetic17 validation

This standalone experiment verifies all four Extend, ten Tensor and three Down
relations over complete N8192 vectors. The three mandatory phases are `[0,4)`,
`[4,14)` and `[14,17)`. It returns a checked result only after all three SDK
verifications and the conservative whole-security floor. It does not connect
their vectors into a complete FHE multiplication graph or grant SQL authority.

Executed with Rust 1.99.0 MSVC on Windows, release, locked and offline dependencies,
`RUSTFLAGS="-C target-cpu=native"`, one Cargo job and two Rayon threads. The source
parent was `c25d35291dbdd5db1ffd53e23f0145e9dc6c47e2`. Root core uses the published
SDK; only this separate experiment selects the reviewed sibling streaming SDK.
The root default-member graph contains core libraries only. Its sole new member
is `limb-range-air`; root lock changes are limited to that package and the new
Scale/Tensor optional dependencies. Existing math, profiles and original tests
remain unchanged; both adapters share the same private integer equation kernels.

## Executed tests and build checks

| Owning library | Default | plonky3 | multistark | Both features |
| --- | ---: | ---: | ---: | ---: |
| Scale | 7 | 8 | 13 | 15 |
| Tensor | 7 | 9 | 12 | 15 |
| Fixed range supports | 3 | — | — | — |

All configurations passed, followed by all **12** consumer tests with zero
failures, ignored or filtered cases. Both upstream SDK oracles also ran before
the first proof, and repeated within the complete suite. Total: **103 runtime
invocations, 101 distinct test configurations, 45 distinct named cases**. The
counts include repeated cases across feature configurations; they are not 103
different tests. Two doctest commands completed successfully with zero cases
(three core libraries and the experiment); those add no test cases to the count.

Strict `-D warnings` Clippy passed for the three core libraries with all targets
and features, and for all experiment targets. The actual default core
`cargo check --release --locked --offline` passed. Executable hashes and discovered
full test names were checked before direct serial execution with
`--include-ignored --test-threads=1 --nocapture`.

The SDK oracles compare all 8192 outputs of every role against actual upstream
RnsScaler and Poly multiplication/addition. The second oracle independently
checks the SDK prime generator and full ordered Q5||P5 basis.

All nine original consumer test names and meaningful controls remain. Three
attacker programs must first generate and pass their own actual SDK proof, then
fail the honest verifier: omitted range query with an out-of-support carry,
omitted Tensor component equations with a canonical wrong quotient, and foreign
complete public preprocessing. Local constraint debugging supplies no proof
acceptance. Other tests reject every last-output substitution, wrong roles/order,
canonical aliases, malformed topology and nested budgets. Three additional
cases exercise each genuine phase, repaired swaps/duplicates/missing/extra units,
full query/setup/last-outer-output transcript transplants and an aggregate decode
budget overflow whose three individual proofs each fit.

## Actual SDK assessment and frame

| Phase | MAIN cells | PP cells | MAIN / PP variables | Outer degree | SDK whole bits |
| --- | ---: | ---: | --- | ---: | ---: |
| Extend4 | 5,473,312 | 1,425,936 | 23 / 21 | 2 | 157.301048 |
| Tensor10 | 4,555,776 | 2,359,808 | 23 / 22 | 3 | 157.301048 |
| Down3 | 4,178,976 | 1,597,968 | 22 / 21 | 2 | 157.419040 |

These reports come from the actual locally reconstructed SDK instances, with
finite terms and no unassessed components. The conservative estimate for this
three-proof union is `min(actual bits) - ceil(log2(3)) = 155.30104806191767`, above
the required 144. All three backends are assessed before main traces or proofs.
The estimate remains conditional on the SDK's security model; it is not an
independent cryptographic audit or an end-to-end system security claim.

Actual schedules satisfy fold4, rates4/7/10/13 and the admitted query ceilings.
The main/preprocessed opening claims are 650/165, 544/282 and 492/186. Conditional
serialized bounds are 2,480,948, 2,554,948 and 2,186,400 bytes; their total plus
the 320-byte header is **7,222,616 bytes**. The corresponding combined bound is
**4,598,008 nested decode elements**. Independent numeric review recomputed these
from the actual schedules, dimensions, claims and canonical frontier formula.

The original caps remain 16 MiB frame, 16,384 elements per sequence and 8 Mi
aggregate decode elements. One bounded decoder reads the fixed `[Proof;3]`; a
component cannot reset its budget. Header boundaries, exact canonical reencoding,
EOF, topology and tighter pruned frontier checks are mandatory. Submitted keys,
reports, auxiliaries and partial phases cannot create a checked result.

## Standalone measurement

| Measured quantity | Value |
| --- | ---: |
| Complete proof frame | 6,505,688 bytes |
| Independent request / output envelopes | 5,899,880 / 5,572,744 bytes |
| Generation, including setup and producer self-verification | 172,380.3214 ms |
| Fresh verification after reconstructing Expected | 1,531.3598 ms |
| Observed CLI elapsed time | 174,361.9554 ms |
| CLI maximum sampled Working Set / private bytes | 1,011,310,592 / 1,008,979,968 |
| Maximum sampled PID Working Set / private bytes across runtime gates | 1,018,015,744 / 1,018,142,720 |
| Largest actual sampling interval | 780.3064 ms |

Generation includes public arithmetic, sequential setup/assessment, current-phase
auxiliaries/traces, all three genuine proofs, self-verification and encoding. It
excludes fixture/request construction and the subsequent fresh verifier. Fresh
verification reconstructs Expected from saved canonical envelopes after dropping
the producer's Expected, and never recomputes the arithmetic or receives Aux.

Sampling was observational, nominally 100 ms, with a sampled 1792 MiB per-PID soft
fuse and a 1200 s per-command limit. The measured gaps preclude treating this as
a hard bound; short tests may finish without a sample. These are standalone
arithmetic process observations, not whole-peer RAM or SQL latency measurements.
There is no fixed 500 ms target and no controlled speedup claim against an earlier
arithmetical monolith, which was not measured here.

## Reproduction and evidence

From the repository root, use the recorded toolchain/environment and an
independent target directory:

```sh
cargo check --release --locked --offline
cargo test --release --locked --offline -p limb-range-air --lib -- --test-threads=1
cargo test --release --locked --offline -p bfv-scale-circuit --lib -- --test-threads=1
cargo test --release --locked --offline -p bfv-scale-circuit --lib --features plonky3 -- --test-threads=1
cargo test --release --locked --offline -p bfv-scale-circuit --lib --features multistark -- --test-threads=1
cargo test --release --locked --offline -p bfv-scale-circuit --lib --all-features -- --test-threads=1
cargo test --release --locked --offline -p bfv-tensor-circuit --lib -- --test-threads=1
cargo test --release --locked --offline -p bfv-tensor-circuit --lib --features plonky3 -- --test-threads=1
cargo test --release --locked --offline -p bfv-tensor-circuit --lib --features multistark -- --test-threads=1
cargo test --release --locked --offline -p bfv-tensor-circuit --lib --all-features -- --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --lib tests::sdk::all8192_outputs_of_all_seventeen_roles_match_actual_upstream_sdk_operations -- --exact --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --lib tests::sdk::actual_sdk_prime_generator_selects_the_same_complete_qp_basis -- --exact --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --lib -- --test-threads=1
cargo run --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml -- security
cargo run --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml -- prove
cargo clippy --release --locked --offline -p limb-range-air -p bfv-scale-circuit -p bfv-tensor-circuit --all-targets --all-features -- -D warnings
cargo clippy --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --all-targets -- -D warnings
cargo test --release --locked --offline -p limb-range-air -p bfv-scale-circuit -p bfv-tensor-circuit --all-features --doc
cargo test --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --doc
```

Frozen source SHA-256:
`D99700A1E09A08956FDDBA6073072F7FAED96DC6B2BFF122170E009532539B04`.
Final native review SHA-256:
`52660B487B35C3987B844ACBE61DAA64245F9C1091B9622F3C01C0B89A0EA662`.
The review checks all source/executable/receipt hashes, 953 inherited external SDK
files, 2,071 current controls and all 16,266 earlier controls. Initial test-only
generic annotations and an unused import were corrected before the successful
source revision. An orchestration dispatch fix reused the identical compiled
executables; the failed pre-test dispatch and original runner remain preserved.
Previous targets were retained; the final target used independent `copy2`
dependency-cache copies without hardlinks or prior native test executables.

## Remaining obligations

This proves seventeen independent public arithmetic relations. Complete linked
MulRelin, the original ciphertext input/output bridges, same-secret evaluation-key
provenance, complete hidden-WHERE semantics, input source/privacy composition,
fresh decentralized heads and PostgreSQL/transaction admission remain open.
Input hiding profiles retain their separate 128-bit backend; the arithmetic
estimate above cannot be applied to them or the complete query.

The run does not establish fit of a complete operation within the unchanged
32 MiB Body, 64 MiB transport or 256 MiB history policies, nor whole-peer RAM,
compact durable storage or practical complete-query speed. Historical SQL tests
were not run by this gate and are not reported green. Requirements and their
mirrored copy match, including hidden WHERE/constants. The overall goal remains
active and incomplete.
