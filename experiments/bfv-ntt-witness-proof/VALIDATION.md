# Native full-vector NTT main-witness validation

Validated on 2026-10-17, after the pure optional circuit publication `7953452`.
This is one experimental public arithmetic stage, not a MulRelin, SQL, locking,
freshness, data-source completeness or key-authority acceptance path. Witness
commitments are not hiding. No production operation or older proof policy changed.

## Reproduction and dependency boundary

The standalone Cargo lock pins the reviewed registry graph. Plonky3 0.8.0 sources
are at `a21e3ed42905040ad49c519e402f018381c12d0c`. No dependency version was silently
substituted. New normal packages were reviewed against published archive hashes;
the allocator-api2 0.2.21 edge is the actual default hashbrown allocation feature.
P3 parallel, diagnostics and test-util features were disabled. The actual BFV
oracle used fhe-math 0.1.1's native NTT, with its default features disabled.

Host: Windows 10.0.26200, x86_64 MSVC; processor identifier `AMD64 Family 26 Model
68 Stepping 0, AuthenticAMD`. Rust 1.99.0, commit
`b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`, LLVM 23.1.1. Release builds used
`-C target-cpu=native`, build jobs two, Rayon limit two and one test harness thread.
The limit is a configuration setting, not a claim that the serial SDK used two
proving threads. A fresh ignored target and sanitized environment were used.

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo clippy --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml --all-targets -- -D warnings
cargo test --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml --lib --no-run
cargo build --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml
# Run the built CLI's security command for both directions and every basis 0..9.
# Complete both exact SDK oracle tests before any genuine proof.
cargo test --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml --lib -- --test-threads=1
```

The CLI commands are `security <forward|inverse> <0..9>` and
`prove <forward|inverse> <0..9>`. Offline commands require the pinned packages to be
cached. Compilation, numerical analysis, SDK oracle execution and proof execution
were recorded separately. No build or zero-test CLI harness was counted as a test.

## Actual security and semantic coverage

All twenty numerical SDK reports passed before the first genuine proof. Every
report gave **157.41904001390932 bits** for the complete selected stage model:
all eleven error terms, both PCS openings, AIR, lookup/GKR, sumcheck and the
declared 256-bit hash collision cap. Independent union recomputation matched.
There were no unassessed or nonfinite terms. The enforced whole-stage floor is
144 bits, with phase target 160, Goldilocks EF5 and zero proof of work.

Both SHA-512 Merkle hashers and the Fiat-Shamir hasher retain all 512 output bits
under distinct domains. The initial transcript includes the full consumer profile
and SHA-512 of each complete canonical request and output wire. Verifier public
setup contains all trusted IO and fixed routing/weights/ranges; no prover VK or
auxiliary certificate is trusted. Verifying never executes the BFV transform.

Both main/public WHIR schedules have four folds of four, derived rates 4/7/10 and
queries 386/176/162/161. Main/public stacked arities are 22/21 with six/five final
variables. Initial claims are 464/156 forward and 499/167 inverse. Unique decoding
requires zero OOD samples in this pinned SDK; this was checked, not bypassed.

All **13 owning tests** passed, zero failed, ignored, measured or filtered:

- Full 8192-coefficient parity against the actual native SDK for all ten Q5/P5
  moduli and both directions; an independent SDK impulse fixes root, ordering
  and inverse normalization. Both exact oracle tests also ran before proving.
- All twenty genuine serialized proofs verified. Proofs were generated and
  dropped sequentially; only four public representatives remained for negatives.
- Eight genuine weaker/foreign-program proofs covered carry, quotient, range,
  address routing, multiplicity, last butterfly, inverse normalization and full
  foreign IO. Each first verified under the attacker's exact AIR/VK, then failed
  under the verifier-owned honest machine. Range and address examples preserve
  every local integer equation, isolating the missing global link.
- Rebuilt full frames, contexts, directions, bases and last output words failed;
  malformed layout, oversized declared sequences, caps and trailing bytes failed
  closed. Full hash outputs/domain separation and the
  complete numerical model have owning checks.

The pure circuit's four feature suites (7/9/15/18 tests) and all fifteen old
consumer tests had already passed after the shared residual-kernel extraction.
All twenty old numerical reports remained exactly equal to their published
baseline. That is separate regression evidence, not new-profile proof credit.

## Observed resources and timing

One public forward/basis-0 CLI operation built, serialized and independently
verified a **1,958,608-byte proof**. Internal prover total was 2627.508 ms:
4.2973 ms certificate arithmetic, 163.0958 ms public setup and 2460.1147 ms
trace/proof/encoding. Verifier total was 183.577 ms, including 162.6838 ms public
setup and 12.5655 ms SDK verification. Verifier total also includes bounded decode
and framing. Setup commits public tables and is real work.

| Owned process | Outer elapsed | Samples | Sampled working-set maximum | Sampled private maximum | Observed OS peak working set |
| --- | ---: | ---: | ---: | ---: | ---: |
| Forward-0 CLI | 3020.2713 ms | 30 | 832,544,768 B | 829,988,864 B | 867,315,712 B |
| Complete 13-test suite | 94810.3127 ms | 944 | 898,883,584 B | 896,708,608 B | 917,577,728 B |

The test harness reported 94.72 seconds. CLI outer time also includes startup,
its preliminary numerical setup, fixtures and result printing, which precede the
library proving timer. Actual sampling intervals were 100.1211–100.6886 ms for
the CLI and 100.0968–110.1269 ms for the suite. Nominal interval was 100 ms.
The owned PID had a sampled 1792 MiB soft fuse and a 1200-second per-child
runtime fuse; neither fired. These are experimental test controls, not a query SLA.

Sampling can miss peaks. The OS high-water value is itself observed through
sampling, and private-byte samples are not a private-byte high-water guarantee.
This is not a hard process RAM bound. The complete peer also needs FHE keys,
storage, transport, caches, other arithmetic stages and concurrent jobs. Its
1–2 GB goal and end-to-end interactive SQL performance remain unestablished.
The single CLI case is not a latency distribution, throughput result or speedup.

## Evidence and remaining composition

Retained ignored source/SDK snapshots, raw stdout/stderr, compiler JSON, exact test
listings, process CSV and SHA-256 receipts link compilation, both SDK oracles,
all twenty numerical reports, first proof and the full suite. Sources and both
new PE files were rehashed after execution; prior 131 PE files were preserved.
Generated evidence and public fixtures are not committed as database contents.

Complete original relinearization material must still be linked through every
required transform and arithmetic edge. A complete MulRelin or multi-stage proof
requires its own composed error accounting and full execution/resource gates.
Source provenance, full SQL selection/completeness, fresh agreed heads and
distributed transaction/lock correctness remain separate required work. A checked
NTT stage cannot become a production `CheckedOperation` or a live SQL grant.
