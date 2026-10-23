# Native R-DEEP regression validation

The [conditional image lemma](R-DEEP.md) is a finite fixed-location algebraic
argument. These tests establish concrete arithmetic and source correspondence;
passing them does not prove complete STARK confidentiality or SQL admission.
All additions are test-only. The fixed production configuration is unchanged.

## Observable coverage

`r_deep_tests.rs` uses actual Gold/EF5 arithmetic, Frobenius minimal polynomials,
synthetic division and explicit inversion of the mixing power-basis matrix.
Its three cases cover:

- Both committed heights k = 1024 and 4096, all 192 distinct query locations,
  all five extension coordinates and the full residual degree 827/3899. They
  reconstruct the required affine direction and check the four conjugate zeros
  that prevent an unrestricted-polynomial uniformity claim. This uses one dense
  full-degree target per height; the general equal-fiber statement is proved in
  the lemma, not by exhaustive testing or statistical sampling.
- Current/rotated OOD terms with the same public claims. A nonbase mixing coin
  covers their combined direction; a nonzero base coin exposes the precise
  abstract span obstruction. Its example exponents 10 and 27 exercise the
  generic identity, not an actual owning proof's next-point column offsets.
- Base-field OOD values, including the algebraic zero-point case, with their
  correct smaller image. Native availability still excludes zero separately.

`native_r_tests.rs` uses the ordinary fresh OS-seeded suite and its actual native
R constructor. On both heights it checks ten raw base columns versus the five
ordinary wrapper columns, inverse DFT, all ten native OOD interpolations against
coefficient Horner evaluation, and native packed compression with powers 0..9.
Independent synthetic division and the native DFT agree with every DEEP row:
8,192 and 32,768 rows in committed bit-reversed coset order. It does not build a
full FRI proof, test statistical independence, or inspect private PCS internals.
The generated matrices are nonparticipant test data and are not persisted.

The zero/base coin cases are intentional coverage of different mathematical
images. No cryptographic policy accepts weaker coins or retries on that basis.

## Reproducible commands

```sh
cargo test --release --locked -p bfv-hiding-stark hash::r_deep_tests:: -- --test-threads=1
cargo test --release --locked -p bfv-hiding-stark hash::native_r_tests:: -- --test-threads=1
cargo test --release --locked -p bfv-hiding-stark --features transcript-audit hash:: -- --test-threads=1
cargo clippy --release --locked -p bfv-hiding-stark --features transcript-audit --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```

The bounded local observations used Rust 1.99.0 MSVC, release opt-level 3,
native CPU, locked offline dependencies, two Cargo jobs and eight shared Rayon
workers. The supervisor held the exact executable handle and checked its image
and creation time. Limits were 120 seconds and 1,792 MiB whole-process memory,
sampled every 20 ms. No pre-existing or unknown process was terminated.

| Observation | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r712, coefficient image | 3 | 0.04 s | 74.3542 ms | 6,479,872 B |
| r714, native constructor/kernels | 1 | 0.02 s | 40.7916 ms | 22,478,848 B |

Both exited zero without recorded faults. The first coefficient build exposed
three ambiguous trait-inference errors; explicit Gold extension traits corrected
them before the successful observations. No source changed during a pinned run.

The final combined transcript-audit gate passed all 28 hash tests in 0.06 s
(r718). Strict audit Clippy passed (r717), as did the canonical requirements
mirror test (r719). Clippy requested a fixed-size slice iterator in the native
test; the final combined run includes that change. Formatting and new local
documentation links were checked. No expensive full-proof or peer-process gate
was repeated for these test-only additions.

Observed executable SHA-256 values:

```text
r712 813DBC98B521F1FA15467BE822AEF7F3A96DF3BC143B597314C0631809D112BA
r714 AA346E6A0AD287E26BEB0D5B8725CF85DACB33258F5E44920E467365827E49EE
```

An independent integer calculation checked the named five-proof local
fresh-coin numerator `(5*p+1151493)` against `p^5 / 2^253`, with
`p=18446744069414584321`. This verifies arithmetic of the limited bound in the
lemma, not its extension to adaptive transcripts or a total security estimate.

These durations are regression-test observations. They include neither full
proof generation nor SQL, network transfer, fresh-version agreement or locks.
They are not evidence that the complete 500 ms request target has been met.
