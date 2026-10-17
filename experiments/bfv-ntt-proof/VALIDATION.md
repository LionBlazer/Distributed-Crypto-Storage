# Full-8192 native NTT validation

Both native transform directions for all ten fixed Q5/P5 moduli passed on
2026-10-17 with Rust 1.99.0, Windows x86_64 MSVC, `target-cpu=native`, two build
jobs and two Rayon threads. Every fixture is explicitly public and nonsecret.
This proves an arithmetic dependency, not full BFV multiplication or SQL.

## Contract and actual checks

The [library](../../crates/bfv-ntt-circuit/README.md) owns canonical full-vector
codecs, exact pinned roots/routing, all 13 forward layers or 13 inverse layers
plus normalization, and the optional shared AIR. It depends directly on the
unchanged [fixed geometry](../../crates/bfv-fixed-geometry/README.md). Prover math
uses bounded u128 operations and allocation-free limb iteration. The standalone
[consumer](README.md) owns configuration, framing, transcript binding, generation
and independent verification; the verifier performs no coefficient NTT,
butterfly or quotient evaluation.

Offline lock resolution added only the new local library to the root lock.
Existing root package identities, checksums and dependency edges stayed unchanged.
The standalone registry packages use the same identities/checksums, with unused
optional edges pruned. Actual metadata and the runtime SDK type-name assertion
confirm native `fhe-math::ntt::NttOperator`, with no tfhe-ntt backend feature.
Requirements and the AGENTS mirror match.

Passed:

- Rustfmt and strict all-target Clippy for the default library, optional-feature
  library and consumer, with warnings treated as errors.
- All 7 default library tests and all 9 optional-feature tests. The feature suite
  repeats the seven default cases and adds two complete AIR/routing cases.
- Both SDK oracle tests before proofs: all 8192 outputs of both directions and
  all ten bases match the actual native operator; impulse tests recover its
  deterministic primitive root and inverse normalization.
- All 15 consumer tests, with no ignored or filtered cases. One mandatory case
  generates, verifies and drops all 20 genuine serialized stage proofs in sequence.
  Four representative proof fixtures are retained only within negative tests.
- Rebuilt canonical certificates reject wrong final/intermediate coefficients,
  stage order, root/output order, omitted inverse normalization and quotient/carry
  changes. Other cases reject foreign genuine contexts, noncanonical values,
  malformed lengths, oversized nested containers and trailing bytes. A genuine
  raw SDK proof under attacker-selected constraints cannot replace the fixed AIR.
- Four separate ordinary CLI generation/verification examples for Q0/P4 in both
  directions, with owned-process memory observations.

These are 31 suite test executions, not 31 distinct tests: the default seven are
repeated in the feature suite. The two focused SDK cases also run inside the
consumer suite. No older unrelated full suite was rerun or credited.

## Actual symbolic/security analysis

All 20 trace-free calls passed before final-profile oracle/proof work. Each basis
has the following actual SDK shape:

| Property | Forward | Inverse |
| --- | ---: | ---: |
| Height / main width | 8192 / 1 | 8192 / 1 |
| Public preprocessing width / public values | 416 / 40 | 448 / 40 |
| Constraints / maximum degree | 105 / 2 | 113 / 2 |
| Quotient chunks / batched functions | 1 / 422 | 1 / 454 |
| Blowup / queries / extension degree | 8 / 192 / 5 | 8 / 192 / 5 |
| Unique / list decoding security bits | 128 / 128 | 128 / 128 |
| Raw public preprocessing bytes | 27,262,976 | 29,360,128 |
| Raw public LDE bytes | 218,103,808 | 234,881,024 |

These are individual-relation bounds. They do not prove 128-bit security for a
future multi-stage composition. Raw matrix sizes are not whole-process RAM bounds.

## Decoder failure and bounded correction

The first candidate generated a proof but correctly rejected it with
`ProofResourceLimit`: the copied 1,048,576-slot budget was too small. Binary
Goldilocks values serialize as eight-byte arrays, charging eight slots plus their
parent slot. Increasing only the sequence limit did not resolve the failure.

A separate ignored diagnostic regenerated known local public SDK proofs using the
same linked configuration, exact AIR and consumer profile words. It used only
bounded typed decoding, canonical reencoding and binary search on the total
budget. For forward Q0 the exact minimum was 1,210,501 slots; inverse P4 needed
1,277,952. Each minimum passed and minimum minus one rejected. Largest observed
containers were 1411/1446 elements, below the unchanged 4096 sequence cap.
Human-readable JSON container counts were recorded separately: they omit binary
field byte-array charges and are not used as binary budget evidence.

The final NTT-only budget is 2,097,152 total slots. A conservative fixed-profile
bound is below 1,884,000: at width 448, row values consume at most 784,512 slots;
13 FRI sibling-value rounds 122,304; at most 16 binary authentication trees with
1600 sibling digests each 947,200; OOD extension values 21,792; other container,
commitment and struct slots below 8192. The per-sequence 4096 and frame 16 MiB limits
remain finite. Existing RNS and production budgets are unchanged. The consumer
profile digest includes all caps, so the revised budget has a distinct profile.

The new regression checks the exact binary Goldilocks row boundary: 4032 slots
decode 448 fields, 4031 rejects. A 65-row nested fixture exceeds the final total
budget while each individual container remains allowed. Final validation reran
compilation, all security/oracle gates and ordinary proofs in a fresh target;
the failed source, logs, artifacts and diagnostic attempts remain preserved.

## Observed complete local stage examples

Each example consumes and produces all 8192 coefficients. Generation includes
arithmetic/certificate construction, preprocessing, SDK proof and frame encoding.
Verification includes decoding, independent preprocessing and SDK verification.
Initial security reporting and fixture creation are outside the inner timers.

| Observation | Forward Q0 | Inverse Q0 | Forward P4 | Inverse P4 |
| --- | ---: | ---: | ---: | ---: |
| Generation | 529.362 ms | 561.320 ms | 524.320 ms | 559.427 ms |
| Independent verification | 459.160 ms | 494.592 ms | 460.215 ms | 490.730 ms |
| Serialized proof bytes | 5,854,289 | 6,280,369 | 5,866,161 | 6,287,249 |
| Maximum sampled working set B | 282,529,792 | 300,384,256 | 283,373,568 | 301,940,736 |
| Maximum sampled private bytes B | 278,978,560 | 300,068,864 | 280,104,960 | 300,113,920 |
| Maximum observed OS peak working set B | 290,025,472 | 309,198,848 | 289,820,672 | 309,288,960 |

The owned-PID observer sampled nominally every 100 ms, with 10/11/10/11 actual
samples and maximum gaps 100.983/100.611/100.675/100.709 ms. Outer observations were
1011.982/1110.363/1011.093/1111.232 ms; polling can delay exit detection, so these
are coarse process observations. The full 15-test process passed in 35.99 s, with 359
samples and maximum observed OS peak working set 596,144,128 B. Its largest actual
sampling gap was 107.858 ms. The 1792 MiB sampled soft fuse never triggered. These
observations establish neither a hard RAM bound nor a complete peer/query latency.
The SQL goal has no fixed 500 ms requirement.

## Reproduction and evidence

The [README](README.md) lists checked commands for all 20 security profiles, both
SDK oracles, representative measurements and the complete suite. Use Rust 1.99,
release mode, locked dependencies and `RAYON_NUM_THREADS=2`.

Ignored local receipts under `.local/ntt-validation-r2/`, SHA-256:

| Receipt | SHA-256 |
| --- | --- |
| `source.json` | `9E2A9F4631747F3382E12E94AB2820A8ED7CAE6304F70C1568295D19B223079F` |
| `compile/success.json` | `A6A1B65EA5FDA4B398E675A0113309EFE9B39CFBCC5E7B08932D7A0C3C99DB03` |
| `numeric/success.json` | `E79DCC6E1D7A8BFEB2BF8931E995EB31A667480664F69DBA05B82BE3AF331DA7` |
| `sdk-oracles/success.json` | `A402D2C51E7ADC659DF0672769B3F93CB114D180E46FF4448D324CCC64E188BD` |
| `cli/success.json` | `43ECC3E94DE9686F22FDB88485ACAFF8E184B6FC744AE5B345508F57203A9512` |
| `tests/success.json` | `AA0244C0B18F70B303D3C1990A41B2470EE38E293A483B2DAB864DD9AA57E836` |

Native receipts precede only documentation status/catalog/report changes. The
failed candidate is under `.local/ntt-validation-r1/`; controlled decoder evidence
is under `.local/ntt-budget-probe-r3/`, using the retained probe-r2 source. The
first diagnostic JSON view undercounted binary slots; the later binary-search
record explicitly separates them. A diagnostic compile argument error is also
retained and is not credited as a successful run.

Full encrypted multiplication still requires all three tensor components,
key-switch embedding and MAC, linked public setup and exact stage composition.
Same-key authority, encrypted source expansion, peer-side predicates, complete
selection, fresh distributed agreement, writer fencing and live SQL/locks remain
required work. A checked NTT stage grants no production operation or SQL permit.
