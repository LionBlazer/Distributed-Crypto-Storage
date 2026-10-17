# Full-8192 public RNS scaling validation

On 2026-10-17, the fixed `Extend5To10` and `Scale10To5` relations passed native
validation with Rust 1.99.0, x86_64 Windows MSVC, `target-cpu=native`, two Cargo
build jobs and two Rayon threads. All fixtures are explicitly public and nonsecret.
This is one arithmetic dependency of encrypted ciphertext multiplication, not a
complete MulRelin or SQL implementation.

## Scope and architecture

The reusable [bfv-scale-circuit](../../crates/bfv-scale-circuit/README.md) owns
fixed-basis math, canonical full-vector codecs, bounded public auxiliary data and
the optional shared limb AIR. It imports the existing Q5 geometry from
`bfv-linear-circuit`. Its default API has no P3 field or backend types.

The standalone [consumer](README.md) owns the exact linked Plonky3 0.8.0 proof
configuration, transcript binding, frame budgets, generation and independent
verification. The verifier checks canonical ranges, complete input/output
bindings and copied Q5 rows, builds its own public preprocessing commitment, and
verifies the STARK. It does not execute `RnsScaler`, reconstruct CRT values or
derive rounding quotients. Public auxiliaries alone are never accepted evidence.
The single main trace column is constrained zero; all 8192 rows of the actual
scaling equations are checked against canonical public preprocessing.

The new 8 MiB experimental frame cap accommodates its 2,580,624-byte auxiliary
certificate. Nested SDK decoding uses the shared `bounded-postcard` library with
4096 elements per sequence and 1,048,576 total container slots. Existing production
proof profiles, operations, 2 MiB cap and network acceptance are unchanged.

## Actual checks

Offline lock resolution added only the new local library to the root lock;
existing root packages, checksums and dependency edges stayed identical. The
standalone lock uses the same registry package identities and checksums, with
unused optional edges pruned. The resolved `tfhe-ntt` feature set excludes nightly.
The original Russian requirements and their AGENTS mirror match.

Passed:

- Rustfmt and strict all-target Clippy for the default library, feature library
  and consumer, with warnings treated as errors.
- All 7 default library tests and all 8 `plonky3` feature tests. The latter includes
  the same seven cases plus the actual AIR forgery case.
- Two SDK oracle tests before any proof execution: the actual six-prime SDK
  generator recovers the fixed five auxiliary moduli, and every coefficient of
  both complete scaling roles matches the actual upstream `RnsScaler`.
- All 14 consumer tests, without filtering or ignored cases. Genuine serialized
  proofs bind both roles and all output coefficients. Cases reject altered query
  identity, profile, representation, modulus order, final residues, truncation,
  trailing bytes, oversized nested sequences and auxiliary high bits.
- Coherently rebound output/auxiliary digests still fail the exact limb relation.
  Canonical quotient, remainder and carry changes fail after rebuilding public
  preprocessing. A genuine SDK proof under attacker-selected constraints and
  preprocessing cannot replace an ordinary scaling proof.
- Both complete `prove` CLI examples, including ordinary independent verification
  and the stage-only checked marker.

The SDK's actual trace-free analyzer produced these values before proof work:

| Property | Extend Q5 to Q5/P5 | Scale Q5/P5 to Q5 |
| --- | ---: | ---: |
| Height / main width | 8192 / 1 | 8192 / 1 |
| Public preprocessing width | 144 | 164 |
| Public values | 40 | 40 |
| Constraints / maximum degree | 64 / 1 | 64 / 1 |
| Quotient chunks / batched functions | 1 / 150 | 1 / 170 |
| Blowup / queries / extension degree | 8 / 192 / 5 | 8 / 192 / 5 |
| Unique / list decoding security bits | 128 / 128 | 128 / 128 |
| Raw public preprocessing bytes | 9,437,184 | 10,747,904 |
| Raw public LDE bytes | 75,497,472 | 85,983,232 |

These security figures model each relation separately; they establish no security
bound for a future composition. Raw array sizes exclude other process allocations.

## Observed local examples

Each CLI invocation generated and independently verified one full stage proof:

| Observation | Extend | Downscale |
| --- | ---: | ---: |
| Input / output residues | 40,960 / 81,920 | 81,920 / 40,960 |
| Generation including arithmetic, preprocessing and encoding | 250.469 ms | 280.436 ms |
| Independent verification including preprocessing | 176.900 ms | 199.225 ms |
| Serialized proof bytes | 3,222,283 | 3,252,971 |
| Sampled maximum working set | 110,841,856 B | 113,717,248 B |
| Sampled maximum private bytes | 107,651,072 B | 109,789,184 B |
| Maximum observed OS peak working set | 125,689,856 B | 137,859,072 B |

An owned-PID observer sampled nominally every 100 ms and recorded actual gaps.
It observed five samples per CLI process, with maximum gaps of 100.633 ms and
100.649 ms. Its outer elapsed observations were 508.743 ms and 508.686 ms; polling
can delay exit detection by about one interval, so these are coarse process
observations rather than precise operation timers. The complete 14-test process
passed in 3.66 s and had 37 memory samples, with maximum observed OS peak working
set 222,306,304 B. A 1792 MiB sampled soft fuse never triggered. These samples do
not establish a hard RAM bound, a peer/network query measurement or a latency SLA.
The SQL goal has no fixed 500 ms deadline.

## Reproduction and provenance

Use Rust 1.99 or newer, release mode, locked dependencies and `RAYON_NUM_THREADS=2`.
The [consumer README](README.md) lists the standalone commands; the library README
lists both feature selections. Run both trace-free `security` commands and the two
SDK oracle tests before invoking proofs.

Ignored local evidence receipts, SHA-256:

| Receipt under `.local/rns-scaling-validation-r2/` | SHA-256 |
| --- | --- |
| `source.json` | `083EAF4C7B2AE57599BD5BA8B0D2C431D4DACD81C11DB0FC559768B2F0A43E86` |
| `compile/success.json` | `3F33FAF0F84EF1D9060B443B68B5063C4EC6609FCD0C713203CBE7D9B4EE24CA` |
| `numeric/success.json` | `2D6958500C4786B5670F25357CA00C6F9C818BFDA2A291BBAB173FE36E6C77F6` |
| `sdk-oracles/success.json` | `E2857A81F4635C17639FE02121FB23348090BD70E46C0995639F2FB86B9EB992` |
| `tests/success.json` | `8ED93279EB6FAB7AD1049D57B58CA9B8C784808148F8BAD3AE19932F1AD55C33` |
| `cli/success.json` | `A08E569DB20778CA1FDFB0211AD5EE99FDDE7BCC6570C4FEFE50589255E51BE4` |

Source preparation and failed attempts are retained separately. The first fmt
launch encountered sandbox `Access denied`; the escalated run passed fmt and
Clippy identified one indexed read loop. The equivalent iterator correction then
passed all checks. The source receipt's descriptive target field says `r2`, but
its explicit `CARGO_TARGET_DIR` and all actual artifact paths correctly show
`.local/target-rns-scaling-r1`. Later observation tooling follows that actual
environment and selects the compiled library test artifacts, excluding the CLI's
zero-test harness. No proof parameters or SDK sources were changed to pass checks.
These receipts precede the documentation-only status/catalog updates.

## Remaining dependency

The caller's Natural PowerBasis label does not prove its source or NTT conversion.
Full ciphertext multiplication still needs exact forward/inverse NTT routing for
the Q/P bases, all tensor components, and linked key switching/relinearization
against the public setup. Same-key authority, compact encrypted-source expansion,
peer-side encrypted predicates, complete selection, fresh distributed agreement,
writer fencing and live SQL transaction/lock acceptance remain separate work.
