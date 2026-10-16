# Bounded selection and packed source opening: validation

Validated on 2026-10-16: combined release build, test compilation, strict
all-target Clippy, eleven trace-free numerical analyses, two separately observed
genuine proof/verification invocations and the complete serial85 suite passed.
Every expected case ran once: 85 passed, zero failed, ignored or filtered.

These are nonaccepting standalone experiments with explicitly PUBLIC NONSECRET
fixture keys, rows and identities. No production API, SQL result, BFV operand
formation, Owner-key exporter, lock protocol or finality claim is added. The
historical byte and canonical reports retain their original scope.

## Two distinct relations

`selection-opening` links the complete original four-row source to an independently
expected private plan commitment and a fixed-capacity selected-tuple commitment.
The plan binds the private TableId, final TRUE mask over all 256 nonnullable ages,
projection code and effective N4 LIMIT. The relation checks all mask positions,
complete matching membership, ordinal-preserving compaction, original age/u16
amount/RowId fields and zero inactive slots. Projection is committed but no
plaintext answer or BFV input is produced here.

Its composite verifier first verifies a genuine **old
`canonical-index-opening`** proof against independently expected source context,
then requires exact source-public-value binding and verifies Selection. The prover
also verifies the source proof before constructing the Selection trace. Missing,
foreign or byte-only source evidence cannot replace this check. Selection still
uses the old canonical C_open/profile; it does **not** silently accept the new
packed source. A packed-source-plus-Selection composition is not implemented or
measured in these runs.

`packed-canonical-index-opening` separately proves the same bounded canonical
source invariant with W7161 instead of W11521. Shared Cha/Poly/P2 arithmetic,
one evaluator and one trace-writing loop retain the old profiles. Six 82-row
groups range-bind feedforward/extracted words through Boolean output state at
CURRENT81 before reset at NEXT82. It retains 112 plaintext u32 fields, 40 immutable
key words and a 256-bit selected raw Polykey view for the unchanged Poly evaluator.
Authenticated word ranges bound TableId/RowId nonzero sums below2^35<p. Six
pairwise per-word zero/inverse tests prevent cancellation from faking distinct IDs.
The separate digest binds this exact layout and capture/absorb schedule.

Both use the same complete public CSTORE packet/root admission and private AEAD
source linkage. All 2348 plaintext bytes enter their salted C_open. Raw keys,
salts, plaintext, masks and identities are not proof public values or periodics.
Candidate P2 commitments, key anchoring and hiding assumptions remain experimental.
Per-proof model estimates of128 do not establish composed128-bit security for two
proofs and their commitment assumptions, or certify production privacy/erasure.

## Actual compile and numerical gate

Compiled parent: `9f8a247ea5e07d78b02256e17276689eaf7efad2`, ROOT branch
`codex/feature/sql-latency`. Combined final source freeze `42379E10...` contains
23 task paths, 36 controls and 85 fully qualified test names: old60 + Selection15
+ packed10. Packed-only seven files and Selection-only seven files retain their
reviewed source; nine shared paths contain an explicit additive dispatch/docs
union, followed by the exact schedule delegation cleanup below.

Actual Rust1.99.0 (`b940084d7`), native x86_64 Windows MSVC,
`RUSTFLAGS=-C target-cpu=native`, offline/locked standalone Cargo manifest,
MAIN Cargo cache and two Cargo/Rayon workers were used. No explicit Cargo target,
dependency resolution, SDK fork, lowered queries or weaker degree declaration was
introduced. All three final compile-only commands exited0: release build, release
tests `--no-run`, strict all-target Clippy. They executed no trace, tests or proof.

All eleven subsequent security-only calls exited0 with empty stderr. The nine
old cases exactly match actual receipt `A415437F...`, including both empty Poly
cases. Selection exactly matches its standalone receipt `A5388C9E...`.

| Actual item | Selection | Packed source |
| --- | ---: | ---: |
| Height / width / public values | 512 / 957 / 88 | 512 / 7161 / 691 |
| Full-width opening points / periodics | 2 / 512 | 2 / 512 |
| Constraints / inferred degree | 4814 / 3 | 16133 / 3 |
| Declared degree bound / quotient chunks | 5 / 16 | 5 / 16 |
| Batched functions | 2094 | 14502 |
| Unique / list decoding estimates | 128 / 128 | 128 / 128 |
| Trace / masked trace bytes | 3919872 / 7880704 | 29331456 / 58703872 |
| Main LDE array bytes | 63045632 | 469630976 |

Both complete row openings count. For packed source,
`2*(7161+5) + 10*16 + 10 = 14502`; for Selection the same formula gives2094.
Original height512/post-hiding degree bits10, q192, r5, blowup8, extension degree5,
four MMCS salt elements and independent OS-seeded randomness remain unchanged.
The conservative declaration5 was not lowered after degree3 inference. These
are pinned SDK-model reports, not empirical security certification. The common
512x512 periodic payload2097152B and its estimated LDE33554432B remain separate;
array formulas omit symbolic, quotient, tree, DFT, stack and other process memory.

## Two actual observed proof invocations

Each command ran once, exited0 after genuine verification, with empty stderr and
no observer abort. All original stdout, metadata, result and CSV files remain.

| CLI mode | Proving ms | Verification ms | Outer observed ms |
| --- | ---: | ---: | ---: |
| `prove selection-opening` | 5671.2797 | 1484.5861 | 7630.9739 |
| `prove packed-canonical-index-opening` | 2521.0821 | 560.8781 | 4348.1479 |

Selection's proving timer includes fresh source Backend construction, source
trace/proving and source verification, followed by Selection Backend construction
and Selection trace/proving. Its verification timer includes fresh Backend setup
and verification of BOTH proofs, with the source verified first. Fixture assembly,
independent public-source audits and the initial Selection numerical report precede
the timer. This is not isolated Selection proving or verification.

Packed source's proving timer includes witness trace generation and STARK proving;
fixture encryption, complete public audits, initial analysis and Backend setup
precede it. Verification uses the same in-memory Backend/proof. Neither timer
includes proof serialization, network, SQL, BFV formation or agreed-head acceptance.
Outer durations additionally include process setup, numerical/setup work and the
observer. These two different relations and historical runs are not a controlled
comparison of width reduction or a measured combined optimized composition.

The hidden owned-child observer requested100-ms waits, two Rayon workers,
separate1792-MiB WS/private/live-OS-peak soft abort checks and a600-s proof timeout.
It only kills/joins its owned child on failure and drains output before disposal.

| Observation | Valid samples | Actual gap min–max ms (mean) | Max sampled WS B | Max sampled private B | Max sampled live OS peak B |
| --- | ---: | --- | ---: | ---: | ---: |
| Selection composite | 28 | 204.846–355.004 (253.720778) | 842686464 | 839540736 | 842686464 |
| Packed source | 14 | 217.726–375.721 (265.130538) | 553873408 | 550789120 | 553873408 |

First/last samples were295.969/7146.430ms and377.573/3824.270ms respectively.
Every CSV row is valid and its recomputed maxima match the recorded result.
Sampling can miss transients and final lifetime peaks. Private bytes are not RSS;
these observations and soft abort thresholds are not hard RAM guarantees or a
whole-system measurement. One instrumented fixture per CLI mode establishes no
causal speedup, median/p95, complete SQL latency or robust500-ms result.

## Preserved failures, source and evidence

The first combined driver `A92E023A...` failed on incompatible PowerShell
`Tee-Object -LiteralPath/-Append` parameters. Cargo had created initial target
metadata, but no Cargo result or executable was recorded. This was a driver
failure, not a demonstrated Rust failure. The corrected driver used a fresh target
and log directory. Its release build/test compilation passed; strict Clippy101
reported only the old free `schedule::boundary/capture` helpers as unused.

The sole Rust-source repair in the combined retry was three arithmetic-neutral schedule hunks:
make the original boundary function const and delegate the old-profile branches
of `Schedule::boundary/capture` to the original helpers. Packed formulas,
equations, profile encodings, tests and other22 source/36 control files are exact.
The inverse patch `87D16965...` reproduces initial combined freeze `50454634...`.
No lint suppression or test removal was used. First logs and both first CLI/test
PEs were archived and hash-checked before the explicitly authorized cached retry.
Compiled Rust, manifests, lock and artifacts remain unchanged. This report and
three README status/link updates are the only post-validation documentation
changes. Earlier donor compile and source-review fixes remain in their original
preserved evidence.

Final CLI SHA256:
`2236D5F5A4C0874F56BE5D0F39A2B3192E9C4627D5BE75BD8AC4F14460579C0B`.
Final test SHA256:
`6F057BA3D17A4F2364ADC203120E199DB4DA2D5AF19A39F9DE54BAC8403A6E8C`.
Standalone lock canonical SHA256 remains `9C2136B7...` (actual compiled RAW
`B5AA8CA0...`); manifests/dependencies and root Cargo are unchanged.

Retained MAIN `.local/` evidence:

- Source: `combined-openings-source-r2-20261016-195222-793/manifest.json`,
  SHA256 `42379E109076335F32E60C2B15AE5D60741CF7D462758EE336BD68B12D9C210A`.
- Compile: `combined-openings-validation-r3/compile-success.json`,
  SHA256 `C856D0E935642E361265B4A5C846F21E11D77F6C54BFF6F69E8727FDEBFC7AFD`.
- Numeric: `combined-openings-numeric-20261016-195651-661/success.json`,
  SHA256 `659D9262D089951F8279741D978DBAEF801B04FB0B78DDA8BB98D8EE1A7C02D4`.
- Selection: `combined-openings-observations/20261016-195819-952-SelectionProve/`,
  success SHA256 `7FB8FFC7C53C89A803F4F3B49B8F982DA88403EF593CA0E9C7403A265F2D6D4E`.
- Packed: `combined-openings-observations/20261016-195840-888-PackedProve/`,
  success SHA256 `B0E832F4577A0DE1B323A14565486025427A75FABE9A75A103C5AAE79CD8059D`.

Observer SHA256 is `B0638E7C...`. Source, receipt and artifact identities match
all three actual runs. No measurement rerun or exclusion was used.

## Complete serial suite

The single full invocation passed all85 cases, each name exactly once, with
zero failed/ignored/filtered, in588.55 harness seconds. All60 old cases remain;
Selection adds15 and packed adds10. Coverage includes genuine and rebuilt
raw-SDK proofs: absent/foreign source rejection, complete mask membership,
LIMIT0/compaction omissions/extras/duplicates/order, original fields/identities,
fresh context/salt binding, packed u32 ranges/feedforward/reset/capture/stale
words, selected Polykey view, and zero/duplicate/canceling identity controls.
No accepting stub or replacement of old cases is used. Stderr contains only the
expected caught single-opening-budget panic; the test and complete process pass.

The same owned observer used a1200-s suite timeout. Outer duration was
588918.0566ms, with2809 valid CSV samples: first387.725ms/last588536.167ms,
actual gaps160.218–661.454ms (mean209.454573ms). Recomputed maxima were
1002569728B working set,1008013312B private and1002569728B sampled live OS peak.
No abort, exclusion or rerun occurred. The suite success receipt is
`combined-openings-observations/20261016-195905-513-FullSuite/success.json`,
SHA256 `44C74BBBA2512DF7FEC8B40797D0994179524DC1B7A67E5016B58637D234B643`.
Source/PE identities match the preceding numerical and two proof runs. As with
those runs, these are sampled observations, not final lifetime peaks or RAM caps.

## Reproduction

From the repository root, use the installed native Rust1.99 MSVC toolchain and
the existing pinned offline cache. Clear inherited encoded flags, target/profile,
wrapper, bootstrap and DCS profiling overrides; set absolute RUSTC/RUSTDOC paths,
`RUSTFLAGS=-C target-cpu=native`, `CARGO_HOME=<root>/.local/cargo-home`,
`CARGO_BUILD_JOBS=2`, `RAYON_NUM_THREADS=2` and offline mode. Select a NEW absent
`CARGO_TARGET_DIR`, preserving all prior targets/logs. No dependency resolution
or explicit `--target` was used. Exact compile command forms are:

```powershell
$manifest = 'experiments/hiding-fri-sha256-gate/Cargo.toml'
cargo build --release --locked --offline --manifest-path $manifest
cargo test --release --locked --offline --manifest-path $manifest --no-run
cargo clippy --release --locked --offline --manifest-path $manifest --all-targets -- -D warnings
```

Stop at the first failed command and retain its target, logs and partial artifacts.
After all three exit0, pin the new CLI/test hashes and source/lock identities.
Run the following CLI argument vectors once each with `security`: `sha256`,
`hchacha20`, `chacha20`, `poly1305-raw`, `poly1305-padded`,
`poly1305-raw empty`, `poly1305-padded empty`, `pair-opening`,
`canonical-index-opening`, `selection-opening`, `packed-canonical-index-opening`.
These calls construct no trace/proof. Require exit0 and both model bounds>=128;
compare the old-nine and Selection reports with their retained controls and
review the new full-width geometry before any witness allocation.

Only then give these exact command lines to an external owned-process guard:

| Executable in the fresh target | Arguments | Timeout |
| --- | --- | ---: |
| `release/hiding-fri-source-primitives.exe` | `prove selection-opening` | 600s |
| `release/hiding-fri-source-primitives.exe` | `prove packed-canonical-index-opening` | 600s |
| the unique `release/deps/hiding_fri_source_primitives-*.exe` | `--test-threads=1 --nocapture` | 1200s |

Run sequentially, once each, without filtering or retrying to improve numbers.
The guard must pin actual source/receipts/artifacts, create hidden owned children,
drain stdout/stderr, sample WS/private/live OS peak with100-ms requested waits,
apply independent1792-MiB soft abort thresholds, kill/join only its own child on
failure, handle the exit/counter race and preserve every result/CSV. Require both
verified stage records and all85 successful names exactly once. Local observer
scripts are retained evidence, not published production tools; bare unobserved
commands do not reproduce this resource-observed validation contract.

No private source/selection-to-BFV formation, typed/NULL catalog completeness,
cross-shard/history continuity, key custody, live SQL proof acceptance, locks,
freshness/finality or production privacy guarantee follows from this milestone.
