# Single checked setup for simple proof gates

Simple CLI `prove` paths previously analyzed a public AIR for security reporting,
discarded it and constructed/analyzed another AIR in `Backend::new` before the
proving timer. They now prepare one existing checked Backend, format the same
security report from its retained public AIR and move that Backend into genuine
proving and verification. This removes duplicate CLI preparation. SDK inference,
proving, verification and exact public-statement checks remain mandatory.

The read-only `checked_public_air` accessor is experiment-private. One formatter
owns the unchanged JSON fields. `security` remains public-only with no Backend
configuration or witness trace; invalid modes reject before AIR construction.
State/Selection/SelectedEncoding composite lifecycles are unchanged. No cache of
private witnesses, configurations or proof-dependent data is added. Dependencies,
lockfiles, profiles and constraints are unchanged. In prove mode, configuration/entropy failure now
precedes security JSON output; it still precedes witness trace construction.

This is a nonaccepting experiment over explicitly PUBLIC NONSECRET fixtures.
It does not establish full encrypted SQL latency, BFV ciphertext formation, live
private locks, finality, complete-composition security or the 500 ms target.

## Actual validation

Release build, test compilation and strict all-target Clippy passed with Rust/
Cargo 1.99.0 MSVC, locked/offline dependencies, native CPU flags, two Cargo jobs
and two Rayon workers. Frozen inputs are four task paths, 84 controls and 24 SDK
anchors. All fifteen trace-free security reports remained field-exact before
any new trace/proof allocation. Both model floors remain 128 bits; complete
openings, constraints, quotient sizing and geometry are unchanged.

The new owning-boundary test observes AIR and trace factory counts. Security-only
constructs one AIR and no trace; invalid mode constructs neither. Prove prepares
one AIR and no trace, then genuinely proves and verifies with that retained AIR
and one trace. Changed kind, request or claimed output rejects before another
witness factory. This tests actual cryptographic work, not a replacement oracle.

The separate exact setup gate passed one test with 121 intentionally filtered
tests in an observed outer interval of 293.588 ms; default libtest
capture is retained. Its filter is separate from the complete suite below.

| Fixed profile / version | Proving ms, min / median / max | Verification ms, min / median / max | Outer ms, min / median / max |
| --- | --- | --- | --- |
| packed-canonical-index-opening / R1 | 1996.674 / 2029.519 / 2193.003 | 492.918 / 494.500 / 523.016 | 3118.726 / 3178.245 / 3469.721 |
| packed-canonical-index-opening / R2 | 1938.127 / 2027.111 / 2097.097 | 450.634 / 467.684 / 479.018 | 2680.811 / 2820.973 / 2902.753 |
| factorized-packed-canonical-index-opening / R1 | 1844.323 / 1975.867 / 2025.050 | 463.506 / 535.499 / 566.728 | 2936.008 / 3440.893 / 3476.250 |
| factorized-packed-canonical-index-opening / R2 | 1853.964 / 1869.947 / 1881.438 | 469.755 / 481.363 / 557.409 | 2686.151 / 2688.468 / 2775.261 |

Observed outer medians: packed-canonical-index-opening: 3178.245 → 2820.973 ms (-11.2412%); factorized-packed-canonical-index-opening: 3440.893 → 2688.468 ms (-21.8671%).

All twelve processes produced and genuinely verified their own proof.

| Fixed profile / version | Largest sampled working set B | Largest sampled private bytes B | Largest sampled OS peak working set B |
| --- | --- | --- | --- |
| packed-canonical-index-opening / R1 | 553574400 | 549916672 | 553574400 |
| packed-canonical-index-opening / R2 | 554262528 | 550641664 | 554266624 |
| factorized-packed-canonical-index-opening / R1 | 498724864 | 499032064 | 522338304 |
| factorized-packed-canonical-index-opening / R2 | 508276736 | 504692736 | 522289152 |

There were 335 samples across the twelve processes, with actual within-process
gaps of 103.4973–122.9849 ms. Sampled working set and OS peak counters
are distinct observations; lower memory is not inferred from removed setup alone.

Each fixed profile compares the preserved R1 binary with the new R2 binary in
R1/R2, R2/R1, R1/R2 order. All twelve children are fresh processes with two Rayon
workers. Each generates and genuinely verifies its own proof; numerical JSON is
field-exact with the prior fifteen reports. Proving includes private trace
construction after Backend preparation; verification is genuine SDK verification.
The outer interval additionally includes fixture work, public analysis, Backend
setup and process overhead. It excludes observer pre/postflight hashing.

Three observations per version/profile do not establish a production SLA or a
causal estimate for each internal timer. These source-profile experiments do not
measure complete network queries or unchanged composites. The earlier
[factorized profile comparison](FACTORIZED-PERIODICS-VALIDATION.md) retains its own
scope: lower sampled working set and slower outer/verification intervals between profiles.
The current comparison holds each profile fixed and changes the CLI lifecycle.

The full serial suite passed all 122 unique expected tests, with no failures,
ignored, measured or filtered tests, in 765.90 s; observed outer interval
765946.821 ms. Every prior 121 case and the new setup case ran.
There were 7099 memory samples; actual gaps were 100.4348–
140.4346 ms, mean 107.908379 ms. Maximum sampled working set/
private bytes/OS peak working set were respectively 1006051328/
1020264448/1006051328 B. No observer abort occurred, stderr was empty,
and all postflight source/artifact guards matched. These suite peaks include
historical profiles and cannot be assigned solely to this setup change.

The observer samples working set, private bytes and the OS-maintained peak working
set for its owned child only, nominally every 100 ms. Its 1792 MiB stop threshold
is a soft experimental guard; missed peaks remain possible. These counters are
distinct, exclude other processes and do not establish a network RAM bound.

## Provenance and reproduction

The source-only donor remains frozen. ROOT imported exactly four Rust files into
19cc683 and preserved the validated R1 documentation. An initial sandbox Git
postflight denial after the four copies was reconciled with exact before/after
hashes and successful Git checks; integration was not replayed. This was not a
native validation failure. Prior binaries, targets, source copies and evidence
remain intact. The new target is isolated. Generated logs, CSV and executables
remain ignored.

Immutable local evidence identifies this run. Independent reproduction remains
useful; no generated evidence is committed.

| Evidence | SHA-256 |
| --- | --- |
| .local/source-gate-setup-validation-r1/source.json | `0F931F3438665673862E3AA71755A768238EE88A0652A10A6B33F6436DEFA9A0` |
| .local/source-gate-setup-validation-r1/compile-success.json | `C8698261A5105B67C339E9CBF954A9FB9A0ED6AC0BC81D80BB43379BFBD50DFE` |
| .local/source-gate-setup-validation-r1/numeric-success.json | `F8228A7A4EA0AA9DE0C773FDFD1B449EF04CCD2920FB36356E5446466466EF55` |
| .local/source-gate-setup-observations/20261016-231614-852-SetupGate/success.json | `8EF61D122C186BC83C903EF95A13A23503F1BCCACB5F49FE9CB1E54E460770D8` |
| .local/source-gate-setup-observations/20261016-231622-329-PairedProofs/success.json | `75F4F3525A6C13FE9488428E597949EAEC3D8BC141D92A44A90758FE7730573C` |
| .local/observe-source-gate-setup-r1.py | `5CB11276EF4BC15464770F9A25884B1D840E471BA7C7CDFA6BA6BAAC7BAD7B6D` |
| .local/source-gate-setup-observations/20261016-231712-284-FullSuite/success.json | `CB26BB8BDC2C6FC449365DB982D13F5049A1E0149DB2E2C908D2C9BD2937B907` |
| hiding-fri-source-primitives.exe | `29300F7D6BA06E838D1AEB10B746969DF783E366B4CD5F1E8864F8FC709AFB11` |
| hiding_fri_source_primitives-27bcc2b47206c364.exe | `06F678DBD6563DD74BFBA8C5CDE30A1C28005649D74E384E55CC2A1707E4AAD3` |

With Rust/Cargo 1.99 MSVC, `RUSTFLAGS=-C target-cpu=native`, two Cargo jobs, two
Rayon workers, the same offline dependency cache and separate old/new targets:

```powershell
cargo build --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --no-run
cargo clippy --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
```

Run the same fifteen `security` cases listed in the prior validation. Run each
binary with `prove packed-canonical-index-opening` and
`prove factorized-packed-canonical-index-opening`; preserve actual outer intervals
as well as emitted internal timers. Run the new built test executable with
`--test-threads=1`. Source/SDK/artifact hashes and immutable child/checked-result,
stdout/stderr/CSV evidence are checked before and after each observed process.
