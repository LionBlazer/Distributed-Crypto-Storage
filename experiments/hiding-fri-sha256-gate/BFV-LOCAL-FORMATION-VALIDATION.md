# Signed local BFV formation validation

Validated on 2026-10-17: release build, test compilation, strict Clippy,
20 trace-free numerical commands, five exact Oracle tests, one genuine complete
LocalFormation CLI and all 212 serial behavior cases passed. This includes all
195 earlier cases and all 17 Local cases, with zero failed, ignored, measured or
filtered tests. Fixtures are explicitly PUBLIC NONSECRET.

## Relation and limits

The distinct `bfv-local-formation` profile links one full level-zero ciphertext
to the old canonical source and SelectionOpening/PV88, their SelectedEncoding,
one KeyTransform and five ordered BasisConvolution statements. The new local AIR
constrains all 40,960 equations `B_i,j + R_i,j - e_j - delta_i*W_j = qi*k_i,j`.
The same bounded noise word is used across all five bases; exact W words open the
existing encoding commitment. The complete canonical ciphertext decoder derives
B from the same ciphertext, rather than accepting a separate coefficient matrix.

Bit-ranged z63 and z20 encode `R = z63 - 2^62` and `k = z20 - 2^19`.
Thus R is in [-2^62,2^62-1] and k is in [-2^19,2^19-1]; k is never a
sign-plus-20-magnitude encoding. Noise is in -20..20 and W is in 0..114688.
The signed R lift reopens the existing raw-Gold C_R, without substituting a
qi-reduced value or changing its producer encoding. The independently checked integer residual interval
[-14835885613567410195, 13835075638878781459] lies strictly inside plus/minus
Goldilocks 18446744069414584321. Zero in the field therefore cannot hide a
nonzero integer multiple of the field modulus within that interval. Seven exact
producer streams, their salts, 0-to-1 carry, clearing and final digests remain
constrained. The [module contract](src/opening/local_formation/README.md) describes
the complete fixed schedule and the remaining authority/privacy boundaries.

The public fixture uses actual canonical source-selected originals, upstream
BFV encoding/encryption and independently generated upstream A randomness.
Caller noise replay supplies a fixture oracle, not an entropy proof. Production
Owner/evaluation-key authority, ciphertext-only peer witness construction,
independently fresh agreed heads, live SQL/lock acceptance, writer fences, MVCC
and finality remain unimplemented. LockReturn168 and version-locking contexts
are not silently substituted for old Selection88. Individual 128-bit model
estimates do not establish a composed-security theorem or production secrecy.

## Actual source and gates

The compiled parent is `00b14edca587821b59c4cdfb7a7ce5baf25b7775`.
The reviewed Local24 overlay preserves the published SQL compiler/consumer and
resolved 142-package graph. Both Cargo manifests/lockfiles and all 42 SDK anchors
remain unchanged. The approved outer duplicate Key verification removal retains
actual same-Key verification in the shared child helper before its Backend/factory.
No SDK fork, private cache, production API or key export was introduced.

R1 source908DF555 built the release and test executables, then strict Clippy
failed on six Local-only style/unused-import findings. No R1 tests or numerical
analyses ran. Four Local files received the reviewed lint-only corrections;
their inverse reproduces the original source. The original logs, metadata,
source copies and two executables remain preserved as failed-stage evidence,
rather than proof-validation baselines.

R2 source `72866FBEDB1E878652A016C6367E80ADBC12D9F5A5719F4D39B7652184D81440`
passed all three compile commands and actual `--list` discovery of 212 unique
names: old 195 plus new 17. The prior 22 executables and two new executables were
hash-checked; a lint-only source change is not a claim of identical PE bytes.

| Gate | Actual status |
| --- | --- |
| Release build / test-no-run / strict all-target Clippy | Three exits 0; no test bodies inferred from compilation |
| Discovery | Exactly 212 unique source names, old 195 plus new 17 |
| Numerical modes | All 20 exits 0; previous 19 complete ordered JSON lists field-exact to SQL baseline71149, including extra geometry objects |
| LocalOracle | Five separate exact tests, each 1 PASS/211 filtered; no ignored or failures |
| Complete Local CLI | Exit0, exact security JSON and `verified_experimental_bfv_local_formation` record, empty stderr, no abort |
| Full212 serial behavior suite | 212 PASS, zero failed/ignored/measured/filtered; old 195 plus new 17, default capture; 1058.70s stdout duration |

The five Oracle cases cover fixed geometry, integer wrap bounds, all 8192 scaled
source-selected words, all 40960 genuine upstream equations, and all seven producer
openings with a complete native-constraint trace check. They supplement the real
proof; they do not replace its AIR.

All 17 Local cases passed in the complete suite. Rebuilt attacks cover the
forbidden sign-and-20-magnitude field alias, common noise and support/slack, the
last coefficient quotient/scaled word, carry/reset/salt hold, idle permutation
and final digest. Other cases reject malformed/foreign source or database,
basis order, request/key/full-ciphertext substitutions and missing evidence
before a local factory; genuine foreign Encoding and fresh salt/profile replay
exercise actual proof boundaries. Raw SDK prove/verify rejection paths supplement
native constraint checks. The last-W case preserves the integer equations while
rebinding other roots, then isolates the independently fixed C_enc constraint.
The five Oracle cases repeat within Full212: 212 unique test cases and 217 test
executions across the two stages, with the genuine CLI counted separately.

Actual Local inference is 13,076 constraints, degree 3, 16 quotient chunks and
25,684 batched functions. T512/W12752/PV44 is the fixed source geometry;
the report has 592 periodics, post-hiding degree bits 10 and two complete row
openings. Batch accounting is `2*(12752+5) + 2*5*16 + 10 = 25684`.
Both SDK estimates reached 128 with unchanged q192/r5/ext5/blowup8, hiding
MMCS/PCS and independently OS-seeded masks/salts. The degree hint remains 5.
PV44 is a source contract, not an extra field invented in numerical JSON.

Separate array payload formulas are 52,232,192B original trace,
104,505,344B masked trace and 836,042,752B main LDE. These are not a process
peak: retained prerequisite proofs, native FHE objects, symbolic analysis,
periodics, FFT scratch, trees and allocator overhead are additional.

## One observed genuine composite

Proving was 46379.98ms; verification was 11596.3394ms. The complete owned process
took 58324.1055ms. These are one instrumented nonsecret fixture observation,
not an interactive SQL result, latency distribution, causal optimization result
or general performance/resource guarantee. Practical complete-operation latency
remains open; there is no fixed latency cutoff in the current goal.

The printed proving timer includes actual source/Selection/Encoding, one Key and
five Basis proof production, prerequisite verification, and the Local Backend,
trace and proof. The printed verification timer includes all genuine predecessor
checks and a fresh Local Backend/SDK verification. Neither isolates the local AIR.
Public fixture construction, upstream encryption/B derivation and initial security
analysis precede those timers; the outer clock includes them and process teardown.

| Process | Outer ms | Samples | Max sampled WS / private / observed OS peak WS, bytes |
| --- | ---: | ---: | --- |
| Complete Local CLI | 58324.1055 | 534 | 1210343424 /1211101184 /1210343424 |

Its 533 actual intervals span 105.5474..113.0190ms, mean 109.14603320825516ms.
The five Oracle children have 9 total samples and 4 within-child intervals;
their first three have only one startup sample each and establish no reliable
peak. The native whole-trace check took 357.275ms with 4 samples, maximum
WS/observed OS peak 119562240B and private 115802112B.

ObserverAA0 samples only its owned PID, with a nominal 100ms wait, a 1792MiB
sampled soft fuse, 900s per Oracle/CLI child and 3600s full-suite timeout headroom.
These timeouts are not an application SLA. It preserves raw process facts before
semantic checking, kills/joins a still-running owned child on failure, and binds
original/checked results, logs, CSV, metadata, tools, source and prerequisites.
Sampling may miss peaks; private allocation and OS peak WS are separate counters.
No hard OS memory limit or whole-host RAM bound follows from these observations.

The serial full suite finished in 1058.70s according to libtest; its owned outer
interval was 1058733.5542ms. Its 9688 valid samples have 9687 within-child gaps
from 104.5535 to 126.1877ms, mean 109.29087264374934ms. Maximum sampled WS/observed
OS peak was 1219887104B and private allocation 1217757184B, with no abort and
empty stderr. These are whole regression-suite observations, not SQL timings.
Default capture was used; all 212 expected names appeared exactly once as PASS.

## Reproduction and retained evidence

Use Rust 1.99.0 MSVC, native CPU flags, jobs2/Rayon2, the cached 142-package graph,
locked/offline Cargo and a fresh target. Clear inherited RUST/DCS/Cargo target,
profile, wrapper and encoded-flag overrides before setting explicit compiler,
rustdoc, CARGO_HOME and target paths. Do not overwrite retained first-failure
targets/logs. The actual validation driverA38 performs this sanitation and pins
the compiler/tool identities; its distinct modes do not advance automatically.

```powershell
$ErrorActionPreference = 'Stop'
function Invoke-Checked([string]$program,[string[]]$arguments) {
 & $program @arguments
 if ($LASTEXITCODE -ne 0) { throw "Native exit $LASTEXITCODE" }
}
$leaf='experiments/hiding-fri-sha256-gate/Cargo.toml'
Invoke-Checked 'cargo' @('build','--release','--locked','--offline','--manifest-path',$leaf)
Invoke-Checked 'cargo' @('test','--no-run','--release','--locked','--offline','--manifest-path',$leaf)
Invoke-Checked 'cargo' @('clippy','--all-targets','--release','--locked','--offline','--manifest-path',$leaf,'--','-D','warnings')
# Use the actual test executable printed by the fresh no-run command.
$cli="$env:CARGO_TARGET_DIR/release/hiding-fri-source-primitives.exe"
$test=(Get-ChildItem "$env:CARGO_TARGET_DIR/release/deps/hiding_fri_source_primitives-*.exe").FullName
if (@($test).Count -ne 1) { throw 'Expected one fresh test executable' }
Invoke-Checked $test @('--list')
# Execute the 19 earlier security commands plus the new command, inspect both
# bounds/actual geometry, then run Oracle/CLI under equivalent external sampling.
Invoke-Checked $cli @('security','bfv-local-formation')
foreach($name in @(
 'fixed_geometry_and_signed_zero_noise_support_do_not_certify_resources_or_entropy',
 'integer_residual_bounds_exclude_gold_wrap_and_sign_plus20_counterexample',
 'actual_source_selected_originals_define_sparse_slots_and_all8192_scaled_words',
 'genuine_upstream_ciphertext_satisfies_all40960_integer_formation_equations',
 'all_seven_exact_producer_openings_and_full_trace_pass_native_constraints')) {
 Invoke-Checked $test @('--exact',"opening::local_formation::tests::$name",'--test-threads=1')
}
Invoke-Checked $cli @('prove','bfv-local-formation')
# Serial full-suite reproduction under the separately described external observer.
Invoke-Checked $test @('--test-threads=1')
```

The earlier 19 exact commands and sanitation are recorded in
[SQL-plan validation](SQL-LOCK-PLANS-VALIDATION.md). The checked command wrapper
stops on the first nonzero exit; the excerpt lists the explicit phases.
The local resource observer is ignored and not part of the published source.
The excerpt alone does not implement its sampling/fuse/timeout machinery.

Immutable local receipts: R1compile0D137C51; R2source72866FBE,
compile5BBA7953 and numericEC854201 under
`.local/bfv-local-formation-validation-r{1,2}/`; Oracle
`.local/bfv-local-formation-observations-r2/20261017-033221-464-LocalOracle/success.json`
(A91F1DA1), and genuine
`20261017-033234-420-LocalProve/success.json`(4965405C).
The actual CLI SHA256 is
`FCD435291DC45E0D8A528C8AF9912EC842613EC40338D3B63F814E3FEF47D31A`;
test SHA256 is
`555B5E744C5530D0EF4B9782C7616E62B53526C71C167CEF8F7276D492D00B25`.
The genuine stdoutA5F1169B and CSV9AB2DC6D remain retained with 534 samples.
Full212 receipt is
`.local/bfv-local-formation-observations-r2/20261017-033526-557-FullSuite/success.json`
(SHA256 `6CEE86992D6BF49A2C94DA375FD5EC468E646673EA92CD368CDEDB410CF26F50`).
Its stdoutFD2E9CA0/CSV83B50652 and independent audit
`.local/local-formation-independent-full212-audit-20261017-035405-887.json`
(5F2E2342) retain the complete names, intervals and counter maxima. Generated proofs, logs, CSV and fixture data are not
committed. Historical reports retain their original scopes and measurements.
