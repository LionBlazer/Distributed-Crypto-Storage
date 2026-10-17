# Fixed PostgreSQL locking-plan validation

Validated on 2026-10-17: actual parser/script/TLS rejection checks, offline dependency
resolution, release/test compilation, strict Clippy, all 19 unchanged numerical
reports, six new experimental cases and both parsed-query CLI gates passed. The
195 discovered experiment names were not a full 195 test run. This stage connects
real fixed-record SQL plans to existing private research proofs; it grants no live
lock or network SQL acceptance. Every cryptographic fixture is PUBLIC NONSECRET.

## Behavior and scope

`QueryPlan::LockingSelect` retains the complete final-TRUE predicate mask, ordered
projection, original LIMIT/OFFSET and one of four strengths with default waiting,
NOWAIT or SKIP LOCKED. The clause may precede or follow the WHOLE row window;
unsupported OF, multiple clauses, split windows, aggregates, ORDER BY, FETCH,
explicit WAIT and trailing SQL reject as whole statements. PostgreSQL 18 has broader
syntax; this is the existing fixed `records` schema, not a full PostgreSQL parser.
The [PG18 locking documentation](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE)
and [pinned grammar](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/parser/gram.y)
anchor the admitted syntax.

The N4 adapter rejects OFFSET or finite LIMIT above 4 and reverse AmountAge;
it does not clamp a parsed window or use an ordinary retained prefix as the lock
candidate set. The request is SHA256(domain || LE64(SQL byte length) || exact SQL
bytes || caller nonce32). CLI obtains its nonce from the existing OS-seeded RNG;
this proves neither nonce entropy nor permission. Actor/controller, TableId,
genesis, control parent, C_old and independently expected C_plan remain caller
obligations. Canonical C_open is rebound to this request; version C_state and its
version tag remain distinct from the fresh query request.

The six new cases test exact SQL/nonce identity, N4/projection rejection, all 12
strength/wait combinations against the real transaction-state oracle, a genuine
canonical SKIP proof beyond the returned prefix, a rebuilt wrong-policy proof,
and a genuine cached certificate with two parsed warm queries. The native oracle
is an independent behavioral check, not a replacement for AIR constraints.

## Actual gates and preservation

| Gate | Actual result |
| --- | --- |
| Root sql-plan all targets | 24 PASS:4 Boolean,4 locking,5 pagination,11 existing plans; no ignored/filtered |
| Root storage-client script filter | 14 PASS,17 filtered out; whole-script rejection before creation/prior execution |
| Typed relational exact rejection | 1 PASS,10 filtered out; actual TLS servers with two independent peer identities, running in threads in the test process |
| Fixed Session daemon exact rejection | Initial Cargo invocation and final direct invocation each 1 PASS/53 filtered; independently running OS peer process |
| Historical GUI package checks | requirements_sync1 and sql_rows7 PASS, no ignored/filtered; these are test consumers, not a live GUI/network fallback |
| Experiment build/test-no-run/strict all-target Clippy | All three exit0; --list discovers exactly195 source names |
| Root four-package all-target test-no-run/strict Clippy | Both exit0; no test-body execution is inferred from no-run |
| Trace-free numerical modes | All19 exit0, blank stderr; complete ordered JSON lists equal the previous BFV baseline 2131, including extra geometry JSON |
| Focused experimental cases | Six separate exact invocations, each 1 PASS/194 filtered; no ignored/failures |
| Parsed canonical and version CLI | Both exit0, genuine proof verification, blank stderr; no abort |

Session and typed tests clear Trace after fixture setup and assert no locking-query
I/O or version change for all 12 mode/policy combinations. Fixture bootstrap may
contact peers. Typed servers are not separate OS processes; the daemon fixture is.
There are 54 unique executed test cases and 55 test executions, including the
final daemon repeat, separate from tool/numeric/CLI executions. Six experiment
cases and seven root cases are new. Four-package compilation rebuilt the shared
dcs-peer executable under its final feature/link set, so the initial daemon
binary hash is not claimed as preserved. The final direct test uses the
post-build proved_sql executable and final daemon, without another Cargo build.
Both original D6FA and final direct receipts remain retained. The final child
actually exited 0 with 1 PASS/53 filtered; its wrapper then wrongly required empty
stderr. Read-only checked-success 79D0 accepts ONLY the source-confirmed normal
`Proof backend: avx512` line, retains original A7FD/raw logs, and rehashes all 25
final root executables. That check performs no rerun, rebuild or source change.
Final peer SHA256: `C02A6447D57F0D4AB1BE0DF2DAAE1FDDF4DF088C83878C1469A184FC783089CB`;
final proved_sql test SHA256: `7AA11E0316A1B7B17BCB0E9DF09273437D601B91382BD67B59BC1C84292D4D3B`.

The old 189 bodies and AIR/trace/profile controls remain preserved; their historical
runs were not repeated here. This preservation and complete numerical comparison
support the focused validation scope, not a new full-suite execution claim.

The parent was `cbe2da2e41774f952198a521361a7e6a4edfa6dd`. The 23-path preview
`8D3D53FF...` became source freeze
`706E481B140A9D53F2FAD2E4FDE1D520798691984223020CB0EEF0602A7F3911`.
All 18 measured BFV Rust files, corrected Key test, prior genuine-byte fixture,
validated README prefixes and requirements remain preserved. Three old native
locking-test helpers become visible to the new sibling cases; their bodies and
all AIR equations/profiles are unchanged. Documentation updates follow validation.

Offline update/metadata adds only local sql-plan 0.1.0 and its experiment edge:
141 to 142 leaf packages, no registry version/checksum or normalized old feature
change. Existing FHE normal edges remain. Root Cargo.lock is unchanged; leaf lock:
`6E35C1FAC96FA44982FBC334B4E295119D75570E5BD4A2D0F0A4022DC6E8E053`.
CLI `DECF3EBA52237D78FA2336C21F360CE9AEEFFAD14DB460E7862673B441527077`
and test executable
`F731B3FAE57E2FD48586A39280A72E16453D03A47DB24D0F5D7B8BD741009352`
remain frozen. Both locking AIRs still report T512/W1948/PV116, 7092 constraints,
actual degree 4, 16 quotient chunks, 4076 batched functions and 512 periodics, with
q192/ext5/r5/blowup8 and both complete row openings. Both model estimates are 128;
this is not a composed-security or production-privacy certification.

## Single proof observations

Normal parsed-query composite: proving 4095.2748ms, verification 893.7532ms.
Version path: cold proving 1717.3525/verification538.2132ms; warm query 1
567.0936/138.0315ms; warm query 2 853.6025/136.0931ms. Retained cache-owned accounting
was 12883420 B, distinct from process memory or a network admission bound.

| Observed process scope | Outer ms | Samples | Max sampled WS / private / OS peak WS, bytes |
| --- | ---: | ---: | --- |
| Normal CLI, source plus lock | 5050.5690 | 47 | 842731520 /839303168 /842731520 |
| Version CLI, one cold plus two warm | 4182.3819 | 39 | 554749952 /551530496 /554749952 |

SQL parsing, nonce/fixture construction and initial security analysis are outside
the printed timers. Normal proving/verification includes real source and lock
work. Version cold Backend preparation and Candidate capacity traversal precede
the respective timers; joint admission and actual verification are inside the
verification timer. Warm lease acquisition/statement fixtures precede timing,
while full Expected/state checks and child Backend preparation are inside.
Outer clocks cover the complete observed child including those excluded phases.
These are single nonsecret fixture observations, not clean SQL latency comparisons.

The six focused children have 104 total samples; 98 within-child intervals span
100.1738..113.5904ms, with maximum WS844763136/private841428992/OSpeak844763136B.
The two tiny cases have only one startup sample each, no interval or reliable peak.
Normal CLI intervals span106.8688..112.3268ms; version intervals102.1864..110.1912ms.
The nominal 100 ms wait is not an exact cadence. Observer 860A uses the reviewed
owned-child lifecycle, a 1792 MiB sampled soft fuse and 900 s child timeout, with kill,
join and stream drain on failure. There was no abort. Sampling may miss peaks;
OS peak WS and private allocation are separate counters. This is not a hard OS
memory limit or whole-system RAM guarantee, and there is no fixed latency SLA.

## Exact commands and reproduction environment

Use the recorded Rust1.99.0 MSVC toolchain and cached dependencies. Replace UNIQUE
with fresh root/leaf target directories for a reproduction; keep stdout/stderr
and the first failure. The actual guarded local drivers are freeze/dependency3283,
leafCompile58AD, numericADB6, owningEE8B and observer860A. Their receipts pin
full source/tool/env/argv hashes. The following setup mirrors3283 sanitization;
root parser/script/typed receipts separately retain their actual environment.

```powershell
$repo = (Get-Location).Path
$tc = 'E:/Users/white/.rustup/toolchains/1.99.0-x86_64-pc-windows-msvc/bin'
$names = @('CARGO_BUILD_TARGET','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTDOC','CARGO_BUILD_RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_ENCODED_RUSTFLAGS','CARGO_BUILD_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_HOME','CARGO_BUILD_JOBS','RAYON_NUM_THREADS','CARGO_NET_OFFLINE','CARGO_TERM_COLOR')
Get-ChildItem Env: | ForEach-Object { $upper=$_.Name.ToUpperInvariant(); if ($upper -in $names -or $upper -match '^(RUST|DCS_|CARGO_PROFILE_|CARGO_TARGET_|CARGO_BUILD_RUST|CARGO_BUILD_ENCODED_RUST|CARGO_ENCODED_RUST)') { Remove-Item -LiteralPath ('Env:'+ $_.Name) } }
$env:CARGO_HOME = "$repo/.local/cargo-home"
$env:RUSTUP_TOOLCHAIN = '1.99.0-x86_64-pc-windows-msvc'
$env:RUSTC="$tc/rustc.exe"; $env:RUSTDOC="$tc/rustdoc.exe"; $env:RUSTFMT="$tc/rustfmt.exe"
$env:RUSTFLAGS='-C target-cpu=native'; $env:CARGO_BUILD_JOBS='2'; $env:RAYON_NUM_THREADS='2'
$env:CARGO_TERM_COLOR='never'; $env:CARGO_NET_OFFLINE='true'; $env:PATH="$tc;$env:PATH"
function Invoke-Checked([string]$exe,[string[]]$arguments) { & $exe @arguments; if ($LASTEXITCODE -ne 0) { throw "Native exit $LASTEXITCODE" } }
$cargo="$tc/cargo.exe"; $pkgs=@('-p','sql-plan','-p','storage-client','-p','dcs-peer','-p','fhe-playground')
$env:CARGO_TARGET_DIR="$repo/.local/sql-lock-plans-root-UNIQUE"
Invoke-Checked $cargo @('test','--release','--locked','--offline','-p','sql-plan','--all-targets')
Invoke-Checked $cargo @('test','--release','--locked','--offline','-p','storage-client','--lib','script::')
Invoke-Checked $cargo @('test','--release','--locked','--offline','-p','storage-client','--test','relational','typed_catalog_lock_syntax_cannot_enter_ordinary_projection_or_network_synchronization','--','--exact','--test-threads=1')
Invoke-Checked $cargo @('test','--release','--locked','--offline','-p','dcs-peer','--test','proved_sql','locking_plans::every_typed_lock_plan_rejects_before_any_peer_io_or_source_version_change','--','--exact','--test-threads=1')
foreach ($name in @('requirements_sync','sql_rows')) { Invoke-Checked $cargo @('test','--release','--locked','--offline','-p','fhe-playground','--test',$name,'--','--test-threads=1') }
Invoke-Checked $cargo (@('test','--release','--locked','--offline')+$pkgs+@('--all-targets','--no-run'))
Invoke-Checked $cargo (@('clippy','--release','--locked','--offline')+$pkgs+@('--all-targets','--','-D','warnings'))
# Use the proved_sql executable printed by that four-package no-run command.
# The recorded final basename below may differ if build configuration is changed.
$finalDaemonTest="$env:CARGO_TARGET_DIR/release/deps/proved_sql-772c8371228e6077.exe"
Invoke-Checked $finalDaemonTest @('--exact','locking_plans::every_typed_lock_plan_rejects_before_any_peer_io_or_source_version_change','--test-threads=1')
$env:CARGO_TARGET_DIR="$repo/.local/sql-lock-plans-leaf-UNIQUE"
$leaf='experiments/hiding-fri-sha256-gate/Cargo.toml'
# The recorded dependency phase used update --workspace --offline and then locked metadata.
# Reproduction from the published, already-resolved lock needs only locked metadata.
Invoke-Checked $cargo @('metadata','--locked','--offline','--format-version','1','--manifest-path',$leaf)
Invoke-Checked $cargo @('build','--release','--locked','--offline','--manifest-path',$leaf)
Invoke-Checked $cargo @('test','--no-run','--release','--locked','--offline','--manifest-path',$leaf)
Invoke-Checked $cargo @('clippy','--all-targets','--release','--locked','--offline','--manifest-path',$leaf,'--','-D','warnings')
$cli="$env:CARGO_TARGET_DIR/release/hiding-fri-source-primitives.exe"
$test=(Get-ChildItem "$env:CARGO_TARGET_DIR/release/deps/hiding_fri_source_primitives-*.exe").FullName
if (@($test).Count -ne 1) { throw 'Expected one fresh test executable' }
Invoke-Checked $test @('--list')
$security=@('sha256','hchacha20','chacha20','poly1305-raw','poly1305-padded','poly1305-raw empty','poly1305-padded empty','pair-opening','canonical-index-opening','selection-opening','packed-canonical-index-opening','state-certificate','version-selection','selected-encoding','factorized-packed-canonical-index-opening','locking-selection','version-locking-selection','bfv-key-transform','bfv-basis-convolution')
foreach ($case in $security) { Invoke-Checked $cli (@('security')+($case -split ' ')) }
$cases=@(
'opening::locking::sql_tests::query_identity_binds_exact_sql_and_independent_nonce_without_choosing_authority',
'opening::locking::sql_tests::bounded_adapter_rejects_oversized_windows_and_reverse_projection_instead_of_clamping',
'opening::locking::sql_tests::actual_parsed_lock_modes_and_policies_match_the_real_transaction_state_oracle',
'opening::locking::sql_tests::genuine_parsed_skip_locked_proof_uses_complete_source_beyond_the_return_prefix',
'opening::locking::sql_tests::a_rebuilt_prover_selected_lock_policy_cannot_replace_the_compiled_plan',
'opening::state::locking::sql_tests::one_actual_certificate_supports_two_compiled_sql_requests_with_distinct_control_parents')
foreach ($case in $cases) { Invoke-Checked $test @('--exact',$case,'--test-threads=1') }
Invoke-Checked $cli @('prove','locking-selection')
Invoke-Checked $cli @('prove','version-locking-selection')
```

## Retained evidence and limits

Local receipts: `.local/postgres-lock-plans-validation-r1/dependency-success.json`
(A3DE5967), `.local/postgres-lock-plans-leaf-compile-r1/compile-success.json`(FED12D16),
`.local/postgres-lock-plans-numeric-r1/numeric-success.json`(71149DBE), parser
`023940-235624`(4352BE08), scripts`024155-705003`(CD927484), typed`024604-682867`
(DE78D26F), and `.local/postgres-lock-plans-owning-r1/{daemon,gui,compile,clippy}`
(D6FA309F/B996964E/DF7CD54E/15A68B6A). Final direct daemon evidence is
`.local/postgres-lock-plans-daemon-final-20261017-030230-648779/checked-success.json`
(79D0D060), with original result A7FDB573 and unchanged raw output. The root parser/script/typed directories
begin `.local/postgres-lock-plans-root-` and contain `result.json`.
Observed receipts are `.local/postgres-lock-plans-observations/20261017-025246-390-SQLFocus`
(D2DC3079),`20261017-025316-359-LockProve`(1EB2E90B), and
`20261017-025329-931-VersionProve`(437D850B), each `success.json` with child logs,
CSV and exact hashes. Independent audit FA07579A retains every child count/gap/peak.
These generated outputs and nonsecret fixture databases are not committed.

This does not implement live FOR UPDATE/SKIP LOCKED, owner key export, lock-registry
history/controller authority, confidential conflict discovery, writer ownership
fences, MVCC/rollback data visibility, post-wait predicate rechecks or finality.
Source/lock proofs and source arithmetic formation remain distinct; LockReturn168
is not SelectedEncoding88. A peer still cannot run owner-witness producers using
only ciphertext, and no network answer or mutation may bypass actual computation,
completeness/source proof and independently fresh agreed heads. Historical BFV189
and other validation reports remain unchanged. Reasonable practical latency is
still an empirical complete-operation requirement, with no hard cutoff.
