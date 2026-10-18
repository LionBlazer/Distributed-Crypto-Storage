# SQL admission guard and raw protocol validation

The SQL facades previously promoted genuine arithmetic over owner-selected
operands without the complete peer FHE predicate/completeness and Source-to-input
formation relations. Jobs mutation admission also lacked the proved connection
from the arithmetic output to new AEAD data/index images. An owner signature
authorizes a write; it does not prove those missing computations.

The guard now refuses fixed SELECT, aggregates, INSERT and additive UPDATE before
pending recovery, synchronization or peer I/O. Typed SELECT and whole-script
preflight enforce the same boundary. Empty sources, false predicates, LIMIT 0 and
zero deltas have no exemption. Retained pending mutations are preserved but cannot
resume. The shared Jobs verifier refuses transitions on Mine, Publish and durable
reopen, including genuine cached arithmetic and valid owner signatures.

Raw arithmetic/custody, initial owner provisioning, Empty confirmations and the
distinct Registry200 control verifier remain separate. Old Jobs mutation histories
fail closed on reopen. No wire cap, application identity, migration, alternate
raw SQL executor or acceptance flag was introduced.

## Actual bounded native gate

This record concerns the guard and supported raw protocol boundaries. It does
**not** establish a working SQL engine. The full SQL suite is **not green**.

| Executed boundary | Actual result |
| --- | --- |
| peer-runtime library, including the two explicitly enabled I/O experiments | 86 passed, zero failed/ignored |
| storage-client library, including genuine signed server refusal and three new TLS scheduler cases | 29 passed, zero failed/ignored |
| process_transport, including two new raw OS-process scenarios | 24 passed, zero failed/ignored |
| SQL capability refusal over actual OS peers | 2 passed |
| Existing locking-plan refusal and old application-policy refusal | 1 + 1 passed |
| Documentation tests | storage-client 0; peer-runtime 2 compile-fail tests passed |
| Requirements mirror and architecture contracts | 1 + 1 passed |
| Retained old zero-delta SQL-success scenario | 0 passed, **1 failed**, not ignored |

The six passing behavior commands ran 143 distinct tests exactly once in the
final R4 source gate. The two I/O experiments were executed with
`DCS_CHUNK_IO_FEASIBILITY=1`, `DCS_PACKED_IO_FEASIBILITY=1` and `--include-ignored`.
They are raw I/O experiments, not SQL latency evidence. Tests used one harness
thread, Rayon 2, Cargo jobs 2, pinned Rust 1.99.0 MSVC, release, locked/offline
dependencies and native CPU optimization in an independent target directory.
Default core check and strict Clippy on all affected runtime/client/daemon targets
also passed. Real OS peers used the exact CLI emitted by their test build.

The native runner observed 25 process instances across six behavior commands.
Maximum sampled per-PID working set was 264,380,416 B; maximum observed OS peak was
408,027,136 B, and maximum sampled private bytes were 289,718,272 B. At most three
owned target processes were sampled together, with maximum aligned working set
302,759,936 B. The nominal 100 ms sampler had an actual maximum gap 1,003.5682 ms.
Commands summed to 51,040.991 ms; that is test-run duration, not SQL latency.
No 1792 MiB-per-PID/1200 s-per-command soft fuse fired. Sampling is not a hard RAM
guarantee or a measurement of a complete encrypted SQL query.

All 2,722 protected historical PE files, 864 SDK anchors and 8,029 old receipt/evidence
files matched their original hashes after the gate. The complete source had 1,152
frozen project files. New source was formatted, compiled and run; no cached test
result was substituted for execution. Generated outputs remain ignored locally.

Earlier attempts are retained: R1 stopped on five test-only Clippy err_expect
findings; R2 stopped before behavior tests because a redundant standalone CLI build
was replaced by Cargo's feature-unified test build; R3 passed 86 runtime and 28 client
tests but one new INSERT refusal fixture used unsupported Rows16. R4 uses the real
Rows256 INSERT contract, without changing the fixed cryptographic parameters.
No earlier failed attempt is counted as a passing final gate.

## Retained incomplete SQL coverage

The [coverage inventory](SQL-CAPABILITY-COVERAGE.md) records 61 unchanged daemon/client
SQL-success scenarios, plus historical GUI expectations. Five additive raw tests
preserve specific cancellation, custody/fallback and required-job failure behavior;
they do not resolve those SQL scenarios. The old bodies were not deleted, ignored
or granted a proof bypass.

The retained test
`zero_delta_update_counts_matched_rows_after_real_proofs_without_publishing_new_images`
was actually executed using the final R4 daemon test binary. It exited 101 with
one failed test at the explicit `encrypted SQL execution is unavailable` guard.
This is a recorded failure, not a successful SQL test or an assertion that the
other 60 cases passed. Full WHERE/completeness, typed ordering/windows/NULLs,
aggregates and atomic SQL mutation recovery require the complete proof pipeline.

Requirement 2 now explicitly keeps WHERE and its constants hidden. Revealing a
predicate polynomial cannot satisfy that contract. The separate private
coefficient-predicate prototype is not part of this gate and supplies no SQL
admission, proof or performance claim here. Full PostgreSQL, transaction data
overlays/writeback, agreed distributed freshness and resource targets remain open.

## Evidence and reproduction

Ignored local evidence is pinned for audit:

| Artifact | SHA256 |
| --- | --- |
| R4 source manifest | F738277CC58F9AD13BA7CC88C708E689F65F52F6BA048F2EBBAE5B18CD6F2D39 |
| Compile receipt | BF72043575A4035B68A974FD32AC50997FA2FD07DB5901A78D7366BC2B351355 |
| Behavior receipt | 69E1EBE93DDE21C3FA5F692C1BC961637297440542E7527893229B77E8213F4B |
| Doctest receipt | 5B051BB5845CEFE3B6DAE2AF55E4E68BF429CC7576E51BF6553143C37F4F27A8 |
| Repository contract receipt | 962DA4B886CA49758B12058D2740D6FC2494B25968C012E3FC82814FBBC02D57 |
| Observed legacy failure receipt | B3DF53D2DD93BBCD34E96D5B233C21B083669AF98BCE5677BAE16B83DB80262A |
| Native closure | D0F3923FA9CCF90F337E52DE01C0D76B6D568BB95512AEFE105097ACCC7A53AB |

Receipts live under `.local/sql-capability-guard-validation-r4`,
`.local/sql-capability-legacy-failure-r1` and
`.local/sql-capability-guard-native-closure-r2`. They include actual executable,
stdout/stderr and observation hashes. Reproduction must use a fresh target so
historical binaries and receipts remain immutable. With the pinned toolchain and
dependencies available, the public owning commands are:

~~~powershell
$env:CARGO_TARGET_DIR = Join-Path $PWD ('.local/sql-capability-repro-' + [guid]::NewGuid().ToString('N'))
$env:RUSTUP_TOOLCHAIN = '1.99.0-x86_64-pc-windows-msvc'
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:DCS_CHUNK_IO_FEASIBILITY = '1'
$env:DCS_PACKED_IO_FEASIBILITY = '1'
cargo test --release --locked -p peer-runtime --lib -- --include-ignored --test-threads=1
cargo test --release --locked -p storage-client --lib -- --test-threads=1
cargo test --release --locked -p dcs-peer --test process_transport -- --test-threads=1
cargo test --release --locked -p dcs-peer --test proved_sql sql_capabilities:: -- --test-threads=1
cargo test --release --locked -p dcs-peer --test proved_sql locking_plans:: -- --test-threads=1
cargo test --release --locked -p dcs-peer --test proved_sql a_real_peer_rejects_initializing_an_old_application_policy_with_the_q2_aggregate_contract -- --exact --test-threads=1
~~~

The exact frozen environment, compiler/formatter, contract compiler arguments,
actual CLI and test inventories are in the source/compile receipts. A normal
unfiltered old SQL-success invocation remains a failing functional expectation;
the limited commands above do not turn it into a green full suite.
