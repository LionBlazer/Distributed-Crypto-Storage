# Registry200 control admission through two OS peers

Validated fixed-scope extraction and genuine two-process control flow. The selected
owning suite executed all 538 discovered tests exactly once, including the two
pre-existing opt-in I/O cases. Requirements synchronization and architecture each
passed one contract test. The two new libraries contain zero doctests; their
actual doctest command completed successfully.

## Change and accepting boundary

The fixed Source/lifecycle verifier is now owned by
[registry200-proof](../../crates/registry200-proof/README.md), and the concrete
owner-authorized control application by
[registry200-journal](../../crates/registry200-journal/README.md).
[peer-runtime](../../crates/peer-runtime/README.md) adds the distinct owner-only
`InitRegistryJournal` request. The existing arithmetic-job application remains a
separate verifier policy; neither policy falls back to the other.

The new [control consumer](src/opening/registry_lifecycle/journal/README.md) uses
the shared [OS-process supervisor](src/opening/peer_process/README.md). It starts
two independently running `dcs-peer` processes, without storing a dummy object or
installing a BFV public setup. The daemon still initializes and reports its normal
proof backend at startup. This experiment verifies control proofs; it does not
execute an encrypted SQL query.

Each accepted transition has strict Journal owner authorization and two mandatory
original hiding-STARK proofs: canonical Source first, then Bootstrap or Lifecycle.
The verifier reconstructs expectations from the independently pinned application,
Genesis and actual validated parent. It checks the immutable Source, sticky
enrollment, request, old registry root and exactly one control CAS. A signature,
profile hash, supplied state or receipt cannot replace these proofs. The request
contains an owner-authorized opaque command commitment; it does not prove SQL
compilation or controller-signature possession.

## Closed evidence

| Gate | Actual result |
| --- | --- |
| R5 strict compile/Clippy and actual binary discovery | PASS; 538 tests discovered, not 538 executions |
| Retained 25 historical profile fingerprints | PASS; exact primitive-to-profile mapping |
| Three actual analytical Source/Bootstrap/Lifecycle reports | PASS |
| Genuine two-OS-peer CLI | PASS |
| R6 complete runtime suite: 191 core/integration + 347 experiment tests | PASS; 538 passed, zero failed/ignored, exactly once |
| New-library doctests | PASS; zero examples in both libraries |
| Requirements synchronization and architecture contracts | PASS; one test each, two total |
| Frozen native-source/artifact closure | PASS; exact code/input hashes, executable bytes and protected history |

R5 measured Source is
`99349E388315006144E02C88489C87CC2A104C387DD70DD102EC2597CA57E6CD`.
The R6 owning-suite Source is
`A1C99ABF79B2CD7CA0DE8A605D94F66FD01E7C2A478E9F7C8CEDB21C197172C3`.
The explicit bridge verifies the same 1,132 current source/input hashes and the
same 15 executable bytes. R6 changes the test orchestration and output locations,
including explicit execution of two existing opt-in filesystem-I/O tests. It does
not represent another CLI proof execution or changed proof mathematics.

The closed run-check receipt is
`106BE8D9F1CC60736068AC930100D7434BB12D960C348669926E7B8353EF79FE`;
the bridge receipt is
`AEF290648EFDF8C71761F4DF877434529A840129E4A0B81035F07349421E78C2`.
R5 compile, numerical and prove receipts respectively are
`7EBC56F0B3A36112B5E2C6F2DD8DAFC201FE12FAFF18FB340C81E938C4230016`,
`786EFAABD406E2777225DC1DA996A55DA496ECC41570DE95B31F2DA96184E669`, and
`568DD176B7EFC138C10BA057ABDA72F07A4FDF0AB1755932A509FB9F11CE5D63`.
The bridged R6 compile receipt is
`0EF9161F1EDAC030FD9068CAFEE6ED7133CD37C323E9051F3650C80437DEBD0A`.

## Actual control operation

The CLI produced four complete owner-signed bodies: Bootstrap, Begin, Acquire and
End. There were exactly four outer transition-producer calls. These are not counts
of primitive STARK proofs or verification attempts.

The first peer genuinely verified and mined each body. The second received and
admitted the exact public mined header/body through real RPC. An independent
client Journal also verified each imported transition. The private Source witness,
controller fixture and private registry preparation stayed in the owner process.
The fixtures are explicitly PUBLIC NONSECRET and are not operational owner keys.

The gate also completed the following checks:

- Fifteen malformed or coherently re-signed variants of the genuine Begin body received concrete
  `RemoteError::Cryptography` failures before mining. The cases cover a missing
  proof, proof corruption, request parent/query/Genesis/application, an attempted
  Source update, old control, enrollment, command/opening roots, both packet tails,
  and omission of either mandatory nested proof. Transport errors or Busy do not
  count as semantic rejection.
- Before deliberately losing the End publish ACK, an independent public-history
  request observed the published block. The interrupted call received no reply
  payload. Retrying the exact retained public block did not grow Journal disk
  accounting and invoked no transition producer: retry generation delta was zero.
- Both original peers exited successfully and were restarted with their exact
  retained participant directories, owning TLS client credentials and declared
  quotas. The restarted processes had distinct new PIDs. Both reinitialized the
  same independently supplied application and Genesis.
- Four bodies were freshly fetched from each restarted peer, one bounded body per
  response. Fresh client Journals genuinely reverified those fetched bytes and
  matched the original exact tip, accounting and End control state.
- A distinct valid sibling reused the exact Acquire body and control roots under
  its real original parent. Two actual Empty blocks made that branch best. The
  old Acquire reference then failed with exactly `Reorganized`, despite the
  sibling having the same Acquire control roots.
- Both restarted peers completed the existing parent-stdin EOF contract. All four
  process completions had code zero and retained exactly the expected startup
  diagnostic, `Proof backend: avx512`. Unknown or additional stderr would fail the
  gate. The supervisor retains bounded logs and rejects forced completion.

Original peer PIDs were 445460 and 458296; restarted PIDs were 458916 and 479528.
The owner/consumer PID was 470144. These identifiers describe this one observation.

## Timers, body sizes and quotas

| Observation | Actual value |
| --- | ---: |
| Four outer owner producer calls | 32,647.7287 ms |
| Full CLI two-peer operation | 107,737.638 ms |
| Observed owner-process elapsed time | 107,941.4446 ms |
| Bootstrap signed Body | 21,737,151 B |
| Begin signed Body | 30,886,927 B |
| Acquire signed Body | 30,876,687 B |
| End signed Body | 30,879,919 B |
| Final Journal disk accounting, each peer | 145,259,777 B |

The owner timer covers the four outer producer calls. The full CLI timer includes
fixture creation, proof generation, real RPC, all synchronization and independent
verification, deliberate cancellation/exact retry, both restarts, fresh history
fetches, fork/ancestry checks and explicit EOF completions. It is not the latency
of one SQL statement or one proof. The outer process timer additionally surrounds
CLI startup/output/exit. No fixed SQL latency cutoff or interactive-completion
claim follows from these observations.

The complete signed Body ceiling stays 32 MiB (33,554,432 B), including request,
update and signature overhead. The full-history Journal ceiling stays 256 MiB
(268,435,456 B). The declared participant quota was separately 512 MiB
(536,870,912 B); that quota does not raise either Journal or Body limit.

The original wire keeps Source <=20 MiB, child <=12,578,091 B, sequence limit
16,384, Source decoded-element budget 24 Mi and child budget 16 Mi. Element
budgets are decoder accounting units, not memory bytes. The measured bodies fit
their unchanged complete-Body and history budgets. The operation did not send an
aggregate history or a new enlarged proof frame.

Application-frame counters were captured before Shutdown/EOF. They exclude TLS/OS
overhead and process-bootstrap framing; the original-PID snapshots also precede
their Shutdown requests. The deliberately cancelled publish is included through
its retained trace. They are not total wire or process traffic:

| Peer PID | Request bytes | Response bytes |
| --- | ---: | ---: |
| 445460 | 661,190,774 | 259,667,526 |
| 458296 | 114,382,786 | 898 |
| 458916 | 30,880,277 | 145,261,478 |
| 479528 | 30,879,317 | 114,383,176 |

## Process observations

| Process | Samples | Max sampled working set | Max sampled private bytes | OS-reported peak working set |
| --- | ---: | ---: | ---: | ---: |
| Owner/consumer 470144 | 330 | 966,070,272 B | 961,441,792 B | 968,069,120 B |
| Initial peer 445460 | 216 | 340,701,184 B | 345,362,432 B | 372,019,200 B |
| Initial peer 458296 | 241 | 277,491,712 B | 280,731,648 B | 308,846,592 B |
| Restarted peer 458916 | 111 | 328,065,024 B | 327,352,320 B | 340,197,376 B |
| Restarted peer 479528 | 87 | 339,922,944 B | 344,215,552 B | 340,123,648 B |

There were 330 concurrent sample groups, covering at most three live processes at
a time. The maximum simultaneous sampled working-set sum was 1,125,076,992 B;
the private-byte sum was 1,112,453,120 B. These sums use the processes present in
one sample group, not a sum of each process's independently observed peak. The
largest actual sample interval was 926.7725 ms. No sampler fuse fired in this
closed CLI run. The raw observation is pinned by memory CSV SHA256
`78292BFA2DCBC3938C793F9B8ED05194E480E6A93AAA9DE6FA76D4E1C2C17A89`.

Sampling can miss short private-memory peaks and does not impose a hard RAM
guarantee. This control-only run installs no BFV setup or data object, and therefore
does not measure a whole FHE storage/query peer with operational keys, data,
arithmetic, caches and concurrent workload. Two processes on one host are not
independent physical failure domains.

## Owning-suite process observations

The 45 separate R6 test commands had 32 commands with memory samples and 13 short
commands without any sample. There were 36 sampled process instances, not a claim
that all process lifetimes were observed. Maximum sampled per-PID working set was
1,538,027,520 B; maximum sampled private bytes were 1,548,664,832 B. The largest
OS-reported peak working set among sampled processes was 1,538,027,520 B. The
largest aligned sums within a command were respectively 1,538,027,520 B working
set and 1,548,664,832 B private bytes. Separate commands did not run concurrently;
these are not a sum of independently observed peaks or whole-suite resident RAM.
The largest actual interval between sample groups was 776.4215 ms. No timeout or
sampled-memory fuse fired. The longest command was 805,439.3664 ms; the sum of the
45 command intervals was 4,225,813.5202 ms, excluding harness guards between them.
These are regression-suite costs, not SQL latency or a hard process-memory bound.

## Analytical security and preserved profiles

The actual linked analyzer returned the following individual-proof reports before
the genuine operation:

| Relation | Height | Width | Constraints | Degree | Quotient chunks | Batched functions | Unique/list bounds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Canonical Source | 512 | 11521 | 28949 | 4 | 16 | 23222 | 128 / 128 bits |
| Bootstrap | 512 | 1082 | 4996 | 3 | 16 | 2344 | 128 / 128 bits |
| Lifecycle | 512 | 6741 | 26562 | 5 | 16 | 13662 | 128 / 128 bits |

All three retain proof degree bits 10, 192 queries, five random codewords, two
opening points and 512 periodic columns. The 25 historical primitive/profile
fingerprints matched the retained before-extraction mapping exactly. This parity
check establishes profile identity; it is not a claim that 25 new computations or
the entire historical test suite were executed by the numerical probe.

These are individual linked-backend bounds. Multiple proofs, application hashes,
owner authorization, network transport and freshness do not automatically compose
to a 128-bit whole-protocol guarantee. No composed-128 claim is made.

## Host and reproduction

The actual compiler reported Rust 1.99.0 (`b940084d7`, 2026-09-28), host
`x86_64-pc-windows-msvc`, LLVM 23.1.1. Builds used release, locked/offline
dependencies, `RUSTFLAGS=-C target-cpu=native`, `CARGO_BUILD_JOBS=2` and
`RAYON_NUM_THREADS=2`. All four actual daemons reported the avx512 arithmetic
backend; this startup label does not establish acceleration of every extracted
Source/Lifecycle operation.

The read-only host inventory identifies an AMD Ryzen 9 9950X3D2 16-Core Processor,
16 physical cores/32 logical processors, Windows 11 Pro build 26200 and
100,547,211,264 B physical memory. The inventory was collected **after** the
successful CLI operation, at 2026-10-18T05:31:42.4928885Z. It is not a controlled
load/frequency observation or a performance promise. Host receipt SHA256 is
`DAAE4CB76FFAFE544C7B073498445E4755DCFE64C503161A95BF83AD1F211687`.

The following entry-point commands are reproduction instructions, not additional
executions performed for this report. Run from the repository root with the pinned
toolchain and an exclusive target directory. Root's retained source/artifact
guards and PID sampler are separate from ordinary Cargo invocation.

```powershell
$env:RUSTUP_TOOLCHAIN = '1.99.0-x86_64-pc-windows-msvc'
$env:CARGO_HOME = Join-Path $PWD '.local/cargo-home'
$env:CARGO_TARGET_DIR = Join-Path $PWD '.local/target-registry-control-peer-reproduce'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_NET_OFFLINE = 'true'

cargo build --release --offline --locked -p dcs-peer
cargo build --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
$env:DCS_PEER_EXE = (Resolve-Path (Join-Path $env:CARGO_TARGET_DIR 'release/dcs-peer.exe')).Path
$cli = Join-Path $env:CARGO_TARGET_DIR 'release/hiding-fri-source-primitives.exe'
& $cli security registry200-peer-control
& $cli prove registry200-peer-control $env:DCS_PEER_EXE

cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_lifecycle::journal::peer_control::tests::actual_two_os_peers_verify_sync_reopen_retry_and_reorganization -- --exact --test-threads=1
```

The test requires `DCS_PEER_EXE`; a missing daemon does not become a skipped pass.
The complete R6 suite passed. Its peer-runtime invocation explicitly
enables the two pre-existing opt-in filesystem-I/O cases:

```powershell
$env:DCS_CHUNK_IO_FEASIBILITY = '1'
$env:DCS_PACKED_IO_FEASIBILITY = '1'
cargo test --release --offline --locked -p peer-runtime --lib -- --include-ignored --test-threads=1
```

The actual R6 execution used 45 disjoint serial test-binary invocations: 191 tests
from registry200-proof, registry200-journal, peer-runtime, version-journal,
storage-client and transaction-state, plus all 347 experiment tests. The harness
reconciled each exact binary/name against actual compiled discovery, exact filter
arguments and successful output. No test was omitted, repeated or ignored. The
new two-process owning test performed a second genuine control operation; it is
separate from the retained R5 CLI timing above. The Source/PE bridge alone is not
another execution.

Requirements and architecture were compiled and executed directly from the
existing `playground/tests/requirements_sync.rs` and `architecture.rs` with the
pinned rustc, actual serde_json dependency and `CARGO_MANIFEST_DIR=playground`.
This produced one passing test per target; it was not a GUI build or a claim of
additional contract cases. The two-library Cargo doctest command completed with
zero examples in each library.

R6 test, doctest and contract receipt SHA256 values are respectively
`96EA207C366ED28D56A3D7B9BAD5B99F49D17825524180590E2981E1B392DCFB`,
`11893BAE3DA9DE3AC7DA4690418C8C740DC133378CE50359F7CCFDE268518333`, and
`AA17773632D06AE92789C0F329FBB3726643C6F6AC8AA6BB8897A74B3283715F`.
The final native closure is
`01FB01B0E19FCF5E32C7893B7B175037A577D60AB2C57F472F5F4B9F0E93A06B`.
It rechecked all 1,132 frozen input hashes, 18 deleted implementation paths,
15 actual executables, 2,578 protected artifacts, 864 SDK anchors, five tool hashes
and 4,893 prior receipts. Subsequent README/report edits change documentation
only; the validated code, manifests and locks retain their exact bytes.

The reproduction block above covers the public entry points and opt-in I/O tests;
it does not by itself execute the entire 538-test selection or Root's artifact
sampler. For the same selected-package behavior after building the daemon, run:

```powershell
cargo test --release --offline --locked -p registry200-proof -p registry200-journal -p peer-runtime -p version-journal -p storage-client -p transaction-state --all-targets -- --include-ignored --test-threads=1
cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- --include-ignored --test-threads=1
cargo test --release --offline --locked -p registry200-proof -p registry200-journal --doc
```

These Cargo commands are reproduction recipes, not additional executions.

## Retained failed attempts

The R4 real operation exited with the gate's generic `first peer shutdown failed`
message after reaching its first completion check. That gate incorrectly required
empty daemon stderr despite the daemon's unconditional `Proof backend: ...`
startup diagnostic. The retained output did not expose the completion text, so no
unobserved R4 stderr content is asserted. R5 replaced that invalid expectation
with code zero plus an exact single recognized startup line, kept the supervisor's
forced-exit/log-cap checks, and retained all four completion logs. The R4 attempt
is not relabeled as a successful complete operation.

R5's default peer-runtime test orchestration did not explicitly include two
pre-existing ignored I/O cases. That was an execution-coverage mismatch, not 86
failed tests or a new mathematical failure. R6 keeps all source and executable
bytes identical and explicitly includes those cases with their existing opt-in
environment guards. R5 receipts remain preserved; R6 closes the complete suite with actual execution. Earlier source/compiler/preparation attempt details remain
in Root's retained history and must not be silently replaced by this summary.

## Remaining scope

This is a genuine, owner-assisted, fixed N4/T2/D2 control-admission experiment over
two OS peers. It proves neither arbitrary PostgreSQL execution nor encrypted
read/write result completeness. It does not add data-writer fencing, MVCC,
encrypted commit/rollback, controller possession/delegation, owner-private restart
recovery, independent replica failure domains or global freshness/finality.
The valid sibling test deliberately preserves fork validity and rejects a stale
ancestry requirement; it does not establish globally final agreement. Current
Body/history quotas remain finite and proof-body pruning is not implemented.

The complete distributed encrypted SQL goal remains active. These results cannot
be used as a SQL grant, writer grant, hard RAM bound, universal latency result or
composed cryptographic-security claim.
