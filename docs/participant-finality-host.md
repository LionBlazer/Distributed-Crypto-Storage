# Proof-bearing participant finality in four OS processes

The explicit `dcs-peer --participant-finality new|existing PATH` mode now runs
the original closed Registry Source/Lifecycle application over real TLS in
independent processes. A participant owns one inventoried workspace, one shared
quota ledger and one proof gate. It neither launches the historical custody/Jobs
server nor enables hidden-predicate SQL. The [host contract](../crates/peer-runtime/PARTICIPANT-FINALITY.md)
records its four bounded local bootstrap frames and lifecycle ownership.

## Storage and process boundary

The closed finality adapter creates four typed control files under
`ParticipantQuota`: Journal, floor, signer WAL and exact binding/signer/profile
metadata. Each creator obtains its own real preflight permit; all appends charge
their complete next extent. Metadata absence is reserved first and the completed
metadata is synced last. A partial install cannot silently become a new signer
on restart. Existing-only recovery requires all files and rechecks original
application proofs, owner signatures, QCs and WAL replay before Ready.

Ambiguous owned I/O poisons the same control/depot/custody ledger. Invalid remote
evidence does not manufacture a successful recovery. No missing-file recreation,
legacy adoption or automatic partial-install repair was introduced. Windows file
sync does not establish directory-entry power-loss durability or protection
against malicious disk rollback.

The trusted host validates independent pins and signer membership before quota
I/O, allocates one actual scheduling gate and moves it into the TLS actor after
full replay. Ready is only a startup observation. Supervisor stdin EOF closes
sockets and joins the actor, including current nonpreemptible proof work, before
releasing the signer and root. The old `--state-dir` mode remains separate.

## Terminal TLS framing correction

Review of the OS follower decoder exposed a terminal framing gap: the server
dropped a successful connection without TLS `close_notify`, while clients did
not check exact EOF. Terminal success now sends `close_notify` and flushes; clients
require clean EOF under the same absolute RPC deadline. A trailing byte or abrupt
TCP close rejects. The intermediate upload Ready frame keeps its connection open.
Busy/Reject remain failures. No proof, authorization, wire-profile or resource cap
was weakened. A real three-connection TLS regression covers clean, trailing and
truncated streams; endpoint status remains an untrusted hint in all three cases.

## Executed behavior

The owning `participant_finality` integration test starts four daemon processes
with explicitly public, nonsecret fixtures and genuine Source/Lifecycle proofs.
Across restart phases it starts 13 daemon instances, with four peers active in
the main phases. It checks:

- Bootstrap and two Begin transitions with owner-signed bodies and actual QCs.
- Existing-only restart into a 2+2 partition: conflicting Acquire candidates do
  not obtain a quorum during the observation interval.
- Joined restart/heal: one competing Acquire becomes final; four independent
  keyless followers verify the same original body and QC.
- Stale competing bodies and genuine blocked WAIT/NOWAIT outcomes reject.
- One validator offline: three-of-four finalize End and the other transaction's
  reacquire; the returning fourth peer catches up sequentially.
- Fresh independent follower verification, stale-acquire rejection, joined
  shutdown and actual quota reopen with exactly four charged control files.

Every follower uses original body bytes and real application/QC verification.
The test-local bounded GetBlock decoder is transport plumbing, not a fabricated
client scheduling gate or proof receipt. A client-owned scheduling API remains
future integration work. The partition observation is a regression scenario,
not a proof of all possible schedules or a permissionless-roster deployment.

Three new adapter cases cover metadata-last recovery/deleted WAL, late quota
refusal and cross-class I/O poison. Three bootstrap cases cover predecode bounds,
exact signer length and neighbor bounds/duplicates. Two new ownership examples
reject cloning or accessing private bootstrap signer state. The terminal-TLS
case above is the seventh new library runtime case. All affected existing library
cases and three legacy process shutdown/supervision cases passed too.

## Reproduction and measured scope

Windows/MSVC Rust 1.99.0, release/offline/locked, native CPU, Cargo/Rayon threads 2:

```text
cargo test --release --offline --locked -p registry200-finality -p peer-runtime -- --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test participant_finality -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p dcs-peer --test process_transport authenticated_shutdown_wakes_the_listener_and_releases_the_process_directory -- --exact --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test process_transport supervised_peer_exits_on_owner_pipe_eof_and_releases_its_directory -- --exact --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test process_transport independent_peer_remains_reachable_after_its_bootstrap_pipe_closes -- --exact --test-threads=1
cargo check --release --offline --locked -p registry200-finality -p peer-runtime -p dcs-peer --all-targets
cargo clippy --release --offline --locked -p registry200-finality -p peer-runtime -p dcs-peer --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

These commands passed **112 runtime cases and seven compile-fail examples**.
Two unrelated opt-in filesystem-I/O cases remained ignored. This is not the full
workspace SQL suite: the previously recorded unsupported SQL cases remain open.
All-target checks and strict Clippy passed before execution; formatting, Core
default build, requirements synchronization and local links passed at completion.
No package version changed. Only five existing test dependencies were added to
the daemon lock entry; four existing peer-runtime dependencies became normal
dependencies of the bootstrap/host path.

| Observation | Library suite | Four-OS control scenario |
| --- | ---: | ---: |
| Full command, including compilation | 184.333 s | 980.771 s |
| Test runtime | 23.99 s peer + 102.25 s adapter | 930.97 s |
| Observer samples | 1,036 | 14,968 |
| Maximum sampling gap | 654.450 ms | 1,746.357 ms |
| Maximum sampled/OS peak working set per PID | 1,036,201,984 B | 1,403,166,720 B |
| Maximum sampled private bytes per PID | 1,035,653,120 B | 1,403,006,976 B |

The nominal observer interval was 100 ms. All 13 daemon instance PIDs were
observed in the four-OS run. No sampled 1792-MiB per-PID fuse or 1800-second runner
abort occurred. The three legacy mode commands took 10.541, 3.633 and 0.783 seconds
including compilation. The observer did not capture every short-lived legacy
child; those samples establish no legacy-process memory bound. None of these
control-history measurements is accepted SQL latency, a full hidden-FHE query
measurement, a formal RAM bound or a scale/availability guarantee.

The 1469-file raw source snapshot after parent
`3b50e2893a4a32230d0d02ac3cc8a5d60812af1d` is retained locally as
`.local/participant-host-native-r1/source.json`, SHA256
`A3BA6AC42F3D0F3B06EF57AF09E68340C25935B9392EEE5DED19CCD0D5DB54B9`.
All files and the exact public inventory matched after all five commands and
before these documentation updates. Library stdout/stderr SHA256:
`6164BF10A6D082557EF329F472BE23C7439EDAEEFAB09F349B4E52D8974BA409` /
`35184135BBF8F23DE1D060BB804C6F918960AC592F525858D685BE4BB23D1101`.
Four-OS stdout/stderr:
`A68A800E751949FC744B1F88299ED8DF0FAF9D305179245751F27EE5E25C3375` /
`6F8722E73602A2C216EB633BAED95B9FA5279A8EAE875D7403C8EA31BEC037EE`.

## Remaining application work

This profile admits only the original Registry Source/Lifecycle application.
The retained full FHE graph and a new closed joint application must still bind
hidden WHERE computation to the exact successful Acquire and fresh agreed state.
Owner pending-state recovery, current-read barriers, delegated authorization,
system-lane work admission, roster activation/reconfiguration, verified history
compaction and general PostgreSQL coverage remain separate unfinished work.
No generic SQL guard was opened by this change. The less-than-one-third malicious
activated-weight premise and non-rollback honest signer assumption remain explicit.
