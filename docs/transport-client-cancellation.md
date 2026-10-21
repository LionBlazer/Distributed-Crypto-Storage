# Client TLS cancellation validation

On 2026-10-21, a real held-response TLS regression exposed an outstanding client
read that did not finish when its cancellation call returned. The server sent
no response and kept its connection alive behind an independent release channel.
The original path failed its two-second observation budget twice: cancellation
returned after about 48 microseconds, but the read returned only after the test
released the server. A shared-descriptor intermediate candidate also failed.
None of those runs counts as a successful fix or a query benchmark.

The private client socket now uses pinned Mio 1.2.4 readiness and a shared Waker.
Cancellation and absolute expiry latch distinct terminal reasons and wake the
actual readiness wait. Every registered socket operation passes through Mio,
including Windows rearming. The outer TLS methods also check terminal state to
cover buffered plaintext and underlying write errors. Internal cancellation is
`ConnectionAborted`: rustls and standard exact-I/O helpers retry `Interrupted`.
The public cancellation check retains its prior meaning. No protocol, verifier,
frame cap, TLS policy or production timeout changed.

The fixed held-response case returned its read error, dropped the actual
connection and joined the workers before server release. Its recorded events
were cancellation start 13,335 us, read error 13,402 us, connection drop 13,598 us
and independent server release after joins 13,678 us. The body took 0.02 s; the
7.421 s runner time included compilation. This establishes this local regression
only. It does not identify the cause of any older 40-second query join tail or
establish complete SQL latency.

## Owning checks

All native commands used the existing release/native CPU policy, offline locked
dependencies, Rayon2 and buildjobs2, with one native job at a time.

| Check | Result and scope |
| --- | --- |
| `peer-transport` suite | 6 unit and 12 real TLS tests passed; bodies 0.23 s and 0.17 s; runner 9.994 s including rebuild |
| Affected strict Clippy | `peer-runtime`, `dcs-peer`, `storage-client/private-input-proofs`, all targets, `-D warnings`: passed in 9.569 s |
| Original actor regression | 16 cases passed before the initial wrapper's 90 s budget expired; this partial run is not a suite PASS |
| Remaining real TLS recovery case | Direct prebuilt exact case passed: body 56.79 s, runner 56.845 s |
| Remaining actor tail | The two previously unexecuted cases passed together: body 0.47 s, runner 1.007 s |
| Requirements mirror | `repository-contracts --test requirements_sync` passed; runner 0.414 s |

The transport tests retain existing endpoint, certificate signature,
key-possession, CA-mode and frame rejection coverage. New genuine cases cover
held TLS response cancellation, absolute response expiry and cancellation during
an unanswered ClientHello. The progressing-read case checks actual byte progress
before expiry and usable I/O after disarming a separate watchdog. Failure cleanup
releases the held server before joining workers.

The timed-out actor wrapper included 26.16 s of compilation. Its exact recovery
case was subsequently built separately and run directly; no production timeout
was shortened. Test-only phase markers measured a 43.582 s interval between the
first QC/offline-signer stop and the second QC/offline-owner reopen, without FHE.
That interval remains unattributed. The separately completed runs cover all 19
affected cases; they are not presented as one uninterrupted 19-test PASS.

## Four actual peers

The unchanged ignored `dcs-peer` integration case
`four_os_progress_peers_prefetch_genuine_bootstrap_control_wait_for_quorum_and_reopen_exact_decisions`
passed through a direct prebuilt-test observer. It used three sequential cohorts
of four real peer processes: partitioned startup, healed existing state and strict
reopen. At most four peers ran simultaneously. The Rust body took **263.72 s**;
the observer took **264.297 s**. This is a multi-operation recovery test without
Predicate/FHE work, not one query or a controlled speedup measurement.

The test retained genuine Source/Bootstrap803/Control815 proofs, no-quorum
refusal, healed weighted QCs, damaged proof/signature rejection, lost ACK and
exact latest retries, Empty decisions and each peer's exact cold replay.
All five phase assertions and the single Rust PASS were observed. All 13 held
process objects, including the Rust root and 12 sequential peers, had matching
creation times and final exit0. No observer fault, unknown expected child,
resource fuse or forced cleanup occurred. All 1,707 pinned source images were
unchanged during the run. An independent source review and 18 failure-only
observer smokes preceded execution; those smokes supply no consensus acceptance.

The root's observed OS peak working set was 924,561,408 B; peers' maxima were
217,112,576--262,021,120 B, below the unchanged 1,792 MiB per-process veto. The
maximum sampling gap was 1,031 ms. Sampled private memory can miss peaks; global
system CommitPeak is not attributed to this test. Final OS CPU counters totalled
252.65625 CPU-seconds across all 13 processes, not elapsed time.

Reproducibility identities (SHA256):

- Observer: `F7CE9EF783459521AFA63FBFE5C3A5A1DF5BAB81F6A98C46DD71548A46AE93D9`.
- Direct Rust harness, 14,942,720 B: `34DB4FF1FA02B0EA39A26B42CB92FB1180CBF870CA96856D4BAC03A7F527E722`.
- Actual peer, 22,142,976 B: `8E272FA18F0CF957B76A885806CD96F10CD654FA2C4F990C478E805F980B44A6`.
- Local final observer record: `B486A7156F7705888AD99A683DAE817F423571AB1B5E5765E17C3D64BFBC2D08`.

Generated logs, binaries, local participant state and credentials remain ignored.
The historical [five-product record](progress-driver-scoped-completion.md) used
the preceding transport; it is not revalidated or relabelled by this control test.

## Remaining boundaries

The initial TCP connect remains bounded by two seconds. Accepted/raw server I/O
and the public `ConnectionDeadline::new(&TcpStream)` still use shutdown-based
interruption; this client fix does not establish prompt interruption of their
outstanding blocking reads. Dropping an actual client connection closes its
socket; cancellation alone does not claim immediate socket destruction or remote
computation cancellation.

The complete ordinary-query target remains **500 ms**, including FHE, genuine
proofs, required agreement and client completion. It has not been achieved. This
change fixes a demonstrated local wait and preserves affected network behavior;
it does not reduce the existing hundreds of seconds of proof production to that
target.
