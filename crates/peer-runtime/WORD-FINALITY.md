# Word finality over real peer processes

This distinct protocol hosts the existing immutable Source/EMPTY265/Control309
durable voter over actual TLS. It provides submission, gossip, candidate and
checkpoint transfer for the fixed Word family. Predicate, SQL, current row-lock
authority, open roster changes and the500ms full-query target remain unfinished.

`finality::WordFinalityClient` requires an independently installed Word Binding.
Replies are untrusted observations. The owner must retain its original intent
and independently verify native proofs, ancestry and weighted QC. `observed_slot`
is an availability hint, not a latest-head proof.

`FinalityServer::bind_word` consumes the actual Word `DurableFinality` and the
process-owned `ProofGate`. The existing bounded actor owns the signer and joins
native work before releasing resources. Word is a distinct typed dispatcher
variant; older candidates/checkpoints/bindings cannot be cast. Word evidence is
inline in the signed Journal Body. There is no Word blob/catalog interface,
plaintext Source opening or FHE secret in the peer. Canonical preflight grants
no computation authority: the actual voter rechecks native proofs and its exact
current snapshot before admission, voting and replay.

The wire is `DCSWFN02`, with its own profile and complete Binding ID. Original,
Joint and Progress domains remain unchanged. The shared8-command/16MiB queue,
8-connection/16-neighbor limits, single Body lease,180s I/O and1800s absolute
operation budgets remain. Body I/O/preflight occur outside signer/proof locks.
These are resource bounds, not measured latency results.

The bounded pending-candidate response carries the current slot, context, parent
and an optional header ID in exactly105 bytes. It is an availability hint only.
A neighbor with no pending candidate in that exact context fetches the original
Body through the single Body lease. The durable actor checks the owner signature
and complete native proof before retaining it; only the elected proposer may
sign. A learned candidate cannot replace existing local pending intent. No
application verification result is cached or supplied by this hint. The retired
`DCSWFN01` transport rejects; there is no compatibility mode or state migration.

`WordParticipantBootstrap::read` consumes exactly five bounded local IPC frames:
configuration, confirmed-work Genesis, two-shard Journal Genesis, complete Word
descriptor and public Source proof. It pins the full Binding and actual roster
signer. `WordParticipantHost::bind` owns the participant quota and four-file voter,
independently verifies Source and replays native proofs before Ready. The Source
bound is `registry200_finality::word::MAX_SOURCE_CERTIFICATE_BYTES`.

`dcs-peer --participant-word-finality new|existing <directory>` is the explicit
process entry. EOF joins actual TLS, signer and native work. Ready is public
metadata only. Existing state cannot be replaced with another namespace,
binding, Source certificate or proof family.

| Direct module | Responsibility |
| --- | --- |
| [Word voter](../registry200-finality/src/word/README.md) | Native/owner checks, weighted QC, signer/decision WAL and durable floors |
| [Word Journal](../registry200-joint/src/word/README.md) | Immutable Source, original native Word and owner-signed transitions |
| [peer-transport](../peer-transport/README.md) | Actual pinned TLS, bounded frames, deadlines and cancellation |
| [protocol-storage](../protocol-storage/README.md) | Exclusive participant files, quota and restart ownership |

## Native validation,2026-10-22

The actual `apps/dcs-peer/tests/word_finality.rs` scenario passed. Four independent
daemons form disconnected pairs: valid owner input cannot finalize without
quorum. Corrupted native evidence re-signed by the actual owner, and submission
from a foreign TLS client, reject. Connected reopen obtains genuine bootstrap
and BEGIN QCs; the owner independently checks Source/Word, signature, ancestry
and each QC. A third four-process opening replays the decided history and rejects
an ancient QC. All12 daemon lifetimes exited0 through their supervisor, without
observer cleanup. BEGIN uses the normal current-private-bank witness producer.

Final capture300/build299 used locked/offline release Rust1.99 MSVC, native CPU
and Cargo/Rayon2. Held handles pinned exact images/creation times and checked
source/binary hashes under the original120s/1792MiB aggregate process fuses.
A20ms polling sleep produced1061 root samples over84.594s. Maximum sampled summed
live working set was577,458,176 bytes; private bytes552,800,256. Summed live
per-process OS peak counters reached1,109,336,064 bytes; this is not an exact
simultaneous physical-memory measurement.

| Observed component | ms |
| --- | ---: |
| Source/bootstrap owner preparation | 2870.598 |
| Submit bootstrap, native admission, consensus and first QC | 29124.857 |
| BEGIN witness and native proof preparation | 291.574 |
| Submit BEGIN, native admission, consensus and first QC | 8946.986 |
| BEGIN preparation through independent proof/QC receiving | **9978.553** |
| Four participant reopen/replay calls after decisions | 20755.950 |
| Whole fault/partition/restart/shutdown scenario | 84318.327 |

BEGIN is a real control-proof/QC operation, with FHE, Predicate, SQL and current
lock authority absent. These numbers do not establish ordinary SQL latency.
Next investigate remote repeated proof checks, candidate propagation and
consensus waiting; submit-to-QC is not pure cryptographic or network cost.

Report SHA256:
`9ADAD68643606E0EF17CA19208429FD14C33FDDB5E6E90713B9CDF9426DB8465`.
The8,414,720-byte test image SHA256 was
`AEE427D6F56E73081A616BAC482952682412670209CB09882560833E99D8A608`;
the23,868,928-byte daemon image SHA256 was
`DC03F218805980566D85B703C9A0FE70D6804DE791E1D0ACB6129503790C6FB2`.

Capture298 passed the unprofiled scenario in83.33s. Earlier296 stopped at the
single-peer observer's obsolete two-console count;297 had loopback TCP rejected
by the sandbox with Windows10013. Neither is accepted as passing. The final
observer retained exact image/creation checks, allowed the intended12 peer
lifetimes and one console per held task, and kept the same memory/time fuses.
It never discovers ownership from a terminated parent's numerical PID. No
unknown/pre-existing process was stopped.

```text
cargo test --release --locked -p dcs-peer --test word_finality four_word_processes_require_native_proofs_and_quorum_then_replay_after_restart -- --exact --nocapture --test-threads=1
```

The daemon's added test-only hiding-STARK dependency computes independent public
fixture commitments. It adds no production dependency or generated output.

After capture300, the test-only Word supervisor declarations moved before the
existing test module for strict Clippy; every function body remained unchanged.
No production Rust changed after that capture. The named images/timings describe
the captured build; final declaration ordering is checked by Clippy.

## Candidate availability and bounded profiling,2026-10-22

The opt-in `DCS_PUBLIC_TIMINGS=1` path now also emits fixed `word_actor` and
`word_finality` observations under the existing bounded diagnostic policy.
Capture315/build314, before availability propagation, passed the same scenario.
For BEGIN, queue wait was usually tens of microseconds (p95 20us), while three
propose attempts performed only one application check. Only the submitted-to
node held pending intent and had to wait for its elected proposer round. This
does not attribute submit-to-QC time to FHE or pure cryptography.

Capture319/build318 enabled pending-candidate propagation and passed the SAME
four-process native proof, foreign-client rejection, partition/no-quorum,
independent receiving and restart/replay assertions. Diagnostics were disabled
for comparison with capture300. No proof, timeout, freshness or resource bound
was weakened. All12 daemon lifetimes exited0, with no observer cleanup/fault.

| Comparable operation | Baseline300 ms | Availability319 ms |
| --- | ---: | ---: |
| Bootstrap submission through first QC | 29124.857 | 3818.836 |
| BEGIN witness/native proof preparation | 291.574 | 293.394 |
| BEGIN submission through first QC | 8946.986 | 3041.997 |
| BEGIN preparation through independent proof/QC receiving | **9978.553** | **4061.618** |
| Four participant reopen/replay calls | 20755.950 | 18476.506 |
| Whole fault/partition/restart/shutdown scenario | 84318.327 | 49566.474 |

These are single observations of the same bounded local scenario, not latency
percentiles or a network-wide guarantee. BEGIN still excludes FHE, Predicate,
SQL and current row-lock authority; the500ms full-query goal is not achieved.
The remaining consensus wait, required repeated native checks and independent
Source/Word receiving need separate profiling. Empty-slot timer activity before
candidate arrival remains unchanged in this stage.

The same120s/1792MiB fuses and20ms polling sleep applied. There were673 root
samples over49.859s. Maximum sampled summed live working set was563,224,576 bytes
and private bytes551,665,664. Summed live per-process OS peak counters reached
1,125,826,560 bytes; this is not simultaneous physical memory.

Capture319 report SHA256:
`55987E99E7EC94AAD2E63AC25F9BDD5F15D2C147768F83BF468437CFB1F8362A`.
The8,415,232-byte test image SHA256 was
`F72E993ABEC430D7C2DE8EAEFCA2BA5406ACBBB596AC447C87E5DEBFAAA53AE2`;
the23,876,096-byte daemon image SHA256 was
`88192BBAB55E4EE1A5F974E549D93FE30666505196E4EAB2D2B7EBA17B4C157A`.

Additional owning checks passed: four bounded diagnostic tests, four wire/domain
tests including canonical availability/context/parent rejection, three queue
lease/expiry/join tests and the dependency-free requirements mirror contract.
Strict all-target Clippy passed for peer-runtime and registry200-finality; the
changed Rust files passed rustfmt check. Only documentation changed after the
captured build.
