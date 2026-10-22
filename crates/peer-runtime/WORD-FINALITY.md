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

The wire is `DCSWFN03`, with its own profile and complete Binding ID. Original,
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
`DCSWFN01`/`DCSWFN02` transports reject; there is no compatibility mode or state migration.

A pristine Word slot waits for authenticated work before starting local round
timeouts. Owner Body import arms it only after genuine native/owner admission;
signed current-context proposals/votes/certificates and valid current QCs also
arm it, including a signed proposal awaiting its missing Body. The first handler
start is retained, so admission verification consumes the original Propose
budget. Metadata, failed native admission, foreign contexts and historical QC
retries do not arm a new slot. Repeated traffic cannot postpone an armed
deadline. Each later native token retains its exact duration, round increment
and ANY-quorum activation rules. A changed context returns to idle. On opening,
persisted own proposal/vote/POL actions or an advanced round/step resume the
clock immediately. This is a local scheduling policy pinned by the v3 transport
profile; owner proofs, voter locking/POL rules, weighted quorums, WAL and floors
retain their original checks. Other application families keep their scheduling.

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

## Work-triggered Word slots,2026-10-22

Capture327/build326 reprofiled the published availability implementation with
`DCS_PUBLIC_TIMINGS=1`. Slot2 had two timeout events and22 vote handler calls
before BEGIN proof preparation finished; across that slot it had eight timeout
events and345 vote handlers. The slot had started spending rounds before the
owner submitted any work. Actor queue waiting was not the main delay.

Capture331/build330 passed the same four-process scenario with the v3 scheduling
policy above and the SAME diagnostic environment, native proof checks,
partition/no-quorum assertions, foreign-client rejection, independent receiving
and durable restart/replay. Slot2 had zero timeout events,17 vote handlers and no
consensus activity before BEGIN proof preparation finished. The four validators
still performed the genuine native checks; no proof success was cached. All12
daemon lifetimes exited0 with no observer fault or cleanup action.

| Comparable profiled operation | Availability327 ms | Work-triggered331 ms |
| --- | ---: | ---: |
| Bootstrap submission through first QC | 4024.213 | 2757.615 |
| BEGIN witness/native proof preparation | 299.041 | 313.301 |
| BEGIN submission through first QC | 3358.763 | **696.776** |
| BEGIN preparation through independent proof/QC receiving | 4402.034 | **1801.497** |
| Four participant reopen/replay calls | 18866.943 | 20088.251 |
| Whole fault/partition/restart/shutdown scenario | 52553.436 | 53603.323 |

These are single profiled observations. Restart work and the whole scenario did
not improve. The BEGIN operation still excludes FHE/Predicate/SQL and current
row-lock authority;1801.497ms is not a full-query result or the500ms goal.
After native BEGIN submission, remaining independently receiving work and owner
proof preparation are material. The receiver currently reconstructs its public
Source/Word setup; reusing an original immutable verified installation must
preserve the full expected source, binding, parent and per-operation checks.

Both captures used the previous locked/offline release environment, held-image/
creation checks,120s/1792MiB fuses and20ms polling sleep, with no concurrent build
or test. Capture331 had618 root samples over53.937s; maximum sampled summed live
working set was562,892,800 bytes and private bytes551,342,080. Summed live
per-process OS peak counters reached1,110,511,616 bytes, not simultaneous physical
memory. The profile records only public fixed labels, slots, ordinals and times.

Capture327 report SHA256:
`66BD088457C2D70530210D9EEFFD86D0DDBEA25F732D80CC70804BFFEF8841FD`.
Capture331 report SHA256:
`250A77E26BF4B66C2F76C61F55C763850E0D7A47FF114755DD8AFE33AE091EE3`.
The8,415,232-byte test image SHA256 was
`73DEAD5002BFF145EBA5E4E07D7ACF2F29C065FC140350F4E8DCF1399AFD59E8`;
the23,861,760-byte daemon image SHA256 was
`9D5B65887AF82BAEDD66E0950E2F856870DAB3527A6FD545C18E7CFD599B0DE9`.

The four clock-policy tests cover idle/foreign contexts, verification time,
sticky retries, context changes and resumed work. All seven Word-filtered unit
tests, three owning queue tests, the requirements mirror contract, strict
peer-runtime all-target Clippy and rustfmt check passed. Only documentation
changed after capture331.

## Independent keyless Word receiver,2026-10-22

The client now uses the real closed `registry200_finality::word::History`, rather
than manually joining a Context and Journal in test code. `History::new` actually
verifies the complete original immutable Source and prepares the Word receiving
role once. Each `apply_operation` independently checks the original owner intent,
owner signature, native Word proof, exact ancestry/context and weighted QC before
publishing its floor. Its private constructor receipt is historical; it grants
no network currentness, SQL acceptance or row lock. Other operation proofs and
Source bootstrap evidence are still genuinely verified. No per-operation success
is retained for reuse.

Capture341/build340 passed the four-process native/partition/restart gate with
diagnostics enabled. Complete BEGIN receiving took1280.227ms. The first-QC phase
line interleaved with another process's diagnostic output, so that component is
not used as a measurement. Test observation records now format the complete line
before one write. Source-install and receiver intervals are explicitly logged.

Final capture344/build343 passed with diagnostics disabled. It retained the same
native proof, foreign-client, no-quorum and restart/replay assertions, and all12
daemon lifetimes exited0 with no observer faults or cleanup. The owner keeps its
original intent pin before each submission, and receives through the production
library History. The same locked/offline release environment, exact held image/
creation checks,120s/1792MiB fuses and20ms polling sleep applied.

| Complete observed component | Capture344 ms |
| --- | ---: |
| Owner preparation including Source/bootstrap and History installation | 3641.458 |
| Independent Source verification and Word receiver installation, within preparation above | 757.560 |
| Bootstrap submission through first QC | 4171.139 |
| Independent bootstrap History receiving | 803.361 |
| BEGIN witness/native proof preparation | 374.773 |
| BEGIN submission through first QC | 687.748 |
| Independent BEGIN History receiving, including native/owner/intent/QC and floor | 83.616 |
| BEGIN preparation through independent History receiving | **1146.250** |
| Four participant reopen/replay calls | 21548.850 |
| Whole fault/partition/restart/shutdown scenario | 55979.012 |

Initial Source/Word setup is recorded separately and remains necessary at client
installation. It was moved into a reusable verified library owner, not replaced
by an accepting flag. These are single local component observations; BEGIN
still excludes FHE/Predicate/SQL, currentness and current row-lock authority.
The500ms full-query target remains unachieved. The complete scenario and reopen
times did not establish a speedup; cold preparation/replay and agreement remain
material. The next full-query composition still needs actual FHE/result
admission, fresh-head agreement and durable private owner-state completion.

There were656 root samples over56.313s. Maximum sampled summed live working set
was564,228,096 bytes and private bytes552,382,464. Summed live per-process OS peak
counters reached1,121,193,984 bytes; this is not simultaneous physical memory.
Capture344 report SHA256:
`F51D10CFA35B77F3180E20D487F1C8DB7679D4922302A18F8FA40CB70D010F0E`.
The8,458,240-byte test image SHA256 was
`124969D5026CBC8BEB8580AE977CC2F348203BCE6815002EC05018F912A6509A`;
the23,864,832-byte daemon image SHA256 was
`5A0F9EE609B775B274727ED22C364E5792F1B085DF7AAE7626AC50915E90AA6B`.

Three owning History tests and six compile-fail ownership contracts passed,
along with strict registry200-finality/dcs-peer all-target Clippy. The History
failure tests compare actual Journal header count, accounted bytes, best/floor
and candidate presence before/after rejection; genuine fixture signatures on
invalid work cannot replace native proof verification. Only documentation
changed after the final capture.

## Confirmed private control state,2026-10-22

Capture359/build358 replaced the fixture's direct BEGIN prover with the normal
`storage-client/word-control` owner. It checks the initial private opening against
the actual historical native/QC root, pins the actual Genesis owner key, retains
public Role preprocessing and uses fresh OS request nonces and secret salts.
The candidate's real header/target comes from History's actual Journal rules.
The private bank is unchanged until the original candidate's native proof,
signature, intent, ancestry and weighted QC are independently checked.

The same four-process test now also checks rejected owner keys/private openings,
old QCs before confirmation, an identical pending candidate after losing its
handle, refusal of another pending mutation and one-shot confirmation. It then
originates a genuine END from the newly confirmed private BEGIN bank, confirms
it and restarts/replays all THREE decisions. The old bootstrap bank would fail
the original old-root witness assertions for that END. Twelve actual daemon
lifetimes exited0; no observer fault or cleanup was needed. Partition/no-quorum,
foreign-client/native-proof rejection and ancient-QC floor checks remain.

| Observed component, diagnostics disabled | Capture359 ms |
| --- | ---: |
| Real Source/Word History installation, within owner preparation | 866.755 |
| Rejection of wrong owner/private opening, using real trial receivers | 3498.383 |
| Private control-owner installation and retained public prover setup | 130.238 |
| BEGIN current witness, fresh proof and signed candidate preparation | 250.160 |
| BEGIN submission through first QC | 823.724 |
| Independent BEGIN proof/QC and private bank confirmation | 85.784 |
| Complete BEGIN path, including the pending/rejection assertions | **1159.751** |
| Complete END from confirmed private state, including old-QC rejection | **1192.734** |
| Four participant reopen/replay calls after three decisions | 23998.015 |
| Expanded partition/rejection/restart/shutdown scenario | 66421.284 |

This is a correctness/lifecycle extension, not a measured full-query speedup.
Neither Control operation includes FHE/Predicate/SQL or a general latest-head/
current-row-lock grant. The500ms full-query goal remains unmet. The owner draft
and bank remain in memory; sealed recovery, durable anti-rollback owner state,
actual FHE/result admission and final SQL/freshness completion remain required.

The existing locked/offline release environment,120s/1792MiB aggregate fuses,
held image/creation checks and20ms polling sleep were unchanged. There were594
root samples over66.735s. Maximum sampled summed live working set was564,183,040
bytes and private bytes553,594,880. Summed live per-process OS peak counters
reached1,122,242,560 bytes, not simultaneous physical memory.

Capture359 report SHA256:
`9D5C60D340CCB93148384CCE5BF81E1319C1933AFF4C9529675EE29CD1E1DC49`.
The8,513,024-byte test image SHA256 was
`4860213AC363C139511D58E73A1E6989FDCFF7AE1CC59121AE60477C6ECFA0C9`;
the23,864,320-byte daemon image SHA256 was
`EA93002308A5FE27CB0335020993EF3BE8A3BFBF38C647A198D45E1D2C233FEC`.

The three original current-state/native-proof tests, protected owner API
compile-fail contract and strict storage-client/dcs-peer all-target Clippy passed.
The root tests retain their independent manual next-bank/result comparisons and
the unchanged genuine native verifier. Only documentation changed after capture.

## Encrypted owner-record recovery,2026-10-22

Capture371/build370 extends the same four-process gate with the normal
[Word control owner's encrypted records](../storage-client/src/word_control/README.md).
The actual immutable EvidenceStore syncs the original pending record before its
candidate is exposed. After submission the test drops the WHOLE Owner and store,
reopens the actual files with a new budget and replays genuine Source/bootstrap
history into a new receiving instance. Restoration verifies AEAD, exact context/
parent/slot/decision, original owner/native argument and the bank/enrollment/next/
result openings. The resumed candidate has exactly the original header and Body;
its operation nonce and proof are not regenerated.

Wrong wrapping key, record family and tag are rejected. Three additional records
have genuinely valid AEAD tags under the explicit PUBLIC NONSECRET test key but
contain a false next bank, false result or damaged native proof. The damaged
proof's Body is genuinely re-signed and mined and its intent pin recomputed, so
hashes/signatures/AEAD cannot substitute for original native verification. All
three restorations reject. The original pending record restores successfully;
actual TLS/QC confirmation syncs the confirmed bank before exposing its result.
Another full Owner reconstruction restores that bank under actual BEGIN lineage
and prepares/confirms a genuine END. No fixture supplies the confirmed bank.

| Observed component, diagnostics disabled | Capture371 ms |
| --- | ---: |
| Real Source/Word History installation, within owner preparation | 869.965 |
| Wrong owner/bank/controller/enrollment opening trials with real receivers | 6388.474 |
| Control-owner installation and public prover setup | 131.929 |
| Fresh BEGIN witness/proof/signed candidate and encrypted pending write | 262.193 |
| Drop/reopen, rejection trials, real history replay and same pending restoration | 12136.796 |
| Observe BEGIN QC after the recovery work above | 12.879 |
| Original BEGIN proof/QC confirmation plus confirmed encrypted bank write | 96.654 |
| BEGIN plus the recovery/rejection work above | 12495.056 |
| Replay BEGIN lineage and restore confirmed private bank | 1804.102 |
| END from restored bank, including original proof/TLS/QC and encrypted writes | 1106.782 |
| Four participants reopen/replay all three decisions | 23049.200 |
| Whole expanded partition/rejection/recovery/restart scenario | 80842.446 |

The QC can arrive while owner recovery trials are running:12.879ms is NOT the
submission-to-quorum interval. The expanded BEGIN interval is likewise not
comparable to the ordinary in-memory BEGIN above. Neither is a full SQL/FHE
query; the500ms target remains unmet. This tests actual Owner/store object and
file-handle reconstruction, not an OS owner-process crash or power failure.
Independent wrapping/signing-key custody, exact latest-record selection, durable
anti-rollback, completed-reply lifecycle and the EvidenceStore Windows directory
durability limitation remain explicit. Predicate/FHE-result admission, general
latest-head/row-lock authority and full composed security remain unfinished.

The unchanged120s/1792MiB aggregate fuses,20ms observer sleep, held executable/
creation checks and locked/offline release environment applied. Twelve daemon
lifetimes exited0; no faults or cleanup actions occurred. There were871 root
samples over81.187s. Maximum sampled summed live working set was564,105,216 bytes
and private bytes552,656,896. Summed live per-process OS peak counters reached
1,133,723,648 bytes; that is not simultaneous physical memory.

Capture371 report SHA256:
`D0254F825B388C6285AD93DB06AF7843F97F591B41EB42FA171562E9809089EA`.
The8,688,640-byte test image SHA256 was
`84B0E62BD0CAEC61E4F29BB7D68B7EEA315F9FD13A39E0AB0A55FF5454A9D2E0`;
the23,872,512-byte daemon image SHA256 was
`7B2FA08713BAA3BE21E4493248E2B999F7940788446EFA1883AB0318896DEA0E`.
The three original current-state/proof tests, three History failure/retry tests,
seven compile-fail ownership contracts and dependency-free requirements mirror
test passed. Strict all-target Clippy passed for storage-client, dcs-peer,
registry200-finality and registry200-proof. Only documentation changed after this
capture; all Rust, manifest and lockfile bytes still match its source pins.
