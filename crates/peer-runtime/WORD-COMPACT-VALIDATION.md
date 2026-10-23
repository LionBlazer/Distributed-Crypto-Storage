# Compact Word upload: actual process validation

## Change and admission boundary

The existing `WordFinalityClient::submit_compact` endpoint omits the three
immutable SHA Source/Role3/DATA frames from an already authored Predicate Body.
Word TLS has the distinct `DCSWFN04` profile and owner-only tag11; the compact
evidence has `DCSWJT01`. The full `DCSWJP02` packet, original signed Body,
OperationId, proof families and durable application identities are unchanged.

The actual installed verifier retains one independently checked immutable DATA
theorem and its three original frames. Resolution requires its complete Expected
and exact frame lengths, restores one full output Body, and checks the original
full Body hash. The handler then runs its existing strict owner authorization,
OperationId preparation and normal native import. One Body lease and one absolute
expiry cover both actor calls; snapshot checks prevent repinning changed state.
Missing cache rejects, with an explicit separate full upload required.

Predicate admission remains unconditional rejection. Restoration yields only
unverified bytes; it creates no proof receipt, pending candidate, QC, current
head, SQL answer or lock. Persisted/exported Bodies remain self-contained and
full. No proof, resource, authorization or freshness requirement was relaxed.

## Executed owning process gate, 2026-10-23

The existing exact four-process test passed at capture r640. Its twelve held
peer lifetimes cover the original partitioned four, connected four and final
restarted four. Real weighted Bootstrap/BEGIN/END agreement and independent
native/QC receiving, no-quorum rejection and durable replay remain asserted.
The complete Rust test took 80.37 s, including setup and hostile cases, rather
than measuring one SQL request.

After actual BEGIN confirmation, the test recovers the owner's explicit
NONSECRET fixture bank from its AEAD record, checks its block/slot/root, and
prepares the normal compiled `FOR UPDATE SKIP LOCKED` statement against it.
It encodes all source rows independently of the query. The genuine SDK FHE
product, independent all-six native verification and 4096-coefficient oracle
are local fixture preparation. The FHE worker is explicitly LOCAL in this gate.
It neither substitutes a plaintext answer for peer execution nor demonstrates
a remotely completed SQL computation. All network Predicate attempts reject.

The full signed Body was 26,091,921 bytes; its compact transport Body was
7,194,162 bytes. The reduction was 18,897,759 bytes (72.4276%). This is an exact
byte comparison of the same candidate, not an isolated latency speedup.
Both counts exclude TLS/framing overhead. The following attempts reuse that
original candidate, except the two explicitly re-signed hostile variants.

| Serialized probe | Interval ms | Actor path at the exact PID/slot | Application calls |
| --- | ---: | --- | ---: |
| Current parent, cold cache |62.358|resolve only|0|
| Foreign TLS owner |63.824|neither resolve nor import|0|
| Explicit full upload, initially cold |1128.483|import|1|
| Compact upload, retained DATA |379.343|resolve then import|1|
| Re-signed changed omitted State bytes |62.923|resolve only|0|
| Re-signed changed fresh product certificate |313.461|resolve then import|1|
| Original compact after hostile attempts |372.658|resolve then import|1|

Each interval includes the upload/response and a final existing status call used
as an actor-loop diagnostic flush barrier. It excludes original query encryption,
proof production and immutable installation. It ends in rejection. It is neither
pure RPC/native latency nor a full SQL/FOR UPDATE timing. The first full upload
does different verification work from a warm upload, so their times cannot
isolate a transport speedup. The complete 500 ms target remains unmet.

The observer correlates exact serialized begin/end markers with the held child
PID and slot 3. `resolve` alone also occurs on cache errors. Only a subsequent
actor `import` and the existing finality `import app_calls=1` demonstrate full
restoration/preflight and entry into the application callback. The count does
not prove all native subchecks succeeded; fixture validity has its independent
native check and the genuine Joint owning case. No ACK, cache token or new
public verification verdict was added for observation.

The changed omitted frame preserves its length/Expected and has a newly signed
full Body/header. Cached original bytes therefore fail the original full hash
before import. No extra native proof is needed for this exact-byte association
test; resolution cannot distinguish those omitted bytes from another valid
proof of the same Expected. All probes leave the participants at slot 3 with no
Predicate candidate or QC. Subsequent END uses the unchanged confirmed bank.
The final restart replays full Bootstrap/BEGIN/END. An old Predicate after END
tests stale-parent rejection, rather than a current-parent cold-cache replay.

## Resource/provenance and finite checks

Windows/MSVC Rust 1.99.0 release opt-level 3/native CPU, locked/offline dependencies,
Rayon 8 and `DCS_PUBLIC_TIMINGS=1` were retained for this observation. Source hashes
and the actual test/peer images were pinned before/after. No other build or heavy
test ran during capture. The observer uses held handles, exact images and process
creation times, including separate console-helper tracking. All twelve peers,
the test process and console helpers exited; there were no fuse faults or forced
cleanup actions. No pre-existing process was terminated.

The capture retained a 1792 MiB aggregate fuse with 20 ms sampling. Its local time
fuse was 180 s to include the added genuine Predicate preparation; production
180 s I/O and 1800 s operation budgets did not change. Maximum simultaneously
sampled working-set/private-byte sums were 921,280,512/847,753,216 bytes. The
sum of individual OS working-set high-water marks among live processes peaked
at 1,472,835,584 bytes; this is not a simultaneous resident-memory measurement.
The largest individual peer OS peak was 295,895,040 bytes.

| Image | Bytes | SHA256 |
| --- | ---: | --- |
| Four-process test |12,672,000|`63034A4CBB01F099104449AE1BD3D55068E97EE3F839A5CDD19C6095F29D6A82`|
| dcs-peer |25,380,864|`EF4C8F0648E06FBB86EF6E3FA39C3DADEFB9C12088ED54661E4C3A52152FD5D6`|

Local receipt `.local/word-process-native-r640-word/result.json` has SHA256
`6C1137B942A64F8C79D6BE2233C8E01B35E02E2F0A8A20083B3F8B5F83BA7858`.
The first sandboxed attempt (r639) failed on loopback socket permission 10013,
before these probes. It is not counted as passed; all its held processes exited.
The successful r640 run used authorized local loopback access. Generated logs,
proofs, binaries, AEAD records and receipts are not committed.

The genuine Joint native case passed again at r634, including exact evidence
roundtrip, fresh encryption, all existing corruption/replay cases, and the three
correlated omitted-length/total mutations. Those mutations pass physical extent
preflight, then reject the actual retained-frame length without changing the
caller's prefix. The owning Rust case took 13.25 s; its OS peak was 771,252,224
bytes. This also is setup/test duration, not query latency.

Finality's Body layout test, compact namespace/extent checks, four wire tests,
and the actual actor queue/lease tests passed. Queue rejection now covers
WordResolve expiry, full queue and disconnect through the real Handle, in
addition to the unchanged caller-waits-for-terminal-reply contract. Strict
all-target release Clippy passed for Joint, Finality, runtime and dcs-peer.

Reproduce the owning boundaries with the stated runtime settings:

```text
cargo test --release --locked -p dcs-peer --test word_finality four_word_processes_require_native_proofs_and_quorum_then_replay_after_restart -- --exact --nocapture --test-threads=1
cargo test --release --locked -p registry200-joint --lib word::tests::predicate::genuine_predicate_proofs_reach_closed_journal_admission_without_publishing_a_bank -- --exact --test-threads=1
cargo test --release --locked -p peer-runtime --lib finality::actor::joint_queue_tests:: -- --test-threads=1
```

The composed cryptographic assessment, remote FHE-to-SQL completion, fresh
weighted-head acceptance and finalized SQL locks remain separate unfinished
work. Neither this byte reduction nor a sub-500 ms rejected probe achieves them.
