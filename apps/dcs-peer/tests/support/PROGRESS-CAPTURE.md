# Public-capture network replay

This opt-in dcs-peer integration test starts four NEW
Progress validators and reuses the original product1 public evidence. It creates
no FHE worker, SourceOwner, private bank, query evaluation or decrypted answer.
It is a network-only cold-verification fixture, not a production restart,
antirollback mechanism, current-head lease, SQL result or complete-query latency.

The original five-job run did not PASS: it stopped on the observer's 8-GiB system
reserve guard. Its first actual product completed with QC, fsynced owner ACK and
public capture. All original children were joined. This test cannot credit the
uncompleted five-job behaviors. Never run either signing ensemble concurrently.

## Invocation and independent pins

Run only the ignored
actual_four_validators_cold_replay_original_product1_without_fhe
test after Root has compiled the matching dcs-peer/test binary. Three explicit
environment inputs are required; absence is an error, not an ignored success:

- DCS_PROGRESS_REPLAY_CAPTURE_DIR: absolute COMPLETE public archive directory.
- DCS_PROGRESS_REPLAY_PIN_FILE: separate absolute Root invocation-pin JSON file.
- DCS_PROGRESS_REPLAY_PIN_SHA256: independently supplied RAW PinSpec SHA256.

This finite fixture additionally pins the original trusted invocation digest
D15F621FD6CDA810946528B8F3B504E1DC47DF35822C0B6B9B662AA098CCE8B0 in source.
An archive cannot nominate its own digest, owner, roster, Rules, setup or dataset.
The pin file's provenance prose and COMPLETE are not proof authority.

No archive bytes or binary fixture are committed/copied into this source packet.
No new CLI, dependency, feature switch, production API, timeout, quota or profile
is introduced. The existing ProgressProcess supervisor inherits the operator's
environment and fixes RAYON_NUM_THREADS=2. Independently opt-in DCS_PUBLIC_TIMINGS
can therefore reach the actual peer; diagnostics never affect acceptance.

## Loader and actual admission

support/progress_capture.rs owns bounded metadata/regular-file loading. It checks
the independent RAW pin before JSON interpretation and the pinned manifest hash
before using archive labels. serde_json Value is not advertised as a general
canonical JSON parser. Both original byte strings are independently pinned.

The loader bounds 148 CAS blobs,162 total files,1GiB total,32MiB per blob,
64MiB setup in canonical one/two chunks,128KiB manifest/pins and64KiB Body.
Journal IPC is exactly716B; Descriptor896B; SetupClaim<=136B. Files are read at
exact extents plus EOF, with hash checks and reparse/symlink/type refusal. An
unexpected directory entry rejects immediately before inventory growth; scans
have the same finite loader deadline. No untrusted filename supplies a path:
only fixed metadata names and canonical hash/extent CAS names are recognized.

Binding is reconstructed using the current concrete canonical codecs and exact
original Work, Journal, Descriptor, setup claim and Rules. The independently
pinned Work bytes bind the actual confirmed weights of the four PUBLIC NONSECRET
fixture signer seeds [1;32]..[4;32], not a count-based quorum. Header-only Journal
checks actual PoW/target/time/lineage; original owner signatures, complete Bodies,
requests/manifests/shard roots and weighted QCs reconstruct Context1..4.

A tiny separately owned temporary ProductStore parses only the canonical catalog
as UNVERIFIED metadata. Its typed quota/store is dropped before any network RPC.
Canonical role/ordinal/caps and setup references derive the full archive closure;
all originals are freshly hash/EOF audited. Ordered whole setup SHA256+SHA512
include repeated chunk IDs twice even if the physical CAS file is deduplicated.
The captured fixture has one setup part. Existing owning SetupClaim/catalog
tests own two-part grammar; the new tiny hash-stream negatives cover ordering,
duplicate counting and either wrong digest without fabricating accepted proofs.

These local checks grant no mathematical acceptance. Every validator starts via
ParticipantInstall::New with its own SAME quota/depot/gate, receives only original
setup chunks and cold-replays Source/input16/output118/Core premises through its
ordinary closed kernel and durable signer/floor path. No accepting verifier,
persisted checked flag, alternate store, fake proof or supplied SQL answer exists.

## Prefix, target and lifecycle

support/progress_capture_network.rs generates fresh test TLS identities, starts
exactly four real processes with matching Ready/PID/profile/Binding and unchanged
10GB fixture capacities. It never calls process_fixture::Fixture::new or creates
an owner/FHE process. Public test signing state is intentionally reset in scratch
directories; that reset is unsafe for production signers and is not recovery.

Only prefix slots1..3 expose a Checkpoint to the transport helper. Their exact
original roles/Body are submitted and their archived QC undergoes actual cold
application/QC/floor verification in each new node. The test requires all four
actual prefix checkpoints to match the independent candidate and semantic decision.

Target QC4 is validated solely as archived reference metadata, then discarded
BEFORE launch. Target has no Checkpoint field. Its exact original Header/Body4
and all canonical roles are uploaded; no target checkpoint is ever seeded.
Three scoped upload workers take one blob turn per peer and hold at most three
bounded role buffers. No queue/store lock or native permit spans a network RPC.

The test accepts one independently valid weighted NEW-process QC4, checks the
whole Candidate/current Context/semantic decision, cancels outstanding clients
and joins all workers. Fresh QC bytes may equal the reference because signatures
are deterministic. No byte-difference oracle or stale QC as a current grant is used.
All four children must then finish successfully through stdin EOF and actual joins.
Errors, timeouts and partial cleanup cannot produce the final joined marker/PASS.

Each loader/prefix/target operation has one unchanged absolute1800s budget;
transport retains its actual180s I/O budget. Retries do not renew the test deadline.
The original header timestamp/target is not rewritten, remined or signed again.
Scratch cleanup rechecks the canonical owned target and parent before recursion.

## Validation boundary

Six loader tests exercise negative byte/I/O/hash-stream cases, not accepted
archive, SQL, math or network positives. One tiny PUBLIC hash-stream success
contrast ensures the primitive is not reject-all; it accepts no SetupClaim or
archive. Two additional ordinary error/cancellation tests ensure that a racing
stop cannot hide an observed invalid reply or erase its joined worker error.
They construct no proof or checkpoint. On 2026-10-20 these eight tests and three
existing supervisor tests passed, along with strict target Clippy. After correcting
the client constructor to the ordinary permissionless TLS path, the latest test
bodies took 0.02 seconds; the build and run took 12.52 seconds.

The actual four-validator replay passed on 2026-10-20 in 254.89 seconds. All four
new children exited successfully, and the independent observer reported no
resource fuse, forced cleanup or changed source. Target uploads finished in
13.843 seconds; its first independently valid NEW-process QC arrived at 188.878
seconds and all RPC workers joined 0.477 seconds later. Each validator performed
three actual application checks, about 41.2--45.1 seconds each. These include
Source/Core/product checks and do not isolate individual proof primitives.
The profile is a network-only diagnostic of the current unpublished v3 source
snapshot, not full SQL, production recovery or five-job acceptance.

The smallest meaningful native sequence is strict affected Clippy + cheap loader
negatives, then ONE actual four-validator replay on the independently pinned
original public capture, with a separate four-child observer. The existing
five-job observer must not be loosened to accept this workload. No extra full FHE
setup is required for a network-only change. Full five-job acceptance subsequently
passed in the separate [v3 Driver gate](../../../../docs/progress-driver-scoped-completion.md)
with capture disabled; that pass does not rerun these capture/replay assertions.

Public test-level phase receipts identify actual child PIDs, derived round0
proposer index, prefix/import/upload, first valid QC and joined cleanup. They do
not isolate peer internal CPU. Actual optional actor/native/fsync diagnostics are
a separately validated opt-in instrument. Compare prefix, target and join costs
separately; differing workloads and upload schedules prevent a causal comparison
with the earlier full Driver run. There is no full-query performance claim.

Root-only example (after setting all three independent inputs):

    cargo test --release --offline --locked -p dcs-peer --test progress_capture_replay actual_four_validators_cold_replay_original_product1_without_fhe -- --ignored --exact --nocapture --test-threads=1
