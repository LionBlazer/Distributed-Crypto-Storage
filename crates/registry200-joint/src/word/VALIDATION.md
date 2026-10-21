# Word journal validation

Validated 2026-10-21 with the pinned Windows x64 release/offline/locked native-CPU
repository environment, Rayon2 and one test thread. These gates establish an
owner-journal application boundary, not distributed SQL or a current lock lease.

The final r137 registry200-joint test image was 24496128 bytes, SHA256
`0C0154C7DACC6E42A2508B8004C0F2E6DB9C971D8D640631EC1D9F7D1A261698`.
Both new owning cases passed in 6.05s. Actual process lifetime was 6079.1591ms,
CPU 8.28125s, OS peak working set 555315200 bytes and sampled peak private memory
550842368 bytes. The observer pinned the executable, source bytes, native image
path and process creation identity, required terminal exit 0/no child processes,
used 20ms memory sampling and enforced 120s/1792MiB ceilings. No forced cleanup
occurred. No own build or other test overlapped the measured run.

The original Word API gate passed its three cases on the separately built r137
proof image (12044288 bytes, SHA256
`83254FFD1FEE09975F9C9D01C0AB50C235D3B5DC7DBA089118866AC16B8197AC`).
It includes all six original owner transition examples/native damage checks and
now pins the exact original Cmd160/Result160 public prefixes. Existing AIRs,
profiles and native field order were not changed by those two getters.

The new application gate generates actual StateCertificate and EMPTY265 proofs
under the actual new journal Genesis, checks the bootstrap against the real
Source, then generates a genuine Begin/Control309 proof from that exact empty
bank. The Journal independently checks owner signature, body/header association,
real mined header, parent/state roots and compare-and-swap before the closed
native verifier runs. A dropped PendingImport leaves header_count unchanged;
successful imports and a separately reverified duplicate pass actual native
checking. The public result carries mathematical status only.

Rejections cover missing Source, foreign C_state with identical version_id both
under the old Genesis and an independently matching foreign Genesis, changed
descriptor/network/shard/key/source fields, foreign old protocol descriptors,
modified immutable Source shard, noncanonical field encodings, trailing
descriptor bytes, unknown Predicate tags, invalid frame roles/advertised sizes,
wrong owner key, replaced enrollment/OldRoot/command, corrupted Word evidence
with a fresh owner signature, and a foreign caller-retained operation pin.
No signature, digest, decryption, fixture outcome or generic callback replaces
native proof verification. The easy public fixture mining target measures no
economic work security or participant weight; confirmation_depth remains 1 under
the existing unmodified Journal profile rules.

One honest Begin receiving call took 73.172ms, including the real owner/body/header
checks and native Word receiving against the already verified immutable Source.
Source installation, bootstrap, proof generation, FHE, transport, weighted quorum,
durable decision/floor and owner SQL completion are excluded. This is a single
component observation, not an end-to-end query or a latency distribution. The
500ms full SQL target remains unproved.

Two external compile-fail cases for private construction/non-Clone receipts,
strict release Clippy on normal/test targets of both affected crates, and the
dependency-free requirements mirror guard passed at r137. Documentation records
were added after executable checks; no executable source changed afterwards.

```powershell
$env:RAYON_NUM_THREADS = '2'
cargo test --release --offline --locked -p registry200-joint --lib word::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::word_inventory::api_tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-joint --doc word:: -- --test-threads=1
cargo clippy --release --offline --locked -p registry200-joint --all-targets -- -D warnings
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

The next boundary must join this exact application to fresh weighted finality
and durable replay. Predicate additionally needs original DATA/Query/product
composition and completed cryptographic assessment. Neither the old Progress
binding/QC nor a historical Word receipt can supply those guarantees by casting
or relabeling. All existing network SQL and lock acceptance guards remain closed.
