# Durable Word validation

Validated 2026-10-21 in the pinned Windows x64 release/offline/locked native-CPU
environment, Rayon2 and one test thread. This is the durable protocol owning
boundary: four real signer objects, real files and encoded consensus messages
in one process. It does not establish independent peer processes, transport,
global latest-head discovery, Predicate/FHE admission or completed SQL.

The r142 finality image was 16081920 bytes, SHA256
`791BCFAEF02D38DC61A692E6267E598F6FBAB2C90E93CB5548CE994718D1E45E`.
The observer pinned source/executable bytes, native image path and process
creation identity, required terminal exit 0 with no child, sampled memory every
20ms, and enforced 120s/1792MiB bounds. All accepted runs had no forced cleanup.
No own builds or other tests overlapped the new Word gate.

| Owning gate | Cases | Test time | OS peak working set | Sampled peak private bytes |
| --- | ---: | ---: | ---: | ---: |
| Word durable bootstrap/Begin/quorum/restart and disk faults, r142 | 2 |37.77s |555888640 |551100416 |
| Existing Progress floor acknowledgement-loss/partial-tail regression, r143 | 1 |4.81s |799535104 |793796608 |
| Existing Joint genuine Kind rechecking before charge/import/publication, r144 | 1 |30.18s |924229632 |932003840 |
| Existing Word journal Source/owner/intent/native rejection cases, r146 | 2 |8.35s |554827776 |549965824 |

The Word process lifetime was 37791.1123ms and CPU 40.8125s. The separate r145
joint image used by r146 was 24496128 bytes, SHA256
`A5392C0570EEAABA378FB5434361989C92F40E7AAEDC2B424D16097F21CEAEEF`.
These are bounded test observations, not a per-query resource or latency claim.

The primary Word gate genuinely proves a StateCertificate, EMPTY265 bootstrap and
Begin/Control309 under the actual new owner Genesis. Four separately installed
durable signers independently import/check the real bodies and use the existing
work-weighted protocol with real distinct signatures. Bootstrap finalizes; two
of four participants cannot finalize Begin. Their already durable partial votes
survive reopening. The reopened proposer rejects a conflicting authorized proposal
even though its Word proof is mathematically valid. Once the remaining messages
arrive, all four finalize the same original Begin and advance the same context.
Historical checkpoint retry performs actual verification without another write;
reopening restores the actual last head/slot through proof/WAL/floor replay.

A damaged native Word argument with a fresh real owner signature/header is rejected
before publication or quota change. Word checkpoint/candidate encodings reject
old Progress decoders. Three external compile-fail cases prevent private signer
construction, signer cloning and old-Parent-to-Word conversion. Internal state
families remain explicitly tagged; legacy getters fail on a Word variant.

The fault gate derives its QC from actual four-party voting, then checks real
AfterSync acknowledgement loss and a nine-byte partial floor append. Uncertain
I/O poisons signer/output and the quota ledger. AfterSync recovery restores the
actual committed decision; a partial tail refuses reopening and remains byte-for-
byte unchanged. No repair, fabricated QC, skipped native verifier, weakened
production timeout or cached accepting flag is involved.

The test relay deliberately withholds traffic for the no-quorum case. Once a
participant advances, authentic delayed old-slot traffic is rejected by the
actual consensus decoder; the relay tolerates those stale-context errors only
after that advance. An initial r141 run incorrectly treated MixedVotes on this
old traffic as a test-driver failure. The r142 correction changes only that
test classification; current-slot errors still fail the gate.

One diagnostic interval covering remaining Begin votes, duplicate checking and
reopening took 6083.647ms. It deliberately includes recovery and excludes original
proof generation/imports and some earlier votes. It is not an ordinary operation
benchmark. The full 500ms SQL requirement remains unmeasured and unachieved.

Strict release Clippy for normal/test targets of finality and joint, the three
compile-fail cases and dependency-free requirements mirror test passed at r145.
Documentation records were added afterwards; executable sources did not change.

```powershell
$env:RAYON_NUM_THREADS = '2'
cargo test --release --offline --locked -p registry200-finality --lib word::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-finality --lib closed::progress_tests:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-finality --lib closed::tests::known_candidate_import_rechecks_genuine_kind_before_any_charge_or_publication -- --exact --test-threads=1
cargo test --release --offline --locked -p registry200-joint --lib word::tests:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-finality --doc word:: -- --test-threads=1
cargo clippy --release --offline --locked -p registry200-finality --all-targets -- -D warnings
cargo clippy --release --offline --locked -p registry200-joint --all-targets -- -D warnings
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

The easy public bootstrap-work target and fixed four-key roster establish only
the actual protocol mechanics under its less-than-one-third Byzantine-weight
premise. Open roster changes, multi-process peer integration, original DATA/
Query/product composition and its cryptographic assessment, client intent/fresh
completion and a full SQL/FOR UPDATE benchmark remain required. No network SQL
or row-lock acceptance guard is enabled by these results.
