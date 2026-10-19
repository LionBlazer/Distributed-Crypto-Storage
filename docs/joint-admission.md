# Closed Joint admission and historical checkpoints

The [fixed Joint kernel](../crates/registry200-joint/README.md) binds a new
application/Genesis to the original complete Source, public BFV setup, owner
anchor and all 33 KeyTransform values. Its signed Body has a small fixed manifest;
detached proof blobs remain in the actual typed participant depot. Old SourceSpec
IDs retain their inner request/head meaning, and the original application never
accepts the foreign new Genesis. No proof/profile/wire cap was relaxed.

The separate [keyless history](../crates/registry200-finality/src/joint/README.md)
owns its concrete JointVerifier and Journal. A historical parent exists only
after actual owner/header/Body, full application and weighted QC checking. Latest
duplicate checkpoints still recheck actual proof bytes. Alternate genuine quorum
subsets/rounds preserve one semantic successor. A parent is historical metadata,
not a fresh SQL grant or a durable signer floor.

## Executed behavior

Six kernel cases and four history cases passed. They cover exact independent
descriptor/setup/Key33 pins, unchanged inner intent binding, bounded canonical
metadata and original role caps, setup/depot reopen, future ingress through the
same ledger and rejection of hash-valid bytes that are not a canonical catalog.
Read-only setup/manifest/catalog references perform no proof verification; all
mandatory actual checks remain in the concrete verifier.

Both boundaries genuinely generate Source/Bootstrap and Source/Begin plus the
private non-Acquire ControlKind proof in owner-signed bodies under the new
Genesis. The history case uses actual four-member computational-weight fixtures
and three-signature QCs, rejects a freshly signed wrong-q body even with its
genuine QC, rejects a wrong owner signature and reconstructs the same state in a
fresh depot/history. Test keys, rows and mathematical openings are explicitly
public nonsecret fixtures. These are local native tests, not independent daemons.

After healthy fresh replay, the test changes and syncs one byte in the actual
retained Kind file. Reusing the same successful original QC/body fails with
`RejectedComputationProof`. Context, parent head/slot/decision/control, ancestry
floor, best validated head and Journal byte accounting stay unchanged. The test
repairs only that owned byte, then deletes that file as its final fault. The same
QC/body rejects again and the shared depot refuses new reservations as Poisoned.
Diagnostic quota usage intentionally remains readable.

The initial full command passed all ten existing durable-adapter regressions,
then failed one newly added test-only expectation that diagnostic usage would
itself return Poisoned. All proof/fault rejection assertions preceding it passed.
Replacing only that expectation with actual typed `reserve(1)` rejection resolved
the failure. The affected new cases were rerun; production source was unchanged.
No failing receipt or unavailable SQL success case was hidden or reclassified.

```sh
# Initial full run: ten original regression cases passed; new diagnostic assertion failed.
cargo test --release --offline --locked -p registry200-joint -p registry200-finality -- --nocapture --test-threads=1
# Corrected new cases: four history, six kernel and two parent ownership contracts passed.
cargo test --release --offline --locked -p registry200-joint -p registry200-finality -- --skip adapter:: --nocapture --test-threads=1
# Three remaining original signer ownership contracts passed separately.
cargo test --release --offline --locked -p registry200-finality --doc -- --skip joint:: --test-threads=1
```

Across these gates, **20 distinct runtime cases and five compile-fail contracts**
passed. Strict all-target Clippy, Core default checking and workspace formatting
passed. The first Clippy attempt exposed extra references around the existing
borrowed BlobId digest API and one borrowed-array comparison; canonical digest
validation also uses an explicit checked discard. Those integration fixes change
neither encoded bytes nor cryptographic equations. The lock file adds one local
package and two existing finality dependency edges, with all external packages,
versions and checksums unchanged.

## Measurements and evidence

The corrected new-case command took 83.143s including 7.35s compilation. History
runtime took 37.34s, kernel runtime 36.91s and the two parent contracts 0.42s.
The initial full command took 173.795s including 9.98s compilation. These are
suite times, not SQL/Acquire latency or a composed FHE operation measurement.

The corrected run's Windows observer retained 467 samples across Cargo and two
actual test executables. Maximum sampling gap was 1315.081ms, maximum sampled
and OS-peak working set 923,115,520 bytes, and maximum sampled private bytes
930,291,712. The initial run retained 921 samples with maximum gap 1704.516ms,
working set/OS peak 1,031,032,832 and private bytes 1,029,804,032. Neither run hit
the 1792MiB per-process soft fuse or 1800s runner budget. Sampling gaps and local
control cases establish no whole-peer, concurrent or full Acquire RAM guarantee.

The corrected 1507-file frozen source manifest SHA256 is
`3B885FF2D70FCE6FBB29280C03ABF83ADC295D827195BC1C3B97E945D9FD93FD`.
All raw hashes and the complete public inventory matched after native and
completion checks, before this documentation update. Parent commit was
`58728f0f91f4be159889eda5734fc88885bef5fc`. The initial manifest was
`6356144873D259270386CA1416800F908A09A9B9CB41915FA9F157E4C02A0A3E`;
the only subsequent code difference is the corrected diagnostic assertion.
Ignored corrected receipts are in `.local/private-peer-native-r1/joint-tests-r2/`.
Stdout SHA256 is
`B3F2D85EFDA1E6F5ABE318075E64D87D805AAA7C24382C52A92B3B30BAFE2513`;
stderr SHA256 is
`238C7D070F241BDD34EA852929D6EE7CB6744E36A8266A4F68A041BC18A78AB3`.
Initial stdout/stderr SHA256 are respectively
`AEF05637958776F89A64E646DD5CCAA5621BF44BD9FDDE8D83BF8304F079F6C2`
and `AABB58D686D6334CAEBD4243CDBD9733BF52F1755E637F6714171BFD380DE990`.
Generated keys, witnesses, proof blobs and receipts are not committed.

The Acquire lane calls the actual retained input16/output118 replay and genuine
Lifecycle/PredicateAcquire verification. A full new-Genesis Acquire through this
kernel/history has **not** yet been executed. The
[ordinary retained OS-peer gate](retained-product-evidence.md) is separate evidence
and cannot establish that missing composition. Local durable Joint signing and
reopen have since passed their [own native gate](durable-joint-finality.md).
Network prefetch, owner staged-state custody and exact-byte retry, fresh own
Acquire completion, ordinary SELECT and general SQL remain unfinished. SQL
entry guards stay closed until their complete required evidence is available.
