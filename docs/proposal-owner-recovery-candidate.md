# Same-owner recovery: bounded API and sealed-composition candidate

This is the separate candidate implementing the boundaries proposed in
[owner recovery research](research-owner-recovery.md). The current owning main
sources and all previous frozen probes/datasets are unchanged. Initial source checks were followed by the separately authorized bounded
release/crypto validation below.
No production recovery or old-dataset-secret reconstruction is claimed.

## Narrow owning APIs

The new [experiment](../experiments/owner-recovery-candidate/README.md) injects
additive modules into NEW ignored source copies:

| Owner | Export/import contract |
|---|---|
| compact-store | Owner::export_secret_for_recovery -> opaque zeroizing image; Owner::restore_secret_for_recovery(image, expected DB16, expected domain16) |
| BFV core | Owner::export_secret_for_recovery(original PublicSetup); Owner::restore_secret_for_recovery(image, expected Geometry, ORIGINAL PublicSetup) |
| Spiral | Existing OwnerState::encode_secret_for_experiment /restore; unchanged original public setup requirement |

Compact image is exactly 80 B: magic8/version2/reserved6, original DB16/domain16
and original key32. The public head supplies independently trusted expected
identities; image import does not establish currentness or authenticate itself.

BFV image is exactly 8,327 B: framing/version/geometry16, implementation-contract
digest32, original full public-keyset SHA25632, parameter-length2, complete exact
46 B parameter wire, secret-length4 and pinned secret wire8,195. Profile/version/
geometry/identity/framing/canonical secret gates precede upstream secret decode.
The owning library has no storage/PIR/demo/sealed-bundle dependency.

The 8,195 B size is a STRICT PINNED PROFILE contract, not universal BFV/protobuf.
Inspected fhe-util0.1.1 variance 10 samples the difference of two 20-bit popcounts,
hence coefficients [-20,20]. fhe0.1.1 protobuf SecretKey has packed repeated
sint64 field 1. Each zigzag coefficient is 0..40 (one byte); canonical 8192-byte
payload requires prefix 0a8040, then exactly 8192 bytes. The gate rejects unknown,
duplicate/trailing fields, altered degree/noncanonical lengths and out-of-support
coefficients BEFORE prost allocation. No security parameter is reduced.

Both images use non-Debug/non-Display/non-Serialize/non-Clone opaque
OwnerRecoveryImage handles backed by Zeroizing, with explicit borrowed secret
AsRef<[u8]> access. BFV owned SecretKey and compact key erase owned secrets on
drop. Upstream BFV serialization's temporary protobuf coefficient copy and
Spiral's internal allocations are not comprehensively zeroized; outer zeroizing
buffers do not solve that audit.

The original public digest binds identity, not a proof of arbitrary secret/key
consistency. Trusted export from the actual live Owner supplies provenance.
Original-key evaluation after reconstruction is a diagnostic acceptance gate,
not a cryptographic proof that arbitrary malicious imported secrets match keys.

## Separate sealed checkpoint

The compositor uses existing XChaCha20Poly1305 with an external 32 B wrapping key
held separately in protected memory. It exposes no wrapping-key file, argv,
environment or secret-logging route. Fresh OS nonce 24 is used per seal.
The outer 112 B framing/AAD binds magic/version/algorithm, exact ciphertext length,
bundle ID32, checkpoint ID32, generation8 and nonce 24. Tag is 16 B.

The confidential body contains BFV/Spiral original-public lengths/digests and
geometry/domain, their secret images, and 3..2000 strictly ordered unique DB
table records: table ID, two bounded leaf filenames, exact image lengths,
two current 112 B heads and compact owner image 80 B. Cached index headers are
not saved: rebuild them only from authenticated original index data. Merkle/NTT
caches remain rebuildable; no plaintext table or precomputed answer is backed up.

Hard bounds are 1 MiB body, exact maximum sealed size 1,048,704 B, 64 B ASCII
leaf names, 8 MiB canonical images, 64 MiB BFV public wire, exact existing
6,029,344 B PIR public wire and 336 B PIR owner image. Table count is checked
before source-copy allocation. The manual parser borrows secret-image slices
from Zeroizing authenticated plaintext rather than creating generic serde
secret copies. All successful public names/heads remain public metadata.

Restore first bounds outer framing, authenticates AEAD, parses the complete
bounded body, then checks an INDEPENDENT expected CheckpointAnchor, catalog
digest, original public wire lengths/digests and every actual physical file's
head/length. Only then do public/secret decoders construct provisional owners.
Any failure drops already-created owners before a result is published.
Full snapshot ciphertext bodies are not authenticated by merely reading their
112 B heads: RestoredTable::read_original_snapshots reads exact bounded images,
rejects extra/truncated bytes, rebuilds full Merkle trees and compares current
trusted heads before decryption or cache construction.

The anchor is public but trusted externally; it is not selected from a backup
peer response. An old valid anchor deliberately permits an old valid checkpoint.
Latest-generation authority, rollback resistance, fsync, atomic snapshot/index/
catalog/checkpoint publication, torn-write recovery, backup replication and
wrapping-key availability remain EXTERNAL. In-flight pending FHE tokens are not
persisted. A new process/session still needs a fresh query-ID domain and separate
persistent replay/update authorization policy.

## Acceptance source and bounded execution plan

Eight new authored tests were executed: compact original data/index reconstruction
and wrong identity/framing; BFV canonical profile gate and opt-in original-key
recovery; three bundle framing/tag/key/path cases; one opt-in integrated checkpoint.
The actual outcome is recorded below.

The real integration fixture creates THREE tiny public synthetic tables and
actual encrypted data/index files plus original public setup files and one sealed
backup. It keeps the wrapping key in separate RAM. It builds original public PIR
peer/cache, exports/seals, then drops original compact owners, BFV Owner and Spiral
owner/client. After reconstruction, it opens unchanged original data/index bytes,
verifies/decrypts real pages, performs real first/middle/last-slot PIR retrieval
against the ORIGINAL peer/cache, and runs a fresh genuine BFV encrypted predicate
through ORIGINAL rotations/product/relinearization keys. No owners, fixtures or
evaluation keys are regenerated to replace the original checkpoint.

Wrong wrapping key, changed ciphertext/tag, truncation/oversize/trailing framing,
wrong external generation/catalog, wrong public wire, BFV geometry/profile/keyset
and compact identity are rejection cases. Results/panics log no secret buffers.
The fixture retains ciphertext/public files only; no plaintext owner image,
seed or wrapping-key file is written. Public fixture plaintext is explicitly
non-secret. Full process termination is not exercised: this stage reconstructs
dropped handles in the SAME process with external wrapping key still in RAM.

Preparation alone:
~~~powershell
.\experiments\owner-recovery-candidate\prepare.ps1 -SourceRepository $mainCheckout
~~~
It emits a new ignored source-T directory and exact source-provenance.json.
Generated package IDs are unique; original library names are preserved for
owning tests. Use a dedicated target/owner-recovery-candidate for the later
locked build. Lock generation, release tests/strict Clippy, explicit ignored
original-key/PIR test execution and native resource observation occur only under
the parent CPU lease. No new 1,000-table write, restart benchmark or performance
claim is authorized by source preparation.

Every sealed bundle/public copy, external 32 B wrapping key, current anchors,
owner images and rebuilt canonical/hash/NTT representation must enter the future
storage/native-RAM ledger. Counts here are format/source bounds, not measured
whole-process RAM, full recovery latency or a newly established 2x result.
The old retained 1,000-table data remains unrecoverable because its original
unsaved AEAD keys cannot be derived from public files.


## Actual bounded validation

Under the explicit exclusive CPU lease, all candidate owning tests passed:
BFV 38 regular runtime cases +one explicitly enabled ignored original-key case
and two compile-fail doctests; compact-store 23 runtime cases; bundle three unit
cases +one explicitly enabled ignored original-checkpoint integration. This is
66 runtime cases and two doctests across the three candidate workspaces.
Both ignored tests actually ran one test each; zero-test filtered outputs in
other targets are not counted as acceptance.

The checkpoint test dropped ALL original compact Owners, BFV Owner and Spiral
owner/client. It decrypted original data AND index pages from the same physical
files, retrieved actual original proof records at slots 0/255/511 through the
original public PIR peer/cache, and evaluated a fresh encrypted predicate using
the original BFV evaluation keys (real rotations and ciphertext products with
relinearization). Returned COUNT 2/SUM 65535 matched the explicit public fixture.
Original public wire remained byte-identical. Neither dataset nor evaluation
keys were regenerated to replace the original owners.

The final Windows integration test observed native peak RSS 363,659,264 B and
private commit 376,266,752 B; all four current/native-peak fields were below decimal
2,000,000,000 B at the test gates. It ran with eight Rayon workers and one test
thread. Native observations cover this same-process tiny fixture, not a restart
latency or 1,000-table memory claim. Test harness wall time 1.78 s includes setup,
sealing, restoration, original-PIR/BFV checks and failure cases; it is NOT a
whole-recovery benchmark or a <=500 ms claim.

Each retained public fixture directory has nine files, 19,436,158 B:
six unchanged canonical images at 232 B each, original BFV public 13,395,426 B,
original PIR public 6,029,344 B and sealed checkpoint 9,996 B. External wrapping key 32 B
and the trusted anchor remain separate RAM; neither is a persisted key backup.
The wrapping key is dropped when the test ends, so these retained tiny encrypted
fixtures intentionally do not establish post-process recoverability.

Strict authored Clippy passed for all three packages. The initial bundle Clippy
run rejected a test-only chunks_exact(3) idiom. Its failure log is retained; the
test now uses as_chunks::<3>().0.iter(), with affected strict Clippy and original
checkpoint integration rerun successfully. No crypto/canonical-file algorithm
changed. Unmodified pinned SDK warnings remain dependency diagnostics.

Validation source/log directory:
.local/owner-recovery-candidate/source-20261015-005557-574, with
initial-lock-and-core-tests.log, store-release-tests.log, bundle-release-tests.log,
bfv-original-key-ignored-test.log, bundle-original-checkpoint-ignored-test.log,
bundle-original-checkpoint-final.log and the per-package strict-Clippy logs.
Source-provenance.json records the initial source copy; the final handoff manifest
records the corrected test and exact validated source/lock/executable hashes.

Reproduce only under a separate CPU/write lease, after source preparation:
~~~powershell
$env:CARGO_HOME = Join-Path $mainCheckout '.local/cargo-home'
$env:CARGO_TARGET_DIR = Join-Path $mainCheckout 'target/owner-recovery-candidate'
$env:RAYON_NUM_THREADS = '8'
foreach ($package in @('bfv','store','bundle')) {
    cargo test --release --locked --offline --manifest-path "$prepared/$package/Cargo.toml" -- --test-threads=1
    cargo clippy --release --locked --offline --manifest-path "$prepared/$package/Cargo.toml" --all-targets --no-deps -- -D warnings
}
cargo test --release --locked --offline --manifest-path "$prepared/bfv/Cargo.toml" --lib owner_recovery::tests::dropped_owner_recovers_with_original_evaluation_keys_and_no_regeneration -- --ignored --exact --test-threads=1
cargo test --release --locked --offline --manifest-path "$prepared/bundle/Cargo.toml" --test original_checkpoint -- --ignored --test-threads=1 --nocapture
~~~

No main or frozen source was edited, no 1,000-table dataset was generated, and no
commit/push was performed by this candidate task. Scope remains reconstruction of
dropped ORIGINAL owner handles within one process. Cross-process restart,
wrapping-key custody, durable publication/latest-checkpoint authority and complete
memory-zeroization/proof audits are still outside this result.