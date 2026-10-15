# Paired exact-index disk aggregate probe

This isolated executable measures complete authenticated age-index selection,
visible or real Spiral data access, fresh BFV encryption, public-only evaluation
and owner decryption. In the fresh 1,000-table run, all 384 ExactIndex matrix
operations completed within 351.1100 ms; the same-process FullPredicate control had
nine operations above 500 ms, maximum 562.2240 ms. See the
[measured report](../../docs/experiment-private-bfv-exact-disk.md) for every group,
disk/peak-RAM accounting, controls, provenance and limitations.

The operations share one Rows256 Owner, PeerEvaluator and complete public keyset.
FullPredicate executes the original encrypted EQ/GE/closed-range circuit.
ExactIndex is separate: its caller must establish a complete exact owner-built
age index, authenticate both current heads/postings/data, and reject any selected
age outside the authorized predicate. It freshly encrypts low/high/COUNT weights
and executes eight encrypted rotations/adds; the owner supplies no SUM/COUNT
answer. Both output types remain UnverifiedAggregate. Coarse candidates, additional
nonindexed conditions and arbitrary SQL are unsupported.

## Ownership and dependencies

- src/main.rs owns authorization, paired scheduling, selected-age gates, typed
  dispatch, whole timers, post-timing oracle, fixtures and fault controls.
- src/disk.rs owns capacity-one held-file reads, trusted complete-head checks,
  admission, eviction and replacement invalidation. Unloaded tables retain no
  snapshots, proof records or NTT caches.
- src/padded_index_codec.rs and its tests own authenticated complete counts/postings,
  bounded varints, duplicate rejection and page-budget checks.
- src/native.rs adapts reviewed cache/server helpers; server_schedule.rs and
  expansion_schedule.rs retain their pinned public-only computations.
- src/resources.rs owns decimal 2 GB current/native-peak guards, 80 MiB reserve,
  checked arithmetic and outside-query thread sampling.

Direct project dependencies are:

- [compact-store](../../crates/compact-store/README.md): owner-only encryption and authenticated compact snapshots.
- [BFV core](../bfv-byte-limb-core/README.md): separate owner/evaluator roles and genuine encrypted operations.
- [spiral-owner-state](../spiral-owner-state/README.md): client state and restoration against original public keys.
- [spiral-cache-core](../spiral-cache-core/README.md): bounded native cache construction.

Other dependencies are pinned Blyss Spiral, Rayon, serde/JSON, SHA-256, getrandom
and zeroize. LICENSE-BLYSS retains the copied MIT notice. Frozen predecessor
packages are unchanged.

## Entry points and reproduction

run.ps1 prepares a unique ignored source snapshot and dedicated
target/private-bfv-exact-disk, pins the SDK, checks CorePackage, and records every
selected core/store/helper source hash. CoreDirectory/CorePackage select the
owning merged main package, not an implicit old candidate fork.

~~~powershell
.\experiments\private-bfv-exact-disk\run.ps1 -PrepareOnly
.\experiments\private-bfv-exact-disk\run.ps1 -Tables 3 -Samples 1 -Threads 8 -Offline
~~~

The measured scale invocation uses Tables 1000, TableIds '0,499,999',
MaxCanonicalBytes 6500000000 and ServerSchedule combined. It creates fresh files
and owners; predecessor AEAD owners were not backed up. The report provides exact
commands and artifacts. A resource-heavy run requires an exclusive CPU/write lease.

31 release owning tests and strict authored Clippy passed. The eight-case scale
matrix has 768 real queries plus six genuine BFV controls and 13 before-BFV rejects.
Fixed256 absence makes actual dummy posting/data fetches and encrypts fresh zero
weights. This is online-owner, one-posting-page/one-data-page, at-most 256 rows.
It establishes no arithmetic proof, portable full-owner backup, crash durability,
physical-cold-disk or network result.
