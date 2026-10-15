# Private BFV multipage disk candidate

Status: **VALIDATED in one fresh three-table run on 2026-10-15.** All 31 authored
release tests, strict authored Clippy and formatting passed. The complete 480-query
matrix returned exact results; its full local maximum was 491.6511 ms (0 over 500).
One additional genuine full-predicate control and 25 before-BFV rejections passed.
This finite local run is not a latency guarantee or a 1000-table measurement.
See the [measurement report](../../docs/experiment-private-bfv-multipage-disk.md)
for every mode, traffic, resource accounting, frozen executable and raw hashes.

The [actual 1,000-table follow-up](../../docs/experiment-private-bfv-multipage-disk-scale1000.md)
reuses the same frozen executable: all 480 answers and 25 rejections pass; actual
files plus observed native peak commit total 1.813729x of 3 GB logical. Five private
Fixed256 uncached-header table misses exceed 500 ms, maximum 522.106 ms. Cached-header
private reads stay below 437 ms; the full all-mode latency target remains open.

This isolated experiment starts from the frozen eight-case
[exact-index disk baseline](../private-bfv-exact-disk/README.md), main source SHA256
D5D8F003BA3CB4606994237DFEEBAF5C2613F795BE33229C9519A5D3114BBC07.
Its historical one-page measurements do not measure this new schedule. Original
file hashes are explicitly the historical initial-copy inventory in PROVENANCE.json.
No frozen package, owning library, SDK or main source is edited.

## Contract and owned changes

The candidate permits a COMPLETE exact owner-index selection of at most 256 rows
across at most TWO posting pages and TWO data pages. Authenticated header counts
preflight the complete selected count; exact offset intervals preflight posting
pages before transport. The codec reads every selected canonical varint across
page boundaries, rejects duplicates/out-of-range/trailing data and returns every
matching ordinal. The complete ordinal set then preflights data pages before any
data fetch or fresh BFV encryption. No page/row prefix is returned on rejection.
Every actual selected age is checked against EQ/GE/closed range, without filtering.

The existing PageSource callback transports serialized lookup responses. Each
actual posting/data response is Merkle-verified against the independently held
current head and owner AEAD-decrypted before use. Cached counts/offsets bind BOTH
exact heads and contain no selected postings. Every Source also checks snapshot/
trusted-head equality and bounds distinct pages before transport. A bad second
page must reject the WHOLE selection before the BFV preparation counter advances.

All fetches are sequential. Visible requests retain public page indices; real
Spiral requests contain public storeID/root plus a serialized encrypted query,
with no added plaintext ordinals. The original shared full BFV and PIR keys,
SDK profile and N8192/Q218/t114689/CBD(20) BFV parameters remain unchanged. The
owner encrypts actual selected byte/COUNT weights, the peer performs the owning
exact BFV eight-rotation aggregate, and the owner only decrypts Unverified results.
Public-fixture oracle work runs after the full read timer, never as an FHE answer.

**NEW Fixed256 schedule for accepted queries (including absence):** exactly 2
authenticated posting fetches and 2 data fetches,
plus one header fetch when uncached, then fresh fixed 256 BFV. A missing slot makes
a real fetch of page 0 and verifies/decrypts it. Posting page 0 is intentionally
refetched separately from an uncached header; header reuse cannot silently remove
one posting slot. AddressOnly reads only real pages. Runtime/test records separate
real page counts and dummy fetch counts; these diagnostics are for public fixtures,
not additional private-wire fields. The old one-page schedule remains independent.
Unsupported budgets and malformed responses abort before BFV and can have a
different failure shape; they are reported as rejected, not padded successful reads.

`disk.rs` retains capacity 1: only one decoded table and one native cache pair is
resident. Held-handle exact-length/root/head admission precedes native conversion;
actual fetched-page AEAD follows PIR recovery and precedes BFV. A miss timer owns
readiness, sequential lookups/proofs, encryption, wire/decode, real FHE and owner
completion; cache-hit timings remain separate. Native whole-process counters and
all data/index/catalog/public keys/owner counts are retained. This is visible/private
read composition, not hidden writes, complete restart, replication or durability.

## Modules and dependencies

* `main.rs`: original transport/wire/profile/accounting helpers; bounded two-page
  Source, exact complete collection and fixed/dummy fetch schedule.
* `fixtures.rs`: explicitly public boundary/duplicate/max/absence inputs and named cases.
* `protocol_helpers.rs`: complete page preflight and zeroization of live field buffers.
* `multipage_run.rs`: actual miss/hit matrix, post-timer oracle, freshness/shape checks,
  before-BFV rejection controls and one retained full-predicate control.
* `multipage_tests.rs`: authored observable boundary, stale/corrupt/wrong-page and
  actual visible/private PIR/BFV integration checks; all authored tests passed.
* Copied codec/native/server/resource modules retain their owning roles and license.

Direct local dependencies: [bfv-query-core](../../crates/bfv-query-core/README.md)
for unchanged Owner/PublicSetup/PeerEvaluator arithmetic/wire;
[compact-store](../../crates/compact-store/README.md) for canonical AEAD/Merkle;
[spiral-owner-state](../spiral-owner-state/README.md) for supported private-key
restoration with retained original public setup;
[spiral-cache-core](../spiral-cache-core/README.md) for native conversion. The old
Rust dependency alias compact_bfv_byte_limb_core is only the existing import alias
for the owning bfv-query-core package, not a new implementation fork. SDK revision
fdb7206517c249603b0c91b65f1f29f95272107c and LICENSE-BLYSS are retained.

## Public fixtures and gates

All tables contain a million fresh synthetic rows, 2048 rows/page. Age 0 at 0..1930
encode 1931 bytes. EQ age 230 selects ordinals 1931..2186 (256), crossing data pages 0/1;
its first two-byte absolute varint starts at index byte 4095 and crosses 4096.
Range250..251 selects 6025..6280, split 128+128, across data pages 2/3. Its first
varint starts 8191 and crosses 8192: prefix payload 1931+257+3810+2+5+17+5=6027,
plus 2164-byte header. This exercises real variable-length varints, not artificial
byte padding inside a bucket. Both complete 256 selections need two posting pages.

Named controls also retain exact 1/4/16/range21, repeated equal row values,
absent age 245, and 256 maximum 65535 rows with EQ255 and GE255. Valid age 249 has
only 3 matches at 8191/8192/10240, but spans THREE data pages and must reject before
BFV. Age240 exceeds 256 and fails count preflight. A synthetic malformed cached
interval tests the third-posting-page boundary; it is NOT claimed a canonical
<=256 posting list. The inherited codec tests retain canonical encoding, duplicates,
missing/malformed buckets and selected-page authentication controls.

## Preparation and validation

The runner copies/hashes all Rust source from this package and the selected owning
core, store and helper modules into unique ignored paths. It checks a clean pinned
SDK. -PrepareOnly performs source copying only, no Cargo/keygen/datasets. Example:

Each generated sibling manifest gets its own explicit empty `[workspace]` when
the original lacks one. Store workspace-inherited edition/rust-version/serde_json
are replaced with explicit pinned values in the generated copy. Original source
manifest hashes and injected `generated_manifests` hashes are recorded separately;
no owning/main/SDK manifest is changed. Preparation, Cargo workspace discovery,
release tests and build all passed against the published owning dependencies. The
reviewed new-package Cargo.lock was accepted unchanged with --locked --offline; no
resolution update, download or SDK edit was needed.

```powershell
./experiments/private-bfv-multipage-disk/run.ps1 -PrepareOnly -Offline `
  -CoreDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/crates/bfv-query-core `
  -PirOwnerStateDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/experiments/spiral-owner-state `
  -CacheCoreDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/experiments/spiral-cache-core `
  -CompactStoreDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/crates/compact-store `
  -SdkDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/private-access/sdk
```

Before any run: obtain the root CPU lease, prepare the source copy, run owning
release tests/strict authored Clippy/fmt and independently review final hashes.
Use explicit E:/Users/white/.cargo/bin/cargo.exe, shared CargoHome and the unique
target/private-bfv-multipage-disk target. Default fresh 3-table matrix has 10 cases,
all 8 access/selection/header modes, first/middle/last supplied table IDs and miss/
hit repeats: 480 genuine BFV reads per sample. Samples are bounded 1..2; the
reported run used one sample. Its entire sequential-query timer includes readiness,
lookup/proofs/authentication, actual FHE and owner completion. All mode samples and
negative outcomes are retained. The 491.6511 ms maximum is measured for this run;
component sums or the historical one-page baseline do not establish this result. Network and physical-cold-disk latency are absent.
All outputs remain ProofStatus::Unavailable; numeric BFV security/noise/CCA and
single-peer computation/completeness proof gates remain unresolved. Owners remain
live; secret recovery images/keys are not written to peer files.


The release executable and complete prepared source were archived before the only
benchmark launch. The first strict Clippy attempt failed on three authored style/
dead-code issues; the corrected final check passed. A pre-run archive whitelist
initially omitted .ps1; its partial source archive remains, and a new complete
archive was used. These preparation failures did not execute or restart a dataset.
The main module retains inherited internal read/paired-diagnostic helpers for
research; the executable entry point exclusively uses multipage_run::run. This is
an isolated compositor, with no dependency from the demo or owning crypto core.

The historical baseline lock (B44D...) is retained separately from the reviewed
new-package lock (BA5F...). Before validation, only three local package identity
lines were adapted to the new multipage name and the published bfv-query-core name.
No versions, registry checksums or resolved dependencies changed. Cargo accepted
that reviewed BA5F lock unchanged in every --locked --offline validation command.
