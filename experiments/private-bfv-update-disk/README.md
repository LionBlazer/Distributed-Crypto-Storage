# Private BFV UPDATE with compact disk writeback

Status: **42 owning tests, strict authored Clippy, fmt and release build passed;
three-table and fresh 1000-table runs completed with the same frozen executable.**
Each run retains 100 ordered point commits and all 50 post-cycle controls. The
[measured report](../../docs/experiment-private-bfv-update-disk.md) includes all
modes, raw hashes, phase timings, rejections and resource boundaries. Actual 1000
files plus whole-process native peak private commit = 1.8142847467x of 3 GB logical
data. Point UPDATE through commit/invalidation max 316.1619 ms; compound UPDATE/
reopen/independent SELECT max 635.3670 ms, with 25/100 above 500. Dry compound
26/100 above 500, max 674.7945 ms, remains reported. No universal 500 ms bound is
established.

This isolated owner-online experiment copies the final eight-case exact-disk
compositor, then adds genuine indexed amount UPDATE using the owning main BFV
core. No library, SDK or frozen probe is changed. Public fixtures only; owner
secrets and recovery images are never written to the generated peer directory.
Retained full public setup files are counted.

`src/selection.rs` owns the shared complete input route: current index/head binding,
all authenticated postings, duplicate/ordinal/count/page budgets, actual data
Merkle+AEAD retrieval and explicit selected-age membership. `src/main.rs` retains
read protocol/profile/resource helpers and the original owning tests; its entry
point delegates to update::run. Historical private read-driver helpers remain
research code, not another promoted API or newly measured entry point.
`src/update.rs` owns the experiment lifecycle, post-FHE local oracle, isolated
ciphertext staging, compact disk publication, both cache invalidation, reopen and
subsequent genuine exact aggregate read. `src/update_controls.rs` owns only public
adversarial echo and explicit read/privacy/header/update controls.
`src/disk.rs` retains bounded held-handle admission/loader ownership and adds a
64 KiB buffered JSONL writer with explicit flush errors and staged public-head
projection. The projection never clones owner secrets or publishes live heads
before image/catalog writes succeed.

Dependencies: [compact-store](../../crates/compact-store/README.md) for canonical snapshots,
AEAD/Merkle and fresh-nonce replacement; [owning BFV core](../bfv-byte-limb-core/README.md)
for Owner/PublicSetup/PeerEvaluator and indexed UPDATE/exact-read APIs;
[spiral-owner-state](../spiral-owner-state/README.md) for supported private-key restoration
with retained original public setup; [spiral-cache-core](../spiral-cache-core/README.md)
for native conversion; pinned SDK fdb7206517c249603b0c91b65f1f29f95272107c and copied
reviewed server scheduler for actual PIR. No dependency enters demo or core code.
Copied SDK-derived source license remains in LICENSE-BLYSS; original hashes are
recorded in PROVENANCE.json as the **historical initial-copy inventory**, not
current modified-runtime hashes. The ignored source-preparation-frozen.jsonl and
final-artifacts.json retain the final runtime/dependency and handoff hash maps.

## Operation and failure boundary

The owner freshly encrypts original amount limbs and active-masked delta limbs;
the public peer performs ciphertext addition. Actual wire/evaluation and owner
unverified decryption precede local checked-add validation of EVERY selected row.
An in-bounds public echo is rejected locally before staging. Global unsigned
overflow rejects without mutation. Arbitrary candidates or an unauthenticated
index are not a supported substitute for exact complete predicate matching.

Successful local verification stages ciphertext snapshot clones, fresh data-page
nonces/revision and an index page0 reseal changing only the first 112 B data head.
Every byte after 112, including counts, offsets and co-located postings, is checked
unchanged. Encoded lengths must remain fixed. Data/index/catalog writes finish
before trusted heads/header publication, then BOTH native caches/loaded snapshots
are invalidated. Canonical snapshots reopen under new independent heads; native
readiness and a subsequent real exact FHE read are measured separately. Old
response/context/header rejection is included in postcommit checks.

Timing fields distinguish update-through-commit/invalidation, reopening/native
readiness, subsequent genuine exact read, and TOTAL including all checks. The
compound total is never relabeled as a faster update. An I/O error can leave
partial files: invalidate and abort without publishing successful heads. This is
not rollback, fsync, crash-atomic three-file commit, network timing, hidden writes,
complete owner restart, arithmetic proof or CCA-safe feedback. All BFV outcomes
remain Unverified / ProofStatus::Unavailable. The final runtime retains live owners;
regenerating keys is not a restart mechanism.

Empty and delta 0 execute actual FHE with explicit NoOpNoReseal policy: no disk or
revision change, but force reopen/fresh-read validation. Fixed256 absence still
performs actual dummy PIR fetches and fresh zero encryption. AddressOnly absence
has its documented different fetch shape.

## Bounded runs and actual validation

Default is three freshly generated independent million-row tables, 2048 rows/page,
a supplied table ID and 100 COMMITTED age 250 / delta 1 cycles rotating all eight
visible/private x AddressOnly/Fixed256 x cached/uncached modes. Per-mode counts
are reported. Before mutation, all eight inherited read cases run in every mode
and one genuine FullPredicate read checks the shared unchanged full keyset.
Controls include public in-bounds echo after actual addition, mixed 64 global
overflow, positive 4/16/range21 updates, absence, maximum 256 overflow and zero delta
in every mode. The frozen all-maximum fixture is not weakened for positive 256.
No actual 1000-table run is automatic under this default. The one measured 1000
run followed source review, owning tests, dry-run audit and a separate scoped
lease. Four-row byte carry and sixteen-row 65535 endpoint controls use another
untouched already-created table: actual inputs 201..204 +55 ->256..259 and
305..320 +65215 ->65520..65535. Indexed age changes are not covered.

All 42 owning runtime tests passed: the original 31 plus 11 new checks for
selection extraction/budgets, complete index-page0 suffix/nonselected-byte/live
snapshot staging, stale context, local arithmetic/false-overflow rejection, actual
successful disk carry/head refresh/reopen and same-ID replay, forged public echo
after genuine peer Add, partial-write abort/invalidation, exact JSONL bytes/short
writes, tail-write/flush errors and staged public-head projection. Independent
source review approved the final runtime. Strict authored Clippy uses --no-deps;
four unchanged SDK warnings remain; CLIENT_TEST is never enabled or touched.

The runner copies and hashes ALL Rust sources from the owning main core and the
new compositor into a separate ignored package, checks the clean pinned SDK, and
uses a unique target and CreateNew dataset directory. `-PrepareOnly` does source
copying only; no Cargo, keygen or dataset writes. Pass dependency directories from
the owning main checkout when this worktree lacks their current copies. Example:

```powershell
./experiments/private-bfv-update-disk/run.ps1 -PrepareOnly -Offline `
  -CoreDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/experiments/bfv-byte-limb-core `
  -PirOwnerStateDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/experiments/spiral-owner-state `
  -CacheCoreDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/experiments/spiral-cache-core `
  -CompactStoreDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/crates/compact-store `
  -SdkDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/private-access/sdk
```

For actual release execution remove PrepareOnly and supply explicit Cargo/
CargoHome/TargetDirectory settings. Use E:/Users/white/.cargo/bin/cargo.exe; do not
assume PATH cargo is Rust. Full test/build/run commands, budgets, fresh-directory
arguments and raw/exe/source hashes are in the measured report. Both datasets/raw
and the pre-actual frozen source/exe archive remain retained. Preserve partial
reports on failure; never write owner keys into the peer directory or claim a
regenerated-key restart.
