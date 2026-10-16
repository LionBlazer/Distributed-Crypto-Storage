# Owner full-image audit CPU-policy comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`43eda8b9b3251db3ccdbf558d4a3d655a9f0f5a4` and
`c137caf358a534fa0be1251a61464b3c052408ac`. Both already include
[bounded peer custody hashing](PARALLEL-AUDIT-MEASUREMENTS.md), owned canonical
Delta reconstruction, streamed persistence, bulk codecs and static UPDATE sources.
This stage only opts the owner into the existing bounded complete-image audit
policy. It does not remove an audit or establish a latency improvement.

## Change and preserved boundaries

`VerifiedSnapshotBytes::decode_for_head_with_workers` reaches the same canonical
parser as the owned factory. Existing factories remain serial by default.
The consuming BFV `Owner::with_audit_workers` builder selects One or Two without
copying/exporting keys or changing trusted heads. `Database::create` explicitly
opts in using the existing bounded worker policy, resolved once from available
CPUs and RAYON_NUM_THREADS. A one-worker budget stays serial. Invalid or zero
requests retain the existing bounded-default semantics; core reads no environment.

Both validation-only and materializing owner imports still audit the complete
data image before the complete index. Image caps, manifest/layout, exact expected
heads, exact lengths and every packet revision precede full leaf hashing and the
unchanged serial Merkle reducer/root comparison. Schema/read geometry and the
owner's actual AEAD header, embedded data head, TableId and count checks follow.
The private index retains its own byte-geometry limits. Full ciphertext auditing
does not add a global semantic RowId-uniqueness scan or replace query proofs.

The borrowed and owned paths share the existing nonblocking helper permit in
their linked compact-store image. Two may use the caller plus one scoped helper
only for public images at least 4 MiB with two or more pages. The helper requests
a 512-KiB stack; contention or spawn failure performs complete serial hashing.
Existing join/panic cleanup remains unchanged. There is no new executor, image
parallelism, cross-RPC cache, proof-DLL pool or total process-thread/RAM guarantee.

At this fixture's geometry, data is 3,187,648 bytes over 3,907 pages and stays
below the helper threshold. The complete 34,416,624-byte index has 8,306 pages
and is eligible. All 12,213 packets, including the encrypted identity tail, still
authenticate. These are source-derived geometry, not measured hashing costs.
Peer physical audits, nonce/object binding, authorization, frames/quotas, durable
writeback, genuine FHE/STARK checks, final freshness and pending recovery remain.

## Full accepted operations

Three fresh alternating pairs ran in
`.local/owner-parallel-audit-measurements/20261016-132426-325/`, in the order
before1, after1, before2, after2, before3, after3. All six independent TLS-peer
scenarios passed and supplied all twelve timers. None was excluded or rerun.
The unchanged fixture has 1,000,000 rows, one final age-42 match and initial
amount one. UPDATE adds one; subsequent SELECT returns exactly `[[42, 2]]`
from the completed encrypted result. Startup, keys, initial table and Status are
outside timing. Each timer wraps the complete successful `Session::execute`,
including the required final full FetchVersion/owner validation for the mutation.

| Complete operation | Before rounds 1 / 2 / 3 ms | After rounds 1 / 2 / 3 ms |
| --- | ---: | ---: |
| UPDATE | 810.739 / 1163.401 / 639.601 | 676.188 / 743.649 / 991.760 |
| SELECT | 299.081 / 250.117 / 297.851 | 302.543 / 257.055 / 274.092 |

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 639.601 / 810.739 / 1163.401 | 676.188 / 743.649 / 991.760 |
| SELECT | 250.117 / 297.851 / 299.081 | 257.055 / 274.092 / 302.543 |

Differences between variant medians are -8.28% for UPDATE and -7.98% for SELECT,
not medians of paired percentages. Both ranges overlap widely. UPDATE paired
differences are -134.551, -419.752 and +352.159 ms; SELECT differences are
+3.462, +6.938 and -23.759 ms. Thus UPDATE's third pair and SELECT's first two
pairs regress. Every UPDATE in both variants exceeds 500 ms.

The healthy post-mutation SELECT normally finds unchanged local/agreed heads
and does not perform the changed-head owner import optimized here. Its observed
lower median therefore is not an isolated measurement of this audit work.
Three pairs establish neither causation, general improvement nor tail latency.
This window's baseline itself is much slower than the previous parallel-audit
window; no host cause is inferred and separate windows establish no cumulative
gain. All samples are retained. Unrelated host background load was uncontrolled.

Owner and peer request eight Rayon threads; all six logs report AVX-512.
The presence-gated RPC/PID diagnostic variables were removed and asserted absent,
and no log contains their markers. No development build, other proof test or
memory monitor ran during this window. No WAN, cold-cache, whole-process memory
or general 500-ms bound follows.

## Frozen artifacts, provenance and reproduction

Both builds use Rust 1.99.0/MSVC release, the implicit Windows x64 host target,
native CPU flags and locked dependencies on the same AMD host. Arithmetic proof
profile v3, kernel ABI, custody profile 2, RPC v2, application v4 and private-index
formats remain unchanged. The existing arithmetic security floor does not
certify the complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-bounded-parallel-audit/release/deps/proved_sql-e6e263165489b721.exe` | `BB3A608EDC194D315EE768D0DA91DE952C08038F9FA2D07D950A71CC24F07078` |
| Before `.local/target-bounded-parallel-audit/release/dcs-peer.exe` | `BA6399877DE89150E9E0F988440C8AB7A767B24665E26A220D2393209B60A668` |
| After `.local/target-owner-parallel-audit-r2/release/deps/proved_sql-ffebb722f081b809.exe` | `46B570824121339ACBD0F54EAE3562E53A4A8DE54E41F3FCA3FB06C43991FC2F` |
| After `.local/target-owner-parallel-audit-r2/release/dcs-peer.exe` | `FCA4767EC026FBDF9F355AB3239110F6E5408023DDE0C0A658E492B25D44B603` |

Both use AVX2 kernel
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 kernel
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
All eight archived executable/kernel copies and eight original files were
independently rehashed. Each owner embeds its original target's peer path;
preserve that path and the peer's adjacent proof-kernels directory. The archive
contains artifacts.json, six logs, timers.json and executed driver.ps1, whose
SHA-256 is `07FFD1EECED9A8FC43CB1CDF50DB6167814C665D802D0400D9768F4C781DAEE1`.
The original measurement driver has the same hash.

Set RAYON_NUM_THREADS and DCS_TEST_PEER_THREADS to 8 and remove
DCS_TEST_RPC_PROFILE, DCS_TEST_FIXED_PIDS and DCS_TEST_TYPED_PIDS entirely.
Invoke each original owner with
`--exact million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore --nocapture --test-threads=1`,
alternating three pairs as above. The archived driver records the exact paths,
source arguments, worker settings and artifact hashes. Reproduction also requires
the unchanged [real fixture](../../apps/dcs-peer/tests/proved_sql.rs); generated
binaries, logs, keys and ciphertext are not committed.

The after executables were compiled from `b6107a7` plus the reviewed fourteen-file
R2 patch. That parent adds only the preceding measurement report to `43eda8b`.
Publication first fast-forwarded to `128a7f1`, an independent standalone crypto
experiment/documentation change, preserving all fourteen reviewed source files,
ten controls and eleven validation artifacts. `c137caf` then committed exactly
those fourteen source paths. No rebuild is attributed to the later parent;
its changed experiment is outside the workspace/runtime dependency graph.

## Validation and remaining scope

The first validation built the peer successfully, then stopped during native test
compilation with four E0308 errors in existing cfg(test) calls to private storage
restore/validate functions. The first target, logs and source manifest remain
preserved. Only those four calls were adapted to the new encoded
image pair and explicit serial policy; assertions and cases were unchanged.
A separate fresh R2 target passed 300 native behavioral tests, six compile-fail
docs, strict five-package all-target Clippy, formatting and requirements mirroring;
one existing aggregate measurement remained ignored. The explicit
`cargo check --release --locked --offline -p compact-query --no-default-features --features tfhe-backend`
also passed. This checks the changed TFHE caller without running its crypto suite.

Two new owner API tests use real encrypted images, including an eligible index,
and cover exact materialization/readback, tail corruption, heads, TableId, other
owner, embedded head and error order. Four core tests now compare borrowed/owned
One/Two paths; a pure product-policy test avoids environment races. Five existing
helper lifecycle tests also passed, with all twelve required tests observed once.
The wider run includes real SQL, TLS, fault, cancellation, replay and recovery
boundaries. Validation uses two Cargo/Rayon/peer workers, separately from timing.

Exact provenance is retained in `.local/owner-parallel-audit-source-r2-manifest.json`,
`.local/owner-parallel-audit-validation-r2/validation.json` and
`.local/owner-parallel-audit-publication.json`. GUI source did not change, so its
suite was not repeated. Full PostgreSQL, private locks, public source-completeness
proofs, production finality and whole-process resource bounds remain unestablished.
