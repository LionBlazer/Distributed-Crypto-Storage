# Borrowed compute custody comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`732a9b315a1c77699d703d8318077a2d6ac4458a` and
`2e7ed89ee3a3ebd269e68fec9e17fecc23df8a4a`. The latter avoids four owned
payload copies during peer compute admission. These observations do not establish
a general or robust 500-ms bound.

## Change and preserved checks

`Prove` and the permitted, explicitly unverified legacy `Evaluate` route now call
private `Store::audit_version`. The complete file is still read into one bounded
disk buffer for each compute RPC. The existing four-field borrowed parser checks
all lengths and trailing bytes before canonical image validation. Namespace and
whole-file caps precede parsing; inner frame geometry and version/head metadata
precede the complete data audit, then the complete index audit. Both audits use
the existing canonical parser, revision checks, leaf hashes and full Merkle roots.
The requested object ID is checked after both audits, not accepted from metadata.

Only the resulting `TargetVersion` survives compute admission. Setup lookup,
the one heavy-work permit, Prove's exact two-head request binding and genuine FHE
proof generation retain their existing order and checks. `TargetVersion` remains
a binding, not a source/completeness or freshness proof. The legacy Evaluate
result remains explicitly unverified and does not become an accepted live SQL
answer. Full, Delta, Copy, Fetch/FetchVersion, PageBatch and ReadImage retain their
existing ownership paths. Owner AEAD/TableId validation, proof acceptance, fresh
agreed heads, durable publication and exact pending recovery remain mandatory.

The shared private store reader preserves known-name lookup, actual file bounds
and invalid/status accounting. A missing known file, substituted object or corrupt
unrequested byte fails; successful complete physical repair clears unavailability.
Every applicable RPC rereads and reaudits both images. There is no cross-RPC audit
cache, stat/metadata custody shortcut, omitted identity tail or new access footprint.

At this fixture's geometry, two 112-byte heads and complete 3,187,648-byte data
and 34,416,624-byte index images total 37,604,496 bytes. These are the four owned
payload buffers removed per applicable compute admission, not measured RSS or a
whole-operation memory saving. The full disk buffer, Merkle work, small metadata
encodings, FHE/proof allocations and unrelated response copies remain.

## Complete accepted operations

Three fresh alternating pairs ran in
`.local/compute-custody-measurements/20261016-154836-630/`: before1, after1,
before2, after2, before3, after3. All six independent TLS-peer scenarios passed
and supplied all twelve timers. No sample was excluded or rerun.

The unchanged fixture creates one actual peer and 1,000,000 encrypted rows:
999,999 age-7 rows and one final age-42 row, initially amount one. UPDATE adds
one; the subsequent genuine proved SELECT returns exactly `[[42, 2]]`. Startup,
keys, initial encryption/storage and Status are outside timing. Both timers wrap
the complete successful `Session::execute`; UPDATE includes publication,
confirmation and final full owner import.

| Complete operation | Before rounds 1 / 2 / 3 ms | After rounds 1 / 2 / 3 ms |
| --- | ---: | ---: |
| UPDATE | 579.327 / 531.361 / 563.051 | 565.899 / 499.232 / 442.420 |
| SELECT | 221.118 / 238.090 / 219.778 | 216.678 / 222.834 / 225.000 |

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 531.361 / 563.051 / 579.327 | 442.420 / 499.232 / 565.899 |
| SELECT | 219.778 / 221.118 / 238.090 | 216.678 / 222.834 / 225.000 |

Differences between variant medians are -11.33% for UPDATE and +0.78% for SELECT,
not medians of paired percentages. UPDATE paired differences are -13.428,
-32.129 and -120.631 ms. SELECT differences are -4.440, -15.256 and +5.222 ms;
its third pair regresses, as does its median. Both operation ranges overlap.
Two after UPDATE samples are below 500 ms, but 565.899 ms still exceeds it.
The 499.232-ms median from three runs does not establish a robust bound.

Both SQL paths can exercise the changed Prove admission, but these full-operation
timers do not isolate its cost or establish causality. They do not estimate p95,
tail latency or general throughput. The preceding window had different absolute
timings; no host cause, cross-window or cumulative/additive improvement is inferred.
Unrelated host background load was uncontrolled. All samples are retained.

Owner and peer requested eight Rayon threads; all six logs report AVX-512.
The presence-gated RPC/PID variables were removed and asserted absent, and no log
contains their markers. No build, other team proof/test or memory monitor ran in
the window. No WAN, cold-cache or whole-process RAM guarantee follows.

## Frozen artifacts and reproduction

Both builds use Rust 1.99.0/MSVC release, the implicit Windows x64 host target,
`-C target-cpu=native` and locked dependencies on the same AMD host. Arithmetic
proof profile v3, kernel ABI, custody profile 2, RPC v2, application v4 and private
index formats are unchanged. Arithmetic security parameters do not certify the
complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-synchronization-cancellation-r2/release/deps/proved_sql-ffebb722f081b809.exe` | `8DCAB98008F4F39B69E2AD5E5CE90D14F3D48078EE1DEE7DF0EFE991AFE7ABFE` |
| Before `.local/target-synchronization-cancellation-r2/release/dcs-peer.exe` | `85C358C8F5FE540EF3579178BCC505CBE52A70BF92E548457DCAD640C3185422` |
| After `.local/target-compute-custody-native-r2/release/deps/proved_sql-ffebb722f081b809.exe` | `5C310108F03BDE0662522F2957052BBB59267FFE397A35675B8212AF5387C22F` |
| After `.local/target-compute-custody-native-r2/release/dcs-peer.exe` | `A211DDE6AA0BEB82A228E2145609C5413CD75FDA698437A3F00D28F8BC88B267` |

Both use AVX2 kernel
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 kernel
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
All eight archived executable/kernel copies and eight originals were independently
rehashed. Each owner embeds its own original target's peer path; preserve that
path and its adjacent proof-kernels directory. The raw archive contains
artifacts.json, six logs, timers.json and the executed driver.ps1. The archived
and original `.local/measure-compute-custody.ps1` both hash to
`2302048A5435712325306031839C64DD8F859442867CE6AEBBB86E267A76CD0D`.
The preceding driver differs only by five literal replacements: run prefix and
baseline owner/peer paths and hashes.

Set RAYON_NUM_THREADS and DCS_TEST_PEER_THREADS to 8; remove DCS_TEST_RPC_PROFILE,
DCS_TEST_FIXED_PIDS and DCS_TEST_TYPED_PIDS entirely. Invoke each original owner
with `--exact million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore --nocapture --test-threads=1`,
alternating three pairs as above. The archived driver records source arguments,
paths, worker settings and hashes. Reproduction uses the unchanged
[real fixture](../../apps/dcs-peer/tests/proved_sql.rs); generated binaries,
logs, credentials and ciphertext remain ignored.

The baseline was compiled from `5940df3` plus the reviewed four-file cancellation
patch, then published as `732a9b3`. The after build compiled that exact `732a9b3`
parent plus the reviewed eight-path compute patch, source manifest
`DA7FCDD0DDBE2E3BCB6C68B321492DED658ADB507639A1E1C159BD355367DC7B`.
Its draft's historical base was `5940df3`; validation recorded the integrated
`732a9b3` parent. Commit `2e7ed89` contains those exact canonical source files.
No rebuild is attributed to an uncompiled later source or unrelated experiment.

## Validation and remaining scope

The first validation built the peer, then stopped compiling process tests with
two E0277 errors: `unwrap_err` required Debug on the successful Response type.
Only those test error extractions changed to `err().expect(...)`; production,
assertions and cases were preserved. The first source, logs, target and artifacts
remain retained in `.local/compute-custody-native-validation/` and its original
target. A fresh R2 target passed 323 behavioral tests, eight compile-fail docs,
strict five-package all-target Clippy, formatting and requirements mirroring;
one existing aggregate measurement remained ignored. Build/test workers were two,
separately from the eight-thread timing window.

Four new store tests cover borrowed/owned error parity, full data/index tails,
namespace and whole-file caps, late hostile lengths/trailing bytes, future page
revisions, unknown versus missing/substituted files and exact physical repair.
One actual process test corrupts unrequested data and index tails, rejects compute,
repairs the file and recovers genuine proved completion. It also checks either
wrong request head and the explicitly unverified legacy Evaluate boundary.
All five new cases, five cancellation cases and five retained regressions passed
exactly once. Existing SQL, TLS, fault, authorization, quota, freshness and pending
recovery remain covered by the owning suites.

Provenance remains in `.local/compute-custody-native-validation-r2/validation.json`,
its archived source/control manifests and the first-failure evidence. GUI source
did not change, so its suite was not repeated. Full PostgreSQL, private locks,
public source-completeness proofs, production finality and whole-process resource
bounds remain unestablished. The general 500-ms objective remains open.
