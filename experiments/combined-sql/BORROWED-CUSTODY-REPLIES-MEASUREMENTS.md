# Borrowed custody reply comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`2e7ed89ee3a3ebd269e68fec9e17fecc23df8a4a` and
`7556f0d1f151eefcc5e2baf002447293ed40bb22`. The latter builds PageBatch and
ReadImage replies from borrowed, fully audited disk images. UPDATE's median
regressed in this window; SELECT's median improved. These observations establish
neither a general speedup nor a robust 500-ms bound.

## Change and preserved checks

Private `BorrowedCheckedImages` retains two canonical audits borrowing one
bounded immutable disk buffer. The same four-field parser checks every length
and trailing byte before metadata validation. Namespace and whole-file caps keep
their original order. The existing canonical compact-store parser audits the
complete data image, then the complete index image, including all revisions,
packet hashes and Merkle roots. Store checks the exact requested object ID only
after both audits. No packet, unrequested identity tail or other image is omitted.

The private reply factories use these checked borrowed images directly.
PageBatch copies its requested membership responses in the original address
order. ReadImage materializes its complete data snapshot and copies the static
index prefix. Each response owns its bytes before the disk buffer drops; no
borrow escapes into network delivery. The existing 1-MiB PageBatch and 16-MiB
ReadImage response caps, 64-MiB global frame, eight connections and one heavy-work
permit remain unchanged. No public core API, wire/disk/profile or access-footprint
change is introduced.

Physical custody and response construction remain separate outcomes in the
existing private read helper. A failed known physical read, full audit or exact-ID
check marks that object unavailable. Successful physical repair clears the marker
even if a well-formed request supplies different heads and response binding fails.
Malformed, duplicate or out-of-range wire requests reject before dispatch and
cannot clear a previous invalid marker. No cross-RPC audit cache, status/stat
shortcut, unchecked capability or alternate-format fallback is added.

Public CheckedObject and owned-image consumers retain their existing paths:
Full/Delta admission, Copy, Fetch/FetchVersion and durable persistence are
unchanged. Metadata-only compute admission still drops each image audit before
starting the next. Owner AEAD/TableId validation, genuine FHE computation and
proof acceptance, exact agreed freshness, final full owner import and pending
recovery remain mandatory. Static SQL reads retain their fixed public footprint;
the raw PageBatch RPC does not authorize query-dependent live SQL access leakage.

At this fixture's geometry the four former RawBundle payload copies comprise two
112-byte heads, 3,187,648 data bytes and 34,416,624 index bytes: 37,604,496 bytes
per applicable custody-reply construction. This structural allocation count is
not measured RSS or a whole-operation memory saving. The full disk buffer,
complete Merkle trees, owned data/page replies, encoding buffers and independent
owner/FHE work remain.

## Complete accepted operations

Three fresh alternating pairs ran in
`.local/borrowed-custody-replies-measurements/20261016-163923-756/`: before1,
after1, before2, after2, before3, after3. All six actual TLS-peer scenarios passed
and supplied all twelve timers. No sample was excluded or rerun.

The unchanged fixture creates one real peer and 1,000,000 encrypted rows:
999,999 age-7 rows and one final age-42 row, initially amount one. UPDATE adds
one; the subsequent genuine proved SELECT returns exactly `[[42, 2]]`. Startup,
keys, initial encryption/storage and Status are outside timing. Both timers wrap
the complete successful `Session::execute`; UPDATE includes durable publication,
confirmation and final full owner import.

| Complete operation | Before rounds 1 / 2 / 3 ms | After rounds 1 / 2 / 3 ms |
| --- | ---: | ---: |
| UPDATE | 822.095 / 597.231 / 541.703 | 609.892 / 645.560 / 652.559 |
| SELECT | 276.343 / 233.024 / 239.086 | 244.931 / 216.073 / 216.969 |

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 541.703 / 597.231 / 822.095 | 609.892 / 645.560 / 652.559 |
| SELECT | 233.024 / 239.086 / 276.343 | 216.073 / 216.969 / 244.931 |

Differences between variant medians are +8.09% for UPDATE and -9.25% for SELECT,
not medians of paired percentages. UPDATE paired differences are -212.203,
+48.329 and +110.856 ms: two pairs regress, as does its median. SELECT paired
differences are -31.412, -16.951 and -22.117 ms. Both operation ranges overlap.
All after UPDATE samples exceed 500 ms; the general target remains unmet.

Both SQL paths use ReadImage, but these complete-operation timers do not isolate
its construction cost or establish causality. Three samples do not estimate p95,
tail latency, general throughput or failure recovery. Unrelated host background
load was uncontrolled. Absolute timings differ from the preceding window; no
host cause, cross-window or cumulative/additive gain is inferred. Every sample,
including the 822.095-ms baseline UPDATE, remains in the record.

Owner and peer requested eight Rayon threads; all six logs report AVX-512.
The presence-gated RPC/PID variables were removed and asserted absent, and no log
contains their markers. No team build/proof job or memory monitor ran during the
window. No WAN, cold-cache or whole-process RAM guarantee follows.

## Frozen artifacts and reproduction

Both builds use Rust 1.99.0/MSVC release, the implicit Windows x64 host target,
`-C target-cpu=native` and locked dependencies on the same AMD host. Arithmetic
proof profile v3, kernel ABI, custody profile 2, RPC v2, application v4 and private
index formats are unchanged. Arithmetic security parameters do not certify the
complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-compute-custody-native-r2/release/deps/proved_sql-ffebb722f081b809.exe` | `5C310108F03BDE0662522F2957052BBB59267FFE397A35675B8212AF5387C22F` |
| Before `.local/target-compute-custody-native-r2/release/dcs-peer.exe` | `A211DDE6AA0BEB82A228E2145609C5413CD75FDA698437A3F00D28F8BC88B267` |
| After `.local/target-borrowed-custody-replies/release/deps/proved_sql-ffebb722f081b809.exe` | `6888898BA9143312846A7FC78B8BAF7D37D6FC57886BD1D13FD1181B005AACA9` |
| After `.local/target-borrowed-custody-replies/release/dcs-peer.exe` | `2B191C75D0E6940D5A50586D8CE41423B40FF3A74AB2DBA00881F07C4DE6AF5B` |

Both use AVX2 kernel
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 kernel
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
All eight archived executable/kernel copies and eight originals were independently
rehashed. Each owner embeds its own original target's peer path; preserve that
path and its adjacent proof-kernels directory. The archive retains artifacts.json,
six logs, timers.json and the executed driver.ps1. Archived and original
`.local/measure-borrowed-custody-replies.ps1` both hash to
`6104227D90607DDF5475F251075B84D208E6E20F3E53E869AF44469B280DA6D3`.
Its exact five-literal inverse reproduces the preceding compute-custody driver:
only run prefix and baseline owner/peer paths and hashes differ.

Set RAYON_NUM_THREADS and DCS_TEST_PEER_THREADS to 8; remove DCS_TEST_RPC_PROFILE,
DCS_TEST_FIXED_PIDS and DCS_TEST_TYPED_PIDS entirely. Invoke each original owner
with `--exact million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore --nocapture --test-threads=1`,
alternating three pairs as above. The archived driver records both source
arguments, paths, worker settings and hashes. Reproduction uses the unchanged
[real fixture](../../apps/dcs-peer/tests/proved_sql.rs); generated binaries,
logs, credentials and ciphertext remain ignored.

The baseline compiled `732a9b3` plus the reviewed compute-custody patch and was
published as `2e7ed89`. The after build compiled its docs-only descendant
`edd61143d4facd1aa6f60b834c551228517aa213` plus the reviewed ten-path reply patch,
source manifest `6054B2104107E7306B87C8D50B198DA2A8387EEBECC571388215AE3213B39B9A`.
Commit `7556f0d` contains those exact canonical files. No rebuild is attributed
to a later uncompiled source or unrelated crypto experiment.

## Validation and remaining scope

One native validation invocation passed 331 behavioral tests, eight compile-fail
docs, strict five-package all-target Clippy, formatting and requirements mirroring;
one existing aggregate measurement remained ignored. All four command phases
exited zero. Functional build/test workers were two, separately from the
eight-thread timing window. A pre-execution driver review corrected only two
expected doctest line numbers; no source fix, native retry or test rerun was needed.

Eight new cases cover exact owned/borrowed response bytes over empty, odd and
partial geometry; owned response lifetime after the disk/store/file drop; wrong
request heads and repaired availability; substituted nonce, missing/unknown files;
and actual TLS omitted-tail corruption, malformed pre-dispatch requests and
post-reply cancellation. Two existing full-audit/cap cases were expanded. All
eight new, two expanded and four retained custody regressions passed exactly
once. Existing SQL, fault, authorization, quota, proof/freshness and pending
recovery checks also passed in the owning suites.

Provenance remains in `.local/borrowed-custody-replies-validation/validation.json`
and its source/patch manifests, logs and independent audit. GUI source did not
change, so its suite was not repeated. Full PostgreSQL, private locks, private
source/completeness proofs, production finality and whole-process resource bounds
remain unestablished. This window does not establish an UPDATE latency benefit.
