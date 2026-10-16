# Received full-version frame comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`c137caf358a534fa0be1251a61464b3c052408ac` and
`e073987cd1add503da230eb8ef65b061ff90ddac`. Both include the preceding
[owner audit policy](OWNER-AUDIT-MEASUREMENTS.md). This stage retains a received
full-version reply through owner validation instead of copying its four payloads.
The observations below do not establish a general or robust 500-ms bound.

## Change and preserved checks

`RemotePeer::fetch_version` returns `Option<ReceivedVersionBytes>`. The value owns
the original immutable response frame, four checked field ranges and copied
version/nonce scalars. The existing borrowed four-field parser checks all lengths
and trailing bytes before the frame can be retained; the actual 64-MiB cap still
includes the 18-byte outer envelope. Its metadata helper is shared with RawBundle.
There is no mutable or unchecked constructor, Clone, Deserialize, self-reference
or payload Arc copy. The ordinary `call`/Response interface remains unchanged.

Only changed-head owner synchronization uses the new path. The endpoint queue
ends before full owner validation; the frame drops before another holder is tried
or shard metadata is staged. Target binding and both exact agreed heads precede
the same complete data/index canonical audits, schema/geometry, index-header AEAD,
TableId, embedded data head and count checks. A metadata binding does not prove
custody. The affected FetchVersion path still fully audits both physical server
images, including the encrypted identity tail. Proofs, freshness, authorization,
quotas, Copy, holder credit, durable publication and exact pending recovery remain.

One private exchange retains TLS/request binding, actual Activity/Trace bytes,
decoding within completed-RPC timing and the final cancellation check. A valid
known unexpected success remains `Ok(None)` and a successful RPC for telemetry
and endpoint failure memory. Remote errors and malformed/unknown replies remain
errors. Busy retry and the existing conditional Some/None synchronization
cancellation policy are preserved; that separate follow-up is documented in the
[client boundary](../../crates/storage-client/README.md).

At this geometry the two 112-byte heads and complete 3,187,648-byte data and
34,416,624-byte index payloads total 37,604,496 bytes. This is the source-derived
payload-copy volume removed per applicable reply, not a measured peak-RAM saving.
The complete 37,604,580-byte response is still received. Canonical audit buffers,
peer encoding, unrelated full-object consumers and all encrypted bytes remain;
there is no cross-RPC custody cache, sparse final audit or new privacy footprint.

## Complete accepted operations

Three fresh alternating pairs ran in
`.local/received-version-frame-measurements/20261016-143007-169/`: before1,
after1, before2, after2, before3, after3. All six independent TLS-peer scenarios
passed and supplied all twelve timers. No sample was excluded or rerun.
The unchanged fixture has 1,000,000 rows, 999,999 age-7 rows and one final age-42
row, initially amount one. UPDATE adds one; the subsequent genuine proved SELECT
returns exactly `[[42, 2]]`. Startup, keys, initial encryption/storage and Status
are outside timing. Each timer wraps the complete successful `Session::execute`.
UPDATE includes mutation publication, confirmation and final full owner import.

| Complete operation | Before rounds 1 / 2 / 3 ms | After rounds 1 / 2 / 3 ms |
| --- | ---: | ---: |
| UPDATE | 526.581 / 576.450 / 442.612 | 468.936 / 536.737 / 412.736 |
| SELECT | 222.861 / 243.516 / 220.268 | 217.766 / 221.795 / 225.451 |

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 442.612 / 526.581 / 576.450 | 412.736 / 468.936 / 536.737 |
| SELECT | 220.268 / 222.861 / 243.516 | 217.766 / 221.795 / 225.451 |

Differences between variant medians are -10.95% for UPDATE and -0.48% for SELECT,
not medians of paired percentages. UPDATE paired differences are -57.645,
-39.713 and -29.876 ms. SELECT differences are -5.095, -21.721 and +5.183 ms,
so its third pair regresses. Both operation ranges overlap. The valid baseline
442.612-ms UPDATE was already below 500 ms; the after 536.737-ms sample still
exceeds 500 ms. Two after samples below 500 ms do not establish a robust bound.

The healthy SELECT normally finds unchanged local/agreed heads and does not
perform the changed-head import optimized here. Its median cannot directly be
attributed to this ownership work. These three pairs do not isolate causality,
establish general improvement or estimate p95/tail latency. The prior owner-audit
window was much slower; no host cause is inferred and no cumulative or
cross-window improvement is calculated. Unrelated host background load was
uncontrolled. All samples, including the valid lower baseline, are retained.

Owner and peer requested eight Rayon threads; every log reports AVX-512. The
presence-gated RPC/PID variables were removed and asserted absent, and no log
contains their markers. No build, other heavy proof/test or memory monitor ran
during the window. No WAN, cold-cache, throughput or process-RAM bound follows.

## Frozen artifacts and reproduction

Both builds use Rust 1.99.0/MSVC release, the implicit Windows x64 host target,
`-C target-cpu=native` and locked dependencies on the same AMD host. Arithmetic
proof profile v3, kernel ABI, custody profile 2, RPC v2, application v4 and private
index formats are unchanged. Arithmetic security parameters do not certify the
complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-owner-parallel-audit-r2/release/deps/proved_sql-ffebb722f081b809.exe` | `46B570824121339ACBD0F54EAE3562E53A4A8DE54E41F3FCA3FB06C43991FC2F` |
| Before `.local/target-owner-parallel-audit-r2/release/dcs-peer.exe` | `FCA4767EC026FBDF9F355AB3239110F6E5408023DDE0C0A658E492B25D44B603` |
| After `.local/target-received-version-frame/release/deps/proved_sql-ffebb722f081b809.exe` | `B66789652F504F01892329CC8423079077146DFB77B656926DA47AC43B2C0909` |
| After `.local/target-received-version-frame/release/dcs-peer.exe` | `7730A1356C5230B4E38FD23E81AF297F5D73A00C87FC5475F2A3ABD03DF26074` |

Both use AVX2 kernel
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 kernel
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
All eight archived executable/kernel copies and eight original files were
independently rehashed. Each owner embeds its own original target's peer path;
preserve that path and its adjacent proof-kernels directory. The raw archive
contains artifacts.json, all six logs, timers.json and the executed driver.ps1.
The archived and original `.local/measure-received-version-frame.ps1` both hash to
`25477BA60D56C30DA6560BE13EF428A8183BBFD10672FFF62B2511CC36B1C570`.
It differs from the preceding driver only by five literal replacements: run
prefix and baseline owner/peer paths and hashes.

Set RAYON_NUM_THREADS and DCS_TEST_PEER_THREADS to 8; remove DCS_TEST_RPC_PROFILE,
DCS_TEST_FIXED_PIDS and DCS_TEST_TYPED_PIDS entirely. Invoke each original owner
with `--exact million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore --nocapture --test-threads=1`,
alternating three pairs as above. The archived driver records paths, source
arguments, worker settings and hashes. Reproduction requires the unchanged
[real fixture](../../apps/dcs-peer/tests/proved_sql.rs); generated binaries,
logs, credentials and ciphertext are not committed.

The baseline executables were compiled from `b6107a7` plus the reviewed owner R2
patch, then published as `c137caf` after an independent standalone crypto/docs
parent `128a7f1`. That publication preserved the compiled sources/artifacts.
The after executables were compiled from `322361f` plus the exact reviewed
seventeen-file frame patch; `322361f` adds only the previous measurement report
to `c137caf`. Commit `e073987` records exactly those seventeen paths. No rebuild
is attributed to an uncompiled later source or unrelated standalone experiment.

## Validation and remaining scope

One native invocation passed 313 behavioral tests, eight compile-fail docs,
strict five-package all-target Clippy, formatting and requirements mirroring;
one existing aggregate measurement remained ignored. All thirteen new behavior
tests, three expanded cases and two new compile-fail cases passed exactly once.
They cover original-frame pointer/capacity, invalid inner metadata, late hostile
lengths, trailing/truncated/wrong envelopes and actual cap boundaries, known
unexpected success versus NotFound, Trace/cancellation and endpoint memory.
Genuine full-image owner cases cover TableId/key/tail binding and a distinct
nonce at the same heads. Real processes cover corrupt-holder failover, restart,
unrequested tail corruption and exact pending retry without another FHE mutation.
Build/test workers were two, separately from the eight-thread timing window.

The original validation.json retains null aggregate totals from a PowerShell
ordered-dictionary summation issue; its thirty per-suite records, four zero exits
and actual required pass lines are intact. Separate verification-summary.json
recounts 313 behavior plus eight docs, zero failures and one ignored case from
those original logs. Nothing was overwritten or rerun. Source/control hashes and
all ten validation artifacts were independently checked before and after normal
publication. Provenance remains in `.local/received-version-frame-validation/`
and `.local/received-version-frame-publication.json`.

GUI source did not change and its suite was not repeated. Full PostgreSQL, private
locks, public source-completeness proofs, production finality and whole-process
resource bounds remain unestablished. The general 500-ms objective remains open.
