# Authenticated UPDATE candidate handoff

This compares source `97bba1cf15ea0cd1d7e645fa21142ea0a95d886f` with
`b596b23c43a230cbdbbcf16bd5c545e847da7e7d`. The latter includes exactly the
private custody-candidate refactor and temporary-buffer lifetime changes over
the same PostgreSQL/LIMIT/Delta implementation. The root integration also has
measurement documentation; it adds no different query behavior.

## Change and unchanged checks

An UPDATE Delta consumes a physically audited base and all verified replacement
pages into sealed complete snapshots. Both new roots must match. A private
immutable candidate then checks the exact target heads and complete canonical
legacy Bundle ID once and owns the bytes accepted by durable persistence. This
removes the second decode/tree reconstruction of those already authenticated
images. Raw Full uploads retain their full audit. Every existing-target replay
still reads and authenticates the whole physical target, including after base GC.

The complete old-base read/hash, all resulting roots, full new-object quota,
fsync/atomic rename, exact IDs and disk/RPC encodings remain unchanged. No state
cache, validation flag, adaptive page access, FHE/profile change or SQL/freshness
proof is introduced. Complete encoded images are still materialized. Temporary
snapshot buffers are released before final encoding; RAM was not measured here.
See the [owning boundary](../../crates/peer-runtime/README.md) and
[Delta contract](../../docs/padded-update-delta.md).

## Complete-operation samples

The public synthetic fixture has one million rows on one actual peer: 999,999
age-7 rows and one final age-42 row, initially amount 1. Each fresh scenario
performs the genuine FHE UPDATE, durably publishes/confirms it, and reads back
exactly `[42, 2]` through a genuine proof. All six scenarios passed the original
exact result, million-row layout and version assertions. Query timers wrap the
complete `Session::execute`, including preparation, actual I/O, proof checking,
completion and final freshness; writes include durable publication/collection.
Startup, key generation, initial table creation and later assertions are outside.

Three fresh before/after pairs ran sequentially, alternating before then after.
There were twelve SQL timers. Native Rust 1.99/MSVC, eight Rayon threads per
owner and peer, the same AMD host as the [combined record](README.md), unchanged
profile-v3/application-v3 and all 81,920 residues were used. Every peer reported
AVX-512. Other build/proof jobs had ended; RPC/PID hooks and memory monitoring
were disabled. No benchmark artifact changed during the window.

| Complete query | Version | Minimum ms | Median ms | Maximum ms |
| --- | --- | ---: | ---: | ---: |
| `UPDATE records SET amount = amount + 1 WHERE age = 42` | Before | 1001.542 | 1158.619 | 1173.446 |
| Same UPDATE | After | 1048.457 | 1076.295 | 1137.149 |
| `SELECT * FROM records WHERE age = 42`, after UPDATE | Before | 356.534 | 357.041 | 358.463 |
| Same SELECT | After | 345.496 | 350.648 | 371.335 |

The difference between variant UPDATE medians is 7.1%; this is not the median of
paired percentage changes. Ranges overlap and one after UPDATE was slower than
its adjacent before sample. These three pairs describe this window, not a tail
or general speedup guarantee. The SELECT shift is not attributed to writeback.
UPDATE still exceeds 500 ms. This does not establish WAN behavior, throughput,
whole-process RAM, full PostgreSQL or live row locks. The current owner source
checks and known-head confirmation fixture still do not discharge the missing
public source/completeness proof or production finality requirements.

## Reproduction and verification

Ignored `.local/candidate-handoff-runs/20261016-065237-242/` preserves six logs,
all twelve timers, the manifest and both exact owner/peer/kernel artifact sets.

| Artifact | Before SHA256 | After SHA256 |
| --- | --- | --- |
| Owner/test | `3D6C85EC774879446CF47E54A053255B98A25467E7648B688AC9128829E5B8A8` | `198CCA1C833E21F85A96F214C0702590C2CFB5F7E299151A2AB41BA1266224E0` |
| Peer | `CAC96AB37DE9669CABFFE5EF7862C36DD3247993D9666FECA91CFA2C2FB67073` | `887156E6C436B308CADC49F18DDCFB5722ADF82723E39E2856EDB5837C130D15` |

Both versions use AVX2 kernel SHA256
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 kernel SHA256
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
Build each pinned source outside timing. Run the compiled test
`million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`
with `--exact --nocapture --test-threads=1`, `RAYON_NUM_THREADS=8` and
`DCS_TEST_PEER_THREADS=8`; clear `DCS_TEST_RPC_PROFILE`, `DCS_TEST_TYPED_PIDS`
and `DCS_TEST_FIXED_PIDS`. Each copied owner still launches its baked peer path:
before uses `.local/target-bfv-query-proof-native/release/dcs-peer.exe`, after
uses `.local/target-verified-candidate-handoff/release/dcs-peer.exe`. The manifest
records those absolute paths. Verify/install matching peers and kernels there
outside timing; copying a peer beside an owner does not redirect that lookup.

The combined candidate branch passed 116 affected behavioral tests and strict
native Clippy. After the final lifetime change, the root independently reran 40
runtime tests, 13 actual-process transport tests, four actual-process fault tests
and all 29 actual-process SQL tests: 86 passed. New custody tests compare exact
Full/Delta disk bytes and every metadata field at 1/2/64/256/257 replacements,
reject a disk-byte hash substituted for the legacy object ID, and reject six
malformed raw Full inputs. Existing corruption, quota, auth, replay, base-GC,
proof/freshness and pending-write checks remain. Formatting, documentation links,
staged diff and requirements mirroring passed.
