# Streamed custody persistence comparison

On 2026-10-16 complete accepted million-row UPDATE and SELECT ran on
`6e38660393f9bfb16482043643f26898eba3f045` and
`544449b109982cacc0eafa3cd7c63a3c51e1f5df`. Both retain the
[owned audited images](OWNED-IMAGE-MEASUREMENTS.md), bulk codecs, Boolean fixed
predicates, static UPDATE sources, custody profile 2, RPC v2 and application v4.
The latter's parent `2569658` adds an isolated SHA experiment and discovery docs;
it changes no root workspace manifest, production dependency or measured path.
The native build used `defd48a`, the documentation-only child of `6e38660`, plus
the exact six-file persistence patch. Those six hashes remained unchanged when
the isolated experiment was incorporated before publication.

## Change and preserved boundaries

The private admission Candidate now retains the already audited RawBundle and its
exact disk length. Persistence writes the existing 40-byte profile header and
unchanged bincode encoding through a 16 KiB BufWriter. There is no second manual
codec. Fixed-codec sizing and complete frame limits are checked before creating
the pending file; bulk byte sizing does not scan the payload again. Existing
quota and target-object checks precede it. Success still requires flush, file
sync, close and rename before maps/ACK; failures clean the current pending file.

At the million-row geometry this removes the 37,604,602-byte complete disk Vec
and its full copy for Full or Delta admission. The retained RawBundle still owns
37,604,496 bytes across its four payloads. Delta still materializes both checked
images and encodes snapshots into RawBundle; this change does not remove those
copies. Both complete physical image audits, including unrequested tails, remain.
Authorization, exact target nonce/object ID, replay, freshness, genuine FHE/STARK,
pending recovery and wire/disk bytes remain unchanged. Allocation accounting is
not a measured whole-process memory reduction.

## Full accepted operations

Three fresh alternating before/after pairs ran in
`.local/streamed-custody-persistence-measurements/20261016-111308-560/`.
All six genuine independent TLS-peer scenarios and twelve result/head/timer checks
passed. The unchanged fixture has 1,000,000 rows and one final matching row.
UPDATE adds one to its amount; subsequent SELECT returns exactly `[[42, 2]]`
from the encrypted result. Setup and initial Status remain outside the timers;
each timer covers the entire `Session::execute` as in the
[decoder comparison](BULK-DECODING-MEASUREMENTS.md).

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 618.809 / 645.880 / 662.486 | 587.864 / 626.811 / 666.603 |
| SELECT | 227.555 / 228.721 / 232.927 | 223.067 / 229.802 / 237.120 |

Differences between variant medians are -2.95% for UPDATE and +0.47% for SELECT,
not medians of paired percentages. Both ranges overlap. UPDATE is slower in two
of three pairs; SELECT has mixed paired directions. These samples do not establish
a latency improvement. Every UPDATE exceeds 500 ms. No sample was excluded or
rerun, and separate historical windows do not establish cumulative improvement.

Owner and peer each use eight Rayon threads; all peer logs report AVX-512.
The driver removed and asserted absence of all three presence-gated diagnostic
variables, and no log contains RPC/PID markers. No development build, other
proof test or memory monitor ran in the window. Unrelated host background load
was not controlled. There is no tail-latency, WAN, cold-cache or RAM claim.

## Artifacts, reproduction and validation

Both use Rust 1.99.0/MSVC release, implicit Windows x64 host target, native CPU
flags and locked dependencies on AMD Ryzen 9 9950X3D2. The arithmetic proof
profile v3, N8192/Q218, 192 FRI queries, blowup 8, degree-five extension and
existing kernel ABI remain unchanged; its 128-bit floor does not certify the
complete storage protocol.

| Artifact under repository root | SHA-256 |
| --- | --- |
| Before `.local/target-owned-verified-images/release/deps/proved_sql-18a2eaec0e34c184.exe` | `1EB9F9612A534D649B4CC0FAEBD131F3BD0BFB2036F307F9DA481726734810CF` |
| Before `.local/target-owned-verified-images/release/dcs-peer.exe` | `45396CA310967166C336E52F15B1A32F487B1BAA6756770891747753B8B66D58` |
| After `.local/target-streamed-custody-persistence/release/deps/proved_sql-18a2eaec0e34c184.exe` | `344699E9DF35F2A1280D6980EE6EFB8F2AEDCB0ECAD764633DC052FE33100366` |
| After `.local/target-streamed-custody-persistence/release/dcs-peer.exe` | `0E0E5E12CA6921DEFC00CF2E359F9267D9268750FD2E9782844697E8CC5F14DB` |

The unchanged kernel hashes and exact eight-thread/no-hook fixture command are
in the [object-profile record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
Preserve each owner's matching baked peer and adjacent kernels. The window
archives all eight exact executables/kernels, logs, timers, source/path/hash
metadata and the executed `driver.ps1`. Generated outputs are not committed.

The six-file change passed 162 native behavioral tests: runtime 67, client 23,
relational TLS 10, real-process transport 15, faults 4 and SQL 43; one aggregate
measurement remained ignored. Six new tests cover exact plain-Vec disk bytes,
64 MiB boundaries including the 40-byte header, short/zero/error writers, quota
before pending creation, and real rename failure/cleanup/retry/reopen. Existing
Full-versus-Delta, base corruption/GC/replay, lost-ACK and pending/tail cases pass.
Strict three-package all-target Clippy, formatting and exact requirements
mirroring passed. GUI source/contracts did not change; GUI tests were not rerun.

Validation logs are in `.local/streamed-custody-persistence-runs/20261016-110035-823/`;
`.local/streamed-custody-persistence-publication.json` records canonical source and
artifact identities. This remains a fixed experimental workload. Full PostgreSQL,
private row locks, public source-completeness proofs, production finality and
whole-process resource compliance remain unestablished.
