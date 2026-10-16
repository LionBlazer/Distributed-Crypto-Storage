# Bulk custody serialization comparison

On 2026-10-16, the complete accepted million-row UPDATE and subsequent SELECT ran
on `87f8a3428ee82b9e7a44dfed40f1cc483b86facf` and
`73ed837dff7b3ad683497d4cfcc8f0e06082efc9`. The latter is based on the
documentation-only child `4b4c97d`. Both include borrowed full-image validation,
static initial UPDATE sources, custody profile 2, RPC v2 and application v4.

Only RawBundle's four byte vectors change their serialization implementation:
a private `serialize_bytes` adapter replaces the ordinary Vec<u8> sequence walk.
Pinned bincode 1.3.3/fixed integers writes exactly the same u64 length and payload;
the size checker also counts the whole byte payload at once. Independent plain-Vec
controls pin raw, Store tag 2, RawBundle reply tag 3 and disk envelopes in both
directions, including actual stored million-row ciphertext. This introduces no
new format, dependency, FHE circuit, parameter, kernel ABI or protocol version.

The derived Deserialize implementation and bounded sequence visitors are unchanged.
This experiment does not include the separately proposed bounded bulk decoder.
Outer version/profile gates, owner authorization, nonce/ID binding, resource and
quota checks, every complete physical image audit, proof verification and final
freshness remain. No unchecked object, trust flag or cross-RPC cache is added.

## Full accepted operations

The unchanged real-process fixture is
`million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`.
One independent TLS peer stores 1,000,000 public fixture rows, 256 per data page.
All amounts are 1; the first 999,999 ages are 7 and the last age is 42. UPDATE adds
1 to that final amount, asserts the changed object/head revision and unchanged
geometry, then SELECT returns exactly `[[42, 2]]` from the real encrypted result.

Startup, keys, table creation and initial Status inspection are outside the timers.
UPDATE includes static source preparation, real BFV/STARK, local verification,
complete Delta admission, journal publication/confirmation and full final agreed
object validation. SELECT includes source preparation, genuine proof and final
freshness before decryption/completion. The easy work target and one descendant
confirmation remain prototype settings, not production finality or attack resistance.

Three fresh alternating before/after pairs ran in
`.local/bulk-serialization-measurements/20261016-094339-878/`. All six scenarios
and twelve exact result/head/accepted-operation assertions passed. No development
build, other proof test or memory monitor ran in the window. Diagnostic variables
were removed and checked absent before launch; all logs have no RPC/PID markers.
Unrelated host background load was not controlled.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 790.556 / 829.921 / 886.018 | 678.189 / 782.429 / 803.914 |
| SELECT | 315.652 / 318.740 / 319.268 | 323.669 / 324.926 / 334.202 |

The differences between variant medians are **-5.72%** for UPDATE and **+1.94%**
for SELECT, not medians of paired percentages. UPDATE's ranges overlap; SELECT's
three after samples are higher than its three before samples. These small samples
cannot establish causation or tail latency. They do not establish a read speedup
or general improvement across workloads. Every UPDATE still exceeds 500 ms.
Keep this window separate from earlier measurements; do not infer cumulative
speedup from different baselines. No memory or WAN claim was measured.

## Artifacts and reproduction

The Windows x64 host is AMD Ryzen 9 9950X3D2. Both builds use Rust 1.99.0/MSVC,
release, native CPU flags and locked dependencies. Before spells out the host
`x86_64-pc-windows-msvc` target; after uses that host target implicitly. Owner and
peer each use eight Rayon threads; all six peer logs report AVX-512. N8192/Q218
proof profile v3 still covers all 81,920 residues with FRI blowup 8, 192 queries,
extension degree 5 and the existing 128-bit floor. This is not a security proof
of the complete storage protocol.

| Variant | Exact owner under repository root | Baked peer directory |
| --- | --- | --- |
| Before | `.local/target-borrowed-custody-validation/x86_64-pc-windows-msvc/release/deps/proved_sql-501f76c956e504af.exe` | `.local/target-borrowed-custody-validation/x86_64-pc-windows-msvc/release/` |
| After | `.local/target-bulk-custody-serialization/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-bulk-custody-serialization/release/` |

| Artifact | SHA256 |
| --- | --- |
| Before owner | `F4B6B04FB752C3BA915B7ED705CF70DB03F2ECFECDE3A53BE5FC0842819DFEA8` |
| Before peer | `3E94E841C5C8C35978D782AC116DD29A821B787543C211D485D438A9BD6AFE36` |
| After owner | `B9948F75C35B334BA167D66037466EEC3FB3A21A61D571057F6D7219108938F0` |
| After peer | `347C111D7ED65AA22E290EB901B4E7516B6E6709D976A8477A26E5AFD19141F6` |

The unchanged kernel hashes and exact eight-thread/no-hook reproduction command
are in the [object-profile record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
The ignored window preserves all six logs, twelve timers, exact owner/peer/kernel
copies, hashes, baked paths and the executed script. Restore the matching peer
and kernels at the owner's baked path outside the timer; a copied owner alone
does not pin its peer. Never overwrite active consumers' binaries. Generated
outputs and ciphertext are not committed.

The change passed 143 native behavioral tests: runtime 54, client 32, transport
14, fault 4 and SQL 39, with one aggregate measurement fixture ignored. Strict
three-package all-target Clippy first caught a test-only tuple type-complexity
lint. A private test type alias fixed it without suppression or production edits;
the affected actual million-row codec case and full strict Clippy then passed.
All logs are retained under `.local/bulk-custody-serialization-*.log`. Formatting,
requirements mirroring, module links and two source reviews passed. These tests
do not establish complete PostgreSQL, private SQL locks, public source-completeness
proofs, production finality or whole-process resource bounds.
