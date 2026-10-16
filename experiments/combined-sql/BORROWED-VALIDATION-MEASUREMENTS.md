# Borrowed full-image validation comparison

On 2026-10-16, the complete accepted million-row UPDATE and subsequent SELECT ran
on `1ad514844085067611cd887598b3db113d495816` and
`87f8a3428ee82b9e7a44dfed40f1cc483b86facf`. The latter is based on `a241d7a`,
a documentation-only child of the before source. Both use static initial UPDATE
sources, randomized custody profile 2, RPC v2, application v4 and unchanged
BFV/STARK, image formats, kernel ABI and admission limits.

## Change and validation boundary

The final agreed-object check previously called owner restore and immediately
dropped its returned Table. It now calls full owner image validation without
materializing packet buffers. A sealed immutable `VerifiedSnapshotBytes` borrows
the actual complete bytes and owns the checked Merkle levels. One canonical
parser validates limits, expected heads, exact lengths, every packet revision
and both complete roots for borrowed validation and owned snapshot decoding.
When a Table is needed, materialization consumes this checked lineage and moves
the same tree without a second root pass. The owner validation and restore paths
share schema/geometry checks and actual AEAD header/TableId binding.

For this public fixture, source-derived geometry accounts for 12,213 packet
buffers containing 37,604,048 bytes across both full images. The discarded Table
no longer materializes those payloads at this final check. This is allocation and
copy accounting, not measured RSS or proof of a faster whole operation. Checked
Merkle storage and complete root hashing remain; owned consumers still materialize
their packets. The shared decoder also changes allocation/hash ordering in those
consumers, so the whole-query experiment must include them.

Every physical custody audit, complete final FetchVersion, holder recovery audit,
authorization, FHE proof and freshness gate remains. No audit cache, trusted flag,
partial-object credit or prefix replacement is added. Full image restore never
claimed global semantic RowId validation: it authenticates all ciphertext and
checks the header, while selected `row_references` reject zero/duplicate IDs.
The new tests retain that existing scope. A public index/source-completeness proof
and live SQL locks are still missing.

## Complete accepted operations

The unchanged existing scenario is
`million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`.
One independent TLS peer holds 1,000,000 public fixture rows, 256 per page, with
all amounts 1. The first 999,999 ages are 7; the last age is 42. The actual query
updates that final amount to 2, changes the object/head revision without changing
geometry, then returns exactly `[[42, 2]]`. Expected rows are assertions after the
real FHE operation, never peer answers.

Startup, keys, table creation and initial Status checks are outside each timer.
UPDATE includes static source preparation, real BFV/STARK, local verification,
complete Delta admission, journal publication/confirmation and final full agreed
object validation. SELECT includes source retrieval/preparation, proof verification
and final freshness before completion. The easy fixture work target and one
descendant confirmation are not a production attack budget or finality guarantee.

Three fresh alternating before/after pairs ran in
`.local/borrowed-custody-measurements/20261016-092214-776/`. All six scenarios,
exact result/head assertions and twelve accepted-operation timers passed. No
development build, other proof test or memory monitor ran in this window.
All three presence-gated diagnostic variables were removed and checked absent
before launch; all logs contain no RPC/PID markers. Unrelated host load was not
controlled.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 918.512 / 939.692 / 977.805 | 913.643 / 946.084 / 968.924 |
| SELECT | 351.527 / 353.472 / 374.586 | 354.003 / 361.947 / 381.205 |

The differences between variant medians are **+0.68%** and **+2.40%**, not medians
of paired percentages. Both ranges overlap. These three samples establish no
whole-operation latency improvement; the change is retained as an explicit
validation/materialization boundary and removal of unnecessary packet copies.
There is no measured memory-saving claim. Every UPDATE still exceeds 500 ms.
Do not combine this window with earlier measurements to infer cumulative speedup.

## Reproduction and artifacts

Windows x64, AMD Ryzen 9 9950X3D2, Rust 1.99.0/MSVC release and
`-C target-cpu=native` are unchanged. Before uses the host target; after spells
out the same `x86_64-pc-windows-msvc` target. Both owner and peer use eight Rayon
threads, and all peer logs report AVX-512. The N8192/Q218 arithmetic profile v3
still covers all 81,920 residues with FRI blowup 8, 192 queries, extension degree
5 and the existing 128-bit floor. This floor is not a proof of the whole protocol.

| Variant | Exact owner under repository root | Baked peer directory |
| --- | --- | --- |
| Before | `.local/target-static-update-network/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-static-update-network/release/` |
| After | `.local/target-borrowed-custody-validation/x86_64-pc-windows-msvc/release/deps/proved_sql-501f76c956e504af.exe` | `.local/target-borrowed-custody-validation/x86_64-pc-windows-msvc/release/` |

| Artifact | SHA256 |
| --- | --- |
| Before owner | `BAEE8839B0CED44CCC540302B66B470A966C7C984F575BD93FE9C15D65394160` |
| Before peer | `E1B028E183ED55CC1FE45B4F6A21643E575C23D1A1E9AF66293A036A49915ADE` |
| After owner | `F4B6B04FB752C3BA915B7ED705CF70DB03F2ECFECDE3A53BE5FC0842819DFEA8` |
| After peer | `3E94E841C5C8C35978D782AC116DD29A821B787543C211D485D438A9BD6AFE36` |

Both exact kernels remain those in the
[object-profile artifact table](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
The ignored window preserves six logs, twelve timers, exact owner/peer/kernel
copies, hashes, baked paths and the executed script. Use the same eight-thread,
no-hook [reproduction command](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
Restore the matching peer/kernels at the owner's baked path outside the timer;
running a copied owner alone does not pin its peer. Never overwrite active
consumers' artifacts. Generated binaries, ciphertext and logs are not committed.

Before freezing, the exact combined change passed 292 native behavioral tests:
query 68, store 43, runtime 51, client 32, actual transport/fault/SQL 57, transaction
state 23 and journal 18. One aggregate measurement fixture remained ignored.
Four compile-fail contracts, strict seven-package all-target Clippy, formatting,
requirements mirroring, module links and three source reviews passed. Persistent
functional logs are in
`.local/borrowed-custody-validation-runs/20261016-091250-642/`.
The six new behaviors cover full-image corruption and binding, selected-ID scope,
public owner validation, canonical decoder/error order, odd/empty/partial page
membership/materialization and lower caller caps. Two new compile-fail cases pin
immutable borrowing and lifetime. These checks establish neither complete
PostgreSQL nor a general 500-ms or whole-process memory bound.
