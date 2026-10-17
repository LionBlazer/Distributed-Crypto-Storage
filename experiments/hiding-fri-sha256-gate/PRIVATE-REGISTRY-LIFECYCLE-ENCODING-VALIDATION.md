# Registry200 original-row encoding validation

Validated experimental [encoding evidence](src/opening/registry_lifecycle/encoding/README.md)
against parent `80ae2b33e856480aa4da7fe287acc4663b501fc7`. A successful Registry200 Acquire Result144 now binds
compact original rows to a complete 8192-coefficient BFV SIMD encoding commitment.
This stage does not form a BFV ciphertext or admit a live encrypted SQL answer.

## Contract and ownership

The client compiles exact SQL bytes and a nonce, while independently retaining the
existing Journal intent identity. Full u64 transaction, revision and sequence
metadata, private controller and salt open the unchanged canonical Command160 and
must match the independently pinned C_cmd. They are consumed by client compilation;
the resulting Expected retains no private opening and cannot be decoded from a peer.
It retains the complete independent source packets, parent identity, PV116,
SQL/nonce identity and projection. This is compiler provenance, not controller
possession, a public SQL parser proof or authority to select a database version.

The new PV136 is profile8 + complete parent PV116 + exact SQL/nonce identity8 +
C_enc4. Verification requires the actual canonical Source and Registry200 Lifecycle
proofs before creating the new backend or invoking the witness factory. Old
Return168 and Registry112 producers remain distinct and cannot be relabelled.
No cached receipt, caller Boolean, plaintext query result or fixture output grants
acceptance.

Source680 is opened at rows 1..85; successful Acquire Result144 at 86..103. Capacity
resets between them. Original padding, all source words, source salt, result salt,
the full transaction ID, operation/outcome and twelve returned/skipped/visited
flags remain bound. Sixteen Boolean routing cells preserve compact returned order,
source ordinal, full age8/amount16 and all eight RowId words. The output uses returned
rows; skipped, visited and OFFSET-only held rows do not become returned tuples.
Identical amounts and ages cannot justify a different RowId. Absent tuples are zero.

The shared stateless coefficient kernel retains the original public inverse-SIMD
matrix, bounded integer equations and all 8192 m/W coefficients, including zero SIMD
padding. Three Poseidon2 gadgets retain the complete 8208-field encoded stream and
row 511 endpoint. The new AIR caches its immutable context once; it does not repeat
profile/SHA/matrix hashing inside constraint evaluation. Existing Selected88 and
Return168 profiles, field order, allowlists and mathematical relations are preserved.

The bounded model remains four immutable source records and the existing two-slot
registry. The compiler supports the existing locking SELECT subset and rejects
unsupported windows/projections. It does not implement arbitrary PostgreSQL.

## Executed verification

Release rustfmt, Clippy all targets with `-D warnings`, test and CLI builds passed.
Actual compiler discovery listed **337** tests: 318 previous and
**19** new. Executed **117 leaf tests**:
all new tests and 98 previous controls. Both actual requirements_sync and
architecture contract tests also passed, for **119 passed**.
The other **220 leaf test bodies were not rerun**. Contracts used release rustc and
the actual built serde_json/Cargo metadata, without building the GUI.

The old controls include all 18 Selected88 encoding tests, all 8 Return168 encoding
tests and both certified-return encoding tests, as well as the previous 70 lifecycle,
Journal, bounded-wire and prerequisite controls. New tests exercise exact full
source/parent expectations before factory entry, missing and genuinely wrong Source
proofs, high u64 words, exact SQL/nonce binding, genuine LIMIT0 and all-skipped
success, full originals under projection, equal-value RowId attacks, duplicate and
reordered tuples, visited/skipped substitution, source words and salts, last
coefficient/quotient/slack/carry attacks, fixed padding, unsuccessful/non-Acquire
parents, malformed profiles/roots/lengths/topology, nested allocation budgets and
bidirectional old/new proof relabelling. Full native BFV SIMD comparison checks all
8192 coefficients; previous controls check all twelve public basis columns.

The separate consumer test creates actual owner-signed Bootstrap→Begin→Acquire
Bodies and admits them through the real Journal verifier. It retains independent
owner inputs before proof production, decodes the accepted original proof pair,
matches its original Journal query and C_cmd to freshly compiled SQL, then proves
and freshly decodes the new encoding frame. This establishes locally validated
history, not a confirmed agreed head or a live lock grant. Test accessors are
cfg(test)-only; production Journal admission does not depend on the encoder.

All **33** security invocations passed the individual unique/list target checks.
All 32 previous complete ordered JSON lists exactly match the prior Journal gate.
The new Source and Lifecycle geometry dictionaries match their previous reports
after excluding only statement_case. The new encoding has W4028/PV136,
297 periodic columns, 6407 constraints, degree4 and
Q16; actual individual unique/list bounds are
128/128 bits. These individual
bounds do not establish composed 128-bit soundness.

No manifest, lockfile, dependency graph, requirement or production SQL consumer
changed. The locked offline graph remains 213 packages. The requirements mirror
matches. All 1309 old EXE/DLL artifacts, pinned SDK and tool files remain unchanged.
The author's frozen source bundle remains immutable. Before compilation, a
separately reviewed Root revision removed only two unused imports from the new
test file; test bodies and production code were preserved.
The first native attempt passed version discovery and rustfmt, then strict Clippy
rejected an explicit drop of a non-Drop fixture witness. Its eleven evidence files
and build artifacts remain retained. The successful fresh-target revision uses a
lexical scope so all original fixture/proof objects end before fresh decode; no AIR,
compiler, codec, test body, profile or JSON/timing scope changed. No proof or test
execution from the failed attempt is counted below.

## Actual frame and resource observations

The distinct DCSLFE01 evidence frame contains exactly three canonical SDK proofs.
The 212-byte header pins all three profiles, C_next/C_result/C_enc and exact lengths.
Limits are 20 MiB Source, 12,578,091-byte Lifecycle, 12 MiB encoding and 48 MiB aggregate.
Fixed trusted topologies and bounded canonical decoding precede actual SDK
verification. Separate 24/16/16 Mi element-slot policies are allocation accounting,
not process-memory guarantees. Existing 32 MiB Journal Body and 256 MiB history quotas
are unchanged. The new evidence is separate from Journal Body and is not registered
as a live response on the existing 64 MiB transport.

The normal prove command uses an explicitly public nonsecret conditional
cryptographic fixture. Its actual complete sizes were:

| Component | Bytes |
| --- | ---: |
| Canonical Source proof | 19301919 |
| Registry200 Lifecycle proof | 11581471 |
| Original-row encoding proof | 7191791 |
| Complete three-proof frame | 38075393 |

Original proof objects and witnesses were dropped before fresh canonical decode
and verification. Generation including Source+Lifecycle+encoding+frame took
**9555.0820 ms**; fresh decode and actual three-proof verification took
**2133.7559 ms**. Full owned-process elapsed was
**12065.0946 ms**. These are local experimental cryptographic scopes;
they exclude application/network SQL completion and do not imply accepted history.
The accepted-history consumer is the separate executed test described above.
No fixed latency threshold is part of the active goal.

The new trace/masked-trace/main-LDE arrays are 16,498,688/33,038,336/264,306,688 bytes.
Those are analytical array sizes, not RSS. The owned-PID observer measured 33
numerical, one normal proof/frame and 17 filtered-test processes:
**51 observations/10843 CSV rows**, with
10792 measured intervals. Largest observed OS peak/working set:
**1255538688/1255538688 bytes**;
largest sampled private usage:**1258184704 bytes**.
Nominal sampling was 100 ms; maximum actual interval was
**111.4441 ms**. No sampled 1792 MiB soft fuse or 1200-second
per-process fuse fired. Compiler and contracts were outside this observer.
This does not establish whole-peer RAM, hostile OOM recovery or distributed limits.

Environment: Windows x86_64 MSVC, Rust 1.99.0; AMD Ryzen 9 9950X3D2 16-Core Processor,
16 cores/32 logical processors. Build jobs and Rayon threads were two;
`RUSTFLAGS=-C target-cpu=native`. Cargo used release/locked/offline and a fresh
`.local/target-private-lifecycle-encoding-r2`. From the standalone leaf:

```powershell
cargo run --release --locked --offline -- security registry-lifecycle-encoding
cargo run --release --locked --offline -- prove registry-lifecycle-encoding
```

Security mode is analytical and creates no proof. Prove mode prints the same three
security reports followed by one verified-size/timing report. Focused test filters
use the compiled executable with `--test-threads=1`. Raw local source snapshots,
logs and CSVs remain under `.local/private-lifecycle-encoding-validation-r2`.
Generated proof files, binaries, operational keys and participant data are not
committed. Fixture seeds/values are explicitly public and nonsecret.

Frozen source manifest SHA256:`DEA2690863E287E36C685A7CE934BE614FA00C561B9572EC0C38B79A976BF26D`.
Root executed-source SHA256:`1888A7A4A9662BC41C2829151F86C2C771282EC84CED61CCF9422E17BA6D01E0`.
Closed gate receipt SHA256:`5C173B7296F0554F39D7718FD01197C2BEA77113F7FF4F4DDB631C6D78E8A377`.

## Remaining requirements

This is an encoding commitment, not a formed ciphertext or proof of the complete
FHE query program. Registry200 BFV formation still needs independent owner-key
provenance, full canonical parameter/setup/key components and exact linkage to this
encoding. Peer-only encrypted selection and complete FHE computation/completeness
proofs remain required. Source/encoding proofs do not solve compact encrypted
storage or peer-side transciphering by themselves.

Fresh agreed-head admission, controller authorization, writer fences for every
writer, WAIT wakeups/rechecks/deadlocks, MVCC/isolation, safe history checkpoints,
private opening recovery and decentralized finality remain open. The existing live
storage-client lock rejection is preserved. The complete PostgreSQL goal, including
FOR UPDATE and SKIP LOCKED end to end, remains active.
