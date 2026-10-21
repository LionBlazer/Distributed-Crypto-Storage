# Dense DATA private proof validation

Executed on 2026-10-21 using Rust 1.99/MSVC, release optimization, target-cpu=native,
two Cargo jobs and the unchanged Gold/EF5/Q192/blowup3/salt4/random5 suite.
This is a test-private complete Formation proof, with no production SQL grant.

## Actual boundary

The H2048 writer consumes the same guarded original equation derivation once.
It writes all 81,920 graph gates, 4096 complete range groups and 580 full hashes.
The FullAir wrapper delegates the exact existing equations and only adds its
private complete-PP factory. Pre-writer goldens pin the 571,450-byte ordered native
relation and every PP cell. Both original Pair/Data full regressions still pass.

The original SDK DATA fixture supplies one independently generated encryption
and two guarded preparations. One honest proof is cold verified, then reused for
foreign-Expected/header, OOD, canonical-field, EOF, frontier and resource attacks.
A second genuine false-wire proof preserves every local equation and final
product but must fail native Lookup(TerminalSumNonZero). Replacing only that
terminal with zero must fail actual native opening/OOD verification. Receiving
never accepts a panic or metadata result as the expected cryptographic rejection.
Inactive slots, range-only cells, unused bits, padding and first hash checkpoints
are checked directly against the actual complete MAIN.

Strict all-target Clippy passed. Two original literal tests and all six dense
tests passed on the same release executable. The new six-test gate finished in
4.28 s on two Rayon threads; it includes both genuine proofs and hostile checks.
Held-process lifetime was 4293.1329 ms, CPU time 7.453125 s, peak sampled private
bytes 518,791,168 and OS-peak working set 527,319,040. The same 120 s / 1792 MiB
fuses, 20 ms sampling, source/image pins and terminal-zero/no-child checks applied.
No observation hit a fuse or required forced cleanup.

## One paired sixteen-thread observation

The original and dense owning proof tests ran sequentially, original first, on
the same executable and source with RAYON_NUM_THREADS=16. Each used the same
public fixture algorithm with fresh keys and proof randomness. Background load
was uncontrolled; this is one observation, not a latency bound or identical-byte
comparison. Production thread policy remains unchanged.

| Phase | Original H8192 | Dense H2048 |
| --- | ---: | ---: |
| Public PP within production | 140.790 ms | 81.634 ms |
| Full private MAIN | 10.860 ms | 9.483 ms |
| Native proving | 859.608 ms | 249.428 ms |
| Complete local production | 1053.305 ms | 381.213 ms |
| Cold receiving PP | 138.080 ms | 78.135 ms |
| Native receiving verification | 67.967 ms | 78.705 ms |
| Complete independent cold receiving | 239.861 ms | 189.762 ms |
| Production plus cold receiving | 1293.166 ms | 570.975 ms |
| Frame bytes | 2,523,539 | 3,281,813 |
| Peak sampled private bytes | 1,346,682,880 | 521,760,768 |
| OS-peak working set bytes | 1,350,975,488 | 528,392,192 |

The dense proof is larger and its native verification was slightly slower in
this pair. The gains came from production and preprocessing. Frame size and
network transport must remain part of future complete-query measurements.
The whole test processes lived 2939.7581 and 1399.8415 ms respectively; their
additional hostile proofs and checks are outside the honest phase timers.

The two-thread dense gate separately measured 1307.454 ms for complete production
and 480.884 ms for cold receiving, with a 3,281,269-byte randomized frame. Its
native proving, production PP and cold PP phases were 910.709, 344.603 and
374.336 ms respectively. These are separate workload observations, not a paired
thread-scaling guarantee.

Executable: 5,787,136 bytes, SHA256
`9BA0AAF25D2C818A0D54523E921137D8F5D069FA3216A52875E68C896072313E`.
The exact executed 119-file source archive is 1,723,388 bytes, aggregate SHA256
`BF77C62AA0CDA02413073AA5D81E0794DD5F7042A15EE890305D208A669EFEC2`.
It retains the complete author packet plus the controlled formatting, SDK/lint
corrections and a private workspace getter. That getter exposes only the existing
computed estimate; checked addition enforces the extra 16 MiB reserve before PP
or MAIN. Original assessment formulas, security gates and all AIR equations remain
unchanged. Detailed receipts stay in ignored local artifacts.

## Remaining scope

This probe returns no accepting DATA/Query token. It does not establish a genuine
WordStmt96/query-mask/QueryCt join, installed Source/DATA authority, lattice/noise
security, current agreed head, SQL/locking finality, WAL recovery or peer-process
operation. The 570.975 ms local component already exceeds 500 ms and excludes
FHE query execution, other query proofs and network agreement. No complete-query
speedup, production memory bound or system-security claim follows from this gate.
Module ownership, fixed limits and focused commands are in the
[inventory README](program/dense_data_inventory/README.md).

## Explicit mathematical facade

The fixed backend is now available through `gold::data::prove_dense` and
`verify_dense`, with a separate digest and 4 MiB frame cap. It consumes the same
guarded Prepared and independently retained Expected. Actual cold native
verification alone creates the existing move-only mathematical result; this
does not install a DATA/key, authorize SQL or establish composed security.
The original H8192 functions/profiles are unchanged, and the frame families
reject each other. Fixture factories and attack helpers remain test-only.

The final six-test native gate passed in 4.33 s, two complete original Pair/DATA
symbolic/PP regressions in 0.06 s, and strict all-target release Clippy passed for
this library and its consuming registry library. Four compile-fail ownership
checks passed. The dense ordered constraints, complete PP and semantic goldens
are unchanged. Public-facade honest receiving and genuine false-wire/terminal
repair failures run the same native backend. No security or resource gate was
relaxed; normal builds now also check the complete inventory summary.

The consuming [QueryCt join validation](../../../registry200-proof/src/registry_progress/word_inventory/query_mask_inventory/VALIDATION.md#dense-queryct-proof-selection-and-paired-observations)
records a paired comparison on the same original ciphertexts, including both
mask and Formation proofs. At16 threads the dense joined component took774.275ms
against1414.933ms for the old backend in that pair. It still exceeds500ms before
SQL, result proofs and network/finality. The whole proof is larger, and neither
that component improvement nor the standalone lower memory observation proves
the full-query target or a composed peer resource bound.
