# One-open Acquire replay validation

Native release validation on 2026-10-20 covers the private
[Acquire run](../crates/storage-client/src/private_predicate/source/locking/joint/vault/acquire_run.rs).
One exclusive open plans at most five original authenticated records and checks
the exact phase chain before restoring the original candidate once. The strongest
required actual product/application verification still runs during every open.
Different inventory and catalog proof collections are independently verified.
No verification result is persisted or reused across opens.

## Owning coverage

The genuine Compute/input16 rejection test passed in the earlier three-case
native batch `test-public-bfv-fixture-owning-r1` (285.84 seconds in the test body,
312.882 seconds including compilation). It constructs independent authenticated
WALs for thirteen hostile phase/pin chains. The same batch includes the genuine
missing-Kind/isolation Host case and existing Control Begin/End reopen regression.
Its source receipt is `E48093622D57F748102238530AF3FBB3B48686478659FB0655DCA04ECD6A79B3`;
the after receipt is `948265C87CFB529B5730CA33A1F3D14897962E7D2C4D49AB61BC275832085B2C`.

The subsequent ignored recovery case passed with a separately running real FHE
peer, actual input16/output118, END and clean EOF. It verifies lost Body and
Completed sync acknowledgements, original signed bytes/invocation, old-QC and
stale-CAS rejection, one-shot recovered rows, genuine End, a healthy independent
reopen after the FHE child is joined, and rejection after deleting genuine output
record117. The final rejection preserves WAL bytes and poisons the shared ledger.
The QCs in this case are genuine local weighted certificates. This case does not
exercise four-validator network agreement or the Host v3 process scenario.

```text
cargo build --release --offline --locked -p dcs-peer
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::durable::tests::acquire_tests::os_fhe_catalog_body_and_completed_lost_ack_recover_original_invocation_then_end -- --ignored --exact --nocapture --test-threads=1
```

`DCS_PEER_EXE` points to the newly built absolute peer executable. The pinned
native environment uses Rust1.99 MSVC, native CPU code generation, two Cargo jobs
and two Rayon threads. Both commands exited0; the test reports1 passed,0 failed.
Peer build took11.263 seconds; the test command took1532.517 seconds including
36.87 seconds of compilation. Its test body took1495.49 seconds. The original
3600-second multi-operation test budget, 1792-MiB per-PID observer fuse and all
production deadlines were retained.

Package formatting and strict release Clippy (`storage-client`, private input
proofs, all targets, `-D warnings`) also passed. The canonical requirements and
the mirrored AGENTS block were compared and remain identical.

## Measured intervals

These are successive test marker intervals, including computation, checks,
storage and waiting. They are not isolated cryptographic or network costs.

| Interval | Seconds |
| --- | ---: |
| Original Source/BFV/Bootstrap/Begin preparation | 27.161 |
| Original Compute preparation and fsync | 108.262 |
| Actual FHE stream, client input/output verification, retention, END/EOF | 499.048 |
| Independent catalog check and signing metadata | 114.653 |
| Body seal with lost ACK, then full original reopen | 220.710 |
| Old-QC rejection, completion with lost ACK, full reopen and decryption | 272.591 |
| ACK and actual End completion | 13.262 |
| Joined FHE child, healthy full reopen | 118.686 |
| Deleted genuine final-output rejection without WAL repair | 120.987 |

Observed owner peak working set was1520488448 bytes; maximum sampled private
usage was1564471296 bytes. FHE peer peak working set was1196044288 bytes; maximum
sampled private usage was1173393408 bytes. The maximum sampling gap was1251.07ms.
The fuse did not fire. Samples and OS peak counters establish these observations,
not a hard memory guarantee for other queries or the combined network host.

## Reproducibility and scope

The full working source inventory contained1610 files, parent
`c4aeeaabd334dc959a315990f06bf5f2bd7dcf3b` on `codex/feature/sql-latency`.
All inventory and runner hashes matched before and after the two commands.
The inventory also includes separate pending network/Host candidates; their
tests were not selected by this gate. The added public phase markers expose no
keys, SQL text or private bank contents. Local generated evidence is not committed.

| Evidence | SHA-256 |
| --- | --- |
| Frozen source receipt | `F122485F1FA9D1687885F2AA9E059F48D6AC8A8E27B65B961214968E5864D18B` |
| Verified after receipt | `C5D88F73EFBE099842DD7828C1FE6E0A74FB6FF0B034B5538ECA281CFDEBB6EE` |
| Actual peer executable,21415424 bytes | `065CD4E0D8994E5A69AEF201F56D1E403927ECB7B76F873D010D97705E9E81C8` |
| Test stdout | `1C18D75913572FA8AAEC30EAA62ADC0F46306A4E9C739CE71DAA95F0CE8B69DF` |
| Test stderr and phase markers | `C31141C4FF78714F618B5EF8B9AB456A3D7186F308A5C8DB5E1D71B0BF3CDF49` |
| CPU observations | `085A1964A46B14BA75674871428A6DA5F8EF1DD45106FAB719DE503FEDDAFC49` |
| Memory observations | `8E77B691479B797FB6A8F9D70B3BA91381756DA9E7B7747DB3A2E8AE37AAA7EF` |

The earlier interrupted run has no terminal test receipt and is not counted as
a pass. This successful run is a correctness baseline for the reduced replay
path. There is no comparable before/after speedup measurement, interactive SQL
latency claim, current-lease guarantee or new general SQL admission.
