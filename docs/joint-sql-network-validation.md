# Fixed-record network SQL driver validation

The seven-child-process Host gate passed on 2026-10-20. Its first Acquire used
the production `JointSqlNetworkHost::execute` from Idle through real encrypted
computation, independently checked weighted QC, private completion and prepaid
ACK. The subsequent second call used the same owned Host and its original
acquire-aware recovery APIs. This does not validate production `resume_original`
on every failure path or enable generic Session/Database/GUI SQL execution.

## Reproduce the owning gate

Build the matching `dcs-peer` image, set `DCS_PEER_EXE` to its absolute path, then
run from the repository root:

```powershell
cargo build --release --offline --locked -p dcs-peer
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::host::seven_os_host_clients_skip_locked_recover_exact_second_call_and_prepaid_ack -- --ignored --exact --nocapture --test-threads=1
```

The measured build used Rust 1.99 MSVC, host-native code generation, two Cargo
jobs and `RAYON_NUM_THREADS=2`. The already enabled Rayon proof paths were not
serial substitutes. The matching peer image was 21415424 bytes with SHA-256
`4FD50FC1FB2F2CF9D7AE1DD5F719B9F3DDC4B815B78AA1D38DF4F1F06383933C`.

The test body passed 1/0 in 3344.39 seconds; the whole monitored test command took
3345.196 seconds. The preceding actual peer build passed in 25.848 seconds. All
1612 source files, the complete source inventory, runner images and peer image
were unchanged across the batch. The source receipt SHA-256 was
`A111D4BB49432A017207A04E8FC1FFE9203859870936A48243CD3B699E0A2CE6`;
the after receipt was
`087A6687AB7227FDC828CA588AC47D543E27E99BC3008FDDA751A89635513C3F`.
Only documentation was updated after these checks.

| Retained observation | SHA-256 |
| --- | --- |
| stdout | `06E90DE92B4258CA57D68E87C674FADD07BC4F77A4484091231D105268A520C8` |
| stderr | `C797A03B8A4E0B59D8EDB7B70EC4437FA0155D6216F3D47BD7BB65B12DF76CC6` |
| CPU samples | `42C464786155E3A8798FD19E3B5E7AB1660A2A188F8FA2188ED726BF52EA12A3` |
| Memory samples | `F5A6662C1ED453C99DBE2850DA656D9D4E04A8CEBF125278AD7EDBC4B97A8CEA` |

## Observable behavior

Four independent validator processes, one FHE process and sequential owner A/B
processes participated. Two logical clients had distinct stable transaction IDs
under the same principal. Genuine Bootstrap/Begin and every final decision were
checked against actual network QCs; no held-row fixture or locally made QC
substituted for these operations.

The first encrypted locking SELECT returned ordinal 0 through actual private
completion. It retained that lock while the second invocation ran. The second
hidden predicate with OFFSET 1/LIMIT 1/SKIP LOCKED skipped that conflict before
counting OFFSET, locked the subsequently consumed matching row and returned no
rows. Both complete FHE streams verified input16, output118, END and clean EOF.
The second invocation/request differed from the first; no third FHE computation
was used for recovery.

After second-catalog fsync, a full local drop/reopen recovered the exact original
draft. Owner A then retained the signed second Body and obtained four submission
ACKs, but exited before second-QC observation/private completion. Owner B opened
the original backups, genuinely replayed the WAL and first retried that exact
saved Body over the network. All four actual QCs and signed Bodies were checked.
The genuine first-operation QC was rejected for the second invocation with an
exact Context error and unchanged cursor. Actual completion recovered the
original empty result and consumed the prepaid ACK. End(A,commit) and
End(B,rollback), stable-ID compaction, final strict reopen and historical reply
checks passed. These End operations finalize lock lifecycle; they are not SQL
data-mutation COMMIT.

Quota refusal before preparation, no-free-reservation-slot ACK, stale cursor,
foreign client, altered original SQL and finite IPC grammar assertions remained
enabled. Public fixture rows served only as initial ingest and expected-value
assertions. No owner-side fixture evaluator supplied an execution result.

## Measured intervals

| Complete observed interval | Seconds |
| --- | ---: |
| First production `execute` | 1277.232 |
| Second FHE stream after Compute fsync | 411.734 |
| Second catalog retention plus local full reopen | 256.073 |
| Owner B strict initial reopen | 233.524 |
| Owner B original retry to four submission ACKs | 232.008 |
| Subsequent four-QC/Body observations | 113.006 |
| Old-QC rejection, second completion and prepaid ACK | 98.195 |
| End A/B through four QCs | 130.043 |
| Final strict reopen | 218.165 |

Intervals include overlapping native computation, verification, storage, RPC and
waiting; none is a measurement of transmission or cryptography alone. Not all
setup/mining/upload intervals appear in the table. This run differs from earlier
manual and local-QC scenarios, so these numbers establish no comparable speedup.
The first call remains far from interactive speed.

Across 94639 samples, maximum working set was 1484943360 bytes, maximum private
usage 1534955520 bytes and OS peak working set 1556393984 bytes. The FHE process's
OS peak was 1206308864 bytes; Owner B's was 1134006272 bytes. Maximum observed
sampling gap was 673.387 ms. The original 1792-MiB-per-PID soft fuse did not fire.
These per-process observations are not a formal peak-memory bound or a complete
DCS resource guarantee. The 10800-second whole-test fuse and production 180/1800-
second transport/operation budgets were unchanged.

## Remaining boundary

The fixed application supports its bounded immutable Source and authenticated
activated roster. Permissionless weight activation, application provisioning,
production SQL-client authentication, current lease/rollback protection,
mutable-source MVCC/EvalPlanQual, general WAIT/NOWAIT/savepoints/deadlocks,
indexes and full PostgreSQL execution remain incomplete. The next optimization
candidates and a four-thread experiment are source/preparation only; this native
record does not validate them.
