# Durable historical Acquire validation

Status: **PASSED native release validation**, 2026-10-20. OwnerVault v2 now
persists one original Acquire through ComputePrepared, recorded public catalog,
exact signed Body, private completion and historical result recovery. It shares
the existing quota, authenticated WAL, generation CAS, History and public depot
with Control. The contracts are in the
[Vault module](../crates/storage-client/src/private_predicate/source/locking/joint/vault/README.md)
and [Acquire grammar](../crates/storage-client/src/private_predicate/source/locking/joint/vault/DURABLE-ACQUIRE.md).

## Source and executable identity

The batch started from `60113d7236af3e80615b44f6a70666f829fcc55a` on
`codex/feature/sql-latency`, with eighteen task paths changed. Its complete
1,581-file source inventory stayed unchanged throughout the native batch:

- Source receipt SHA-256:
  `44AA42566DC9D2CBF278535724ADB56A940A82C2F3B4BA598967CB62C179D82A`.
- Verified after receipt SHA-256:
  `E885E6961AAB6CC8D4867025A26ECB8360E5AFA348A9A51EE6C4E4D5857852BC`.
- Actual `dcs-peer.exe`: 21,412,352 bytes, SHA-256
  `A40F915DD525E5F6CAFACE66D2772D685B0F351D26608E28BA1C97C28AA4EB8A`.

The peer was built from this source before either OS gate and checked unchanged
after both. These were storage-client library tests; no app integration-test
build replaced the pinned executable. The local immutable receipts and raw logs
are retained outside Git; generated outputs and original private records are not
published. Publication changes after the batch are documentation only.

Windows/MSVC Rust 1.99.0 used release/offline/locked builds,
`RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two Rayon threads. The proof
backend reported AVX-512. Existing chunk/packed I/O experiment environment flags
were inherited; those flags gate unrelated explicitly named I/O tests and are
not used by these owning cases. The observer sampled individual process memory
with a 1,792-MiB safety fuse. This is an observation, not a process-wide allocator
cap or a guarantee for other hardware, inputs or schemas.

## Executed gates

| Gate | Result | Whole command seconds | Maximum OS process peak bytes |
| --- | --- | ---: | ---: |
| Two ordinary Acquire recovery/quota cases | 2 passed, OS case ignored | 469.419 | 1,528,684,544 |
| Existing Control owning cases | 5 passed | 142.592 | 1,069,453,312 |
| Genuine OS FHE with local-QC recovery faults | 1 passed | 1,230.119 | 1,520,852,992 |
| Existing six-process Control restart on v2 | 1 passed | 88.608 | 973,799,424 |
| Finality and client documentation contracts | 15 + 27 passed | 9.539 | 79,659,008 |
| Strict six-package Clippy, all targets | passed | 2.388 | 10,895,360 |
| Default core check | passed | 2.042 | 80,105,472 |
| Actual peer release build | passed | 10.113 | 77,647,872 |
| Workspace format check before publication | passed | 1.840 | 11,063,296 |

No memory/time fuse fired. The longest OS gate recorded a maximum sampling gap
of 504.527 ms; the ordinary cases recorded 428.634 ms. The table reports the
largest peak of one observed process, not a sum across validators. The FHE case
took 1,229.63 seconds inside the test; it includes original fixture construction,
actual evaluation and repeated full restore/proof checks for injected failures.
It is not an ordinary SQL-query latency measurement.

One initial Control-regression invocation omitted Cargo's `--` separator before
the libtest `--skip` option and failed argument parsing in 0.237 seconds. It ran
no test. The corrected command below passed; the original failed invocation is
retained in the after receipt. Earlier compile/lint attempts retain their own
source receipts and are not counted as passing this batch.

The ordinary cases exercise original Source/Owner/Anchor/Ready/capsule recovery,
the exact invocation/request/Key33, missing Formation and unproved catalog
rejection, wrong original material, terminal quota reservation, lost Compute
fsync acknowledgement and reconstruction of the remaining quota on reopen.
Existing Control assertions retain their coverage of real proof/QC/private bank,
exact retry, generation CAS, torn I/O, lost acknowledgements, a foreign bank and
an unsaved genuine successor.

The FHE evaluator is an independent OS peer. Its real input16/output118 stream
must finish through END and clean EOF in the same shared store before a catalog
is accepted. Body and Completed fsync acknowledgements are then lost deliberately.
Fresh Vault open restores the exact saved signed Body and original private
pending, rejects an older QC, replays all mathematics and accepts the genuine
local weighted QC. Recovered rows belong to the original invocation; generation
two and its bank must already be durable. A repeated completion fails CAS. A
real new typed End closes that actual acquired bank at generation three.

That case reopens Vault objects within the test process. Its QC is assembled by
the genuine local fixture, not by four network validators. The separate Cold
Control regression uses four actual validators and sequential owner A/B PIDs,
but performs no FHE Acquire after restart. These passing gates do not establish
their combined durable Acquire/owner-process/four-validator scenario. The older
[full network Acquire gate](joint-owner-lifecycle.md) retains its separate source
and evidence scope.

## Reproduction commands

Run the native commands sequentially with the environment above. Set
`DCS_PEER_EXE` to the absolute executable from the preceding release build;
missing binary is a hard failure. Offline reproduction needs the locked
dependencies already present.

```powershell
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::durable::tests::acquire_tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::durable::tests:: -- --skip acquire_tests:: --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-finality -p storage-client --features private-input-proofs --doc
cargo check --release --offline --locked
cargo build --release --offline --locked -p dcs-peer
```

With that actual peer image pinned:

```powershell
$env:DCS_PEER_EXE = 'C:/absolute/path/to/dcs-peer.exe'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::durable::tests::acquire_tests::os_fhe_catalog_body_and_completed_lost_ack_recover_original_invocation_then_end -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::six_os_processes_restore_original_owner_epoch_and_complete_only_the_saved_control_intent -- --ignored --exact --nocapture --test-threads=1
```

The strict package check was:

```powershell
cargo clippy --release --offline --locked -p bfv-product-evidence -p registry200-joint -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Remaining contract

The v2 storage profile explicitly rejects v1; there is no migration, fallback
recreation or old-bank repair. Original independently authenticated material and
the original public prefix remain mandatory. Restored results are historical
original-invocation delivery, not new queries or current leases. No persistent
verified bit replaces proofs. Windows directory durability, whole-Vault rollback,
SDK scratch erasure and physically once decryption across crashes remain outside
these guarantees.

General SQL/Session admission, stable durable client-to-transaction mapping,
PostgreSQL WAIT/NOWAIT behavior, mutable data COMMIT, readonly freshness barriers,
permissionless live roster activation, compaction and ordinary-query performance
remain unfinished. This validation does not change the requirements or open the
existing fail-closed public SQL guards.
