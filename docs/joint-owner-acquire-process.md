# Durable Acquire across owner processes and four validators

Status: **PASSED native release validation**, 2026-10-20. Seven distinct child
processes exercised an original encrypted Acquire, owner replacement, exact
submission retry, genuine four-validator QCs, historical private completion,
new End and full final reopen. The owning contract is
[ACQUIRE-PROCESS.md](../crates/storage-client/src/private_predicate/source/locking/joint/vault/ACQUIRE-PROCESS.md).

## Source and executable

The native batch started from `f30f9e8b47b6bc8ccf7899eba43e74cdd11f1fec` on
`codex/feature/sql-latency`, with seven additive test/support/documentation paths
changed. Its complete 1,588-file inventory stayed unchanged through both OS
gates:

- Source receipt SHA-256:
  `C694D7F11CE6F2101E1457E1519D1EF3C38AA756FF88B2CDBFA7385C963F72A9`.
- Verified after receipt SHA-256:
  `B627110AD01DB6926ED00819FBDBB50AB28A9E890BA29ED8E253B7E420AB364F`.
- Actual `dcs-peer.exe`: 21,412,352 bytes, SHA-256
  `A40F915DD525E5F6CAFACE66D2772D685B0F351D26608E28BA1C97C28AA4EB8A`.

The peer was built before the OS gates and its bytes were checked again after
both. No application integration-test build replaced the executable. Publication
changes after the frozen batch are documentation only. Local immutable receipts,
memory samples and raw logs remain outside Git; no private records are published.

Windows/MSVC Rust 1.99.0 used release/offline/locked builds,
`RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two Rayon threads. The proof
backend reported AVX-512. The observer imposed a 3,600-second whole-command fuse
and a 1,792-MiB individual process memory fuse. Neither fired. Inherited chunk and
packed I/O experiment flags are not read by these owning tests. Measurements
describe this fixed schema, hardware and fixture only.

## Executed gates

| Gate | Result | Whole command seconds | Maximum OS process peak bytes |
| --- | --- | ---: | ---: |
| Seven-process durable Acquire restart | 1 passed | 2,074.306 | 1,516,175,360 |
| Existing six-process Control restart | 1 passed | 103.940 | 962,822,144 |
| Strict six-package Clippy, all targets | passed | 2.501 | see local receipt |
| Actual peer release build | passed | 0.470 | see local receipt |
| Default core check | passed | 0.488 | 62,406,656 |
| Requirements mirror test | 1 passed | 51.955 | 102,244,352 |
| Workspace format check | passed | 1.870 | 11,071,488 |

The seven-process test itself reported 2,073.89 seconds. Its 63,207 memory samples
had a maximum gap of 507.358 ms. The maximum individual process private bytes were
1,480,007,680. Peaks are not a sum across participants or a process allocator cap.
This test includes original material construction, multiple proof verifications
and full WAL replays. It does not measure the latency of an ordinary SQL query.

The source extends the existing bounded launcher with a separate exact 160-byte
Acquire authority frame. The old Control entry remains 128 bytes. Both reject an
incorrect length before spawning; malformed Control input therefore fails
earlier than the worker's existing check. No valid old protocol, timeout, proof
rule, production process entry point or SQL admission guard changed.

## Observed behavior

Four actual validator processes certified Bootstrap and Begin. Owner A synced
the original ComputePrepared record, sent its input16 to a separate actual FHE
peer, required output118 followed by END and clean EOF, replayed the resulting
catalog and synced the exact signed Body. It received four real submission ACKs
and exited before asking for the Acquire QC or completing the result. The
supervisor joined A and its output reader, and terminated/joined the FHE peer,
before starting owner B.

B received only original independently authenticated custody and external
authorities. Its strict Acquire-aware reopen replayed the log from the external
Bootstrap prefix, checked the separate Begin QC and repeated the exact saved
Acquire as its first network action. No pending Rust object, secret key object,
new encryption, fresh nonce or proof generation for that invocation crossed the
owner-process boundary. B obtained four real Acquire QCs, rejected an older
genuine QC, replayed the original mathematics and private completion, and synced
generation two before returning the original historical rows. Repeated
completion could not advance the bank.

A new End then obtained four actual QCs and synced generation three. After
acknowledgement and dropping the existing opener, a fresh exclusive quota/Vault
open replayed the completed log, restored Idle and matched the exact final cursor
and End head. The owner custody, WAL and depot shared the owner's actual quota
ledger. No local QC assembler or test acceptance flag supplied a network answer.

Seven distinct child PIDs were required: four validators, one FHE peer and two
sequential owners. Cargo and the test supervisor were also observed, giving nine
cumulative PIDs in the memory receipt. The shared supervisor joins and cleans up
children before reporting its final result. Log hashes are:

- Seven-process stdout:
  `AAD643F0CCA55B1D4C5BB9721CEE6B27191FF705CC49554890AEBFEEF7DF1C2F`.
- Seven-process stderr:
  `BA7ECA70C65D2ED636CD445A922DA07485FED9DB1E54BCD82047E4DF0F1E3140`.
- Existing Control stdout:
  `7B522ED27CBF6337061E6A5896B79AD863313C1FBF54564BDCF8F9F9A806DBA0`.

## Reproduction

Run sequentially with the environment above and the locked dependencies already
available. A missing peer executable is a hard failure.

```powershell
cargo clippy --release --offline --locked -p bfv-product-evidence -p registry200-joint -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo build --release --offline --locked -p dcs-peer
$env:DCS_PEER_EXE = 'C:/absolute/path/to/dcs-peer.exe'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::six_os_processes_restore_original_owner_epoch_and_complete_only_the_saved_control_intent -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::acquire::seven_os_processes_recover_original_durable_acquire_then_finalize_end -- --ignored --exact --nocapture --test-threads=1
cargo check --release --offline --locked
cargo test --release --offline --locked -p fhe-playground --test requirements_sync
cargo fmt --all -- --check
```

## Remaining contract

The submission outcome was lost after healthy Body fsync and ACKs. This test does
not inject a lost fsync acknowledgement; the earlier
[local-QC fault gate](joint-owner-acquire-vault.md) covers that separate case.
Recovery returns the historical original invocation, not a new query or current
lease. Independent original material custody remains required. Whole-Vault
anti-rollback, portable power-loss durability, native SDK scratch erasure and
physically once decryption across crashes remain unestablished.

This fixed-roster, fixed-schema gate does not enable generic Session SQL or
implement mutable data COMMIT, stable durable client mapping, PostgreSQL WAIT,
NOWAIT, permissionless roster activation or compaction. Those are still separate
work. The requirements and fail-closed public SQL guards remain in force.
