# Stable logical clients and prepaid terminal records

Status: **PASSED owning native release validation**, 2026-10-20. The explicit
[JointSqlHost v3](../crates/storage-client/src/private_predicate/source/locking/joint/vault/host/README.md)
owns the existing concrete owner Vault, quota, History and shared public depot.
Two opaque logical client IDs may share a principal while retaining separate
stable transaction IDs and exact original-call retry associations. Completed
fsync publishes the actual successor bank and client-map change atomically.

The distinct v3 header, file identity and AEAD authenticate the fixed client
bindings. Old v2 APIs, bytes, proof rules and profile remain unchanged; no
automatic migration or fallback is introduced. Three Control/five Acquire
maximum WAL records include prepaid ACK. Reopen reconstructs the remaining
reservation before exposing the owner API. The existing record/file/quota caps
remain in force. The read-only `acquire_draft(call, cursor)` recovery accessor
checks the original client/call association before the underlying phase and CAS;
it supplies original signing metadata, never a proof-acceptance token.

## Source and executable

The frozen native batch started from
`ecd8af3c4b9a88f22c459c8b983b2e8b5e9a1b36` on
`codex/feature/sql-latency`, with sixteen task paths changed. All 1,594 inventoried
source files stayed unchanged throughout the batch:

- Source receipt SHA-256:
  `34659DC32F895DDC324F12B0BFD35C3A61CAB07A68A4BFA483E692A488004AEB`.
- Verified after receipt SHA-256:
  `CF1AE1E76B18A723380C04DD2A043C3AA05631CB24E9CC66C0E57A287D15F38F`.
- Actual `dcs-peer.exe`: 21,412,864 bytes, SHA-256
  `E415F3F0181C6126BEDCC0A2E03423D466106BB4D18DEEEE3F342E874669801C`.

The executable was rebuilt after the earlier Ready-restore refactor and pinned
before the OS gate. Its bytes were checked unchanged afterward. Publication
changes after this batch are documentation only. Local immutable receipts and
raw logs remain outside Git; no original private records are published.

Windows/MSVC Rust 1.99.0 used release/offline/locked builds,
`RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two Rayon threads. The proof
backend reported AVX-512. The observer used a 1,792-MiB individual process fuse
and bounded whole-command deadlines; no fuse fired. Inherited chunk/packed I/O
experiment flags are not read by these owning cases.

## Executed gates

| Gate | Result | Whole command seconds |
| --- | --- | ---: |
| Full durable owning suite | 13 passed, 1 explicitly ignored OS case | 1,002.237 |
| Existing six-process v2 Control recovery | 1 passed | 87.207 |
| Finality and client documentation contracts | 15 + 27 passed | 10.000 |
| Strict eight-package Clippy, all targets | passed | 2.471 |
| Default core-only check | passed | 0.457 |
| Actual peer release build | passed | 33.267 |

The owning suite includes five new Host cases, one fixed client grammar case and
seven existing v2 Control/Acquire cases. The test itself reported 951.20 seconds;
the whole command includes compilation. Maximum observed individual test-process
OS peak was 1,538,641,920 bytes, private bytes 1,585,360,896, with a maximum memory
sampling gap of 524.691 ms. The six-process gate peaked at 958,885,888 OS bytes
with a 382.648-ms gap. These observations are not a general allocator cap,
whole-network memory sum, ordinary-query latency or a before/after speedup.

The first strict compile attempt found unused intermediate reexports and a
redundant error-return block. That failed source and its logs are retained in a
separate receipt. The final source routes the same Host exports through their
existing parent and uses equivalent `?` propagation. It adds no lint suppression
or proof/profile/cap change. Independent immutable before/after review confirmed
the exported-name multiset and error/publication ordering.

## Observable coverage

The genuine owning cases verify two clients with one principal, stable IDs after
End compaction, exact and altered intent retries, stale cursors and older QCs,
missing Kind rejection, resource/record refusal before work, wrong wrapping key,
lost Body/Completed/ACK fsync acknowledgements and retained terminal capacity.
Completion and ACK succeed while other reservation slots are occupied. The
packet-limit case never reopens its deliberately repeated Idle packets as a
valid history.

The actual input16 Compute case reserves five maximum records before native
preparation, restores the original invocation, encrypted request and all Key33,
and rejects foreign client/intent, stale CAS and pre-catalog draft access without
changing cursor, WAL extent or accounted usage. It does not produce output118 or
complete a v3 Acquire. Local owning QCs are genuine mathematical fixture
certificates, not four-validator network observations.

The separate six-process regression uses four actual validators and sequential
owner A/B processes. It exercises the unchanged v2 Control path, not Host v3
network completion. The ignored genuine OS/FHE test also retains its separate v2
scope. These passes must not be relabeled as the new two-client v3 network gate.

## Reproduction

Run sequentially with the environment above and locked dependencies available:

```powershell
cargo clippy --release --offline --locked -p bfv-key-transform -p bfv-query-core -p bfv-product-evidence -p registry200-joint -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::durable:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-finality -p storage-client --features private-input-proofs --doc
cargo check --release --offline --locked
cargo build --release --offline --locked -p dcs-peer
$env:DCS_PEER_EXE = 'C:/absolute/path/to/dcs-peer.exe'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::six_os_processes_restore_original_owner_epoch_and_complete_only_the_saved_control_intent -- --ignored --exact --nocapture --test-threads=1
```

## Remaining contract

Full v3 output118, genuine four-validator Acquire completion, positive
catalog-fsynced/pre-Body recovery and the five-record Acquire ACK path still need
the separate two-client OS gate. Its source review alone supplies no runtime
credit. Original authenticated material and exact caller SQL/client/sequence
custody remain necessary. The fixed logical bindings are not a network client
authentication or delegated-rights protocol.

Replies are historical original invocations, not current leases. Generic public
SQL/Session admission, WAIT/NOWAIT/deadlock and mutable-data semantics, new readonly
freshness barriers, live permissionless roster activation, whole-Vault rollback
resistance, compaction and ordinary-query performance remain unfinished. Existing
fail-closed guards, Windows durability and native scratch-erasure qualifications
remain unchanged.
