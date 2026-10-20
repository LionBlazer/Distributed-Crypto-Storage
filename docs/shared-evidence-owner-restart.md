# Shared evidence ownership and owner process recovery

Native release validation passed on 2026-10-20. One concrete shared public depot
now serves product recording, ingress and the fixed Joint verifier. A separate
owning gate restores the original private owner in a new OS process and completes
its saved historical Control operation through four actual validators.

## Implementation boundaries

`ProductStore::into_shared` transfers the already-open store and its typed ledger
into `SharedProductStore`. Clones open no second directory or budget. The existing
exclusive recorder and the new shared recorder use one closed verifier/replay
implementation. Only bounded local blob read/hash/EOF or publication holds the
private mutex. SDK proof work, network waits, cancellation checks and transport
END/EOF run outside it. Original setup hashing remains streamed before SDK use.
Public bytes and catalogs carry no verification, freshness or SQL authority.

`JointEvidenceIngress::recording_store` clones this same owner before the depot
moves into History. `ProofGate::new` lets an actual standalone composition own
one native resource gate and pass clones to all heavy consumers. Constructing
another gate does not enforce a process-global singleton. A permit conveys no
proof validity, authorization, agreed head or lock grant.

The process recovery gate uses bounded private stdin for external wrapping and
database-signing authorities. A retains authenticated original Source, Owner,
anchor and Ready backups, plus independently pinned public setup, complete Key33,
exact Key proof and Source material. Its custody files count against the same
quota. It fsyncs the signed Begin before submission and exits before private
completion. After A and its reader join, B restores those originals, verifies the
actual saved request/QC/private openings, completes Begin and End, then strictly
reopens the WAL and quota. All six child PIDs are distinct and joined.

The reusable supervisor is test-only. Old peer startup/Ready/TLS/deadlines and
the old Acquire test body remain unchanged. Its single module is reused at the
owning client boundary. The [process contract](../crates/storage-client/src/private_predicate/source/locking/joint/vault/PROCESS-RESTART.md)
describes custody, exact retry and failure boundaries.

## Executed checks

Commands ran serially with locked offline dependencies, Rust 1.99/MSVC,
`RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two Rayon threads. The actual
proof backend reported AVX512. Whole-command times include compilation.

| Check | Result | Whole command |
| --- | --- | ---: |
| Evidence-store and Joint owning libraries | 12 + 8 passed | 35.591 s |
| Resource gate clone/busy/unwind | 1 passed | 15.916 s |
| Public API documentation contracts | 8 passed | 9.446 s |
| Strict six-package all-target Clippy | Passed | 1.826 s |
| Default Core build / workspace formatting | Passed | 2.273 / 1.688 s |
| Shared recorder on actual OS FHE peer | 1 passed | 544.161 s |
| Unchanged four-validator/FHE Acquire regression | 1 passed | 1393.126 s |
| Four validators plus sequential owner A/B recovery | 1 passed | 103.208 s |

The shared product case checks all 16 input proofs and 118 output records through
actual END and clean EOF. After original private owners/producers drop and the
peer stops, fresh keyless replay checks the retained originals again. Repaired
Encoding-child and record splices, missing/corrupt/trailing references and foreign
pins reject. The four-validator regression separately verifies actual QCs, fresh
full mathematics, exact own completion, committed projection/window flags and
hostile evidence. Its result still explicitly grants no general SQL capability
or persistent current lease.

For the shared N4 case, preparation took 77.223 s and stream/full verification
363.051 s; the reported preparation-to-completion interval was 443.821 s. Fresh
retained replay took 43.686 s. It sent 265,090,453 and received 253,993,062
application bytes. Retained logical public evidence before corruption was
508,719,425 bytes. These observations establish neither interactive speed nor
general database storage fit, and are not a controlled speed comparison.

| Process scenario | Largest OS peak working set of one PID | Largest sampled private bytes | Largest sampling gap |
| --- | ---: | ---: | ---: |
| Shared product/replay | 1,453,379,584 B | 1,481,207,808 B | 426.899 ms |
| Four validators/FHE Acquire | 1,496,178,688 B | 1,441,398,784 B | 541.663 ms |
| Owner A/B and four validators | 958,255,104 B | 952,709,120 B | 382.523 ms |

The Windows observer used a 1792-MiB-per-PID soft fuse; no run crossed it.
Sampling, OS peak working set and private bytes describe different observations.
They do not establish a hard limit for every process or larger workload. The
multiphase process harness allows 3600 seconds; production 180-second I/O and
1800-second operation bounds, protocol byte caps and consensus rules are unchanged.

The first Cold run failed on a legitimate transient `WouldBlock` fetching a
candidate after QC retrieval. Only that test fetch gained the existing bounded
retry; other errors and exact QC/context/byte checks remain hard requirements.
Earlier compile-only attempts found test imports/module duplication and lint
issues; the final strict build passed. The new duplicate-ingress fixture accounts
for the full temporary file even when its content already exists.

## Reproduction and image provenance

```sh
cargo build --release --offline --locked -p dcs-peer
cargo test --release --offline --locked -p bfv-product-evidence -p registry200-joint --lib -- --test-threads=1
cargo test --release --offline --locked -p peer-runtime --lib proof_gate::tests:: -- --test-threads=1
cargo test --release --offline --locked -p bfv-product-evidence -p registry200-joint -p peer-runtime --doc -- --test-threads=1
cargo clippy --release --offline --locked -p bfv-product-evidence -p registry200-joint -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
cargo test --release --offline --locked -p dcs-peer --test private_product private_product_success::shared_retained_product_replays_after_private_owners_drop_and_rejects_repaired_splices -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::tests::full_acquire::four_os_quorum_and_fhe_peer_complete_only_the_exact_own_joint_acquire_after_fresh_replay -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::process_tests::six_os_processes_restore_original_owner_epoch_and_complete_only_the_saved_control_intent -- --ignored --exact --nocapture --test-threads=1
```

The last two commands require `DCS_PEER_EXE` to name the absolute built peer path.
Cargo rebuilt the peer while compiling the owning product test. Its executed
image was 21,412,352 bytes, SHA256
`C959ECF5B6CAE267568CDF1FF6C22DBAA03E9CB286C6B4A49375117A728C23A3`.
It differs from the earlier standalone build; that original record is preserved.
The executed image pin was corrected after that rebuild and checked before and
after the final Cold run. The two later client-library test commands did not
rebuild the peer executable.

The frozen runtime/test source inventory contained 1,575 files. R3 source SHA256
was `161D1C91943B59CC206920A2B748B0D40AF975F8420E17486AF183B8A5EFA56A`;
R4 was `D3316D722F8101C8351A38B3B0B862C8BD6F20C650EF46136CC0770AFC208695`.
Their sole delta is the Cold test's bounded candidate fetch. Source, unchanged
runners, result/stdout/stderr hashes and the executed image were rechecked before
publication documentation changed. Requirements and their mirror remain equal.

## Remaining work

This stage establishes shared storage ownership and historical Control recovery.
B restores Ready but performs no new FHE evaluation after that restoration.
Durable Acquire continuation, recovered client/transaction mapping, ordinary
Session/SQL admission, WAIT/NOWAIT driving, encrypted data COMMIT and permissionless
roster activation remain separate work. The existing SQL guards stay closed.
External recovery authorities and original public/private records remain required;
the same-machine process scenario establishes no power-loss or anti-rollback
theorem, universal RAM bound or full PostgreSQL compatibility.
