# Historical Control Vault validation

The fixed-N4 Joint owner can persist its guarded BEGIN/End state, preserve the
exact signed candidate before submission, and strictly reopen the original
operation after lost acknowledgements. The owning release gates passed actual
Source/Lifecycle/ControlKind mathematics, owner-signed Bodies, genuine local
weighted QCs and real files. They do not establish an OS owner restart, a new
four-validator network pass, durable Acquire continuation, a current lock or
general SQL admission.

The [Vault contract](../crates/storage-client/src/private_predicate/source/locking/joint/vault/DURABLE.md)
defines the phase transitions, independent recovery inputs, resource ownership
and filesystem qualification. The [private Control codec](../crates/storage-client/src/private_predicate/source/locking/joint/control/README.md)
owns the fixed private formats. Prior [typed lifecycle process validation](joint-owner-lifecycle.md)
remains separate evidence for four actual validator processes and an FHE peer.

## Ownership and publication

`OwnerVault` opens its own concrete `JointHistory` and `JointDepot` from the
caller's same `ParticipantQuota`. Its WAL has an exclusive lifetime file lock,
fixed role/profile/binding/identity pins, bounded authenticated records, a hash
chain, and a generation/pending-ID/record-digest CAS. It cannot accept an unrelated
History, verifier, ledger or successful-proof flag.

Before exposing submission bytes, `seal_body` rechecks the exact signed candidate
and all Source/Life/Kind prerequisites, reserves the append and complete terminal
allowance, then writes and syncs BodyPrepared. Its read-only History preflight
returns `()` and publishes neither a Journal node nor a finality receipt.
Reopening a pending record yields SubmittedUnknown. The retry retains the
original Header/Body/request/manifest/private candidate and salts.

Completion performs actual `apply_control` and consuming private completion,
then writes and syncs the next bank/outcome before returning success. An error
after History advances or after uncertain file I/O retains charges and poisons
the owner/shared ledger. Strict reopen can finish the exact saved target; a
different genuine successor without its private bank yields RecoveryRequired.
An authentic encrypted record alone cannot authorize an old or false bank.

The initial genuine public checkpoint/Body prefix and fetched encrypted Source
remain mandatory independent inputs. The caller still holds Source/BFV backup
authorities and supplies its one native proof resource gate. No keys are saved
beside the WAL. Private Idle410, Control731 and the existing Acquire capsule1242
have separate roles. The Registry274/Transaction129/Savepoint37 grammar is shared
without changing the old capsule's field order or validation errors.

## Executed release checks

All checks ran sequentially on Windows with the existing isolated native runner,
`RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two Rayon threads. The
1792 MiB per-PID observation fuse, operation limits and existing peer timeouts
were unchanged. No new peer binary was needed for these local gates.

| Check | Passed | Whole command seconds |
| --- | ---: | ---: |
| New private Control grammar and genuine restore | 2 | 54.065 |
| New Control WAL proof/QC/file failure and recovery cases | 5 | 142.957 |
| Existing encrypted Acquire capsule and genuine restore | 2 | 182.373 |
| Existing Control allocator/compaction/failed-close cases | 2 | 63.348 |
| Existing private Acquire grammar | 1 | 0.475 |
| Existing generic SQL capability rejection | 3 | 1.941 |
| Finality/client ownership documentation examples | 15 + 27 | 12.592 |
| Strict Clippy, all targets of six affected consumers | passed | 2.294 |
| Core default-member compilation | passed | 3.946 |
| Workspace formatting | passed | 1.690 |

The five new WAL cases cover:

- Real Begin/End, exact finalized-target retry, independent namespace/WAL reopen,
  generation CAS and double-open rejection. An existing terminal lease completes
  actual proof/QC replay with all other 4095 reservation slots occupied.
- Actual Body and Completion sync followed by injected lost acknowledgements.
  Same-handle operations reject; strict reopen finds the exact durable phase.
- Terminal-allowance recreation refused by the actual shared quota, plus a real
  partial completion write that is rejected without truncation or an old bank.
- A valid AEAD record containing a false private bank, a wrong wrapping key and
  an unsaved genuine successor, all rejected without a usable-state fallback.
- Unauthorized owner signature, damaged retained ControlKind and a genuine
  checkpoint for the wrong operation, rejected without advancing WAL/History.

The largest observed OS peak working set was 1402826752 bytes in the old genuine
capsule case; the new WAL batch peaked at 1070452736 bytes. The corresponding
sampled private-byte peaks were 1432563712 and 1070129152. These are local test
process observations, not full application/network resource or latency claims.
The WAL batch had 1225 process samples and a maximum 368.569 ms observation gap;
brief unobserved allocations and other processes remain outside that evidence.

The unchanged runner executed the following commands. The shell variable only
abbreviates the common test module prefix; it changes no test selection policy.

```powershell
$jointTestModule = 'private_predicate::source::locking::joint'
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib "${jointTestModule}::control::state::tests::" -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib "${jointTestModule}::vault::durable::tests::" -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib "${jointTestModule}::vault::tests::" -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib "${jointTestModule}::control::tests::" -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib "${jointTestModule}::vault::codec::tests::" -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib session::capability_tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client -p registry200-finality --features private-input-proofs --doc -- --test-threads=1
cargo clippy --release --offline --locked -p protocol-storage -p work-finality -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

The native source receipt SHA-256 is
`2D2568565A4FE4488DA95D6EFDAD0A477DD289A740C0A3DA10BC309840700C11`;
the after receipt is
`129F383F574E14062302712121982095DAC17FA01F466F2FB8599A3B01CB1F60`.
All 1569 files, runner hashes and ten completed result/log sets were rechecked
unchanged. Only documentation and three module/test opening doc-comment lines
were updated afterwards; executable and test bodies remain the tested bytes.

The first Clippy attempt failed on two unused imports: MAX_CHECKPOINT_BYTES and
SeekFrom. Removing those imports and formatting the same two files was the only
code correction before the successful frozen batch. Its source/after receipts
`B744687525CE9C825E080CB6760A4A24D0F5C6A1C53880F45E555C0EFC986290`
and `E553295BEF06F5811E3C3E21158D3C3C5857F4B9DE5ACC33AF8B8A93D91B0E50`
retain that failure. No runtime test failed. The requirements mirror was compared
as text before integration and before publication; this is a consistency check,
not an application test.

File sync precedes outcome publication. Directory sync remains Unix-only;
Windows directory-entry survival across power loss is not established. Neither
authenticated chains nor process-local CAS provide whole-file rollback
protection. Source/BFV full cold reconstruction and fresh-network reconciliation
require separate owning tests. The generic SQL Session remains closed while its
actual Joint execution and freshness contracts are incomplete.
