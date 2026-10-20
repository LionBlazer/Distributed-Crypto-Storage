# Joint owner preparation and in-memory recovery validation

The fixed-N4 owner adapter now prepares genuine BEGIN/End operations, transfers a
completed private Registry into the unchanged strict Acquire producer, and restores
an original ComputePrepared operation from a bounded owner-encrypted capsule.
Completion consumes exact sealed application/QC evidence and reopens the captured
commitments. This stage supplies library APIs; it does not persist a Vault, survive
an OS restart, implement encrypted SQL data COMMIT or open the generic SQL Session.

The [Control owner](../crates/storage-client/src/private_predicate/source/locking/joint/control/README.md)
and [recovery owner](../crates/storage-client/src/private_predicate/source/locking/joint/vault/README.md)
describe the public contracts. The [closed History](../crates/registry200-finality/src/joint/README.md)
owns proof/QC checking. Prior independently running validator/FHE gates, including
two-Acquire held-row SKIP LOCKED, remain separately pinned in the
[participant record](joint-participant-finality.md); they are not new recovery or
restart evidence.

## Checked behavior

BEGIN and End reload the real encrypted Source and construct actual Source,
Lifecycle and ControlKind proofs. The owning test checks two transactions, stable
transaction IDs after End compaction, an actually admitted FailCurrent prefix and
a failed Close that reports AbortedRegistry. Registry close/abort does not commit
or roll back encrypted SQL data. Wrong own intent, malformed proof and false
private roots must fail; a latest semantic retry replays the actual premises.

`JointOwnedLockingControl` has no raw-bank getter. Both owned preparation routes
check the complete historical parent/context stamp and original BFV setup, anchor,
Ready epoch and ALL33 values before extracting the private control into the same
actual Acquire producer. `prepare_joint_locking_owned_recoverable` adds
`JointOwnedRecovery` options to that route; no alternate verifier is introduced.

The recovery envelope is exactly 1242 bytes: header144, private payload1082 and
tag16. The owner wrapping key is independently supplied. The full association
binds the historical head including state_root, independent installation/setup
pins, exact requests/provenance, original BFV request and all borrowed public
proof bytes. Authenticated encryption establishes association, not computation.
Restore independently reopens Cmd48/Cmd160/Result144, enrollment and both Registry
commitments, then actually verifies Source/input16/Lifecycle/Link. It recreates
the same original pending request without encryption or reproving. Output118 and
the exact own Acquire QC are still required for completion.

The genuine restore case drops Source/BFV Owner, Ready epoch and original prepared
handles, restores the real independently backed-up owners, and uses the owned
recoverable route. Valid-AEAD false projection, mask, flags, salts, controller,
Registry, TableId and final RowID are rejected. Re-sealed false or missing proof
premises must fail their actual verifiers. Separate private-grammar tests reject
nonbinary flags, absent padding, uncompacted banks and noncanonical field aliases.
The pure enrollment64/Registry200 helpers retain independently checked literal
field order; Result144 parity retains all opcodes/outcomes and u64 boundaries.

These owning proof tests use genuine local three-of-four Work signatures. They
do not start independent validators. Shared test fixtures are now owned once by
`joint::tests`; Control and recovery tests import them within that cfg(test)
boundary. No duplicate-module lint suppression or production app dependency was
added. Explicit owned banks and command words are guarded on failure; caller
copies, removed model temporaries, field vectors, allocator history and SDK
scratch are outside a blanket memory-erasure claim.

## Executed native gates

Windows x86_64 MSVC, Rust1.99, release, offline locked dependencies, native CPU and
Rayon2 were used. Every run had a 1792 MiB per-PID memory fuse and 1800-second
supervision deadline; production caps were unchanged. The R5 batch after fixture
consolidation observed working set 1470574592 bytes, private
bytes 1532903424 and OS peak working set
1505824768 bytes. These are sampled observations of this
local batch, not an end-to-end query latency, aggregate-memory or general resource
guarantee. Each elapsed value below is whole supervised command time, including
compilation where needed. Repeated cases in separate batches are not distinct
coverage credit.

| Local receipt label | Scope | Result | Seconds |
| --- | --- | --- | ---: |
| `joint-owner-control-native-control-r2` | Control intent and genuine BEGIN/End | 2 passed | 92.151 |
| `joint-owner-control-native-recovery-r2` | Recovery envelope and genuine restore | 2 passed | 185.379 |
| `joint-owner-control-native-owned-producer-r2` | Normal owned Acquire producer | 2 passed; 2 OS gates ignored | 151.588 |
| `joint-owner-control-native-lifecycle-r2` | Core Lifecycle and exact field parity | 6 passed | 34.726 |
| `joint-owner-control-native-lifecycle-legacy-r3` | Original experiment Lifecycle regressions | 21 passed | 204.893 |
| `joint-owner-control-native-finality-r3` | Original and Joint finality regressions | 19 passed | 167.205 |
| `joint-owner-control-native-doc-r3` | Ownership compile-fail contracts | 37 passed (11 finality, 4 proof, 22 client) | 11.444 |
| `joint-owner-control-native-all-owner-r5` | All regular Joint owner tests after fixture consolidation | 7 passed; 2 OS gates ignored | 415.977 |
| `joint-owner-control-native-clippy-r5` | Strict Clippy, all targets of the three affected packages | passed | 1.298 |
| `joint-owner-control-native-fmt-check-r5` | Workspace formatting check | passed | 1.837 |

The two expensive OS gates remain explicitly opt-in; their ignored count in this
unit batch is not a passing process test. R3 doc tests passed before the cfg(test)
fixture ownership change; the production APIs are byte-identical to R2/R3.

Reproduce the regular owner batch from the repository root:

```powershell
cargo test --release --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-finality --lib -- --nocapture --test-threads=1
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_lifecycle::tests:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-proof -p registry200-finality -p storage-client --features private-input-proofs --doc -- --test-threads=1
cargo clippy --release --locked -p registry200-proof -p registry200-finality -p storage-client --features private-input-proofs --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Source and retained failures

The parent was `e8c54d8703fe87f00643816ee05b0c5548babd62` on
`codex/feature/sql-latency`. Each source inventory contains all1550 tracked or
nonignored files. After receipts rehash every source, runner and result log.
Publication changes documentation only after the R5 audit.

| Inventory | Source SHA256 | After-receipt SHA256 |
| --- | --- | --- |
| R2 | `32EA8512B7BBEE36302934ECE579E496BDE1E4418867DC981761B62B768B45EF` | `0A3A9694C45560787B8DD9315869A577353A1B69DE23DC93C7A82CE32BFCA8D2` |
| R3 | `73B214A73EDC0473889A7EECF620BB68B157C292F564E5B300CEFB54E00B6A38` | `AB90C1E28D73376FD77CCA1B91A55075EE9E419053A997A50ED34516E7A75994` |
| R5 | `A352B5AB5B9C63BFD948421C33F345BE06BBC039C52C2A4A6A574395994C2481` | `AF5491124229ABA6BF073788B4CE05F591B426CFF081129F18268B4A156766FC` |

Local manifests and result/log receipts live under
`.local/joint-owner-control-native-r*/` and
`.local/private-peer-native-r1/joint-owner-control-native-*/`; generated evidence
and participant state are not committed. R2 to R3 changed only the experiment lock;
R3 to R5 changed only six cfg(test) fixture files. The lock synchronization adds
existing local workspace packages/dependency edges and preserves every existing
external package version, source and checksum. The root lock is unchanged.

Earlier failed commands remain retained: R1 found a missing normal proof
dependency in finality; one R2 command named a nonexistent Cargo test target,
then the documented experiment command correctly refused the stale lock. No
tests ran in those failed commands. R3 strict Clippy found duplicate test-module
inclusion; R4 found the resulting unused import. R5 fixes ownership directly and
passes strict Clippy. No ignored, weakened or invented success replaces them.

## Remaining owner integration

There is no filesystem Vault, exclusive owner opener, durable generation CAS,
BodyPrepared exact signed-byte lost-ACK phase, durable completion or restart
gate. Copying a valid capsule can recreate multiple handles; move-only Rust
values enforce one use per instance only. An old authentic backup is not current
state. Whole-vault rollback protection, fresh-network reconciliation, owner
authorization/signing custody and bounded retained-history compaction remain
separate work. No current lease, general SQL support, composed128 theorem or
BFV same-secret RK guarantee follows from this stage.
