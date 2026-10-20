# Owner recovery and historical Joint WAL

The ComputePrepared capsule API captures and restores one historical Acquire
without filesystem I/O. The [Control path](DURABLE.md) and new
[Acquire continuation](DURABLE-ACQUIRE.md) share ONE bounded owner-private WAL,
phase CAS and exact-byte retry engine. The v2 owning tests, genuine OS-FHE/local-QC
recovery case and six-process Control regression passed; see the
[native record](../../../../../../../../docs/joint-owner-acquire-vault.md). No API
supplies a current-lock check, rollback protection or SQL admission. Private
Source/BFV/Ready backups remain independently pinned bounded external inputs;
the new phase record stores the original capsule and twenty public references.

The earlier v1 [Control process restart gate](PROCESS-RESTART.md) passed with
four actual validators and sequential owner A/B processes, restoring the
original Source and BFV Owner/Anchor/Ready before exact Begin/End completion.
Its [executed record](../../../../../../../../docs/shared-evidence-owner-restart.md)
remains historical evidence. The same Control case also passed on v2. Combined
durable Acquire with four validators and owner-process recovery remains pending.

| Direct dependency | Responsibility |
| --- | --- |
| [Joint producer](../mod.rs) and [shared producer](../../produce.rs) | Actual all-original Source/input16/Lifecycle/Link preparation; default route captures nothing |
| [Private codec](codec.rs) | Fixed private grammar, complete public association, XChaCha20Poly1305 envelope |
| [Restore](restore.rs) | Independent parent/setup/anchor/ALL33 checks, all commitment openings and actual proof replay |
| [Lifecycle field owner](../../../../../../../registry200-proof/src/lifecycle/circuit/commitment.rs) | Exact original Enrollment64/Registry200 preimages without unrelated Source DATA |
| [Core pending owner](../../../../../../../bfv-query-core/src/coefficient_predicate.rs) | Rebuild the exact original encrypted request/pending binding without encryption or FHE |
| [Control WAL](durable.rs), [file/AEAD engine](durable_wal.rs), [tests](durable_tests.rs) | Historical private bank, phase CAS, exact signed candidate, conservative quota and strict replay |
| [Acquire continuation](durable_acquire.rs), [fixed public inventory](acquire_inventory.rs), [owning tests](durable_acquire_tests.rs) | Original-material authentication, real input/output replay, exact pending continuation and historical original-invocation completion |
| [Participant storage](../../../../../../../protocol-storage/src/lib.rs) | One actual ledger and exclusive namespace; existing CONTROL class ceiling |

`JointRecoveryKey::new(Zeroizing<[u8;32]>)` accepts an independently custodied,
high-entropy owner wrapping key. It grants no database, peer, controller or signer
authority. No key getter, callback, public secret serializer, password KDF, OS
backend or adjacent key file exists. `JointRecoveryIdentity` is an independent
record location; it is not a durable generation or an anti-replay counter.

After Begin, call `SourceOwner::prepare_joint_locking_owned_recoverable` with the
opaque `JointOwnedLockingControl` and
`JointOwnedRecovery::new(control_parent, identity, key)`. It checks the complete
owner parent/context stamp before extracting the private control into the same
actual producer and recovery capture. No raw-bank getter or alternate verifier
exists. The owning restore test uses this route.

The lower-level `SourceOwner::prepare_joint_locking_recoverable` takes actual BFV,
Ready epoch, fetched Source, compiler and control arguments plus
`JointRecovery::new(parent, identity, key)`. Success returns a separate move-only
handle whose `into_parts` yields the existing prepared inputs and a ciphertext-only
`EncryptedJointRecovery`. The ordinary `prepare_joint_locking` and legacy producer
pass `None`: they retain no extra private mask. WAIT/NOWAIT takes the existing early
nonadmitted branch and produces no recovery record or staged success.

The private preimage is captured while the actual Link opening is still alive.
It contains all 256 mask bits; exact transaction/principal/controller/revision/
sequence; strength, wait, offset, limit and **projection**; returned/skipped/visited
flags; Cmd48/Cmd160/Result144 salts; both original and next Registry; controllers;
enrollment/old/next Registry salts; TableId, all four full RowIDs and original
ordinals. Projection is reopened against Cmd160: Result144 alone does not bind it.
No ages, amounts, SQL/private blind, Source key/Ckey salt/opening salt, BFV secret,
Shat, proof collection or decrypted answer is stored in the private payload.

The source-defined format is 144 header + 1082 fixed private bytes + 16 tag = 1242
bytes. Two transaction slots and two savepoints per slot have explicit presence
bits and zero absent padding; booleans, dimensions, counters and salts are checked
against the actual `Val::ORDER_U64`. There are no attacker-sized private vectors.
`from_bytes` checks exact length/namespace/version/role/reserved bytes before a
record copy; it verifies no tag or proof. The complete header is AEAD associated
data: distinct namespace/role, record32, full SHA512 operation association, random
nonce24 and exact length. The association includes independently pinned full
Joint binding/descriptor/genesis, sealed historical parent metadata, exact
canonical outer/inner request and provenance, original BFV request, and every
borrowed original public proof byte. It is a binding, never a proof-success cache.

`EncryptedJointRecovery::restore_compute_prepared` accepts independent
identity/key/BFV/Ready epoch/historical parent and `JointRecoveryInputs` borrowing
the original public material. It authenticates the tiny payload, checks the exact
inner/outer intent and complete Source/setup/anchor/ALL33/request association,
reopens original Registry/enrollment/Cnext, and calls the real
`predicate_acquire::circuit::Witness::new` to reopen Cmd48/Cmask, Cmd160/Ccmd and
Result144. It then actually re-verifies all input16, Source/Lifecycle and Link
proofs. All decoded proof backends remain owned/dropped by the existing verifiers;
the borrowed proof collection is not cloned into the record or result.

Only after those checks does the existing Core pending restore consume a copy of
the **same exact** BFV request. No new encryption, nonce, proof or answer is created.
`RecoveredJointComputePrepared::into_parts` returns that real pending object and
the existing opaque `JointLockingCandidates`. Completion still requires the exact
sealed `VerifiedJointAcquire` and full output118 proof path. No public factory for
that receipt, current Registry, lease or owner-state installation is added.
The original proof profiles, wire formats, caps and security policies are unchanged.
This owner-authenticated backup establishes no new public same-secret RK theorem,
composed security level, process RAM bound or performance result.

Private payloads and explicit copies use `Zeroizing`/guarded Drop, including error
branches. This excludes caller copies, native Gold/SDK traces, registers, allocator
history and temporary cryptographic scratch. Ciphertext can be copied and restored
twice; move-only Rust handles enforce one use per instance only. The capsule alone
supplies no durable continuation. Control and Acquire add their local phase
CAS/fsync/lost-ACK paths in the shared WAL under their linked contracts.
Whole-vault rollback, owner signing-key custody, fresh-head reconciliation and
history compaction remain separate requirements.

Owning source tests include real Bootstrap/Begin/Kind/QCs, actual input16 and Link,
lexical Owner→Anchor→Ready restoration after originals drop, exact pending/roots,
and valid-AEAD false projection1/3, maskbit255, flags, salts, controller, Registry,
TableId and final RowID mutations. A re-sealed corrupted proof must fail the actual
verifier; a genuine fresh same-anchor Key with different transformed4 must fail
full33 pins. Grammar tests and literal original field-order tests are separate.
The envelope, private-grammar and genuine restore cases passed on the native
release build; the [owner validation record](../../../../../../../../docs/joint-owner-preparation.md)
pins source and results. These tests establish no new full output118 completion,
OS restart, current lease or durable anti-rollback claim. The prior real process
Acquire/contention gates remain separately recorded evidence.

The earlier v1 [Control Vault validation](../../../../../../../../docs/joint-owner-control-vault.md)
also reran both capsule cases and the private grammar after their shared Registry
codec extraction. The later v2 record above covers its own new tests and Control
regressions without extending those earlier capsule measurements.

## Bounded managed owner candidate

The new [JointSqlHost v3](host/README.md) passed its owning native release gates
over this SAME concrete WAL/quota/History/shared depot. The
[validation record](../../../../../../../../docs/joint-sql-host-validation.md)
also records the old v2 Control process regression on the same source. Its
distinct local profile/header/file identity authenticates two independently
configured logical client bindings, a complete root-opened Registry bijection,
stable transaction ids and bounded original-response retry metadata. Completed
fsync includes both private successor bank and client-map delta; prepaid three
Control/five Acquire records include ACK. Existing v2 APIs/bytes/meaning remain
unchanged, with no automatic migration or fallback. The frontend is deliberately
incomplete and leaves all existing Session/Database/script SQL guards closed.
Full Host v3 output118/four-validator/owner-process completion remains a separate
pending gate; existing v2 results above are not v3 validation evidence.
