# Historical Acquire continuation (owner Vault v2)

Status: **PASSED native release owning validation**. The two ordinary recovery
cases, genuine OS-FHE/local-QC fault case, five Control cases and six-process
Control restart regression passed on the v2 source. The
[native record](../../../../../../../../docs/joint-owner-acquire-vault.md)
pins their source, actual peer image, commands and observations. These separate
gates do not establish a combined four-validator durable Acquire/process restart.

This extension uses the existing `OwnerVault`,
exclusive WAL, `ParticipantQuota`, concrete `JointHistory` and shared public depot.
There is no second Vault, generic verifier callback, persisted verified flag,
Session bypass, database data COMMIT, current lease or anti-rollback mechanism.
The existing Control public methods retain their meaning in this new format.

`owner_vault_profile_digest`, the profile-derived file identity and the file / phase
magic explicitly name v2 (`DCSOVL02`, `DCSOVP02`, `DCSOVA02`). Old v1 is never read,
migrated, recreated on open failure or silently interpreted as v2. The operator
must explicitly install a new v2 Vault from an actual independently verified
prefix and its matching private Idle. A lost newer bank cannot be recovered from
an older backup by choosing new salts or replaying `Registry::step`.

## Modules and dependencies

- `durable.rs` owns the single create/open engine, CAS, Control transitions and
  sealed historical parents. `durable_acquire.rs` is its private child and owns
  original-material restore, Acquire transitions and guarded projected results.
- `durable_wal.rs` remains the one authenticated bounded append writer. Both the
  original owned-lease `append` and Acquire's borrowed-lease `append_reserved`
  call that writer. A promised terminal lease remains owned on early errors;
  any uncertain append poisons the owner/participant and retains unused charges.
- `acquire_inventory.rs` owns exactly twenty public content references. It uses
  existing Source/Encoding and Lifecycle frame codecs and their original caps.
  It never serializes private Aux, a proof vector, Ready backup or plaintext rows.
- `acquire_live.rs` is a private original-object owner used only by the network
  driver's same-execute fresh Idle path. It has no public constructor or restore
  shortcut; its owning validation status and remaining full checks are documented in
  the [network module](host/network/README.md).
- `JointHistory::check_acquire_candidate` is a concrete read-only check of the
  actual signed Header/Body and all input16/output118/Source/Life/Link premises.
  It returns `()` and supplies no later import authority. `apply_acquire` still
  checks the actual QC and fresh full mathematics independently.
- `JointEvidenceIngress::recording_store()` returns the same actual shared store
  used by History. The existing shared RPC recorder performs native work,
  verification, END and clean EOF outside individual short depot locks.

These modules directly use the existing BFV Core owner-state/Ready/capsule
restoration, `bfv-product-evidence`, concrete Registry finality, `protocol-storage`,
SHA-256 and OS randomness. They add no cryptography or new proof/wire profile.

## Independently retained original material

`OwnerVaultAcquireMaterial` borrows the complete original public setup, authentic
owner anchor and ALL Key33, independent `OwnerStateIdentity`, external wrapping
authority and original Owner / anchor / Ready encrypted records. It also borrows
the independent Source identity/authority/488-byte record and the original
Acquire capsule identity/key. These authorities must remain external: the Vault
does not create a key file beside its ciphertext, choose a password KDF or import
an OS credential. All records are constructed by their existing bounded parsers;
the potentially 20 MiB Ready record stays outside the 1 MiB phase record.

Before restoring the BFV secret, the descriptor is reconstructed from the
independently pinned complete setup, anchor and Key33 and compared byte-for-byte
with the installed binding. A phase also binds the exact encrypted original
backup identities by digest. Those hashes and AEAD labels are association checks,
not secret-origin proofs. The real Source restore audits original AEAD/index,
Table, all four RowIDs and Ckey. The real Owner/anchor/Ready restoration reopens
both private roots and genuinely verifies Key. Capsule restoration reuses the
original pending ciphertext bytes and rechecks input16, Source/Life/Link,
Cmd48/160, Result144 and old/next Registry openings. No restore path encrypts a
new operand, proves a new input, creates a new nonce, salts a new opening or steps
the Registry model.

## Exact phase grammar and call order

1. In Idle, `prepare_acquire(cursor, fetched, material, sql, txID, principal)`
   first reserves four record slots and four unchanged maximum-record extents.
   It then generates a new private blind, public nonce, query ID and invocation
   ID after the call begins; restores the actual original owners/Ready; and uses
   `prepare_joint_locking_owned_recoverable` on the saved Idle. WAIT/NOWAIT returns
   `NonAdmitted`, retaining Idle. It cannot become an empty successful query.
2. On success it retains exactly these public roles: provenance claim, original
   encrypted request, Key, deduplicated Source, two Encoding children, ten Basis,
   two Formation, Lifecycle child and PredicateAcquire Link. ComputePrepared
   saves the original outer request, next/result roots, capsule1242, that fixed
   inventory, exact preceding Idle410/stamp, original-material digest and invocation
   ID. It fsyncs before `OwnerVaultAcquireWork` exposes original public RPC work.
   The public API drops the original in-memory BFV pending and private candidates;
   future attempts use the authenticated exact restore path. A private fresh-live
   driver may retain those original objects only within its exclusive current
   call, without changing any public/default/recovery contract or WAL bytes.
3. Move `work.into_parts()` into
   `RemotePeer::prove_private_product_recorded_shared` with the SAME
   `vault.evidence_ingress()?.recording_store()`. Hold the host's one actual
   ProofGate around native work. Do not hold any depot/History mutex across RPC.
   Only actual input16/output118 verification plus END and clean EOF can produce
   the recorder's catalog. Interrupted output has no completed catalog; this
   slice does not implement resuming a partial proof stream.
4. `save_acquire_catalog` freshly restores/verifies the original inputs/Link and
   independently replays the complete recorded product before appending the
   catalog reference to ComputePrepared. It remains an untrusted public ref,
   never a stored proof receipt. `acquire_draft` returns only the original outer
   intent and its fixed manifest for signing; it does not release a submission.
5. `seal_acquire_body` checks the actual exact owner-signed candidate with the
   closed read-only History path, then appends/fsyncs BodyPrepared. `submission`
   returns the ORIGINAL saved Header/Body. Reopen treats any such record as
   SubmittedUnknown regardless of whether a send occurred. Lost ACK handling
   retries these exact bytes FIRST; it never re-signs, reparents, resalts or proves
   another operation.
6. `complete_acquire` restores original private pending/candidates, obtains this
   call's actual full-proof `VerifiedJointAcquire` from `history.apply_acquire`,
   and performs the existing unconditional private association/Result144 checks
   before its one completion decrypt. It saves the ACTUAL next Idle and QC under
   generation+1, fsyncs, then releases the original invocation's projected rows.
   Any uncertainty after History advances poisons the owner and keeps accounting.
7. `acknowledge` appends Idle with that same bank. A second completion at the old
   cursor fails CAS. The consumed rows owner clears its explicit projected fields
   on Drop; this does not promise erasure of SDK/compiler/allocator history.

The fixed Acquire subrecord is bounded by 8192 bytes, and each existing per-role
proof/ciphertext bound applies before retaining/loading bytes. The old 64 KiB
Body, 1 MiB record, 16 MiB file, 128-record, 16 MiB external replay and 256 MiB
CONTROL caps remain unchanged. Public evidence counts against the same actual
participant total and depot class. The measurements in the native record cover
the explicit tests, including repeated recovery and proof replay. They establish
neither ordinary-query latency nor general SQL RAM or disk fit.

## Strict reopen and historical redelivery

`open_existing_acquire` and Control-only `open_existing` share one private engine.
The Control entry returns `RecoveryRequired` upon an Acquire; it never returns a
partially restored owner. The Acquire entry fully replays every original input,
recorded product, signed candidate and QC using the independent original material
before returning. It reacquires all remaining terminal bytes and record slots
before exposing any pending operation. Missing originals, a different authentic
backup, absent/corrupt public proof or unavailable quota refuses recovery. A
genuinely newer unsaved bank also gives `RecoveryRequired`, with no old-bank fallback.

Completed rows are not serialized or trusted from AEAD plaintext. After restart
they are reconstructed by fresh full verification and completion of the saved
ORIGINAL invocation. `take_recovered_acquire` labels them with that invocation ID
and `is_recovered_invocation()==true`; it never presents them as a new query or
fresh lease. It can deliver once per opened instance, while opening an authentic
old backup remains possible. The guarantee is durable bank CAS for this log,
not physically once decryption across crashes, global anti-rollback or safe
recovery of lost later salts. A new nonce-bound own Acquire can linearize after
its invocation under the independently activated roster; readonly queries and
reconciliation of old pending/old Vault/roster need their separate freshness policy.

## Native owning gates

The two passing ordinary tests generate genuine Source/input16/Life/Link and original
private backups, then exercise strict Compute restart, wrong wrapping key,
unproved catalog rejection, actual missing last Formation, terminal quota refusal,
lost Compute fsync ACK and quota reconstruction. Existing Control test assertions
are preserved; their fixture only captures additional backups for new tests.

The passing explicit opt-in OS FHE case requires `DCS_PEER_EXE`, verifies the genuine
118-record stream through END/EOF in the SAME shared store, loses Body and
Completed fsync ACKs, strictly reopens, redelivers original rows after durable CAS,
and uses the installed acquired bank for real typed End. Vault drop/reopen occurs
inside the test process; the FHE evaluator is an independent process. Its QC is a
genuine local fixture, **not four-validator agreement**. The six-process Control
restart also passed on v2, with four validators and sequential owners. Existing
four-OS Acquire/finality gates remain separate. Combined durable Acquire owner
process recovery, full PostgreSQL, autonomous freshness and Session admission
remain unestablished.
