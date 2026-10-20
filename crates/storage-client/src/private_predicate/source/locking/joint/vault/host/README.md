# Bounded Joint SQL owner orchestration

This module passed its owning native release gates on 2026-10-20. It owns
the existing concrete `OwnerVault` and its single WAL writer, ParticipantQuota,
keyless JointHistory and shared evidence depot. It does not enable Session,
Database, scripts or a general SQL executor. There is no peer protocol, proof
profile, consensus timeout or resource-cap change.

| Direct dependency | Responsibility |
| --- | --- |
| [Client grammar](state.rs) | Fixed Clients200/Pending56 grammar and closed retry transitions |
| [Vault](../durable.rs) | Actual Source/Control bank audit, genuine private completion, same History, phase CAS and poison handling |
| [WAL](../durable_wal.rs) | One locked append/fsync/AEAD implementation and existing FileCharge/reservation transfer |
| [Acquire continuation](../durable_acquire.rs) | Original Source/BFV/Anchor/Ready restoration, input16, full retained output118, exact candidate and original pending completion |
| [Private Control state](../../control/state.rs) | Root-opened complete Registry/map bijection, default Bootstrap check and private allocator+1 |
| [Statement parser](../../../../../../../../sql-plan/src/lib.rs) | Bounded whole-input frontend only; no execution or authority |
| [Owning tests](tests.rs) | Genuine local proof/QC, actual file/AEAD, retry, compaction and accounting examples |

## Public boundary

`JointSqlHostPins::new(binding, identity, [client_a, client_b])` fixes exactly two
independently configured logical client ids and their principals. Ids are sorted,
distinct and nonzero; principals are 1 or 2 and may coincide. The bindings are
authenticated in the installation profile/header, AEAD associated data and every
private record. A handle returned by `host.client(id)` is a routing identity,
not authentication, delegated permission or database authority. The embedding
owner must authenticate its callers and authorize this configuration.

`create_new`, `open_existing` and `open_existing_acquire` use the same existing
Vault ownership contract. Creation and replay of the initial record require the
actual default Bootstrap Registry bank, not merely an empty post-End map. Real
fetched Source, TableId, all four RowIDs, Ckey, enrollment and registry openings
are checked. The caller supplies the independent binding and bounded genuine
Bootstrap/history prefix; no verified parent is decoded from owner AEAD bytes.
An acquire-aware reopen also needs the original independently pinned Source,
Owner, Anchor, Ready, setup, ALL33 and recovery material.

`host.call(client, sequence, exact_sql)` parses the entire bounded statement and
creates an opaque owner-private exact intent. Its digest has no public getter
and is never reused as the peer-visible SQL identity. The accepted first subset
is empty-mode BEGIN; COMMIT/ROLLBACK without either explicit CHAIN form; and the
existing bounded UPDATE SKIP LOCKED select. Modes, CHAIN, WAIT, NOWAIT, ordinary
reads, other strengths and unsupported windows/projections fail before I/O.
This deliberately incomplete subset is not PostgreSQL transaction equivalence.

`prepare_control` returns actual Source/Life/Kind owner-signing metadata;
`seal_body` checks the exact owner-signed candidate and fsyncs BodyPrepared before
`submission` can return its original bytes. `prepare_acquire` returns actual
input16 work only after ComputePrepared fsync. The same concrete catalog,
seal-acquire, submission and completion methods recheck every original proof and
QC; no client bit, catalog identity, hash or TLS session supplies proof success.
All later methods require the same opaque call and phase cursor. There are no
mutable Vault, Registry, History, key or store-guard getters.

After actual catalog fsync but before Body fsync, `acquire_draft(call, cursor)`
recovers the ORIGINAL signing metadata through the existing read-only Vault
accessor. This includes catalog-only strict reopen: `ExistingPending` need not
repeat FHE or call `save_acquire_catalog` again. The wrapper first checks the
same pending client/intent and then the exact phase CAS; a missing catalog is a
hard Phase rejection. It produces metadata only. `seal_acquire_body` still
performs the unchanged full original-material/proof/candidate verification.

The composition owner must use its ONE actual ProofGate around native work and
keep network I/O outside owner/depot guards. Host supplies no network scheduler,
deadline, current-head discovery or autonomous execution guarantee.

## Private durable grammar

The explicit new v3 file identity/header `DCSOVL03`, record namespace and private
snapshot magic `DCSOVP03` are distinct from v2. There is no migration, fallback or
format reinterpretation. The existing v2 APIs, bytes and semantics remain on the
closed `None` branch of the same private engine.

Clients200 is magic8 plus two 96-byte entries: clientID32, principal1, reserved7,
active stableTx8 (zero means none), lastCompletedCall8, private intentDigest32 and
lastCompletedRecordSeq8. Pending56 is presence1, clientSlot1, closed verb1,
reserved5, callSeq8, private intentDigest32 and stableTx8. Idle has no Pending;
every other phase has one. All padding is zero and all lengths are fixed.

The complete active map is a bijection with the genuinely reopened Registry's
transactions, including each principal. Count, slot or principal alone is
insufficient. Begin allocates checked `allocator + 1` inside the private audited
bank seam; callers cannot choose ids. End uses the mapped stable id, so removal
and compaction cannot rebind another client. Acquire preserves the map. Only
actual Begun, Closed/Aborted or Acquire completion changes its metadata.

New calls require checked `last + 1`. One global pending invocation blocks other
new work. The owner selects its random invocation before the control nonce or
query blind/nonce/id. There is NO Intake record: a crash before the first
Body/Compute fsync does not promise to recover that randomness. After that fsync,
retries restore the same exact request, proofs, candidate, salts and pending
object; they do not allocate another transaction, prove again or re-encrypt.

Completed atomically records the actual successor bank, map delta, result,
last-call association and its actual WAL sequence before returning success.
The existing 128-record, 1 MiB-record, 16 MiB-file and 256 MiB-Control caps stay
unchanged. Three Control or five Acquire maximum record extents/slots, including
ACK, are preflighted and reserved before preparation. Completed retains the
remaining ACK lease; strict reopen reconstructs all remaining capacity before
any owner API escapes. Other valid users may exhaust availability before reopen;
then reopen fails closed. There is no rollover, compaction or silent repair.

`acknowledge` clears Pending only and preserves the last response reference.
The bounded sequence 1..128 is metadata, not a receipt. Forward replay verifies
the original exact client/principal/call/verb/transaction/intent/invocation,
actual transition and proof/QC at its original context before retaining a reply.
It never installs an old QC against the current head. Only each client's latest
completed call can be redelivered; overwritten/lower calls are stale. A matching
live retry reports `HistoricalLast`, which itself supplies no result authority.
`take_recovered_reply` consumes the actual result freshly rebuilt by this
exclusive open. If it was already consumed or this instance did not replay it,
the caller must explicitly reopen (`RecoveryRequired`); no second hidden store
or persisted proof-success cache exists.

## Verification and limits

Five Host owning cases and the fixed client grammar passed, together with seven
existing v2 owning cases. The older six-process Control gate also passed on the
same frozen source and newly built peer image. The
[validation record](../../../../../../../../../docs/joint-sql-host-validation.md)
pins source, executable, commands and observations. The owning cases use actual Bootstrap/Source/Life/Kind, genuine local
weighted QCs, file locks, real AEAD and the same quota writer. They cover two
clients sharing a principal, End compaction, exact/altered retries, stale cursor
and old QC, lost Body/Completed/ACK sync acknowledgements, wrong wrapping key,
missing Kind, quota/record refusal and prepaid ACK with all reservation slots
occupied. A separate real input16 Compute case restores the original request,
invocation and ALL33. The deliberately saturated packet-limit test never adopts
or reopens its repeated Idle packets as a valid phase history.

The genuine Compute-only case also rejects pre-catalog draft access, a foreign
client, a changed exact intent and stale CAS without changing the cursor, WAL
extent or quota. A positive catalog-fsynced/pre-Body reopen must be exercised by
the separate actual process gate using a genuine completed FHE catalog; no fake
catalog is used as positive evidence here.

Full Host v3 two-client output118/four-validator/OS-restart completion and its
five-record ACK path still require a separate genuine gate. Existing v2 gates
are not new v3 execution evidence. No fake rows, local model answer, second
WHERE/window application or accepting verifier is used in these source tests.

The external wrapping key, public proof inventory and independently authenticated
history remain separate custody requirements. Healthy handles use local phase
CAS; uncertain write/sync retains charges and poisons owner/ledger. File sync is
not a Windows directory-entry power-loss theorem. AEAD supplies no whole-vault
rollback resistance. Client retry labels supply no delegated-rights protocol.
Explicit owned private grammar buffers, intent digests and bank copies use
guarded clearing; caller copies, native SDK traces, register/allocator history
and cryptographic scratch are excluded. Replies remain historical original
invocations: no current lease, SQL-data COMMIT, general WAIT/deadlock semantics,
fresh-head policy, history compaction or production SQL admission is supplied.
