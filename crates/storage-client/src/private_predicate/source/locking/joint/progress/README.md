# Progress installation owner

## v3 same-execute completion

The new Progress APPLICATION contract v3 yields a new App/G/Rules/Binding; old v2
requests, manifests, QCs and private WAL/banks are rejected, never migrated or
relabelled. The 02 grammar and Core896/math profiles remain exact. Only the
keyless Owner's private live Driver path reuses the original genuine stream's
completed native mathematics within one synchronous call. It retains a move-only
`PreparedRecording`/`SubmittedRecording` pair: full original Attempt+Cursor,
actual Context/parent, then full fsynced after-Attempt/Cursor/catalog/Header/Body.
The Work stamp binds the BEFORE encoding with catalog=None; Submit atomically
adds its actual catalog. Both exact encodings are checked, not a modified stamp.

After an independently valid exact QC the SAME native gate is reacquired before
consuming the frame. SAME-store full original-byte association and actual
Source/query/Core896/current Journal/QC/Result160/whole old+next private roots and
unchanged Commit fsync remain mandatory. Only that fsync frees a Parked global
flight or installs Done/Error/Control. No frame, boolean receipt, SDK key/proof
bank or completed response is stored as cross-call authority. Native permits and
store locks release before validator upload/consensus waiting; an internal Busy
may retain the frame only within this call. Every public Pending/error/drop
discards it.

Public Work::compute/submit/complete stay cold with unchanged contracts. EVERY
cold/reopen/duplicate/validator path still performs full native input16/output118
checks; Submitted recovery uses original Body first and cold completion, while
cold Prepared may require actual Work again. Done-only decryption, no Parked
rows/ACK/lastCompleted, original statement/ALL33 and unsupported SQL boundaries
stay exact. The fixed v3 Driver gate passed with five genuine FHE jobs, eleven
actual QCs, one full parked Owner replay and exactly forty WAL records; see the
[validation record](../../../../../../../../docs/progress-driver-scoped-completion.md).
Owner82 measurements remain separately scoped. No controlled full-query speedup
is established.


This module adds the distinct, closed `private_predicate::progress` owner. The
historical Joint host, wire formats, SQL Session capability guards and all proof
profiles remain unchanged. The earlier Owner82 (v2) record covers six fast owning
tests and one genuine OS FHE/local-QC/recovery gate; see the
[validation record](../../../../../../../../docs/progress-owner-validation.md).
This is the current fixed four-row schema, not general SQL.

## Responsibilities and dependencies

`Owner` owns one genuine `progress::History`, its SAME `ProgressDepot` ingress,
one quota-accounted AEAD WAL and the private Registry208 bank. The embedding
process supplies clones of its ONE `peer_runtime::ProofGate`; this module does
not allocate another gate. `SourceOwner` independently restores and audits the
actual encrypted data/index images. BFV custody uses `bfv-query-core` original
Owner/Anchor/Ready backups and full Key33, including CsHat. `registry200-proof`
produces Source/input16 and the actual Control815/Predicate896 relation. The
actual peer-runtime product request executes FHE remotely and verifies/records
input16/output118. `registry200-finality` replays those exact public originals,
owner signature and weighted QC before any private Result160 opening. File and
depot accounting use the same `protocol-storage::ParticipantQuota`.

Private implementation modules:

- `prepare`: genuine custody/proof production and guarded attempt grammar.
- `inventory`: fixed nineteen references and exact same-store catalog matching.
- `completion`: actual own-operation expectation, QC, typed opening, root check
  and Done-only BFV decryption. No predicate/window builder is called here.
- `state`: canonical Bank/Statement/Progress grammar and logical-client ledger.
- `wal`: strict locked, precharged, XChaCha20Poly1305 append and fsync.
- `host`: preparation/remote execution/submission/completion/ACK lifecycle.
- `tests`: fast private codec/file faults and one explicit genuine OS FHE gate.

No implementation imports an app/process launcher. Test supervision is reused
only under the existing owning cfg(test) boundary.

## Public contract and usage

`Pins::new` independently pins the durable Progress Binding, owner identity,
two logical client routes and private controllers. `Material` borrows externally
custodied original encrypted Owner/Anchor/Ready/Source backups and authorities.
Ready is never regenerated on resume: restore recomputes Shat, reopens both roots,
compares ALL33 and verifies the stored original Key proof before new Basis work.

1. `Owner::create_new` consumes a new local authority and opens one depot/WAL.
   It genuinely replays supplied Bootstrap/Empty lineage, requires Active and
   independently opens its EMPTY bank. `open_existing` instead strictly replays
   the whole bounded encrypted log and every committed proof/QC.
2. `Call::sql` retains the exact private SQL until preparation. It supports bare
   BEGIN/COMMIT/ROLLBACK and the existing fixed locking SELECT syntax. Transaction
   modes, CHAIN, other queries and unsupported syntax reject explicitly. Separate
   `savepoint`/`rollback_to`/`release` constructors accept an owner-retained opaque
   name; they do not pretend the SQL parser already recognizes those statements.
3. `prepare` fsyncs the original call/attempt before returning `Ready`. `work`
   yields the exact prepared remote product input job; Control has no FHE job.
   `Work::compute` calls the actual RemotePeer recorded shared-store API while
   holding the same process-owned gate. It returns sealed `Computed` mathematics,
   not SQL, a lock or a freshness grant.
4. `submit` consumes that actual computed object, independently matches every
   catalog premise, signs the exact Request/Manifest/update, mines under the
   genuine current History target and fsyncs the complete Body/Header before
   returning `Submission`. `pending_submission` returns those same bytes after
   uncertain delivery. An import ACK alone never completes SQL.
5. `complete` requires the exact weighted QC, freshly invokes actual
   `History::apply_operation`, opens captured canonical Result160 against the
   sealed Step, checks the whole next bank/root and fsyncs the resulting bank and
   client ledger before installing either. Errors after a possible History
   advance poison the live owner until a strict cold reopen.
6. Only `Done(Reply)` returns rows, decrypted from that operation's actual
   encrypted product and projected using its opened cumulative selected flags.
   `NoWaitError` has no rows. Control returns typed Begun/Closed/Aborted or its
   named-control result. Only terminal results can be acknowledged.

`Waiting` is authenticated private Parked, with no rows, terminal reply, ACK or
lastCompleted advance. Its fsynced Bank1228/Book512 retains original Statement,
full mask/window/projection, invocation, client call and stable transaction ID.
Only after this fsync does the one global flight clear so the other client can
End. `resume` accepts no SQL replacement and creates a fresh q/nonce/Copen/input16
and output118 attempt under the SAME original statement and Key33. Progress
follows stable IDs through transaction compaction. Retrying a parked call returns
Waiting; a resume before another actual revision changes also returns Waiting.
`advance_empty` genuinely imports an Empty QC while idle, preserves private bank
and parked calls, and emits no operation receipt or SQL outcome.

A Cursor is CAS metadata for a live WAL prefix. Decoded snapshots, catalog IDs,
flags, Status, signatures, hashes and successful decryption cannot manufacture
proof acceptance, QC, freshness, an installed bank or a SQL permission.

## Exact private grammar and bounds

The new file magic is `POWAL001`. Its header is 104 bytes: magic8, local owner
profile32, finality Binding32 and complete independent owner pins32. Each record
has a 72-byte prefix, bounded encrypted payload and 16-byte tag. Sequence and
previous ciphertext digest are AEAD-associated together with the whole header.
The writer locks the file, precharges its next extent, writes all bytes and calls
`sync_all` before installing the new in-memory prefix. An ambiguous write poisons
both owner and accounting; there is no automatic repair/truncation. On Unix the
new file's parent directory is synced; Windows currently has the same explicit
lack of a directory-fsync guarantee as the existing owner WAL.

Canonical private layouts are Statement342, Progress408, State1092, Bank1228,
logical Call56, Parked128 and Book512. A fixed attempt currently encodes 6,839
bytes within its 8,192-byte cap: call and custody/before bindings, current pending
labels, original statement, captured Result160, candidate whole bank, independent
old/next/result roots, nineteen content refs and exact outer Request2764. Ready
backup (up to the original Key proof bound) stays external; it is not stuffed
into a record. Canonical field aliases, missing presence bytes, reserved padding,
noncanonical transaction compaction and trailing bytes reject.

The log admits at most 128 records, 1 MiB per complete record and 16 MiB per file.
Bodies are capped at 64 KiB before owner publication. Initialization lineage must
fit the same single-record cap. Before proving, the owner reserves four slots
and the derived worst-case bytes for Prepare, Submit, Commit and terminal ACK.
Reopen restores the remaining reservation before returning a pending owner.
Bank/book changes are one Commit record and authenticated references to the
already durable exact Attempt and Submission in its immutable hash chain.

The grammar uses Init, Prepare, Submit, Commit, ACK and Empty records. Replay
checks every legal phase transition and derives bank/book from the actual proof
and QC, comparing the whole canonical recorded bank/book. No persisted success
flag, boolean verifier, cached proof receipt, private bank getter, unchecked
constructor or raw serialization API is exported. Every committed replay again
checks the real underlying product and exact source/setup/Key/profile. Terminal
cold recovery decrypts the original actual product again, never stored rows.
Any missing original, authentication failure, strict tail failure, quota/record
exhaustion or missing proof/QC rejects instead of selecting a fallback.

## Historical Owner82 (v2) verification

Six fast tests passed in 0.07 seconds (36.30 seconds including the rebuild).
They exercise canonical
private codecs, syntax rejection, real AEAD/writer round trips, wrong authority,
strict truncation, shared quota poison, preserved durable prefixes, partial
writes and lost fsync acknowledgement. The ledger workflow checks Parked,
another client's End and exact terminal ACK. These tests
claim no proof-positive result from model state.

The separately run ignored owning gate passed in 585.77 seconds including Cargo
startup. It requires `DCS_PEER_EXE` and uses one public
BFV setup, original custody and independent OS FHE peer: genuine Bootstrap,
Begin, input16/Core896, actual remote FHE/output118, distinct weighted signatures,
Result160, atomic fsync, lost acknowledgement, cold full proof/QC replay,
Done-only decryption, ACK and actual End815/QC. It reports phase intervals and
never substitutes a fixture answer. Its three-key QCs are explicitly local
mathematical fixtures; it does not claim four-validator network agreement.

The fixed-source WAIT/ordinary End/resume, SKIP LOCKED and NOWAIT workflow is now
covered by the v3 Driver gate. Parked RollbackTo/cancellation, deadlocks, EPQ,
general SQL/schema/MVCC/writers, Session/PGwire, delegated rights and general
latest-head/lease admission remain unfinished; existing capability guards stay
closed. This gate does not cover every savepoint/error scenario.

## Closed network Driver source

The additive [network Driver](host/network/README.md) consumes this actual Owner,
uses its SAME ingress/quota/ProofGate and the real remote product route, uploads
exact saved public premises, independently checks one weighted QC and then calls
actual Owner completion. Waiting is owned; terminal Outcome is borrowed only
after every worker/watcher joins. The private shared Proposal path preserves
public submit/WAL/profile contracts and mines bounded chunks before full-current
publication checks. The current owning network filter passed 17 tests (one heavy
case initially ignored), and strict all-target storage-client Clippy passed.
The full v3 gate supplies bounded network evidence; earlier Owner82 and
compile-fail records keep their own scope. Session remains a separate boundary.
