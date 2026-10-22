# Originating-owner Word control

The optional `storage-client/word-control` boundary owns the original owner's
in-memory private Registry208 bank, controller/enrollment openings, signing key,
closed Word History and fixed Control prover setup. It prepares genuine native
Control transitions and installs their private candidate bank only after the
original operation's native/owner/ancestry/weighted-QC checks succeed. It adds no
Session, PGwire, GUI, Predicate, FHE-result or SQL/row-lock acceptance route.

`Owner::new` consumes an independently installed History, the actual owner key
and guarded private Material. It requires an active checked historical parent,
the exact Genesis owner key and a canonical Registry208 opening matching that
parent's native-proof/QC-checked commitment. The root check opens an already
verified commitment; it is not a substitute for the original proof or QC.
It also opens the original Enrollment64 commitment using that same checked
Source/header, table IDs, controllers and enrollment salt. Those hash comparisons
open existing native-proof/QC commitments; they do not replace proofs. No mutable
History, bank or key getter exists.

`Owner::prepare` accepts the original Control opcodes0/3/4/5/6 and a protected
Source opening. It pins the complete installed Source, exact parent, enrollment
and old root, then derives the proposed next bank and Result160 through the
original witness recipes. It uses fresh fallible OS entropy for the public
owner nonce and secret next-bank/command/result salts. Each field draw has eight
canonical rejection attempts and fails closed. The original enrollment salt is
retained. The Role-only prover holds public preprocessing, not private inputs or
operation verdicts. Every operation produces a new native argument.

The exact request/evidence/Body is signed with the consumed owner key. Header
metadata and difficulty come from that SAME closed History through its actual
Journal target rules; `Mining` supplies only timestamp, current-time claim and a
finite mining-attempt budget. A peer still validates its own actual clock/rules.
Candidate metadata and submission ACKs are not verification or agreement.

Only one private draft may exist. It retains the original signed candidate,
unpredictable owner nonce, intent identity, complete Word expectation and guarded
candidate/result openings. Dropping a Pending handle retains that draft in Owner;
`resume_pending` returns the exact same bytes without drawing another nonce.
Preparing another mutation fails until confirmation. A rejected QC retains the
old bank and draft. `Pending::confirm` accepts no replacement response Body,
verifier or accepting flag: it checks the retained original candidate through
the actual History and matches the full native Word binding before replacing
the private bank. An impossible post-History mismatch poisons Owner. Success is
one-shot; a second confirmation fails. `Confirmation::result_words` exposes only
that confirmed Control operation's guarded original Result160 opening.

This records the exact own ordered mutation. It is not a general latest-head
oracle or permission to accept a read/lock on historical data. A later concurrent
decision still requires lineage/private-state catch-up. Predicate opcodes remain
closed. Dropping the whole Owner after submission does not cancel a network
decision. Secret clearing is best effort, not a claim about every temporary
stack/allocator copy.

## Encrypted immutable recovery records

`RecoveryKey` consumes an independently custodied high-entropy wrapping key; it
has no Clone, Debug or export. `RecoveryIdentity` names an owner-selected record
family. `Owner::checkpoint` encrypts the private bank/controller/enrollment
material and, when present, the EXACT original signed candidate, intent, full
Word expectation and guarded next/result openings. Only ciphertext is written
through the existing immutable [EvidenceStore](../../../protocol-storage/README.md).
The complete record is bounded by its unchanged32MiB blob cap before encoding or
allocating private buffers. DCSWOR01/WOPRIV01, full original Binding, record family,
profile and length are authenticated with XChaCha20Poly1305 and a fresh OS nonce.
Source/Word/finality/wire profiles and exact resource/grammar limits enter the
recovery profile. This is a distinct encrypted record, never a serialized verdict.

`Owner::restore` requires an independently installed and natively replayed History
at the record's EXACT context, parent, slot and decision, the actual owner signing
key, wrapping key, record family and independently retained exact BlobId. It
checks complete file identity/length/EOF and AEAD, then reopens the bank and
enrollment commitments against real History. A pending operation is checked anew
through `History::check_operation_candidate`: genuine owner/header/ancestry/native
proof and original intent. The full native expectation, next bank and Result160
must match the verified argument. No query is reexecuted, nonce regenerated or
accepting flag decoded. Restoring an idle confirmed record permits the next real
Control operation from that checked private bank.

`prepare_stored` syncs the encrypted pending record BEFORE exposing its candidate;
an I/O failure discards only the new unexposed draft. `resume_stored` reseals the
same retained/restored operation without changing its original request or proof.
The caller must independently retain its returned record identity before send.
`StoredPending::confirm` requires the original full proof/QC confirmation, then
syncs the new encrypted confirmed bank BEFORE exposing Result160. An uncertain
post-confirmation storage failure poisons Owner; the original pending record can
still be restored under its original replayed parent and independently confirmed.

Record selection, key/signing-key custody and a durable latest-record/anti-rollback
floor remain caller obligations. A valid older ciphertext and an older replayed
History do not establish currentness. Confirmed records retain the bank, not an
exactly-once completed-reply log; keep the original pending record and real QC when
recovery of that reply is needed. No record garbage collection is added. The
store's documented Windows directory-entry power-loss limitation remains. These
snapshots do not provide a complete owner vault, general fresh-head barrier,
process/power-failure theorem or SQL/row-lock admission.

| Direct dependency | Responsibility |
| --- | --- |
| [Original Word](../../../registry200-proof/src/registry_progress/word/README.md) | Fixed private witness recipes, canonical Registry208 commitment and native Control proof |
| [Word journal](../../../registry200-joint/src/word/README.md) | Exact owner-authorized request/evidence association and control heads |
| [Word History](../../../registry200-finality/src/word/README.md) | Independent immutable Source, original intent, native/owner/ancestry/QC and mining metadata |
| [version-journal](../../../version-journal/README.md) | Owner signature and real header/target/Body grammar |
| [protocol-storage](../../../protocol-storage/README.md), XChaCha20Poly1305 and SHA2 | Bounded immutable encrypted records, independent file identity and authenticated private snapshot grammar |
| Ed25519, OS entropy and zeroize | Actual signature, fresh nonces/salts and scoped private buffers |

The [real four-process consumer](../../../../apps/dcs-peer/tests/word_finality.rs)
uses this normal SDK path for BEGIN and then END from the confirmed private bank.
It rejects foreign owner/controller/enrollment openings, old QCs and a second
pending operation. It drops and recreates the whole Owner/store, restores the
identical candidate, rejects wrong key/family/tag and authenticated false next/
result/native-proof contents, then restores the confirmed bank and performs END.
It replays all three decisions after restarting validators. This tests actual
file/Owner lifecycle; it does not kill an OS owner process or test power loss.
[Measurements and scope](../../../peer-runtime/WORD-FINALITY.md)
do not establish the500ms full SQL/FOR UPDATE goal.
