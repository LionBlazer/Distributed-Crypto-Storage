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
Enrollment/controller consistency is also enforced by the original private
witness recipes before proving. No mutable History, bank or key getter exists.

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
closed. In-memory draft retention does not provide process-crash recovery,
durable key custody, an anti-rollback owner floor or a sealed recovery capsule;
these remain necessary before full SQL admission. Dropping the whole Owner after
submission does not cancel a network decision. Secret clearing is best effort,
not a claim about every temporary stack/allocator copy.

| Direct dependency | Responsibility |
| --- | --- |
| [Original Word](../../../registry200-proof/src/registry_progress/word/README.md) | Fixed private witness recipes, canonical Registry208 commitment and native Control proof |
| [Word journal](../../../registry200-joint/src/word/README.md) | Exact owner-authorized request/evidence association and control heads |
| [Word History](../../../registry200-finality/src/word/README.md) | Independent immutable Source, original intent, native/owner/ancestry/QC and mining metadata |
| [version-journal](../../../version-journal/README.md) | Owner signature and real header/target/Body grammar |
| Ed25519, OS entropy and zeroize | Actual signature, fresh nonces/salts and scoped private buffers |

The [real four-process consumer](../../../../apps/dcs-peer/tests/word_finality.rs)
uses this normal SDK path for BEGIN and then END from the confirmed private bank.
It rejects foreign owner keys/openings, old QCs and a second pending operation,
resumes an identical candidate, and replays all three decisions after restarting
validators. [Measurements and scope](../../../peer-runtime/WORD-FINALITY.md)
do not establish the500ms full SQL/FOR UPDATE goal.
