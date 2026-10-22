# Word receiving and durable voting

This distinct application plugs the genuine immutable SourceVersion and original
Word journal into the existing private durable consensus engine. It owns actual
work-weighted voting, candidate verification, signer WAL, decision WAL and the
durable journal floor. It is not a network actor, a latest-head oracle, Predicate
admission, an SQL result or a row-lock lease.

`Binding::new` pins independently installed Word descriptor/owner Genesis,
consensus Rules, the real bootstrap-work validator roster, and a bounded public
Source certificate. The certificate is retained as immutable shared public bytes;
its length/hash enter the binding identity. The descriptor commits the complete
Source heads/packets/C_key/C_state. Binding construction is metadata only. Every
participant create/open independently verifies the Source natively before its
fixed Word verifier becomes usable. No proof-success flag, owner key or secret
opening is retained in Binding.

`History::new(binding)` is the signer-free client receiver. It independently
verifies the installed immutable Source and retains the fixed native Word public
receiving setup. It owns its in-memory Journal, current Context, selected floor
and exact last historical context; no mutable Journal or caller-supplied verifier
is exposed. `apply` follows other historical work through actual owner, Word,
ancestry and weighted QC checks. `apply_operation` additionally requires an
`OperationId` retained from the original request/evidence before network submission.
It returns a move-only `VerifiedOperation` containing that fresh mathematical
receipt and the checked historical parent. Creating an intent pin from a peer's
reply cannot establish that it was the caller's requested operation.

Every fallible QC/successor/native/intent/control check precedes publication of
the exact unpublished import. An unexpected floor failure poisons the receiver.
The latest semantic retry is rechecked read-only under its retained real prior
Context, including owner/native verification; an ancient QC or conflicting
decision cannot roll back history. No operation verdict is cached. Empty work
may advance historical metadata but cannot mint an own-operation receipt.
`checked_parent` and `context` expose historical observations. History is not
durable owner state, a global currentness barrier or a SQL/row-lock grant.

`History::candidate_header` derives authoring metadata from its exact floor and
the real Journal target history after checking the transition owner signature.
It does not accept a caller-selected parent/target or grant publication/proof
authority. The [client control owner](../../../storage-client/src/word_control/README.md)
uses this boundary before actual bounded mining and QC-based private confirmation.

`Candidate` and `Checkpoint` use DCSWCV01/DCSWCQ01. Word Rules have their own
algorithm identity selected before Work bootstrap. Old candidate/QC/parent types
and Rules cannot be relabeled as Word. The bounded `CandidateBlock` is shared
untrusted transport data only. DCSWFL01/DCSWFR01/DCSWFM01 and separate file/hash
domains isolate durable floor/metadata from the earlier applications.

`DurableFinality::{create_participant,open_participant}` own the actual exclusive
signer and shared participant quota. `import_candidate`, `propose`, `receive`,
`receive_checkpoint`, `checkpoint_after`, `timeout`, `on_timeout` and `outbound`
delegate to the same closed engine, with a fixed Word application variant. The
engine never receives a caller-supplied accepting verifier. Its internal control
state is a tagged Registry/Word enum, not a cast between proof families. Every
Word transition uses the real owner/body/header/native verifier. Source is an
already verified immutable theorem; every Word operation is independently checked.

The unchanged engine persists decisions before floors, floors before advancing,
precharges writes, poisons after uncertain I/O, and replays actual application
proofs on reopen and historical duplicates. Its existing same-drive handoff is
bound to the exact state pointer, context, candidate, parent and floor and never
escapes the drive. Nothing serialized can restore a proof verdict. Corrupt tails
are rejected; they are not repaired or adopted. Four control files remain owned
by the existing participant storage lifecycle.

`finalized_parent` exposes private-constructor historical full-proof/QC metadata.
It does not attest global currentness after return and cannot authorize SQL or
locks. The fixed current roster still assumes less than one third of its confirmed
work weight is Byzantine; open roster changes remain unfinished. The
[Word TLS host](../../../peer-runtime/WORD-FINALITY.md) now supplies independent
processes with native proof/QC/reopen checks. Network scheduling remains outside
this library. Predicate/FHE product admission and final client
SQL completion are not enabled here.

Direct dependencies are [registry200-joint Word](../../../registry200-joint/src/word/README.md),
the private `closed` engine, `pins`/`participant`/`store`, existing version-journal,
work-finality and protocol-storage, plus SHA2 and Ed25519. Public Source bytes are
installation input; bootstrap/operation bodies are charged by the durable journal.
No GUI, fixture evaluator, local SQL fallback or external consensus network is used.

The four-party native proof/voting/reopen and fault cases passed the
[owning validation](VALIDATION.md). The recorded test intervals are not SQL times.
The owning [History tests](history_tests.rs) additionally cover source installation,
invalid owner/native proof even with real fixture QC signatures, invalid QC,
foreign binding/previous decision, independent intent, unpublished-state
preservation, semantic retry and ancient-QC rejection. The real process consumer
and timings are recorded in the [Word TLS record](../../../peer-runtime/WORD-FINALITY.md).
