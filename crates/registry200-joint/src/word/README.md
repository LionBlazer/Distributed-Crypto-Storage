# Immutable SourceVersion and Word journal

This distinct application composes genuine StateCertificate/Word EMPTY265 and
Control309 native proofs with the owner-authorized version journal. It is one
step toward the new SQL proof route, not a SQL, freshness or lock capability.
Predicate is rejected: its eventual admission must include the original DATA,
fused Query and actual FHE product, with assessed cryptographic security. A Word
predicate proof by itself cannot authorize a result or a lock here.

The public [`predicate` packet codec](PREDICATE-PACKET.md) defines the complete
bounded evidence grammar needed before that Joint branch can be implemented.
`PredicatePacket` contains original public request/output bytes and all six
proofs. `BorrowedPredicate` reconstructs its metadata against an independently
retained Source; it accepts no caller-supplied theorem or association digest.
Parsing and `expected(&WordExpected)` perform no native proof verification,
authorization or freshness check. This stage changes no Lane, application
contract digest or Predicate admission rule, and adds no RPC or accepting
callback. Existing Predicate rejection remains in force.

`Descriptor` owns complete independently installed SourceVersion metadata,
network and distinct source/control shard IDs. DCSWAD01 encoding includes both
full heads and packets, C_key and C_state, with canonical bounded decoding. Its
application identity pins all proof profiles and these exact bytes; equal
version_id with another C_state is a different installation. `Application::new`
requires a matching independently authorized Genesis and exact sorted initial
shards. DCSWCH01 control heads are distinct from all earlier registry families.
The Source shard cannot change. Bootstrap changes Pending to Active; subsequent
controls retain enrollment and prove the original full old/next registry roots.

`Request` binds application, parent, independent owner nonce, enrollment and all
original Word claims. DCSWRQ01 has 368 bytes, including canonical Goldilocks
fields. `Evidence` bounds and frames detached real proofs under DCSWJE01. A
bootstrap carries Source and EMPTY proof; a control carries one native Word
proof. Frames contain no accepting flag. `OperationId` is an unverified full
request/evidence association; callers must retain their original intent, rather
than derive an expectation from a responder's proposed bytes.

`Verifier::new` genuinely verifies the immutable Source and independently creates
the public Word receiving setup. It retains only the private move-only Source
mathematical capability and public setup, not proof bytes, randomness, private
openings or per-operation verdicts. Every control creates its expectation from
that original verified Source and the actual journal parent, then runs the native
Word verifier. The bootstrap also independently verifies its attached Source and
EMPTY proof. Retaining an immutable theorem proves no latest network head.

`check` verifies historical mathematical consistency with an independent operation
pin. `check_block` first uses the Journal's real owner signature, body/header/work
checks. `prepare_import` exposes an exclusive unpublished Journal handoff; dropping
it changes nothing. A future finality boundary must validate an independently
current quorum before committing and using it for locks. `VerifiedOperation` has
private fields, no Clone or serialization, and grants mathematics only. No public
caller can substitute an accepting verifier callback.

The fixed `TransitionVerifier` implementation supports validator-side Journal
calls: the actual Journal checks owner authorization first, and the callback
always performs native Word verification. Its association ID is metadata, not a
client intent or owner capability; direct trait calls establish mathematics only.
The [durable Word voter](../../../registry200-finality/src/word/README.md) is the
separate owner of consensus, signer WAL, quorum and durable floor admission.

Direct dependencies are [registry200-proof](../../../registry200-proof/README.md)
for immutable Source and exact Word proof contracts, compact-store for canonical
public commitments, SHA2, p3-field and [version-journal](../../../version-journal/README.md)
for owner/body/header and pending import ownership. The predicate codec directly
uses [Gold Formation](../../../bfv-ciphertext-formation/src/gold/README.md) for
the original DATA/query metadata and [Gold public input](../../../bfv-query-core/src/gold/README.md)
decoding through the `gold-evaluator` feature. Its normal dependency edge does
not enable `gold-owner` or acquire a secret key, private mask or decryption API.
No old SourceSpec, Key33,
product stream or historical finality token is reinterpreted. There is no current
QC, weighted finality, durable floor/reopen, network SQL or GUI acceptance path.

The actual Source/bootstrap/Begin/owner handoff and rejection cases passed the
[native validation](VALIDATION.md). Its component timings are not full SQL times.
