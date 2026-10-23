# Immutable SourceVersion and Word journal

This distinct application composes genuine StateCertificate/Word EMPTY265 and
Control309 native proofs with the owner-authorized version journal. It is one
step toward the new SQL proof route, not a SQL, freshness or lock capability.
Predicate remains rejected. Its candidate now reaches the actual journal
verifier, which reconstructs the original DATA, fused Query and FHE product
expectations and initially checks all five SHA AIR proofs plus the original
product certificate. An exact immutable
State/Role3/DATA theorem may then be retained; Word/Query/product are checked
afresh on every call. Successful mathematics still
cannot authorize an operation: composed cryptographic security is unassessed.
A Word predicate proof by itself cannot authorize a result or a lock here.

The public [`predicate` packet codec](PREDICATE-PACKET.md) defines the complete
bounded evidence grammar used by this closed Joint Predicate branch.
`PredicatePacket` uses only the DCSWJP02 identity, containing the original public
request/output, explicit canonical Cw and all six unverified evidence frames.
`BorrowedPredicate` reconstructs its metadata against an independently
retained Source; it accepts no caller-supplied theorem or association digest.
Parsing and `expected(&WordExpected)` perform no native proof verification,
authorization or freshness check. `Lane::Predicate`, `Request::predicate` and
`Evidence::predicate` frame unverified candidates only. The accepted transition
set and application contract digest remain unchanged; no RPC or accepting
callback is added. Predicate cannot return a `VerifiedOperation` or import.

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
proof; a Predicate carries one complete `PredicatePacket`. Frames contain no
accepting flag. Predicate requires nonzero StmtRoot, while bootstrap/control
require zero. `OperationId` is an unverified full
request/evidence association; callers must retain their original intent, rather
than derive an expectation from a responder's proposed bytes.

`Verifier::new` genuinely verifies the immutable Source and independently creates
the public Word receiving setup. At construction it retains the private move-only
Source mathematical capability and public setup, without proof bytes, randomness,
private openings or per-operation verdicts. The later bounded Predicate DATA
retention is described below. Every control creates its expectation from
that original verified Source and the actual journal parent, then runs the native
Word verifier. The bootstrap also independently verifies its attached Source and
EMPTY proof. Retaining an immutable theorem proves no latest network head.

Predicate derives its Word expectation from that same verified Source,
application Genesis, actual journal parent, enrollment and actual old registry.
The original public request must bind that complete expectation. A private
helper uses `word::read::hash::Verifier` for all five SHA arguments and the
original product certificate, or retained receiving with a matching
`data_formation::hash::CheckedData` theorem. The per-query move-only
result is discarded before an unconditional `RejectedComputationProof`. There is no
Predicate `Proof` variant or accepting result construction. Only a later
assessed admission policy may expand the accepted transition set, and that
change must also introduce a new application contract identity.
The new Predicate family neither changes the original Source/Bootstrap/Control
proof contracts nor extends a five-AIR security model to those older families.

The private `predicate_receiving` module owns one in-memory DATA theorem and
literal copies of its three original public proof frames, bounded by the packet
limit. Reuse requires full DATA metadata equality and exact equality of all three
frames. Any changed proof triggers actual six-proof verification. Replacement
occurs only after all native checks succeed; ordinary rejection preserves the
old theorem. Old proof bytes are dropped before replacement copies allocate.
The mutex serializes only this verifier's Predicate checking, with no I/O or
consensus under the lock. Poisoning rejects. No proof hash, persisted verdict,
query receipt, imported setup or current-head assertion is retained.

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
The six-proof Predicate/actual-parent/closed-import cases passed the separate
[closed journal validation](PREDICATE-JOURNAL-VALIDATION.md).

## Compact transport reconstruction

`predicate::transport::compact` removes only the three immutable SHA
State/Role3/DATA frames from original complete evidence. Its distinct DCSWJT01
bytes retain the original full DCSWJP02 header and all lengths; they cannot be
decoded as Journal evidence. The actual Word TLS consumer uses
`Verifier::append_predicate_transport` to copy the exact original public frames
directly from this verifier's single retained `CheckedData` into the eventual
full Body allocation. Full DATA Expected equality, actual cached frame lengths
and all canonical bounds are mandatory. Missing or mismatched cache rejects;
no theorem, query verdict or admission token is imported or exported.

Reconstruction is unverified public serialization. The consumer must match the
original full Body hash and strict owner signature before OperationId and normal
native import. A different valid proof for the same DATA Expected cannot replace
the original signed bytes. All supplied full-frame changes still require native
revalidation; restoration never changes or evicts the retained entry. Predicate
admission remains unconditionally closed, and the durable proof family is unchanged.
