# Next private source-opening relation (not implemented)

This contract is the next dependent experiment after the backend gate. It is not
an implemented relation, selected cryptographic profile or accepting API.
[Requirements](../../REQUIREMENTS.md) remain unchanged. The complete obligations
in [private-lock-source-proof.md](../../docs/private-lock-source-proof.md) and the
independent [finality gate](../../docs/lock-finality-research.md) still apply.

Use a fixed public four-row, one-shard geometry. The actual compact-query format
produces 12 data plaintext bytes and 2,336 index plaintext bytes, each in one
CSTORE page. Data and index packets have 60 and 2,384 bytes respectively. Every
proof consumes both complete packets regardless of predicate or selection, so
this small experiment introduces no selected-page address/count shape.

The public statement must pin an experimental profile, immutable data/index
heads, an independently fixed AEAD-key commitment and a fresh hiding commitment
to the opened logical relation. The key, decoded rows, TableId/RowIds and opening
salts remain private. The key commitment must fix the actual key: CSTORE's
independently random `key_domain` is not such an anchor. A freshly salted binding
commitment needs its own reviewed construction and canonical encoding; a bare
hash of guessable rows is insufficient. None is implemented by the backend gate.

Exact constraints must establish the existing CSTORE leaf/snapshot SHA rules,
canonical geometry/revisions, the actual 106-byte AAD, HChaCha20 derivation,
ChaCha20 counter-zero Poly1305 key and counter-one stream, Poly1305 clamping,
modulo-2^130-5 arithmetic, padding, encoded lengths and tag, then the complete
index/header/row-ID interpretation. SHA padding/chaining and integer carries must
be constrained, not supplied as trusted witness-generation outputs.

Source-derived work for these two actual packets is 46 SHA compressions for both
snapshot roots, two HChaCha evaluations, 40 ChaCha blocks including key derivation,
and 163 Poly1305 blocks. This excludes commitments, index semantics and all BFV
work. It is operation counting, not a trace size, speed prediction or RSS bound.
The pinned P3 tree provides SHA compression; no matching XChaCha20Poly1305 AIR
was found there. Its exact constraints need an independent adversarial review.
RustCrypto source is an oracle/specification reference, not a circuit compiler.

The owner-side witness custody boundary belongs beside compact-store's private
Owner key; do not add a generic key exporter, serializable witness or secret log.
The backend consumes bounded private witnesses and returns only reviewed public
bindings/proof. No production module may depend on this experimental workspace.
Availability, recovery and genesis approval of key/control commitments require
separate design. The first experiment uses generated, explicitly non-secret test
fixtures and supplied immutable heads, without live grant/publication.

A successful source opening still cannot accept an encrypted SQL answer. Subsequent
composition must constrain the same canonical semantic plan and complete ordered
candidate set; tie the same private IDs to complete old/new lock state, conflicts,
own upgrades, OFFSET, LIMIT and exhaustion; and bind original fields/slots to the
exact original BFV job. Public canonical BFV conversion can use the existing
independent `circuit_request` boundary. Private input formation must constrain the
real encoding and all five moduli with one coherent secret/error polynomial,
not independently chosen residues or a precomputed plaintext answer. Honest
key/seed sampling and noise/security assumptions remain explicit. Existing real
peer FHE execution and arithmetic verification stay mandatory.

Negative cases must alter tag, nonce, address, page revision, key/domain/head,
SHA chain/padding, index tail/coverage/RowId, commitments/openings and semantic
plan/request identity. Later composition must reject omitted candidates/conflicts,
false SKIP, another BFV request/output, replayed transaction generation/sequence
and unauthorized changed pages. Tests must reach the constraints with malicious
traces, rather than only test honest-generator rejection. Finishing those relations
still does not resolve finalized-parent/committee safety or PostgreSQL WAIT/death
recovery. No metadata-only lock receipt substitutes for any of these gates.
