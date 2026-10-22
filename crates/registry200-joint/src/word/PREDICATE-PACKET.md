# Complete unverified Predicate packet

Public `word::predicate` owns one bounded grammar for the original public
DATA/Word/Query/FHE evidence needed by a future Joint Predicate operation.
`PredicatePacket` owns encoded unverified bytes; `BorrowedPredicate` parses
borrowed bytes against an independently retained Source. Neither type is a
mathematical result, journal transition, current-head receipt or lock authority.
The existing Joint Predicate branch remains closed.

## Wire and ownership

The `DCSWJP01` packet has a fixed384-byte header:

| Byte offset | Field |
| --- | --- |
| 0 | Eight-byte magic |
| 8 | Fixed packet profile SHA256 |
| 40 | Complete packet length, LE64 |
| 48 | Original DATA request nonce, 32 bytes |
| 80 | Complete KeyBinding29, each word LE64 |
| 312 | Query vector commitment4, each field LE64 |
| 344 | Eight payload lengths, each LE32 |
| 376 | Eight reserved zero bytes |

Eight ordered payloads follow:

1. The literal original `GOPREQ01` public request, with its nonce, ordered
   DATA/Query ciphertexts and protected input binding.
2. The candidate original Ct3 output.
3. StateCertificate evidence for the immutable Source version.
4. The original Role3 version-encoding frame.
5. Dense DATA Formation evidence.
6. Word Predicate evidence.
7. Fused Query Formation evidence.
8. The full product arithmetic certificate.

The first25 KeyBinding words must fit u32, its last four and all four Query
vector words must be canonical Goldilocks values. Reconstruction also checks the
fixed parameter digest in KeyBinding. The DATA nonce must be nonzero.
Each payload must satisfy its owning profile's bounds; the complete packet is
capped at `version_journal::MAX_BODY_BYTES - 4096`, reserving space for the
surrounding signed operation. All six proofs are mandatory. Exact framing,
canonical fields and complete EOF are structural requirements, not evidence of
valid arithmetic. Original request and Ct3 parsing retain their own canonical
ciphertext/residue checks and perform no FHE computation. No private key, mask,
Stmt96 opening, salt, checked flag,
supplied proof theorem or caller-selected association digest is encoded.

The normal SQL producer's `ProvedPublicQuery::packet` packages its same original
request, Word and fused Query evidence with the matching DATA metadata, the
caller's three immutable proof frames and actual product response. It exports
unverified evidence only. The packet introduces no additional evaluator,
simulation route, owner-private premise conversion or network service.

## Independent reconstruction

The receiver supplies its own complete Source expectation. It must not install
that expectation merely from this packet or a responder's claims. Parsing uses
the original Role3 `BorrowedFrame` header to obtain Cw, then derives the original
encoding statement from that Source and all29 canonical KeyBinding words.
The header's Cw is still unverified until the genuine Role3 proof is checked.

The parser reconstructs the original DATA request from the recorded DATA nonce
and the literal first ciphertext in `GOPREQ01`. The existing DATA composition
derives its complete association, Cw/Cs contexts, roots and binding from the
original Source/Role3 metadata. That full binding must equal the one retained by
the original `GOPREQ01` request. A matching version tag or freely supplied hash
cannot replace those derivations. The Query vector and candidate output remain
unverified public endpoints.

`expected(&WordExpected)` derives the normal complete `word::read::Expected`
from those reconstructed endpoints and an independently selected Word
expectation. It binds the original request's context to
`SHA256(WordExpected::binding())`, preserving the full original Word association.
The caller must obtain the Word parent/old root from the actual authorized
journal state. This pure metadata operation neither authenticates that parent
nor proves it is the current network head.

Parsing does not invoke a proof verifier. Actual receiving must subsequently
call the original full `word::read::verify` with all six evidence frames and
this independently reconstructed expectation. Successfully decoding a packet,
constructing its expectation, checking TLS or checking the owner's signature is
insufficient. The codec accepts no alternate verifier or serialized verdict.

## Integration boundary

This grammar is a prerequisite for carrying the complete original public
argument in a real journal candidate. It does not change `Lane`, the Word
application contract digest, `TransitionVerifier`, admission or finality policy.
No RPC, new accepting callback, latest-head oracle or durable registry update is
added. A later actual Predicate branch must join full native receiving to the
original authorized journal parent and fresh weighted agreement before granting
SQL/Result160/lock authority.

The current Source/Word/DATA/Query hiding suite retains its individual native
128-bit policies. The144-bit floor belongs to the separate historical
SHA512/WHIR backend; neither is a completed security assessment of this combined
protocol. Product arithmetic remains conditional on its published classical
random-oracle model. This packet claims no new composed cryptographic security,
full-query500ms result or production-peer memory bound. It changes no underlying
proof relation, timeout, resource fuse or accepted proof format.

Direct dependencies are the original Word/Source/DATA composition and Role3
frame parser in `registry200-proof`, public Gold request decoding in
`bfv-query-core/gold-evaluator`, metadata/bounds in `bfv-ciphertext-formation`,
canonical original Ct3 parsing and wire identity in `bfv-unrelinearized-product`,
canonical public commitments, SHA2, p3-field and the journal's body limit. The
normal dependency direction introduces no `gold-owner`, secret opening,
decryption, fixture generator or application-policy dependency into a core
cryptographic library.


## Executed validation, 2026-10-22

Based on `8f775c7170f8aff87804cb1eb7cd0d343c40c89b`, the normal compiled SQL
consumer exports a genuine packet, reparses it with independently retained Source
and Word metadata, and invokes the full native six-proof receiver. The protected
owner completes only from that real checked public result; all4096 decrypted
coefficients match the independent oracle. The existing retained-DATA and
owner-private cases also remain covered.

The five owning `word_query::` cases passed. New packet cases reject short and
trailing frames, all eight hostile advertised lengths, bad profile/total/reserved
bytes, noncanonical key/vector fields, missing mandatory proof, a foreign Word
expectation, and changed C_state with the SAME Source version tag. A separate
mutation of each of the six actual proof payloads passes only structural parsing
and fails the actual full native receiver. No decoder success is treated as a
proof verdict. Independent read-only review found no new codec/association defect.

One genuine packet was26,326,384 bytes, below the unchanged32MiB body ceiling
with the4096-byte reserve. Encoding, parsing, full cold six-proof verification
and client decryption took2132.934ms. This interval excludes proof production,
transport, current-head agreement, owner authorization, consensus and locks;
it is not a full SQL query time. The normal prepared-query production/product/
retained-DATA receiving/decryption interval in the same process took2678.080ms.
The complete500ms SQL/locking target remains unmet.

The source/image-pinned release/MSVC Rust1.99.0 capture used native CPU,
locked/offline dependencies, Cargo jobs2, Rayon budget2, the unchanged120s and
1792MiB fuses and20ms sampling sleep. No build or other heavy test ran during
capture. The five cases took31.69s (process lifetime31702.784ms), with no faults,
forced cleanup or surviving task children. Sampled working-set/private peaks
were647,368,704 /668,143,616 bytes; OS peak working set was647,692,288. These
scoped observations do not establish production-peer memory or latency bounds.

The generated receipt is not committed:
`.local/word-cmd-native-r450-storage-client-observe-tests/result.json`, SHA256
`D82F9F09568D9A4FEF36089FBC15B1B65DFE7B8409416BE2A2970B9E897CB909`.
Its27,192,832-byte test image SHA256 is
`FFE620F7516C2476215319D9B2CF877224C7FF69316C039606AC1D56F3DD9E66`.
Strict all-target Clippy passed for Joint and the `word-query` client; all five
client compile-fail examples, formatting and local documentation links passed.
The normal dependency feature tree independently reports `gold-evaluator` and
absence of `gold-owner`/storage-client in Joint's dependency direction. The only
lockfile change adds the existing product library as a direct local dependency;
no dependency version changed.

Reproduce the affected behavior with
`cargo test --release --locked -p storage-client --features word-query --lib word_query:: -- --test-threads=1`.
This codec change does not alter the journal contract or accepted lanes; the
expensive weighted-finality/process recovery gate was not repeated. Actual
Predicate consensus and its security/freshness/owner lifecycle obligations remain
open; no admission or production timeout was relaxed.
