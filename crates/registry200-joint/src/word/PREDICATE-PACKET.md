# Complete unverified Predicate packet

Public `word::predicate` owns one bounded grammar for the original public
DATA/Word/Query/FHE evidence used by the closed Joint Predicate candidate path.
`PredicatePacket` owns encoded unverified bytes; `BorrowedPredicate` parses
borrowed bytes against an independently retained Source. Neither type is a
mathematical result, journal transition, current-head receipt or lock authority.
The existing Joint Predicate branch remains closed.

## Wire and ownership

The `DCSWJP02` packet has a fixed416-byte header. The former DCSWJP01 identity is
rejected; there is no old-format fallback:

| Byte offset | Field |
| --- | --- |
| 0 | Eight-byte magic |
| 8 | Fixed packet profile SHA256 |
| 40 | Complete packet length, LE64 |
| 48 | Original DATA request nonce, 32 bytes |
| 80 | Complete KeyBinding29, each word LE64 |
| 312 | Query vector commitment4, each field LE64 |
| 344 | Original DATA encoding commitment Cw4, each field LE64 |
| 376 | Eight payload lengths, each LE32 |
| 408 | Eight reserved zero bytes |

Eight ordered payloads follow:

1. The literal original `GOPREQ01` public request, with its nonce, ordered
   DATA/Query ciphertexts and protected input binding.
2. The candidate original Ct3 output.
3. SHA StateCertificate evidence for the immutable Source version.
4. The SHA Role3 version-encoding frame.
5. SHA dense DATA Formation evidence.
6. SHA Word Predicate evidence.
7. SHA fused Query Formation evidence.
8. The full product arithmetic certificate.

The first25 KeyBinding words must fit u32, its last four, all four Query vector
words and all four Cw words must be canonical Goldilocks values. Reconstruction also checks the
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
the explicit canonical Cw fields to derive the complete encoding statement
from that Source and all29 canonical KeyBinding words. SHA Role3 does not export
Cw in its frame; the packet does not read a statement from a proof header.
Cw remains unverified until the genuine SHA Role3 proof is checked against this
independently reconstructed full statement.

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
construct the SHA `word::read::hash::Verifier` with this independently
reconstructed expectation, then call `verify_and_retain` with all six evidence
frames. Successfully decoding a packet,
constructing its expectation, checking TLS or checking the owner's signature is
insufficient. The codec accepts no alternate verifier or serialized verdict.

## Integration boundary

`Request::predicate` and `Evidence::predicate` now carry the complete argument
in a real signed journal candidate under `Lane::Predicate` (tag2). The common
Joint `Verifier::check` constructs the Word expectation from the retained verified
Source, application Genesis, actual parent and old registry, then invokes the
fixed SHA native receiver. The bounded private receiver can retain an actual
immutable State/Role3/DATA theorem after full native success. Reuse requires the
complete DATA expectation and literal equality of all three proof frames;
Word/Query/product remain fresh native checks on every invocation. Any changed
immutable proof requires full six-proof receiving again. Even genuine mathematics
ends in an unconditional
`RejectedComputationProof` before any `Proof`, `VerifiedOperation` or pending
import can be created. Owner authorization runs first on actual Journal paths.

The existing application contract digest remains unchanged because its accepted
Bootstrap/Control bytes and semantics remain unchanged and Predicate never
succeeds. The candidate grammar has its own packet profile, lane tag and full
operation association. A future accepting Predicate policy must introduce a new
application contract identity covering its full read/packet/security policy,
and establish fresh weighted agreement before granting SQL/Result160/lock
authority. No RPC, new accepting callback, latest-head oracle or durable registry
update is added here.
The accepted Source/Bootstrap/Control paths keep their original proof family.
Their contracts and security obligations are not authorized by the distinct
five-AIR SHA candidate model.

The SHA Source/Word/DATA/Query candidate retains its individual native
128-bit numerical policies. These are not a quantitative composed security
assessment. The144-bit floor belongs to the separate historical
SHA512/WHIR backend; neither is a completed security assessment of this combined
protocol. Product arithmetic remains conditional on its published classical
random-oracle model. This packet claims no new composed cryptographic security,
full-query500ms result or production-peer memory bound. It changes no underlying
proof relation, timeout, resource fuse or accepted proof format.

Direct dependencies are the complete Word/Source/DATA metadata and closed SHA
receiving family in `registry200-proof`, public Gold request decoding in
`bfv-query-core/gold-evaluator`, metadata/bounds in `bfv-ciphertext-formation`,
canonical original Ct3 parsing and wire identity in `bfv-unrelinearized-product`,
canonical public commitments, SHA2, p3-field and the journal's body limit. The
normal dependency direction introduces no `gold-owner`, secret opening,
decryption, fixture generator or application-policy dependency into a core
cryptographic library.


## Executed validation, 2026-10-22

The following record describes the former DCSWJP01 packet and proof family.
It is historical evidence, not validation of the current SHA DCSWJP02 path.

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


## Executed SHA candidate validation, 2026-10-23

The normal compiled SQL public producer and DCSWJP02 packet passed the five
owning `word_query::` cases, including the unchanged owner-private regression.
The exact Joint Predicate case also passed. Both use real encrypted inputs,
native proofs and original product certificates. The client checks all 4096
completed coefficients against an independent oracle after public receiving.
Old and SHA fixtures prepare only their required proof family.

The cases reject the former packet magic, noncanonical Key/vector/Cw fields,
a changed canonical Cw, hostile lengths/truncation/trailing bytes, foreign full
Source/DATA/Word endpoints, each of the six damaged evidence frames, Query replay,
foreign owner and repeated private-material use. A genuine old Word proof cannot
satisfy SHA public receiving; a genuine old Source proof cannot replace the SHA
State argument even though Bootstrap/Control retain their original family.
The original SHA candidate still verifies after those failures. Source review,
staged Rust formatting and unified patch applicability checks also completed.

| Client interval | Milliseconds |
| --- | ---: |
| SHA Word + fused Query production | 345.968 |
| Actual FHE product + certificate | 29.685 |
| Public receiving with retained SHA DATA | 174.183 |
| Owner product completion/decryption | 0.860 |
| Observed prepared-query interval, including overhead | 551.336 |
| Packet encode/parse, cold complete receiving and decryption | 896.633 |

The packet was 26,071,436 bytes, within the unchanged packet ceiling of
32 MiB minus the 4096-byte signed-body reserve. The 551.336 ms interval starts with an already
prepared original encrypted query. It excludes SQL compilation/current-state
preparation, original query encryption and immutable installation. The cold
packet interval excludes proof production.

Joint initial complete Predicate checking took 1066.602 ms;
identical-candidate rechecking took 192.738 ms;
after failed arguments it took 176.882 ms.
A genuinely fresh encryption with different QueryCt, nonce, vector and product
was checked in 167.190 ms using the exact retained
immutable DATA evidence. Word/Query/product remain fresh checks.
The real owner-authorized Bootstrap/BEGIN lineage was established first;
`check_block` and `prepare_import` still rejected Predicate unconditionally and
left the journal count, ancestry floor and old registry unchanged.

The source/image-pinned Windows release probes used `RAYON_NUM_THREADS=8`, one
test at a time, 120 s and 1792 MiB whole-process fuses and 20 ms memory sampling.
Both exited successfully without observer faults or forced cleanup.

| Probe | Sampled working set, bytes | Sampled private bytes | OS peak working set, bytes |
| --- | ---: | ---: | ---: |
| Client (5) | 703,102,976 | 718,962,688 | 707,964,928 |
| Joint (1) | 704,610,304 | 699,359,232 | 704,974,848 |

Local uncommitted receipts and exact successful release images:

- `.local/word-cmd-native-r596-storage-client-observe-tests/result.json`, SHA256
  `D504C4CEDA4FA469CBB4020F50830B0500ABD93E53A3B4860EEE911B4A33ED68`.
  Image `storage_client-c008f05691d9e6a4.exe`, 28,616,704 bytes,
  SHA256 `809EE6451E24BD426831055006D65845D3E07D4BAF842C1EB4262D29A1414718`.
- `.local/word-cmd-native-r598-registry200-joint-observe-tests/result.json`, SHA256
  `23AC927D3E1750D2CCA79A1E8217ABDB37E13DEDB0437829529825CB7A34CBAC`.
  Image `registry200_joint-21214164f83c6b09.exe`, 27,107,328 bytes,
  SHA256 `2D67000E9F4CE8540DC4B4FF5883FE411BC888691C921A7E96319CF6E2F6EAD6`.

These are local mathematical intervals, without transport, fresh weighted
agreement or lock granting. They establish neither composed cryptographic
security nor complete SQL acceptance. The full 500 ms SQL/FOR UPDATE target remains
unmet; no admission guard, timeout, resource bound or old accepted proof family
was relaxed. Strict all-target release Clippy passed for Joint, the word-query
client and registry proof crate. All six client compile-fail interface cases and
the dependency-free requirements mirror test passed.
