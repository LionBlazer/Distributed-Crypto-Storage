# Fixed whole-pair private AEAD byte-opening candidate

Status: the frozen R5 candidate passed release build, strict Clippy, eight fresh
security analyses, all 47 serial tests and one genuine whole-pair proof followed
by verification. [PAIR-OPENING-VALIDATION.md](../../PAIR-OPENING-VALIDATION.md)
records exact scope, failures, artifacts and external observation limits. This
module is a private consumer inside the [standalone experiment](../../README.md),
with no production accepting API, Owner-key exporter/importer, wire format or SQL
connection.

The candidate links one private master key to authentication/decryption of BOTH
complete CSTORE packets, then binds every decrypted byte to a fresh salted
commitment. Its explicitly known nonsecret fixture key/plaintext occupy private
witness columns. This exercises a bounded private-in-proof relation;
it is not evidence of production secrecy, erasure, key anchoring or finality.

## Owned boundaries

| File | Responsibility |
| --- | --- |
| `statement.rs` | Complete canonical core audits, exact independent heads/geometry, immutable public values and canonical commitment decoding |
| `fixture.rs` | Known nonsecret RustCrypto-encrypted source fixtures and fixture-only canonical writer |
| `schedule.rs` | One public height512 schedule, 42 jobs, 163 MAC blocks and exact absorb/capture rows |
| `air.rs` | All cross-primitive, immutable-bank, output-buffer, header and salted-sponge constraints |
| `trace.rs` | Separate nonserializable/non-Clone private witness and genuine shared-arithmetic trace generator |
| `poseidon.rs` | Internal native-equivalent pinned width12 permutation gadget |
| `commitment.rs` | Two exact fixed-length, domain-separated encodings and native fixture oracle |
| `tests.rs` | Native/oracle equivalence, full-source admission, genuine whole relation and rebuilt inconsistent-component proof cases |

The only project-library edge is experiment -> [compact-store](../../../../crates/compact-store/README.md)
for the existing complete canonical parser/root checker. There is no reverse edge.
The private backend distinguishes public `PublicStatement` from the old
self-generating public `PrimitiveStatement`. `prove_with_trace` checks exact public
values before invoking a witness factory. No verifier-only fake trace/panic method,
key-export callback, extra proof backend, hidden cache or recursive relation is used.
Existing Cha and Poly wrappers share arithmetic/generation helpers with this
module; their existing 33 genuine/adversarial test names and cases are preserved.

## Exact public source and private links

The fixed public footprint is 172 data-image bytes and 2496 index-image bytes:
112-byte heads plus one 60-byte/2384-byte packet. Data layout is exact
`CQAGEAMOUNT00001`, width3, rows-per-page256, rows4. Index layout is exact
`CQAGEINDEX000003`, width1, rows-per-page4096, rows2336. Both independently expected
heads must have the same database/key domain. The core parser audits every public
packet/revision and complete root before AIR construction. Canonical public SHA
runs outside AIR; no unproved private SHA is substituted.

There are exactly **691 public fields**: profile8 + request8 + both heads56 + both
packets611 injective little-endian u32 words + C_key4 + C_open4 canonical fields.
Digest decoding rejects u64>=Goldilocks modulus rather than reducing it. The same
checked immutable source creates the AIR's public constants; all actual public
values enter the SDK transcript and are constrained equal to those constants.
Schedule tables are verifier-owned, never supplied by the proof. The pinned SDK's
periodic-count transcript binding alone is insufficient to authenticate arbitrary
periodic contents.

Private immutable K256/SK512/PK512 bit banks and two four-field salts copy on EVERY
nonlast transition. Seven 788-column Cha lanes execute all 42 H/Cha jobs with the
canonical constants, both packet nonces and exact counters. All 512 output bits
are linked at each CURRENT boundary and retained until the next output boundary;
copy is skipped only on the transition whose NEXT row is a boundary. Normal Cha
uses its SAME initial-state feedforward; H has no feedforward. Counter0 first32
bytes are the exact Poly key. No keystream, key, salt, decrypted word or intermediate
state is a public value or periodic. Only the specified binding commitments depend
on private values in the public statement.

MAC uses 7 separately padded AAD blocks, 1/146 separately padded ciphertext blocks
and LE64(106)||LE64(12/2336), with full hibit2^128 for EVERY block. The packet
revision, not global revision, is AAD. The two MAC states reset independently and
final tags compare the actual public packet tags. Canonical H<p is checked even on
padding rows. Local cyclic carry equations remain below2^58, not a 130-bit field
equality; tag addition is modulo2^128.

Plaintext is actual public-ciphertext XOR authenticated counter1+ output: data3
words then index584 words. Only12 data bytes and32 bytes of final index counter37
are consumed. Index first28 decoded words equal the exact public data head. All
2348 bytes enter C_open exactly once. This is a BYTE-opening and header link,
not an age-index/RowId/coverage/uniqueness/SQL/BFV/control proof. The fixture's
remaining index bytes deliberately make no logical-index validity claim.

## Candidate fixed commitments and schedule

The construction/assumptions below are experimental candidates, not selected
production cryptography or an independently certified 128-bit commitment scheme.
Use pinned `default_goldilocks_poseidon2_12`, rate8/capacity4/output4, overwrite
absorption, and explicit fixed zero padding. Domains are exact16 bytes:
`DCS/KEY/PAIR/v1!` and `DCS/OPEN/PAIR/v1`; version1.

C_key is26 fields +6 zero fields: domain4/version1/key length1/database4/key-domain4/
K8/rho_key4. It must be fixed independently BEFORE this request; random key_domain
alone is not an anchor. The fixture fixes its known nonsecret key anchor before
assembling the request. Production approval, key rotation, availability and recovery
remain unimplemented.

C_open is674 fields +6 zeros: domain4/version1/lengths2/profile8/request8/heads56/
C_key4/rho_open4/all587 plaintext words. Prefix87 is deliberately unaligned. There
is no padding of individual stream chunks. Four uniform field salts use pinned
rejection sampling from independently OS-seeded CSPRNG streams, not u64 reduction.
Entropy is4*log2(p), approximately256 bits. rho_key is stable per anchor;
rho_open is freshly sampled for each fixture opening and independent of PCS seeds.
Witness/SDK buffers are not claimed erased.

C_key absorbs at rows0..3, C_open blocks0..9 at4..13, then blocks10..14 at81..85,
15..28 at162..175,29..42 at243..256,43..56 at324..337,57..70 at405..418 and
71..84 at486..499. Exactly two private carry fields retain payload33/34,145/146,
257/258,369/370,481/482 at CURRENT rows86/176/257/338/419. Previous-copy is skipped
by NEXT capture, not current capture. Capacity resets at rows0/4; all other active
absorbs retain the prior capacity, while eight rate fields overwrite. Gaps retain
the complete checkpoint and use zero permutation inputs. Final outputs equal the
public commitments at rows3/499. All permutation equations are unconditional,
including the initial external MDS and exact4/22/4 rounds. Separate input registers
prevent the S-box relation from substituting higher-degree XOR expressions.

## Resource and validation gates

Source accounting is W11079/T512/r5/blowup8: trace45,379,584B, masked trace90,800,128B,
main LDE726,401,024B. The one reused512x512 public selector table adds2,097,152B
plain field payload; its full8192-row LDE payload would be33,554,432B. These are
separate array estimates, NOT additive process peaks, RSS, speed or compliance.
Quotients, symbolic DAGs, DFT, trees, salts, stacks, matrices and proof copies are
not included in those array estimates. Immutable public prefix/MAC constants are derived once per AIR, with
no secret/request lifetime cache.

The candidate retains conservative declared degree bound5. Actual SDK inference
found 27,835 constraints and degree4, with 16 quotient chunks and 22,338 batched
functions counting BOTH complete width openings. Both decoding estimates reached
128 in the pinned experimental model. The declaration was not lowered afterward;
PCS/RNG/Fri parameters are unchanged.

`security pair-opening` constructs bounded fixture/public metadata and symbolic
analysis, never a trace. `prove pair-opening` builds and verifies the entire linked
relation. Fresh R5 analysis, all 47 genuine/adversarial tests and one genuine proof
passed; native-P2 equivalence alone is not the AEAD result. The report includes
the initially failing public Poly1305 proofs and the precise unnormalized-selector
correction. Any production key custody/interface, private logical-index/source/SQL
relation, proof protocol, freshness/finality or acceptance design remains unmet.
