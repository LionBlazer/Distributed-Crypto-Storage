# Fixed whole-pair private source-opening candidates

Historical byte-opening status: the frozen R5 candidate passed release build, strict Clippy, eight fresh
security analyses, all 47 serial tests and one genuine whole-pair proof followed
by verification. [PAIR-OPENING-VALIDATION.md](../../PAIR-OPENING-VALIDATION.md)
records exact scope, failures, artifacts and external observation limits. This
module now also contains a validated bounded canonical N4 index relation: nine
actual numerical cases, one genuine proof and all60 serial tests passed. Its
[separate report](../../CANONICAL-INDEX-VALIDATION.md) records exact current
source and limitations. This module is a private consumer inside the [standalone experiment](../../README.md),
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
| `schedule.rs`, `layout.rs` | Two fixed public height512 schedules/layouts, 42 jobs, 163 MAC blocks and exact absorb/capture rows |
| `air.rs` | All cross-primitive, immutable-bank, output-buffer, header and salted-sponge constraints |
| `trace.rs` | Separate nonserializable/non-Clone private witness and genuine shared-arithmetic trace generator |
| `poseidon.rs` | Internal native-equivalent pinned width12 permutation gadget |
| `commitment.rs` | Source-key/open encodings and shared fixed-length sponge/native fixture oracle |
| `tests.rs` | Preserved byte-opening native/oracle, admission, genuine and rebuilt inconsistent-component cases |
| `canonical.rs`, `canonical_tests.rs` | Complete fixed N4 index invariant, bounded witness auxiliaries and preserved original source/rebuilt cases |
| `packed_tests.rs` | Separate packed-profile geometry, authentic core fixture, genuine proof and rebuilt malformed-witness cases |

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
correction. Production key custody/interfaces, general/cross-version private
index/source/SQL relations, proof protocols, freshness/finality and acceptance
designs remain unmet.


## Canonical N4 index relation

`canonical-index-opening` is a distinct Kind/profile sharing the exact AEAD,
P2 evaluator and one trace-writing loop. `pair-opening` retains its byte-only
profile, width and tests. Neither selects production cryptography or accepts SQL.
The [core-owned public codec vector](../../../../crates/compact-query/tests/fixtures/README.md)
provides an independent byte-compatibility control without a compact-query
runtime dependency or an Owner-key interface. All fixture keys/rows/IDs are
explicitly PUBLIC NONSECRET. The index vector excludes the first112 bytes;
fixture encryption supplies the actual independently constructed data head.

The real N4 index remains2336 bytes: data head112, TableId32, counts256*u32,
offsets257*u32, four used posting bytes, eight zero bytes and four32-byte IDs.
Capacity is8 posting bytes before32-byte alignment, not4. Every histogram count
and prefix offset is constrained from the same four authentic data age bytes.
A Boolean4x4 permutation covers each ordinal once, sorted by(age,ordinal).
Eight-bit nonnegative adjacent age differences and zero/inverse auxiliaries
establish bucket ties; the actual posting word must encode the first absolute
ordinal and subsequent positive within-bucket deltas. All four values fit one
canonical varint byte. All unused posting/alignment bytes are zero.

The age and permutation banks are constant on ALL512 rows; ages bind actual
counter1 XOR bytes atrow80. Eight reusable groups of four byte comparisons check
all513 header words at the exact existing P2 input slots, including the existing
stale-word carry path. There is no permanent256-bucket bank. TableId first-half
popcount captures at CURRENT80, skipping only the predecessor->capture copy;
row161 combines the second half. Row485 retains all four IDs in I35/I36/I37.
Popcount inverses enforce nonzero TableId/IDs, and six XOR-popcount inverses
establish pairwise distinct IDs. Each sum is at most256, below Goldilocks.
No raw identity is a public value. No ID sort or TableId!=RowId rule is added.

C_open uses the new semantic profile while retaining its exact fixed encoding
and freshly sampled private salt. It commits the entire authentic row/index byte
sequence, including the current ordinal->RowId map. C_key is still an independently
fixed AEAD-key anchor, not a logical-table anchor. The new relation does not prove
independently expected private TableId, identity continuity across writes/shards,
a typed/NULL catalog, BFV operand formation, a semantic SQL plan, query result
completeness, ownership/conflict handling or finality. Those remain separate gates.

Source accounting appends442 columns: ages32, permutation16, sort30,
header-comparison352, identity inverses11, TableId-half1. W11521/T512 gives
trace47,190,016B, masked94,420,992B and main LDE755,367,936B under the unchanged
backend array formulas. Existing512 periodics remain2,097,152B plain payload;
its estimated LDE is33,554,432B. These are separate bounded array estimates,
not whole-process RAM or speed claims. Actual numerical analysis found28,949 constraints, degree4,16 quotient chunks
and23,222 batched functions with both model estimates128. Declared degree bound5
was retained. One genuine proof/verification and all60 serial tests passed; the
report preserves the initial Clippy failure and limited resource observations.
These do not establish production privacy, RAM or interactive latency.

## Private bounded selection

The [nested Selection module](selection/README.md) opens this exact OLD canonical
C_open and proves bounded complete ordinal selection under a committed private
plan. Genuine source verification remains mandatory first; the packed profile is
not silently composed. Its proof and15 new cases passed within the combined85;
the [validation record](../../SELECTION-PACKED-VALIDATION.md) states exact scope.
It remains nonaccepting. Old byte/canonical relations and profiles are preserved.

## Packed canonical source candidate

`packed-canonical-index-opening` is a distinct experimental Kind/profile with
W7161, T512, 691 public values and two full-width opening points. Native build,
strict Clippy, actual numerical analysis, one observed CLI proof and all ten new
packed cases passed within the complete85. The
[combined report](../../SELECTION-PACKED-VALIDATION.md) records exact evidence.
Historical security estimates and timings above retain their original scope. The
existing byte/canonical profiles retain W11079/W11521, their 81-row schedule,
profile encodings and owning cases. All three share the Cha/Poly/P2 arithmetic,
one AIR evaluator and one trace-writing loop. Selection or SQL acceptance does
not follow from this new source candidate.

The seven Cha lanes still use 788 bit/carry columns each. The packed layout
replaces 3584 retained output bits with 112 plaintext u32 fields and 1280 key bits
with 40 immutable words: K8, SK16, PK16. A separate 256-bit selected raw Polykey
view is tied word-for-word to the proper PK bank on every row, including padding;
the existing Poly evaluator applies its unchanged clamp and tag arithmetic.
The master key is range-bound by the first bit-state input. Both subkeys and
Polykeys are range-bound by their authentic primitive output bit states. Their
constant banks cannot select different values before and after capture.

Each of six groups now occupies 82 rows. QR transitions use rows0..79 relative
to the group; row80 contains the final permutation state. Its transition to
row81 range-binds the feedforward/extracted output in the next 512 Boolean
state bits. Normal Cha has `state + input = output + 2^32 * carry`, with Boolean
carry and each integer side below2^33; H extracts its eight words and zeroes the
remaining words. At CURRENT81, ciphertext XOR those bits defines each retained
plaintext u32. The next transition resets the bit state to the next job input,
while the plaintext words remain available. H, counter0 and unused final-block
words have zero plaintext fields. No unchecked field-to-u32 cast supplies an AIR
range constraint.

Packed group captures are81/163/245/327/409/491. C_key still absorbs at0..3;
C_open blocks0..9 at4..13, 10..14 at82..86, 15..28 at164..177,
29..42 at246..259, 43..56 at328..341, 57..70 at410..423 and71..84 at492..505.
All 587 authentic plaintext words enter once. The same ten stale words are
captured at87/178/260/342/424 before a later buffer overwrite, with only the
predecessor-to-capture copy suppressed. Final commitment checks are3/505.
The profile digest binds this exact schedule, layout, primitive constants and
semantic constraints; it does not reuse the old canonical digest.

Canonical ages remain32 persistent bits, authenticated at81. The same header,
offset, histogram, permutation, posting and padding checks read the shared P2
slots. TableId halves use four nonnegative authenticated u32 words each,
captured81/checked163. The total eight-word sum is below2^35<p, so a nonzero
inverse cannot accept field cancellation. Each final RowId uses the same sum
bound for nonzero. For each of six ID pairs, eight Boolean zero flags and eight
inverses establish exact word equality: `d*z=0`, `d*inv=1-z`, `z*inv=0`.
The count of unequal words is in0..8 and must have a nonzero inverse. Equal and
oppositely signed differences cannot cancel into a false distinctness result.
All word-zero auxiliaries are zero outside the final capture. This appends538
canonical columns (including96 word-zero auxiliaries) to the6623-column base.

Unchanged backend parameters are q192, r5, blowup8, extension degree5, original
height512/post-hiding degree bits10, MMCS salts4 and independent OS-seeded mask,
MMCS and private commitment-salt streams. The conservative degree declaration
remains5. Actual inference found16133 constraints, degree3,16 quotient chunks and
14502 batched functions, with both model estimates128. The CLI numerical floor
still precedes trace/proof allocation; this is not production security certification.
Source array formulas give trace29,331,456B, masked58,703,872B and main
LDE469,630,976B; the existing periodic payloads remain unchanged. These separate
array estimates omit trees, symbolic AIR evaluation, quotients and other process
memory. No peak RAM or latency improvement has been measured.

The ten passed packed cases include the core-owned encrypted vector/native C_open,
every captured word, old-shape parity, a genuine proof and cross-profile rejection,
rebuilt range/carry/reset/capture/stale/key/view/identity/header substitutions, and
real re-encryption of invalid zero/duplicate IDs and zero TableId. They do not
weaken or replace the old cases. Reproduction uses
`security packed-canonical-index-opening` followed by the externally guarded
`prove packed-canonical-index-opening` as described in the report; proofs remain private
in-process test artifacts. This candidate adds no key authority, identity history,
BFV formation, private query completeness, freshness, finality or live consumer.

## Version-bound certificate

The [separate state module](state/README.md) reuses packed source and Selection
evaluators under new domains/profiles. Its single-entry cache requires actual
source verification and exact expected state. Both new numerical reports passed
with bounds 128/128; genuine cold/warm CLI proofs and all 97 tests passed. The
[validation record](../../VERSION-STATE-VALIDATION.md) describes exact timing,
capacity and sampled-memory scopes. Agreement and freshness remain external.

## Factorized public-periodic source profile

The distinct `factorized-packed-canonical-index-opening` profile uses 32 low
columns of period 32 and 16 high columns of period 512, expanding
`low[r%32] * high[r/32]` to the original 512 row selectors. `factorized.rs`
owns public constants/profile encoding; `OpeningAir` shares the original
packed evaluator and per-instance public OnceLock; `factorized_tests.rs`
owns equivalence and genuine/rebuilt proof cases. Existing profiles,
Selection/State and SelectedEncoding keep their original basis and guards.

Actual SDK inference is degree 5 with 16 quotient chunks and both 128-bit model
floors. All 121 serial tests passed. The
[validation record](../../FACTORIZED-PERIODICS-VALIDATION.md) preserves exact
proofs, security, binary identities and observed memory/timer scopes.
It reports lower memory and slower outer/verification intervals, establishing
no speedup or 500-ms target. No SDK fork, custom verifier, new witness columns,
private cache, production acceptance, formation or lock/finality guarantee
is introduced. Fixtures remain explicitly PUBLIC NONSECRET.

## Simple source-gate setup ownership

`gate_relation` receives one checked Backend from shared CLI `prepare_gate`,
reports its retained public AIR and then uses it for genuine proving/verification.
A shared formatter preserves the security JSON. Public-only `security` and the
State/Selection/SelectedEncoding composite lifecycles are unchanged. All 122 tests
passed; the [validation record](../../SOURCE-GATE-SETUP-VALIDATION.md) compares
old/new executables for each fixed profile. This remains a nonaccepting experiment.

## Validated private locking candidate

The [closed N4/two-transaction locking relation](locking/README.md) links complete
private source candidates to exact ownership/conflict/window transitions. It is
nonaccepting; old profiles remain unchanged. Sixteen numerical reports,
three genuine source-plus-locking proofs and all 146 serial tests passed. The
[validation record](../../PRIVATE-LOCKING-VALIDATION.md) reports seconds-long fixed-fixture
operations. Registry anchoring, lifecycle, FHE formation, writer enforcement, MVCC
and finality remain open.

## Validated version-bound locking candidate

The [typed version-lock module](state/locking/README.md) reuses actual verified
StateCertificate admission and the closed-registry locking evaluator. State source
version tags remain distinct from fresh query/control context; old CanonicalIndex
locking stays separate. Seventeen numerical reports, one genuine cold/two-warm
chain and all 158 serial tests passed. This additive candidate remains nonaccepting;
the [validation record](../../VERSION-LOCKING-VALIDATION.md) limits all observations.

## Compiled and numerically gated BFV prerequisites

The distinct [full8192 KeyTransform](key_transform/README.md) and
[complete-ciphertext BasisConvolution](basis_convolution/README.md) profiles passed release build,
test compilation, strict Clippy and all nineteen numerical CLI gates. Both new
actual AIR reports have degree3 and unique/list bounds128. Three native oracle
filters and both genuine proof commands also passed in single observed runs. The
complete 189 serial behavior suite also passed; see the [validation record](../../BFV-KEY-BASIS-VALIDATION.md).
These nonaccepting owner-witness candidates add no Owner key export, authorized
BFV/evaluation-key binding, entropy proof, complete formation, live SQL/lock grant,
writer fence or fresh final agreement. Earlier validated profile/report facts
remain unchanged.

## Signed local BFV formation

The [bounded full8192 local relation](local_formation/README.md) opens all five Basis roots and the existing SelectedEncoding root with common bounded signed noise and integer-safe equations. The [validation record](../../BFV-LOCAL-FORMATION-VALIDATION.md) retains the R1 lint failure, actual 20 numerical reports and one observed genuine full-composition CLI.

All 212 serial behavior tests passed: the 195 earlier cases and all 17 Local cases, with no failures or ignored tests. The actual Local degree 3 differs from the unchanged declared hint 5; both model floors reached 128 per proof, without a composed-security theorem. Its owner/client-local witness, key authority, entropy, network freshness and live SQL/lock acceptance remain open. The observed 58.3s process is not an interactive SQL result or general resource/latency guarantee.

## Successful lock-return encoding and formation (validated experimental relation)

[Return168 encoding](locking/encoding/README.md) opens actual successful returned
originals from a canonical source/lock composite or exact admitted StateLease/lock
evidence. It shares the full coefficient arithmetic while preserving old
SelectedEncoding's profile/source layout. [Returned formation](locking/formation/README.md)
consumes the new exact C_enc with actual same-key/five-Basis verification before
child setup; old LocalFormation is a distinct producer contract.

The [validation record](../../LOCK-RETURNED-BFV-VALIDATION.md) records
successful release/no-run/strict Clippy, 23 numeric calls, three native oracles and
three genuine CLI proof compositions. The full 235-case suite passed on the same source. No source/custody,
controller authority, freshness, writer-fence or network acceptance gap is resolved
by treating the public owner-local fixtures as peer computation.

## Initial private registry candidate

[RegistryBootstrap](registry_bootstrap/README.md) supplies a distinct source-first
initialization relation. Enrollment64 and Registry112 share the same private
controllers, and all stable table/row identities come from the complete canonical
C_open. The registry's IDs1/2, revision2, Active/sequence1 and empty holdings are
AIR constants. Actual release/Clippy, 24 numerical modes, 85 affected tests and
genuine source/child proofs passed; see the
[validation record](../../PRIVATE-REGISTRY-BOOTSTRAP-VALIDATION.md). Earlier profiles
and reports retain their original scope.

## Bounded private control proof transport

[proof_wire](proof_wire/README.md) serializes the original linked SDK Source and
control proofs, retaining random openings, salts and authentication data. Owning
Bootstrap/Locking wrappers reconstruct only proposed outputs from independent
Expected, then bounded-decode and verify the real Source-first pair. See the
[validation record](../../PRIVATE-PROOF-WIRE-VALIDATION.md). Expected authority and
Journal lineage remain external; no production acceptance rule changed.

## Private control lineage

The separate [private_journal](private_journal/README.md) module binds independent
Expected values to the actual owner-authorized Journal callback. Stable Pending
and Active heads avoid query-dependent no-op updates; complete original proofs
are reverified on first admission and durable reopen. Exact known duplicates
retain Journal idempotence. The
[validation record](../../PRIVATE-CONTROL-JOURNAL-VALIDATION.md) covers actual
lineage, rejected tampering, stale CAS and local forks without claiming a live
SQL grant or partition-safe finality. Earlier reports retain their stage scope.

## Private Registry200 lifecycle

The distinct [lifecycle relation](registry_lifecycle/README.md) proves an empty registry and
Begin, Acquire, FailCurrent, Savepoint, RollbackTo, Release and End under bounded
N4/T2/D2 semantics. Real Source-first proofs and all 21 new owning tests passed;
see the [validation record](../../PRIVATE-REGISTRY-LIFECYCLE-VALIDATION.md) for 296 discovered versus
48 executed leaf cases, numerical security and measured component sizes. The
relation remains owner-local and has no existing wire/Journal, live SQL, MVCC,
controller-signature or encrypted data commit authority. Earlier stage reports
retain their original scope.


## Registry200 proof transport

The internal proof_codec shares fixed SDK topology and canonical bounded serialization only; each typed wire owns its role/profile/resource policy. Registry200 uses registry_lifecycle/wire and leaves the legacy wire unchanged. Actual signed Body transport has no Request200 parser, Journal admission or live SQL grant. See the
[validation record](../../PRIVATE-REGISTRY-LIFECYCLE-WIRE-VALIDATION.md).


## Owner-authorized Registry200 Journal

registry_lifecycle/journal now supplies the distinct Request200/Control200 owner-authorized adapter over registry_lifecycle/wire. It checks actual previous heads and proof-derived next roots. The historical Registry112 adapter and live SQL acceptance path are unchanged. See the
[validation record](../../PRIVATE-REGISTRY-LIFECYCLE-JOURNAL-VALIDATION.md).


## Registry200 original-row encoding

registry_lifecycle/encoding binds successful Result144 returned flags to compact original tuples, all RowId words and all 8192 coefficients. It requires both actual original proofs before its backend and preserves legacy producer contracts. See the
[validation record](../../PRIVATE-REGISTRY-LIFECYCLE-ENCODING-VALIDATION.md).
