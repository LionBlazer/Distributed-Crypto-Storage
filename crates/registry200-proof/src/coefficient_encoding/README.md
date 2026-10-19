# Private coefficient encoding relations

This module owns two distinct fixed N4 mathematical AIRs. SourceAllOriginal
opens the original Canonical Source680 and encodes every original row in twelve
coefficient lanes. PrivateMask opens a new privately salted Select-mask Cmd48
and encodes its complete reversed truth table. Neither role executes SQL, verifies
an evaluation key, forms a ciphertext, admits a Journal mutation or grants a result.

| Direct dependency | Responsibility |
| --- | --- |
| [Source](../source/mod.rs) | Single canonical Source claim/profile, Source680 fields and fixed public selectors |
| [Source opening expressions](../lifecycle/opening.rs) | Original salted field packing; no lifecycle operation is added |
| [bfv-key-transform](../../../bfv-key-transform/README.md) | Existing typed Key Statement/PV33 and exact Formation-compatible vector digest ABI |
| [bfv-hiding-stark](../../../bfv-hiding-stark/README.md) | Existing width12 Poseidon gadget and fixed hiding backend used by the consumer |
| [bfv-ciphertext-formation](../../../bfv-ciphertext-formation/README.md) | Exact validated EncodedOpening handoff, without a Formation proof or Key grant |
| p3-air/field/matrix, zeroize and sha2 | AIR/trace expressions, guarded owned witnesses and canonical full-context labels |

`statement` owns reaudited CanonicalSource, independent BfvBinding and low-level
Expected/Statement claims. `layout` is a public circuit ABI for caller-owned trace
writers. `air` constrains the two private-main relations. `commitment` owns their
shared 8208-field vector schedule and distinct new command digest. `Role` fixes
all profiles and dimensions; a caller cannot supply a profile or modulus.
`wire` owns the original bounded DCSCEP01 frame and actual Source-first
cryptographic verification. `wire::verify` accepts independently pinned Expected
and bytes, returning a read-only VerifiedEncoding with the complete Statement,
including C_w. Its private fixed backend constructs and assesses the actual AIR;
callers supply no configuration, verification key or security report. The
experiment owns SQL compilation and fixtures. [circuit](circuit.rs) owns the
private witness and one actual trace writer; the private producer module owns
fixed proving and self-verification. No production callback selects a trace,
configuration, verification key or assessment.

`circuit::Witness::source` and `private_mask` capture their complete Expected and
fixed role after validating the caller-owned opening and canonical salts.
`coefficients()` computes guarded mathematical W under that stored role;
`statement()` uses the same stored context. There is no caller-selected role or
Expected parameter that can reinterpret an empty private-mask plaintext as Source.
The explicit low-level `trace(&Statement)` rejects other roles but allows false
same-role claims for genuine adversarial AIR tests; its output contains secrets
and is never proof authority. Private production row refresh/bit helpers are not
exported. The experiment retains a separate test-only coherent-attacker helper.

`prove(&Expected, &circuit::Witness, source_bytes)` first requires the full captured
Expected, including all Source691, original packets, setup, Key33, query labels and
C_mask. It verifies real bounded canonical Source bytes and drops the decoded
Source/backend before child assessment and trace allocation. It then proves,
self-verifies and frames the unchanged DCSCEP01 pair. Its opaque Evidence exposes
only the complete Statement and bounded public bytes (`into_parts` consumes it).
Persisted bytes are reverified; no cached Boolean or evidence-object identity can
skip Source. Executed producer and input16 checks are recorded in the
[producer/epoch validation](../../../../experiments/hiding-fri-sha256-gate/PRIVATE-INPUT-PRODUCER-EPOCH-VALIDATION.md).

## Exact values and ownership

All source values are pinned: PV691 includes its profile8, full q8, both112-byte
heads, both complete packets, independent Source C_key and C_open. Expected clones
and reaudits the CanonicalSource. The full original BFV setup-id32 is a separate
label from the old Key descriptor's PARAMETER-ONLY digest. KeyPV33 is preserved
completely, including scope, epoch, C_s and C_sHat. BfvBinding is public mathematical
context, not a verified Key, Owner association or proof of same-secret evaluation
keys. The BFV domain/C_s are distinct from Source's AEAD domain/C_key.

| PV range | Source role | Private-mask role |
| --- | --- | --- |
| 0..8 | Distinct role profile | Distinct role profile |
| 8..699 | Complete SourcePV691 | Complete SourcePV691 |
| 699..707 | Full setup32 as8u32 | Full setup32 as8u32 |
| 707..740 | All KeyPV33 | All KeyPV33 |
| 740..748 | Encoding context8 | Encoding context8 |
| 748..752 | C_w, four canonical Gold values | C_w, four canonical Gold values |
| 752..760 | absent | Privately blinded exact-SQL identity32 as8u32 |
| 760..768 | absent | Separate public nonce32 as8u32 |
| 768..772 | absent | Independently pinned C_mask, four Gold values |

The base context hashes complete SourcePV691 and separately length-delimited
original heads/packets, full setup and ALL KeyPV33. The query base additionally
hashes blinded SQL identity and public nonce. It excludes C_mask/C_w/proof bytes.
Query encoding context binds C_mask only after that commitment exists. Every
encoding context excludes its own C_w. Source coefficient VALUES are query
independent; its existing Canonical Source proof and commitment still bind q.
Context binding does not establish trusted setup origin, agreed freshness or that
AIR parsed SQL. Consumers must compare complete Expected and, downstream, the
complete independently pinned Statement INCLUDING C_w, not just its inputs.
Statement::producer_identity owns the domain-separated hash of ALL public values,
including C_w. Fresh consumers can derive this public metadata after verification
without retaining a private witness; the label itself is not proof authority.

## Source relation

For original ordinal i and field f=presence/age/amount, lane L=3i+f has a single
nonzero coefficient at512L+age_i, weighted by1/age_i/amount_i. These are coefficient
polynomials, not SIMD slots or selected/compacted Return168 tuples. Every row,
including age0/amount0, has a presence lane. All 8192 scaled coefficients satisfy
W=78307*m mod114689. The first twelve plaintext bytes supply all96 data bits across
Source fields87..89, TableId is118..125, and all eight words of every RowId are
642..673. Full Source680, including674..679 zero padding, is opened once.

Eight persistent scaled age/amount weights use Boolean17-bit W/slack and16-bit
quotient:78307*v=W+114689*k and W+slack=114688. Each active coefficient has an
11-cell zero/equality gadget against the original age. Every gap j256..511 and
all n>=5888 are zero. All data, identity, weights and salts remain bound through
row511. Changing only TableId/RowId may leave the numerical W unchanged but changes
Source identity/context; it cannot replay against the original independent pin.

## Private-mask relation and digest

Cmd48 is NEW:domain4/version1/queryProfile8/baseContext8/blindedSQLidentity8/
mask8/privateSalt4/zero7. Its mask is256 Boolean MAIN bits packed into eight u32
words. It never enters public preprocessing, Aux or the evidence frame. Query
W[n]=78307*mask[255-n] for n<256 and is zero for every remaining coefficient.
The compiler must independently pin this command; the AIR does not prove parsing.
A high-entropy PRIVATE SQL blind is distinct from a public nonce; a public nonce
alone is not a hiding commitment for low-entropy WHERE/constants.

Both roots use the EXISTING Formation ABI:context8/privateEncodingSalt4/zero4/
W8192, exactly8208 fields. Three P2 gadgets hash context/salt/first8 on row0,
previous carry8/current first8 on middle rows, and the final extra8 on row511.
The fourth P2 opens Source on0..84 or Cmd48 on0..5 with independent zero capacity
and actual endpoint checks. Checkpoints/carry, final8191 and padding are constrained.
The shapes are H512/W2000/PV752 and H512/W1288/PV772, with conservative declared
maximum degree hint5. [Native validation](../../../../experiments/hiding-fri-sha256-gate/PRIVATE-COEFFICIENT-INPUT-VALIDATION.md)
measured degree4, individual128-bit floors, bounded pair sizes and selected process
resources. These observations do not establish a whole peer resource guarantee.

The [experiment consumer](../../../../experiments/hiding-fri-sha256-gate/src/opening/coefficient_encoding/README.md)
requires the genuine canonical Source proof before any child factory and calls
the library verifier directly for both roles and the linked input16 scenario.
The pair cannot establish a Key proof, either operand's Formation, complete private
MulRelin, hidden-query/source provenance beyond this relation, SQL completeness,
writer rights or a fresh agreed head. Individual floors do not imply composed128.
Explicit owner buffers can be guarded; field vectors, traces, FFT/LDE and SDK
allocator scratch are not claimed securely erased.

## Bounded byte frontend

`wire::BorrowedFrame::parse` checks the exact 184-byte header, all profile/context
bytes, canonical C_mask/C_w roots, reserved bytes and complete lengths before
proof decoding. Parsed slices carry no cryptographic authority. The pair cap is
32 MiB; Source is at most 20 MiB and child at most 12,578,091 bytes. Sequence and
total decoded-container limits remain 16,384 and 24 Mi/16 Mi elements respectively.
Element counts are distinct from byte and process-memory limits.

`wire::verify` actually verifies Source with the original fixed hiding suite and
individual security assessment, drops its decoded proof and backend, then constructs
and verifies Encoding. Failure returns no partial result. VerifiedEncoding retains
only public statement metadata. Downstream composition must use its complete C_w
and separately verify actual Key, Basis and Formation prerequisites.

Producer helpers `wire::encode_source` and `wire::encode_with_source` canonically
serialize existing SDK proofs. They do not verify them. The Source encoder reaudits
the mutable low-level Source claim before AIR construction. Both keep the original
frame bytes, profiles, caps and proof topology. Native regression evidence is in the
[extraction validation](../../../../experiments/hiding-fri-sha256-gate/COEFFICIENT-WIRE-EXTRACTION-VALIDATION.md).

`wire::join(Expected, encoded_root, original_source, original_child)` exposes the
same bounded canonical raw-parts assembler for public evidence retention. It
checks framing, lengths and canonical root representation only, verifies neither
proof, and creates no alternate profile or authority. Consumers must still call
the unchanged actual `wire::verify` with independent complete pins.
