# Full8192 signed BFV local formation

This standalone experimental module has native validation for its fixed local
coefficient formation relation over one real level-zero BFV ciphertext. The
[validation record](../../../BFV-LOCAL-FORMATION-VALIDATION.md) reports actual
compile/numeric/oracle/genuine-composite gates and their precise limits.
All 212 serial behavior tests passed: the 195 earlier cases and all 17 Local cases, with no failures or ignored tests. Fixtures remain PUBLIC NONSECRET. This adds no production
network SQL verifier, Owner key interface or security/resource certification.

The private `Expected` fixes independently expected canonical source, old
SelectionOpening/PV88, SelectedEncoding, and exactly five ordered Basis statements.
Every basis uses the same full canonical ciphertext/parameters/request and the same
KeyTransform descriptor, C_s and C_Shat. Database scope is checked against the
source head. BFV key-domain and AEAD key-domain remain distinct. No independently
provided B/A vector, NTT table, digest label or authority Boolean is admitted.

| Dependency | Reused contract |
| --- | --- |
| [Canonical opening](../README.md) and [Selection](../selection/README.md) | Actual source-first complete N4 selection proof |
| [SelectedEncoding](../selection/encoding/README.md) | Exact old C_enc context and natural8192 scaled W words |
| [KeyTransform](../key_transform/README.md) | Same private signed-support key and exact C_Shat producer encoding |
| [BasisConvolution](../basis_convolution/README.md) | Five exact C_R contexts and checked full-ciphertext B ownership |
| Existing Poseidon2 and private Backend | Unchanged P2 gadget and hiding-FRI configuration |

`prove_inputs` creates real prerequisite proofs. A single actual KeyTransform
proof is retained with five child Basis proofs; each child helper verifies that
proof against its exact Expected before its factory. There is no trusted-cache
flag. `prove_with_trace` and `verify` check the actual source/Selection/Encoding,
KeyTransform and all five Basis proofs before the local Backend/factory. Missing
or foreign evidence rejects. Backends are scoped sequentially; completed proofs
are still retained and contribute to whole-process resources.

The existing bounded canonical ciphertext decoder derives B_i from the SAME
decoded ct[0] changed to PowerBasis, storing only that canonical selected-basis
public vector. Bytes/level/representation/seed/c0/c1 caps and exact-roundtrip checks
remain mandatory. This public coefficient transform neither executes private SQL
nor supplies an unproved private plaintext transform.

All40960 equations constrain `B_i,j + R_i,j - e_j - delta_i*W_j = qi*k_i,j`.
One e_j is reused across all five bases. With bit-ranged z63 and z20,
`R = z63 - 2^62` is in [-2^62,2^62-1] and `k = z20 - 2^19` is in
[-2^19,2^19-1]. This is not a sign bit with 20 magnitude bits. Noise uses 6 bits
minus20 and6-bit slack summing40; W uses17 bits and17-bit slack summing114688.
For the fixed five qi/delta, the integer residual is between
-14835885613567410195 and13835075638878781459, strictly inside plus/minus
Goldilocks18446744069414584321. A zero field residual therefore is an integer zero.
The unique signed63 lift reopens the SAME raw-Gold C_R and original producer
encoding; no qi-reduced R is substituted.

Seven exact streams open five old raw-Gold C_R, old raw-W C_enc and fresh raw-signed
C_e. Old role/profile/context/salt encodings are preserved. Only C_e gets a new
domain/context, binding full producer identities/ciphertext/request/layout without
its own root. PV44 is profile8/common-context8/C_enc4/five-C_R20/C_e4. Hashes are
binding under the existing model; expected identities are not authorization.

T512 handles16 coefficients per row. Each stream has three unconditional P2
gadgets,12 checkpoint fields,4 immutable salt fields and8 carries. Row0 absorbs
context8, salt4+zero4 and coefficients0..7; coefficients8..15 are captured from
the SAME ranged/equated fields. Row1 absorbs that carry and16..31. Remaining rows
use two coefficient blocks and an idle third gadget with zero INPUT and fully
constrained permutation. Carry is initially zero, clears after row1 and stays
zero; checkpoints follow the last ACTIVE gadget. Each stream has1026 absorbs
and its final root is gadget1 at511. Transition guards use the actual SDK selector.

Static W12752 consists of5376 sponge/checkpoint/salt/carry columns and7376 range
bits. There are512 physical selectors plus80 public B periodics, total592.
Calculated payloads are trace52232192B, masked104505344B and main-LDE836042752B.
These exclude prerequisite proofs/witnesses, FHE objects, symbolic DAG, periodics,
FFTs, quotient/MMCS/proofs and allocator overhead. They are not process RAM bounds.
The declared degree hint remains 5; actual SDK inference found degree 3, 13,076
constraints, 16 quotient chunks and 25,684 batched functions. Both per-proof model
floors reached 128 with unchanged q192/ext5/r5/blowup8 before the trace/proof gates.
The separate process observation is empirical and does not establish RAM bounds
or composed security.

The public-nonsecret fixture first constructs actual canonical source and selected
originals. SIMD slots come ONLY from `EncodingWitness.original()`: age0..4,
amount4096..4100 and presence512..516, with every other slot zero. It uses actual
upstream encoding/encryption, fixed public key/noise fixture seeds and exact CBD
caller replay for e; upstream independently generates the public A seed. Key
serialization/decryption checks are fixture controls, not accepting evidence.
No provided Owner key is imported or exported. Rebuilt tests rehash downstream
commitments, attack signed ranges/wrap/noise/W/last coefficient and retain real
prerequisite/genuine-composite tests. The serial suite exercises biased signed 20-bit
field-alias rejection, common noise/support/slack, the last quotient/scaled word,
carry/reset/private salts, idle permutation/final root, malformed or foreign
source/basis/ciphertext/requests, missing evidence before the factory, genuine
foreign Encoding and fresh salt/profile SDK replay. Native fixture checks remain
separate from the rebuilt proof/rejection cases.

This source candidate is contextually rebound over published SQL integration 00b14edca587821b59c4cdfb7a7ce5baf25b7775.
The [Key/Basis validation](../../../BFV-KEY-BASIS-VALIDATION.md) and [SQL-plan validation](../../../SQL-LOCK-PLANS-VALIDATION.md)
retain their measured scopes; neither validates this new LocalFormation Kind or its composed proof.
The original Local donor and reviewed single-line duplicate-verification removal remain pinned
in ignored preparation evidence. Current Local numerical and genuine-composite
observations are recorded separately in the new validation report.
The report records suite coverage and process-resource scope; historical reports
retain their own measured scopes.

C_s and a parameter/setup digest do not bind the authorized BFV decryption or
evaluation keys. Key authority/lifecycle, CBD entropy/independence and composed
security remain unmet. The witness is owner/client-local; peers cannot derive it
from encrypted bytes. LockReturn168/PV116, LockOwned and VersionSelection cannot
be relabelled into old Selection88/C_enc: they require distinct typed bridges.
Proof-cache admission is not network freshness. Live ciphertext-operation proof,
writer fencing, MVCC, private control anchoring and final agreed heads/finality
remain separate requirements; this module does not accept live SQL or locks.

## Shared integer implementation

The exact evaluator and seven-stream row writer now belong to the reusable
[formation library](../../../../../crates/bfv-ciphertext-formation/README.md).
This adapter preserves its original profile, public values, contexts, fixture
policy and arithmetic. The new Registry200 composition has a distinct producer
boundary; it does not reinterpret this legacy Selected88 relation.
