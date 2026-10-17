# Full BFV basis convolution source candidate

This private standalone module proposes one full degree-8192 negacyclic
convolution prerequisite. Release build, test compilation, strict Clippy and
trace-free numerical gates passed. The native CRT oracle and one genuine
proof-first composite also passed in observed processes. All 189 serial tests
passed; the [validation record](../../../BFV-KEY-BASIS-VALIDATION.md)
keeps them separate. It creates no production verifier, Owner key interface or
network acceptance.

`Statement::Expected` independently fixes the complete KeyTransform statement
(setup descriptor, C_s, C_Shat), query request, canonical parameter bytes,
complete canonical upstream ciphertext bytes and basis 0..4. Its constructor
accepts no independent coefficient vector or Ahat/digest label. `prove_with_trace`
proves and genuinely verifies the full KeyTransform prerequisite before the
child factory. `verify` verifies that actual prerequisite before the child proof;
missing/foreign evidence is rejected. Individual SDK model bounds do not establish
the composed security of two proofs and their commitment/hash assumptions.

The decoder uses the pinned fhe/fhe-math/fhe-traits 0.1.1 codec with fixed N8192,
t114689, variance10, the existing five ordered qi, level0, exactly two Ntt
polynomials and canonical residues. Parameter bytes must equal the trusted fixed
serialization before any attacker parameter construction. Exact ciphertext
roundtrip rejects unknown, duplicate, trailing and noncanonical encodings. Both
seeded and unseeded canonical ciphertexts are supported. The upstream Rq wire
stores coefficient bytes even for Ntt: public A is derived from the decoded
`ct[1]` changed to PowerBasis, rather than treating wire bytes as an NTT vector.
The query context includes all ciphertext bytes, including c0/B, seed and level.

The coefficient payload is exactly
8192*(43+43+44+44+44)/8 = 223232 bytes per polynomial. Pinned protobuf fields
add at most 11 bytes per Rq and 4 bytes per ciphertext polynomial wrapper;
two unseeded polynomials therefore fit 446494 bytes. A seeded ciphertext fits
223281 bytes (one polynomial plus its 32-byte seed and wrapper). The 512 KiB
pre-decode cap accommodates both. The cap bounds supplied bytes, not all decoder
or allocator memory. Parameter input has a separate 1024-byte cap.

Input hashing reuses KeyTransform's EXACT role1 context, salt and raw natural
Goldilocks C_Shat encoding: context8 || private salt4 || zero4 || vector8192.
Output C_R uses a new profile/role/context binding that same source, full
ciphertext/setup/request/basis/qi/level and transform order. It hashes raw Gold
residues, with an independently sampled private output salt. Salt entropy is a
producer obligation, not an AIR theorem. The setup digest identifies canonical
parameters; it does not certify a BFV decryption/evaluation key authority.

The fixed one-bank schedule is input hash rows 0..205, hold 205→206,
public-Ahat multiplication plus bit reversal 206→207, inverse DIT transitions
207..219, normalization N^-1*psi^-j 220→221, then output hashing 221..426.
The bank holds on every other transition. All five Poseidon2 gadgets execute
unconditionally; inactive inputs are zero but their permutation outputs are not
assumed zero. Partial final rows use gadget0 as the last ACTIVE checkpoint.
Transition guards use the SDK transition selector, never 1-is_last_row.

Static T512/W9452/PV62 arrays are 38,715,392 bytes for the trace,
77,471,744 masked bytes and 619,773,952 main-LDE bytes. These omit expression
DAGs, periodic interpolation, FFTs, proofs, FHE objects and allocator overhead;
they are not process RSS bounds. The actual trace-free report gives degree3,
9534 constraints,16 chunks,19084 batched functions and128/128 finite SDK bounds.
Existing q192/ext5/r5, two full-width openings and hiding settings stay unchanged.
The conservative declared bound5 is distinct from actual inferred degree3.

Public-nonsecret fixtures construct actual upstream SecretKey/encryption and
check serialized-key/CBD replay and decryption parity. No supplied Owner key is
exported; fixture seeds are explicitly public. Normal fixture dependencies use
only already-locked versions; transaction-state remains dev-only. The oracle
reduces the original A_i into two existing qi, applies their independent native
NTTs and centered CRT, and checks every coefficient. Rebuilt negatives target
source/context, inverse stages, ordering, normalization, holds, salts, partial
hash rows and inactive gadgets through the raw SDK boundary.

One genuine composite verified this candidate convolution modulo Goldilocks;
that observation does not establish full BFV formation. Its unique integer
lift relies on the genuine KeyTransform support and exact public A support;
later local formation must also open signed63 R and constrain all five equations
B_i+R_i-e-delta_i*W=qi*k with shared secrets/noise/encoding. Neither actual
BFV ciphertext formation, noise entropy, same authorized decryption key,
SelectedEncoding linkage, peer FHE query execution, complete SQL, lock fencing,
fresh agreement nor finality follows from this module. Reasonable latency and
whole-process resources remain empirical requirements.


## Nonsecret client fixture setup capability

`public_fixture_with_setup` optionally builds the full public setup from the SAME
actual upstream fixture key used for encryption. The opaque `PublicFixtureClient`
retains that nonsecret client key and exposes only public setup and explicitly
unverified canonical-product decryption for client test completion. It exports no
key bytes/reference/callback. Existing fixture paths omit this extra setup work.
This fixture helper serves the [certified projection job](../locking/formation/job/README.md);
its honest fixture equality is not a production proof of setup/key authorization
or evaluation-key consistency.

The six new owning cases and independent-process CLI passed real proof and client
completion checks; see the [validation record](../../../CERTIFIED-PROJECTION-JOB-VALIDATION.md).


## Shared implementation

The AIR, complete canonical public ciphertext decoder, original profile payload and
pure writer now delegate to [bfv-basis-convolution](../../../../../crates/bfv-basis-convolution/README.md).
This adapter retains its historical Kind/request/fixture policy, exact old test
bodies, allowlists and caps. The shared writer computes immutable contexts once
outside its row loop. A new borrowed protobuf/residue gate rejects malformed
allocation-amplifying envelopes BEFORE SDK math while preserving canonical valid
seeded/unseeded/variable-time forms. The
[Owner Basis validation](../../../../../crates/bfv-basis-convolution/OWNER-BASIS-VALIDATION.md)
records the rebuilt old scenarios and actual new Owner proofs.
The separate opaque actual Owner job is not this module's public fixture capability.
