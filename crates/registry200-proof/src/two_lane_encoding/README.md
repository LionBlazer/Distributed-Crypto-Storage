# Two-lane private encoding mathematical candidate

This new namespace owns two distinct fixed hiding AIRs: SourceAllOriginal and
PrivateMask. It changes no old coefficient/Key/Formation/progress proof profile,
wire, current application, SQL admission or consensus rule. Nine owning tests
passed with genuine Source/child proofs and observed resources; see the
[executed validation](VALIDATION.md). This supplies one mathematical input
boundary for an experimental N4096 unrelinearized product. Same-secret
Formation, assessed product composition and real DCS admission remain open.

## Relation and independent expectations

The closed parameters are N4096, ordered Q=[1073692673,1073668097], T65537 and
SCALE16389=(Q0*Q1) mod T. SourceAllOriginal opens the original Canonical Source680
under its existing C_open, including the full data, index, TableId, all RowIds
and padding. It encodes every original row i in two natural polynomial lanes:
512*(2*i)+age_i has weight256+age_i;512*(2*i+1)+age_i has weight amount_i.
No stored row is selected or compacted. PrivateMask opens a distinct salted
Cmd48 containing all256 Boolean mask bits and places mask[255-n] at n<256,
with every other coefficient zero. Both roles prove W=SCALE*m mod T for ALL4096
coefficients, including gaps and final4095. The roles have different profiles.

Eight Source weights prove their exact integer scaling using Boolean W17,
slack17 and quotient15:16389*v=W+65537*k and W+slack=65536. The raw presence/age
value is256+age in[256,511]; amount is u16. These bounds exclude field aliases
and fit the15-bit quotient (max16388). Eight per-row equality gadgets prove the
original age selects the one correct coefficient; inactive gap gadgets are zero.
All96 data bits, full TableId/all32 RowId words and original Source fields
87..673 are linked to the real Source opening. Source fields674..679 are fixed
zero by the reused opening relation. Every relevant persistent bank/salt/weight
and all256 query bits carry across the full512-row trace.

statement::KeyBinding is independently supplied PUBLIC CANDIDATE METADATA:
database4/domain4/epoch1/fixed-parameter-profile8/key-ID8/C_s4, exactly29 fields.
C_s is a canonical purported secret commitment, not a verified key. The database
must equal the original Source database. This type contains no old Key33/C_sHat,
private key, actual setup, Formation result or security authority. A future
same-secret Formation/owner contract must independently prove and authenticate
these exact pins before using an encrypted answer. Changing any metadata changes
the new context; it cannot relabel an old Key or setup proof.

Expected::source and private_mask re-audit the complete Source and retain the
full independently supplied key metadata, blinded SQL identity/public nonce
and C_mask. The new base context hashes complete Source691, both raw heads and
packets, role/metadata, and the query labels where applicable. Encoding context
additionally binds C_mask but excludes its own C_w. Statement retains C_w and
requires full equality, not only a context hash. No AIR parses SQL text; the
client/compiler must independently pin the intended complete mask/command. A
public nonce alone does not hide low-entropy SQL/operators/constants. Callers
own high-entropy private salts/blinds; low-level canonical setters do not supply
randomness or owner authorization.

## Commitment schedule and geometry

The NEW vector stream has4112 fields:context8/private salt4/zero4/W4096. It uses
width12 Poseidon2 with rate8, carried capacity4 and overwrite mode. One delayed
8-word block is consumed per row; row0 absorbs context then the salt prefix,
rows1..510 consume the prior row's W, and row511 consumes W510 then flushes W511.
Thus514 permutations cover all512 coefficient blocks and both prefix blocks.
The extra gadget is zero except at first/last. The final root is explicitly
constrained; vector checkpoints and the delayed words carry through every row.
An independent sequential hash test covers the complete stream and last word.
This root/context ABI is not the old8208-field Formation commitment.

The third Poseidon gadget opens the genuine Source680 in85 blocks or Cmd48 in6
blocks, with actual endpoint constraints and independent reset capacity. Shapes
are H512/W1656/PV740 for Source and H512/W1040/PV760 for PrivateMask. PVs are
profile8/Source691/key-metadata29/context8/C_w4, plus blinded-SQL8/nonce8/C_mask4
for Query. The degree hint is5; the actual immutable AIR is analyzed by the fixed
backend and must meet its individual128-bit floor before full trace allocation.
No composed128, lattice security, BFV noise, product correctness, SQL completeness,
freshness, authorization or whole-peer resource guarantee is inferred.

## Public entry points and bounded lifecycle

circuit::Witness::source/private_mask accept explicitly caller-owned guarded
private openings. They validate the full role/commitment and capture Expected.
coefficients and trace are low-level mathematical helpers containing secrets;
no Owner getter, caller-selected profile, verifier callback, raw proof constructor
or formation_opening compatibility route is added. Native field traces and SDK
scratch are not promised securely erased. The test-only refresh helper uses the
SAME actual permutation writer to rebuild hostile commitments/checkpoints.

prove(Expected,Witness,original_Source_bytes) first checks complete captured
Expected, genuinely verifies the existing Source proof, drops its backend/proof,
then assesses/proves/self-verifies the new fixed child. Evidence retains only
the public child statement/bytes. wire::verify(Expected,original_Source_bytes,
child_bytes) performs canonical header preflight, actual fresh Source verification
before child backend construction/decoding, then genuine child verification.
Both paths call the concrete source::verification::verify every time; no cached
Boolean, success token or alternate verifier can skip it. VerifiedEncoding exposes
only the full mathematical Statement, not SQL/Key/Formation/finality authority.

wire::verify_pair accepts independently expected SourceAllOriginal and PrivateMask
roles, one original Source and two child frames. It requires literal equality of
the complete Source public values/raw heads/packets and all 29 candidate key
fields before parsing both bounded frames. It genuinely verifies that one Source,
then both children sequentially, dropping each backend/decoded proof before the
next. VerifiedPair becomes available only after all three proofs pass. No Source
verification token escapes or survives the call. The original single-child APIs
and all proof/profile bytes remain unchanged.

DCS2LE01 has a152-byte header:magic8/tag1/zero7/profile32/complete Expected identity64/
C_w32/payload length4/zero4. C_w alone remains an unverified claim during parse;
the full proof must authenticate it. Exactly one child is at most12 MiB including
header; original Source is separately bounded by the unchanged20 MiB cap, never
copied into child wire. Sequence cap16384 and decoded child-element budget16Mi
are inherited concrete limits, with verifier-derived width/chunks and canonical
bounded decode/reencode. There is no new aggregate transport/Journal frame or cap
increase. A future two-role catalog must explicitly account for one Source and
both children; the per-child cap is not a whole-operation storage/memory theorem.

Direct module dependencies are Source/admission/lifecycle opening/range helpers,
the existing bfv-hiding-stark engine/Poseidon/bounded codec, pinned P3 AIR/matrix/
field/symmetric/STARK types, SHA256/SHA512 and zeroize. The new fixed::Backend
branch dispatches this exact typed AIR and preserves all old branches/profiles.
The sole additional Cargo edge is test-only fhe-math0.1.1 with default features
disabled, for the actual Modulus::scalar_mul_vec primitive used by SDK plaintext
lifting. No product, peer runtime or consumer dependency is added.

## Owning tests

Nine tests passed. Cheap checks independently build all4096 raw
plaintext coefficients and apply the ACTUAL SDK modular scaling primitive,
compare zero/all/threshold masks, and compare the streamed commitment against
an independent full sequential digest. Genuine cases share one actual public
Source proof and two actual new child proofs, then reverify their bytes. Repaired
foreign key-epoch/SQL/nonce/C_mask headers, corrupt genuine Source commitments,
child corruption, role/profile/cap/EOF and full Expected/private-opening changes
must reject. Two additional low-level malicious child proving attempts rebuild
all hashes with a false last coefficient in each role; actual constraints and
proof verification must reject. Other repaired private bank/weight/mask failures
use the real AIR checker and incur no extra proving. Total direct prove sites
are one Source, two honest children and two malicious child attempts, not any
Key/Basis/Formation/FHE/network proof. Source-first checks remain fresh on every
production verify despite setup reuse in the explicitly public test fixture.
The pair tests compare both complete verified statements with independent single
calls, reject swapped/duplicate roles and foreign Source/key contexts before
proof work, and exercise repaired headers, Source corruption and each damaged
child through the all-or-nothing pair frontend.

Strict all-target Clippy, the cheap SDK/vector checks, nine existing admission/
profile/wire checks and requirements synchronization passed. The original seven
tests took 17.18 s; the later nine-test pair gate took 35.62 s, including the
additional real verification comparisons and attacks. In the same later run,
two single calls took 2674.165 ms and the joint call took 1595.910 ms on identical
proof bytes. This remains above the 500 ms complete-query target before Formation,
FHE product, consensus or transport. The validation record preserves the commands,
evidence identities and scope of these component observations.
