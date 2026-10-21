# Two-lane private encoding mathematical candidate

This new namespace owns two distinct fixed hiding AIRs: SourceAllOriginal and
PrivateMask. It changes no old coefficient/Key/Formation/progress proof profile,
wire, current application, SQL admission or consensus rule. Ten owning tests
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
Test-only fhe-math0.1.1 (default features disabled) supplies the actual
Modulus::scalar_mul_vec primitive used by SDK plaintext lifting. Test-only
p3-fri0.8.0 supplies the independent direct-SDK assessment oracle; its version
was already resolved. No production or peer runtime dependency is added.

## Owning tests

Ten cases are covered. Cheap checks independently build all4096 raw
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

The subsequent [single-collection assessment validation](../../../bfv-hiding-stark/ANALYSIS-VALIDATION.md)
records unchanged SDK parameters for these actual AIRs, the nine proof/framing
cases passing in23.94s and the additional analytical case passing separately
in0.70s. Joint verification in that run took1060.086ms. This remains a partial
mathematical boundary above the complete-query target.


## Consuming CoreGold Formation composition

The additive `formation` namespace connects the genuine existing Source691 and
both two-lane encoding proofs to the new N4096/Q2 CoreGold Formation relation.
It preserves the existing encoding and Source profiles. The composition has its
own profile digest and uses only the new literal `gold::Request`; it admits no
old N8192 Key33, Formation or public-product envelope by relabeling.

`formation::Expected::checked` retains complete independent public statements,
Source heads and packets, key metadata29, request bytes, request q and mask nonce.
The Cs528 context commits the first25 key-identity values and the new CoreGold
profile, excluding Cs itself and the query. This key identity is metadata and
supplies no key authorization or lattice-security assessment. C_key remains the
independent AEAD commitment in the original Source proof.

`Prerequisites` borrows unverified original Source, Source-child and mask-child
bytes with the existing 20MiB/12MiB/12MiB caps. Both production paths first check
the complete bounded frame claims, then freshly verify the original Source and
both encoding children. No stored checked flag, SourceVersion capability, caller
verifier, callback or opaque-pair factory replaces that actual verification.

`PrivateInputs` consumes both final Witnesses and guarded serialized SDK secret
and Cs salt. `formation::prove` pins the independent expectation and exact literal
request, verifies prerequisites, and passes the SAME already-scaled W4096 words
and encoding salts by ownership to the opaque lower openings. The crate-private
consuming helper computes each W once, moves its existing encoding salt, then
drops the plaintext, private mask and original opening salt. It performs no
second SCALE multiplication. The source/mask coefficient compiler is shared with
the fixture without exporting a new raw opening getter. Existing public
`Witness::coefficients` and all old producer semantics remain unchanged.

The concrete lower `Prepared` and `gold::prove` paths enforce complete Cw/Cs
openings, the same secret, all four ciphertext-component equations, and native
shape/security/resource gates before private MAIN construction. Their returned
bytes are explicitly unverified. `formation::verify` repeats fresh Source/pair
verification and the actual cold CoreGold verifier against the independently
retained expectation. Only this receiving function creates the private-field
`VerifiedFormation` mathematical result. Neither result type grants SQL
acceptance, current-head freshness, consensus, key installation or authorization.

Direct added dependencies are the existing normal `bfv-ciphertext-formation`
library plus test-only pinned SDK encryption, native batch-proof decoding and
bounded Postcard crates. The lower formation module owns all MAIN/PP/config
lifecycles. No production network, Session, owner WAL or App is enabled here.

The one owning test
`formation::tests::genuine_final_witnesses_form_actual_sdk_ciphertexts_then_require_fresh_receiving_proofs`
uses explicitly public nonsecret rows with ages [0,1,128,255] and amounts
[65535,0,255,65534]. It constructs the mask over the public age domain, encrypts
m=W*SCALE^-1 mod t with one actual SDK key, removes seed compression and compares
all decrypted input coefficients as a fixture-only encryption oracle. The same
serialized secret produces Cs528 and the lower Formation witness. Only after the
new literal request q is known does it build final C_open, Source and both child
proofs, then consume those SAME final Witnesses. There is no owner-row selection
or substitute peer result computation.

ONE genuine full-chain Formation proof is reused for receiving rejections.
Cheap role/q/nonce, noncanonical tail, secret-domain and wrong Cs guards run
before the full proof. Wrong independent Cw and frame binding reject before the
lower native proof; a canonical decoded/reencoded OOD mutation must reach the
actual cold native verifier and return exactly Verification. Honest resource
failure fails the test. Internal repaired-wire false proving belongs to the
lower owning tests and requires no new upper test hook.

The [executed owning gate](../../../bfv-ciphertext-formation/src/gold/VALIDATION.md)
passed in16.93s including mutations. Fresh successful receiving took1800.541ms;
its Source/children were freshly verified in that call. The actual mathematical
path still exceeds the500ms complete-query goal before product computation,
transport or consensus. The unchanged120second/1792MiB held-PID fuses passed.
Public numeric phases distinguish Source/children proving, consuming Formation
and fresh receiving. Empty or oversized Formation frames reject before any
prerequisite proof verification. Unexpected native panic is Backend, so the
repaired OOD case's exact Verification assertion excludes panic. No complete-query,
BFV-security, composed-protocol, SQL or freshness guarantee follows from this gate.


## Math-only encrypted product composition

The additive `product` namespace closes the exact public association between
the actual Source/encoding/CoreGold Formation and the separately extracted
`bfv-unrelinearized-product` arithmetic certificate. It does not change the
existing Formation or original eighteen-point UNASSESSED product profiles/codecs.
Its distinct composition digest is metadata, not an assessed cryptographic,
SQL, authorization, current-head or consensus grant.

`product::Expected::checked` independently retains the full Formation Expected
and the complete claimed public-product Expected. It creates both from the
original canonical Gold Request, independent Source/mask Statements and claimed
Ct3. `Request::ciphertexts()` supplies the SAME ordered literal Ct2 bytes; the
product nonce is exactly the Gold nonce. The GFMRQ001 and UCPITQ01 envelopes/q
are never cast or compared as identical. Claimed Ct3 remains untrusted after a
constructor; canonical metadata parsing proves no computation.

`BorrowedPrerequisites::checked` owns only borrowed UNVERIFIED frames. Its caps
are the existing Source20MiB, each child12MiB, Formation32MiB and exactly1,737,899
product bytes. Empty, truncated and oversize frames reject before fresh proof
work. `product::verify` first calls the fixed complete public arithmetic checker, then freshly calls
the actual complete `formation::verify` in the SAME synchronous call. Public
arithmetic failures reject before expensive native Formation; both checks are
mandatory before any result. It accepts no caller-provided verifier, boolean,
serialized capability, preverified object or cached verdict. Lower objects drop
inside the call. Only that function creates private-field move-only
`ArithmeticCheckedQuery`, retaining complete PUBLIC Expected; it exposes no
plaintext rows or SQL/locking status.

The direct new normal dependency is the cohesive
`bfv-unrelinearized-product` core library, never experiments/fixtures/CLI. The
original product frame, all coefficient/scaler/PIT checks and eighteen-point
profile stay intact. Product FS/oracle-budget composition, N4096 lattice/noise
assessment and whole-operation resources remain unresolved; this module does
not promote arithmetic to an assessed DCS proof.

The SAME existing full-chain Formation test/FQN is extended instead of adding
another heavy fixture. A keyless SDK evaluator takes only actual encrypted Ct2
bytes and public parameters, computes one genuine unrelinearized Ct3 and returns
its exact bytes. An owner-only test object retains the SAME SDK key/parameters
and guarded independent full4096 ring oracle; no such object reaches the public
evaluator/checker. It decrypts the actual checked response ONLY AFTER successful
new receiving composition. No public oracle value supplies a peer output or
accepted SQL answer. The original serialized secret still moves into the single
Formation producer, and the original Formation rejection assertions remain.

One actual Source, two child proofs and ONE actual full Formation proof serve
the complete owning gate. The arithmetic frame is produced once. Canonical
foreign-last-output claim, last reduction-quotient corruption and caps are
receiving rejections on that SAME proof. Both the old direct Formation path and the NEW product wrapper reject the SAME
corrupted Formation header and repaired OOD, with exact nested Binding/Verification
errors. Omitting actual Formation in the composite cannot pass these cases; no panic/Proving/Resource path can count as honest success.
Two compile-fail examples protect private construction and move-only ownership.
Public numeric phase timings distinguish SDK product, arithmetic production,
Formation, fresh receiving and post-check client decryption. No secret/private
rows/mask/salt or proof bytes are logged.

The single owning native gate passed in 19.21 s including genuine SDK product,
all-coefficient client completion and the old/new hostile cases. Fresh complete
receiving took 1730.017 ms; post-check client completion took 1.070 ms.
Two new privacy examples, strict Clippy, the lower owning tests and the actual
experiment consumer passed. The [executed product record](../../../bfv-unrelinearized-product/VALIDATION.md)
contains phase timings and whole-process observations under the unchanged
120-second/1792-MiB fuses. No second heavy fixture or compatibility lane was added.
OwnerQuery input-proof removal, new registry/Result semantics, actual fresh
weighted QC and durable SQL completion remain separate work. Full500ms SQL
success is not claimed by this mathematical composition.

## Request-independent immutable-version DATA encoding

Earlier Source/mask API descriptions above refer to the unchanged roles1/2.
The new role below has a separate prerequisite dispatch.

`Role::VersionSourceAllOriginal` (tag3) and the closed
`Expected::source_version(&SourceVersionExpected, KeyBinding)` constructor bind
all4096 DATA coefficients to the actual StateCertificate C_state opening. The
private prerequisite enum retains the complete independently supplied version
expectation: original images/heads/packets, AEAD C_key, version tag and C_state.
The static version tag is never cast to the canonical query q. KeyBinding remains
public BFV metadata; AEAD C_key is a distinct commitment, not BFV Cs authority.

The source-like AIR and owner-side `Witness::source_version` use the actual State
opening prefix/680fields, same eight data lanes, canonical scale16389 and complete
Cw4112 commitment. Constructor checks the State opening before building a trace.
The new role has a separate profile/tag while the existing Source1, mask2,
Formation and product profiles remain byte-exact. Old `verify_pair` and Formation
still require exactly Source1 plus mask2; the new role is not a query or Formation
compatibility path. It supplies no ciphertext Formation, source-version freshness,
BFV key authorization, hidden-mask query composition or accepted SQL result.

Both production `prove` and receiving `wire::verify` freshly dispatch to the
actual `source::version::verify` according to the private constructor-sealed
prerequisite family. The canonical family continues to use its original concrete
verifier. There is no caller flag, callback, raw-Statement version constructor,
serialized success or retained proof-verification cache. Producer Evidence is
UNVERIFIED; only the new role omits redundant child self-verification. Every
receiving call constructs the fixed backend and actually verifies the child.
All old Source1/mask2 producer self-verification and per-frame caps stay unchanged.

The existing public source fixture supplies original images/plaintext, with one
separate genuine StateCertificate proof and one genuine Role3 child reused by
new tests. They cover fresh receiving, missing/corrupt/foreign-family prerequisite
bytes at producer and receiver, repaired C_state/key-epoch/family headers, exact
old profile digests and a repaired lastW coefficient with an actual false child
proving attempt. Two compile-fail examples protect private VerifiedEncoding
construction and move-only ownership. All fourteen owning tests passed in
33.32 s, followed by the unchanged full Formation/product gate in 18.91 s, two
privacy examples and strict Clippy. [Executed version validation](VERSION-VALIDATION.md)
records the actual source/child production and fresh receiving phases, the
unchanged resource fuses and the four preserved native profile digests.
Fresh State plus child receiving took 712.602 ms; it is not a complete query.
The static proof does not establish the 500 ms target or the remaining
single-DATA Formation/query/fresh-head composition. New SourceVersion native
failures retain `SourceVersionProof(BackendError)`; repaired OOD tests require
exact cryptographic Verification rather than accepting a wrapper panic.

## Immutable-version DATA Formation

The additive data_formation namespace consumes exactly one Role3
VersionSourceAllOriginal encoding and the new CoreGold DATA Formation proof. Its
independent Expected accepts only the sealed StateCertificate source family. It
binds the whole State public claim, both complete raw heads/packets, C_key,
C_state, all candidate key29 metadata, Cw and the complete literal GFMDQ001
request. Version identity remains request-independent; it is never compared or
cast to a query q. Original Pair, mask, Formation and product profiles remain
unchanged. The old Pair APIs do not accept this new role.

secret_context(KeyBinding) is pure public metadata for DATA-specific Cs528. Its
separate domain includes the fixed DATA profile and the first25 key values. It
excludes its own Cs, Source/Cw and request, so owner-side Cs construction is
acyclic. AEAD C_key and BFV Cs remain separate commitments. Metadata does not
verify key authorization, lattice security or currentness.

Prerequisites borrows one State frame (20MiB) and one child (12MiB). Its closed
verification checks complete Statement/Cw association and freshly calls actual
wire::verify, including source::version::verify and native Role3 verification.
The producer does this before consuming the SAME final Witness. The crate-private
consuming helper moves its already-scaled W and encoding salt exactly once into
ScaledOpening and drops the source plaintext/original opening salt. SDK secret
bytes and Cs salt move into SecretOpening. The actual lower DATA producer then
applies its fixed security/resource gates before private MAIN. No raw opening,
callback, caller-selected verifier or serialized checked state is adopted.

Receiving first rejects empty/over32MiB DATA frames, checks the independently
retained literal request and fresh prerequisites, then invokes actual cold native
DATA verification. Only this route creates private-field move-only
VerifiedDataFormation containing public Expected metadata. It supplies no
source-version freshness, QueryCt/Cmd theorem, SourceVersion cast, SQL result,
lock/QC, BFV/noise/composed-security or500ms guarantee.

One owning fixture uses one genuine StateCertificate, one Role3 child and one
actual DATA Formation proof. The same SDK secret produces the DATA-specific Cs
and unseeded DataCt2. The ciphertext encrypts m=W*SCALE^-1 mod65537 so internal
SDK scaling happens once. Missing/foreign State, full Cw/request/nonce, bounds,
header and canonical decoded/reencoded OOD mutations reuse those same proofs.
State OOD must report exact SourceVersionProof(Verification) at producer and
receiver; DATA OOD must report exact Formation(Verification), excluding panic.
Honest resource/proving failure fails the test. Two compile-fail examples protect
the receiving result's private construction and ownership.

The fixture additionally compiles two different private masks over the public
age domain, encrypts them under the same retained SDK key and reuses the SAME
accepted DataCt. A public evaluator receives only ciphertexts/public parameters
and genuinely computes each Ct3. Actual complete conditional arithmetic checking
precedes owner decryption and an independent full4096 ring oracle comparison.
This is a local test of encrypted arithmetic/input reuse, not a production
OriginatingQuery capability, query proof, SQL/locking/freshness/network path or an
assessed product policy. It adds no query Formation proof or second Pair operand.

Direct production dependencies are the parent Role3 Statement/Witness/wire,
actual SourceVersion through that dispatcher and bfv-ciphertext-formation::gold::data.
The public product library and SDK are used by the owning test only. The
[executed DATA validation](../../../bfv-ciphertext-formation/src/gold/DATA-VALIDATION.md)
records this genuine chain, its hostile cases, two ownership examples and the
unchanged full Pair/product gate. Fresh mathematical receiving took 1378.583ms;
the two fixture products took 65.408/64.543ms after query encryption. These are
local mathematical timings, without the complete SQL/finality path or a 500ms
claim. Resource fuses and actual proof rejection remain unchanged.

`data_formation::prove_dense` and `verify_dense` now explicitly select the fixed
H2048 DATA backend while retaining the same complete Expected and mandatory fresh
State/Role3 checks. The SAME final W/salt/key are consumed, with no private getter
or second derivation. `dense_profile_digest` identifies this composition; the
original profile and H8192 API remain unchanged. Neither receiver negotiates or
falls back to the other frame. The new private Word read composition exercises
this public API together with the exact original Stmt96/QueryCt proof and actual
conditional product checking; it creates no SQL or current-head capability.
