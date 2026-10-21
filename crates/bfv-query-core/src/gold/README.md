# Protected Gold owner inputs

`gold-evaluator` separately exports the bounded untrusted `PublicRequest`, fixed
public `Evaluator` and `UnverifiedProduct`, plus public parameter/binding metadata.
This feature compiles no Gold Owner, private mask, custody, input equation or
decryption implementation. `gold-owner` includes it and enables those private
roles. Both use identical existing parameters, profile digests and wire bytes.
The evaluator owns its own SDK public parameters; it never calls an owner helper.
`UnverifiedProduct::into_parts` transfers only untrusted output/certificate bytes.

The optional `gold-owner` family owns generated or independently pinned imported
N4096/Q2/t65537/variance10 SDK secrets, original owner-encrypted DATA/query inputs, conditional public-product
checking and client-side full-ring decryption. It is separate from the old
N8192 Owner/PublicSetup family. No conversion, bootstrap,
Source admission, storage-client SQL compiler, finality or runtime route exists.

The lower DATA expectation supplied here is independently selected mathematical
METADATA. This module neither verifies State/Role3/DATA evidence nor fabricates
an admitted-data token. The future upper owner must actually admit that exact
DATA ciphertext and verify fresh authorized state, rights, Cmd/Source/locks,
Result and current weighted QC before exposing a SQL response or mutation.

## Owned contracts

- `Owner::generate(scope,context)` obtains fresh fallible OS entropy, samples
  the actual SDK CBD20 key with ChaCha20 stream2 and its Cs salt with stream3,
  computes the actual packed Cs, then uses the complete guarded import checker.
  It supplies no enrollment, key authorization or receiving security flag.
- `KeyExpected::checked` requires the exact fixed Parameters and canonical full
  Cs context/root plus owner scope. `Owner::from_sdk` consumes guarded actual
  SDK bytes and Cs salt, validates ALL4096 coefficients and opens Cs using the
  real lower SecretOpening before the SDK decoder. Same key_id alone is useless.
  No SDK secret/key/private-salt getter, Clone, Debug or public callback exists.
- `Owner::originate_data` consumes4096 canonical unscaled private words and
  encrypts them with separate ChaCha20 DATA streams4/5. Move-only `OriginatingData`
  exposes only ciphertext and salted commitment metadata. `prepare_data` checks
  this literal original ciphertext and same Cs/context before making the actual
  lower `data::Prepared`; native proving/verification is still required.
- `InputBinding::checked(InputScope)` fixes database/App/G/Rules/context/parent,
  client/controller/principal/stable transaction/call/snapshot, SourceVersion,
  DataAdmission, original Statement/Cmd, attempt and nonce. All fields are public
  metadata pins, not authority. Raw SQL, operators/constants and mask remain
  private. Any salted commitments must come from the protected future compiler.
- `Owner::originate` consumes typed `Mask256`, full binding and DATA metadata.
  It generates p[255-age] for all256 mask bits, performs real SDK encryption
  with an owner-controlled error stream and independently remasks A while
  preserving every coefficient of the SDK phase. It retains that original
  unseeded canonical QueryCt and fixes the literal ordered
  [DataCt,QueryCt]. There is no arbitrary QueryCt->OriginatingQuery constructor.
- `PublicRequest::formation_request` derives the original ordered endpoints and
  a nonce hashing the full protected request for the lower native composition.
  `Owner::prepare_query` retains the private key/mask: it checks original Ct/nonce,
  same Cs, all canonical Stmt96 words, original mask bytes and Cw opening, then
  returns only the original fused Query `Prepared`. This grants no Word semantics.
- `PublicRequest` is untrusted bounded public wire; decode mints no private
  scope. `Evaluator` receives ONLY public ciphertexts and performs genuine SDK
  multiplication without RK, followed by a complete public arithmetic certificate.
- `Owner::bind_statement` checks the complete canonical Stmt96 root against the
  original InputBinding, its exact private mask and zero padding, then runs the
  actual private input equations with the original QueryCt and same S/Cs. Its
  borrowed `OriginatingStatement` is an owner-private premise, without a public
  Query proof. It exposes public endpoints/header/root only. The optional upper
  [owner read](../../../registry200-proof/src/registry_progress/word/read/OWNER.md)
  joins that premise to independently checked DATA, Word and product arguments.
- `Owner::complete` independently checks that certificate against the ORIGINAL
  pair and full request-derived nonce BEFORE SDK decryption of all4096 values.
  `DecryptedProduct` is conditional mathematical plaintext, not SQL-selected rows,
  a current lock, Source completeness or a finality receipt. Failed evidence does
  not consume the borrowed originating scope. A caller-supplied checked result
  cannot replace the actual arithmetic verifier.

## Protected cold custody

`seal_key` creates an exact4315-byte `EncryptedKey`, using XChaCha20Poly1305
with a fresh fallible OS nonce. The fixed header binds profile, record identity
and complete independently retained KeyExpected. `restore_key` authenticates
those same pins, decrypts only the bounded SDK bytes/salt and reopens ALL4096
coefficients against the actual Cs before creating Owner. No generated/verified
flag is stored. The caller must protect CustodyKey independently; filesystem
durability, anti-rollback, enrollment and exclusive-writer policy stay outside
this library. See the [generation contract](GENERATION.md).

`seal_origin` uses fresh XChaCha20Poly1305 nonce and a caller-custodied
`CustodyKey`. Its fixed header binds family/profile, record identity, exact
KeyExpected/DATA binding and SHA512 identity of the entire original PublicRequest.
The bounded encrypted payload retains the mask and exact original request. No
origin/verified flag, private seed, SQL text or secret key is serialized there.
No unsalted private-mask digest appears in the public header.

`RestoreExpected` independently retains complete InputBinding, compiled Mask256,
DATA metadata and exact original PublicRequest (including nonce and Ct bytes).
`restore_origin` first checks complete independent header pins and AEAD, compares
all original plaintext fields, then runs the actual lower all4096 Q0/Q1 input
consistency check using the SAME actual SDK S/Cs and recompiled already-scaled W.
This checks shared bounded E and exact K. It creates no PP/MAIN/proof or accepted
DATA capability. The transient private Cw uses zero salt and is never exposed or
serialized; its purpose is solely to call the existing complete private equations.

The actual SDK still samples its intermediate A's seed internally. The private
`encryption` module supplies ChaCha20 error coins, then applies an independent
ChaCha20 uniform polynomial BEFORE constructing any PublicRequest. Both streams
start at counter0 with separate stream IDs and one fresh fallible256-bit OS seed.
The [sampler contract](SAMPLER.md) proves exact phase/noise preservation and
distinguishes ideal randomness from the concrete PRG assumption. Entropy failure
returns no input; no public seed/RNG/entropy callback is accepted.

Restore never tries seed replay, re-encryption or a fresh request substitution.
Only this original encryption/remasking path or the protected authenticated
original-input equation path can mint OriginatingQuery. Bounded consistency does
not prove honest random sampling: trusted producer/custody provenance remains
explicit. Custody alone also supplies no rollback protection, exclusive writer,
fsync, WAL/CAS ordering or current-head assurance; those belong to the future
concrete storage-client owner. Never treat an old valid record as a new call.

## Bounds, dependencies and assurance

Public requests have a fixed640-byte header and two existing128KiB ciphertext
caps. Conditional certificate length is the exact lower fixed frame. Custody
is capped at263132 bytes, checked before AEAD allocation. Imports are exactly4099
SDK-secret bytes. Masks, imported SDK bytes, Cs salts, private W, AEAD plaintext
and decrypted coefficients use scoped guards. The SDK SecretKey zeros on Drop;
private field scratch is overwritten. SDK/protobuf/FFT/intermediate allocator or
OS copies are not promised securely erased.

Direct libraries are the existing SDK/fhe-math/fhe-traits for real computation;
[Gold Formation](../../../bfv-ciphertext-formation/src/gold/README.md) for actual
Cs and private input equations; [unrelinearized product](../../../bfv-unrelinearized-product/README.md)
for the complete conditional arithmetic certificate; hiding Poseidon/P3-field
for the fixed private commitment; pinned ChaCha20/rand for key/DATA/query randomness,
and XChaCha/SHA2/zeroize for custody. `rand_chacha0.9.0` is an explicit optional
dependency of `gold-owner`; it was already present transitively through the SDK.
No registry, SQL parser, consensus, experiment, GUI or fixture dependency is added.
The upper readonly core_expected getter supplies metadata, never a proof lease.

Composed security and SQL assurances remain unestablished. The completed
[classical numerical estimate](../../../../experiments/lattice-cost-prefix/ESTIMATE.md)
and conditional lower noise theorem retain their stated assumptions.
The arithmetic model remains explicitly UNASSESSED; its classical ROM/noise
conditions do not become a production crypto assurance through this wrapper.
Hidden WHERE is an architectural requirement, not a new confidentiality theorem.
Delegated/raw-input clients, output-driven DML and transferable SQL claims are
not enabled. Current peer predicate/lock/QC obligations are unchanged.

The original four owning cases exercise actual SDK product+complete arithmetic before
an independent post-check full4096 oracle, destroyed-owner cold restore, AEAD/
scope tampering, repaired authenticated wrong QueryCt/Q1 error and wrong mask
requiring concrete Arithmetic, wrong SDK/Cs and codec bounds. Public parameters
are shared; real keys and owner objects remain fresh. No Source/Formation proof,
accepted fixture answer, fake verifier or checked-DATA factory is used. All four
cases and three compile-fail contracts passed before the sampler change. Three
additional owning sampler cases check disjoint20-round streams, complete exact
phase preservation under different masks, and entropy-failure rejection followed
by honest origination. The [validation record](VALIDATION.md)
reports the measured scope and remaining costs. No <=500ms complete-query result
or whole-peer memory/security claim follows from these local contracts.

The v3 [generation and native-preparation path](GENERATION.md) additionally uses
an actual generated/restored owner for genuine dense DATA and fused Query proofs,
then actual public FHE/product verification and client completion. These are
native Formation results without Source-version/Word semantics, fresh QC or SQL.

`Owner::complete_checked_product` accepts only the sealed move-only result of the
actual lower arithmetic checker. It requires the original full request nonce
and literal ordered DATA/query ciphertext bytes before decrypting. This lets an
upper proof composition retain its actual checked product without running that
same certificate twice. `complete` still performs a fresh full arithmetic check
and delegates to that path. Neither entry point verifies Source, Word, history,
current finality or SQL authority. The registry Word read exercises this optional
feature through a dev-dependency only; Owner has no registry dependency.
