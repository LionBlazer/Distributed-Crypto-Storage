# Protected Gold owner inputs

The optional `gold-owner` family owns import-only N4096/Q2/t65537/variance10
SDK secrets, original owner-encrypted query inputs, conditional public-product
checking and client-side full-ring decryption. It is separate from the old
N8192 Owner/PublicSetup family. No conversion, key generation, bootstrap,
Source admission, storage-client SQL compiler, finality or runtime route exists.

The lower DATA expectation supplied here is independently selected mathematical
METADATA. This module neither verifies State/Role3/DATA evidence nor fabricates
an admitted-data token. The future upper owner must actually admit that exact
DATA ciphertext and verify fresh authorized state, rights, Cmd/Source/locks,
Result and current weighted QC before exposing a SQL response or mutation.

## Owned contracts

- `KeyExpected::checked` requires the exact fixed Parameters and canonical full
  Cs context/root plus owner scope. `Owner::from_sdk` consumes guarded actual
  SDK bytes and Cs salt, validates ALL4096 coefficients and opens Cs using the
  real lower SecretOpening before the SDK decoder. Same key_id alone is useless.
  No SDK secret/key/private-salt getter, Clone, Debug or public callback exists.
- `InputBinding::checked(InputScope)` fixes database/App/G/Rules/context/parent,
  client/controller/principal/stable transaction/call/snapshot, SourceVersion,
  DataAdmission, original Statement/Cmd, attempt and nonce. All fields are public
  metadata pins, not authority. Raw SQL, operators/constants and mask remain
  private. Any salted commitments must come from the protected future compiler.
- `Owner::originate` consumes typed `Mask256`, full binding and DATA metadata.
  It generates p[255-age] for all256 mask bits, performs real SDK encryption,
  retains the original unseeded canonical QueryCt and fixes the literal ordered
  [DataCt,QueryCt]. There is no arbitrary QueryCt->OriginatingQuery constructor.
- `PublicRequest` is untrusted bounded public wire; decode mints no private
  scope. `Evaluator` receives ONLY public ciphertexts and performs genuine SDK
  multiplication without RK, followed by a complete public arithmetic certificate.
- `Owner::complete` independently checks that certificate against the ORIGINAL
  pair and full request-derived nonce BEFORE SDK decryption of all4096 values.
  `DecryptedProduct` is conditional mathematical plaintext, not SQL-selected rows,
  a current lock, Source completeness or a finality receipt. Failed evidence does
  not consume the borrowed originating scope. A caller-supplied checked result
  cannot replace the actual arithmetic verifier.

## Protected cold custody

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

The actual SDK samples A's seed internally with thread RNG, independently of the
caller RNG. Restore therefore never tries seed replay, re-encryption or a fresh
request substitution. Only actual SDK generation or this protected authenticated
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
for the fixed private commitment; pinned XChaCha/SHA2/rand/zeroize for custody.
No registry, SQL parser, consensus, experiment, GUI or fixture dependency is added.
The upper readonly core_expected getter supplies metadata, never a proof lease.

All composed security, lattice/noise and SQL assurances remain unestablished.
The arithmetic model remains explicitly UNASSESSED; its classical ROM/noise
conditions do not become a production crypto assurance through this wrapper.
Hidden WHERE is an architectural requirement, not a new confidentiality theorem.
Delegated/raw-input clients, output-driven DML and transferable SQL claims are
not enabled. Current peer predicate/lock/QC obligations are unchanged.

Four executed owning cases exercise actual SDK product+complete arithmetic before
an independent post-check full4096 oracle, destroyed-owner cold restore, AEAD/
scope tampering, repaired authenticated wrong QueryCt/Q1 error and wrong mask
requiring concrete Arithmetic, wrong SDK/Cs and codec bounds. Public parameters
are shared; real keys and owner objects remain fresh. No Source/Formation proof,
accepted fixture answer, fake verifier or checked-DATA factory is used. All four
cases and three compile-fail contracts passed; the [validation record](VALIDATION.md)
reports the measured scope and remaining costs. No <=500ms complete-query result
or whole-peer memory/security claim follows from these local contracts.
