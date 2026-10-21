# BFV query core

Experimental owner-online exact BFV roles, extracted from the frozen
`experiments/bfv-byte-limb-core` baseline. This crate is the ongoing owner of its
cryptographic implementation; product adapters depend on this crate and never on
that historical experiment. No production security or query-proof claim follows.

The direct [bfv-fixed-geometry](../bfv-fixed-geometry/README.md) dependency owns
the unchanged degree, plaintext modulus and coefficient bases. The linear and
product circuit dependencies own their respective canonical arithmetic contracts.

The schema-neutral byte projection path is independent of the historical
`age/amount` layout. `Owner::prepare_byte_select` encrypts original encoded bytes
and binds an opaque schema/table/query/chunk/catalog digest plus both storage
heads. Its public mask selects byte positions corresponding to requested columns;
it must never encode a plaintext row predicate. Each chunk holds up to
`BYTE_SELECT_CAPACITY` (8,191) bytes, including arbitrary text, null markers and
binary data. Streaming callers can split wide rows or large values and have no
128-row bound in this primitive. One reserved zero lane makes even full projection
use a nonidentity polynomial; returning the original ciphertext is not the same
canonical operation.

`PublicUpdateEvaluator::{evaluate_byte_select,byte_select_circuit_request,
restore_byte_select_circuit_output}` expose genuine ciphertext-by-public-polynomial
projection and its exact canonical proof statement. The caller independently
verifies arithmetic through [bfv-query-proof](../bfv-query-proof/README.md).
`compact-query::byte_select::{check,complete_checked}` composes checked evidence
with final client decryption. The low-level
`Owner::decrypt_byte_select_unverified` always returns an explicitly unverified
result. Pending tokens retain only shape, public masks and bindings, never original
plaintext values. Complete authenticated indexed selection, schema semantics,
chunk coverage, authorization and fresh agreed state belong to the storage client.
The byte kernel does not prove arbitrary SQL comparisons or hide access patterns.

`Owner::prepare_polynomial_aggregate` uses the strict Q2/R2 coefficient layout:
low bytes at `[0,2560)`, high bytes at `[2560,5120)` and one presence marker per
original selected row at `[5120,7680)`. The unchanged public polynomial
`1+x+...+x^255` produces ten independent 256-row band sums at each field's
`(band+1)*256-1` endpoints. No source aggregate is calculated by the owner.
`POLYNOMIAL_AGGREGATE_CAPACITY` is 2560; the separate row/mutation limit remains 256.
The product has degree at most 7934, below 8192, and each coefficient is at most
65280, below the unchanged plaintext modulus 114689. Unsigned decoding checks all
band counts/limb bounds, the full cardinality-only coefficient envelope, the exact
presence suffix and zero tail `[7935,8192)`. It combines actual decrypted band
values with checked arithmetic (maximum sum 167,769,600), rather than returning
retained source cardinality as the answer. Empty sources still encrypt zero.

The existing Rows256 setup, FHE parameters, full-residue product proof profile
and kernel ABI are unchanged. Q1/R1 and version 1 reject; no migration is supplied.
The exported `POLYNOMIAL_AGGREGATE_SEMANTICS_ID` identifies this accepted operation
language separately from the cryptographic profile. Request/response decoding
remains capped at two MiB. `aggregate_circuit_request` independently constructs
the exact full-residue public-polynomial statement; `restore_aggregate_circuit_output`
restores its encrypted result only. A genuine proof consumer must check the exact
statement before `decrypt_polynomial_aggregate_unverified`. This uses no rotations
and leaves complete selection, source authentication and freshness to its caller.
The older exact-index rotation experiment remains unverified.

One packed input remains 8192 u64 coefficients (64 KiB before encryption), one
ciphertext and one proof per shard. Increasing occupied support does not increase
the public kernel's L1 norm of 256 or introduce negacyclic/plaintext wrap. This
algebraic bound is not a new security or noise-profile approval; genuine maximum
source and partial-band decryption/proof tests cover the implemented parameter set.

Owner owns the only secret key; PublicSetup contains only original parameters,
relinearization and rotation keys; PeerEvaluator restores public material only.
Inputs are fresh encrypted selected fields. Public contracts include generic
Equal/AtLeast/ClosedRange COUNT/SUM, explicitly caller-asserted exact-index aggregate,
indexed encrypted row projection, indexed amount addition and bounded encrypted batch
append. Indexed wire contracts bind operation/keyset/geometry/query ID and both
opaque 112-byte heads. Generic pending tokens also bind their local owner keyset;
they do not add malicious-response authentication. Results remain Unverified;
UPDATE/INSERT callers must locally check decoded values before writeback.

`Owner::require_public_setup` checks the original parameters, geometry and full
keyset association through the existing private validation path. It performs no
encryption, exposes no secret material and supplies no computation/finality grant.
The [Joint client gate](../../docs/joint-locking-inputs.md) covers a foreign setup
with identical geometry and a canonical reconstruction of the correct setup.

`PublicSetup::update_parameters` extracts the pinned parameters, geometry and full
keyset identity for indexed addition. `PublicUpdateEvaluator` performs the same
encrypted limb addition as the full evaluator, with identical request/output bytes,
without unused rotation/relinearization keys or wall-clock instrumentation. This
descriptor must be bound to the caller's trusted public setup; its identity is not
self-authenticating. Validated immutable public parameters are cached once per
process; no secret key or row data enters that cache. This reduced execution path
does not itself supply a computation proof or authorize accepting a SQL answer.

`PublicSetup::from_public_material` assembles the existing public container for
callers that already hold public parameter/relinearization/rotation bytes.
It uses the existing setup codec, typed geometry and exact pinned parameters,
checking the complete 64 MiB encoded-size cap before copying. This bounds the
encoded setup rather than process RAM. Evaluation-key blobs
remain opaque and byte-exact, including their original order. As with `from_bytes`,
this container does not validate their mathematical structure, same-secret origin
or owner authorization; the full evaluator parses keys when it uses them. The
stripped evaluator retains the hash of the COMPLETE setup, never a parameter-only
substitute. Callers must independently authenticate that identity. Upstream rotation
keys serialize a HashMap, so decoding and reserializing them is not a canonicality
check for the original full keyset bytes.

`PublicUpdateEvaluator::encode_public_select(context, projection, canonical_ct)`
wraps an existing ciphertext in the same ExactPublicProjection request and codec,
with an empty private mask. It receives no Owner, secret key, original slots or
pending token and performs no encryption. The new boundary checks context lengths,
a 512 KiB ciphertext cap, two level-zero NTT components, canonical residues and exact
upstream roundtrip before retaining the original bytes. The pinned unseeded ceiling
is 446,494 bytes; compressed seeded inputs also fit. It does not establish same-key
formation, complete all-active source selection, zero padding, authorization or a
fresh agreed head. Those proofs and expected bindings must precede any accepting
consumer. A canonical ciphertext under another key remains syntactically valid.
The encoder returns only request bytes; arithmetic conversion/restoration and
unverified evaluation keep their existing contracts. No wire ABI or existing
Owner path changes. Validation passed all 90 owning tests and three compile-fail
doctests, with strict all-target Clippy. The new cases cover exact codec/byte
preservation, public setup identity, canonical input rejection and actual complete
FHE projection. These are syntax and binding checks; this API adds no computation
proof, key authority or production acceptance.

`PublicUpdateEvaluator::request_context` validates a supported original UPDATE,
exact-set SELECT or version-3 INSERT request, including every ciphertext's level,
component count and representation, then returns its public `QueryContext`. Runtime
and journal validators can compare both heads against independently agreed storage
state without exposing private request types or executing an SQL/FHE operation.
It rejects earlier INSERT versions and the private-active SELECT domain; returning
a well-formed opaque head does not establish that peers agreed on it or its freshness.

`PublicUpdateEvaluator::circuit_request` converts the exact original ciphertexts to
the canonical NTT residue representation of [bfv-linear-circuit](../bfv-linear-circuit/README.md).
`restore_circuit_output` reconstructs a
normal upstream ciphertext response without repeating the addition. Both are
representation adapters, not verification/acceptance APIs. The proof requester must
retain the canonical input digest and verify it, the output digest, and a trusted
circuit identity before decrypting/using the response. Freshly prepared updates are
tested against the upstream operator byte for byte for both geometries and limb
carry/overflow cases. The original query ID, complete data/index heads, geometry and
keyset remain bound through the original request digest. An opaque bound head is
not evidence that peers agreed on it or that it is current.

The private `canonical::public_product_request` owns the shared level-zero
two-component NTT product representation for row projection, byte projection and
coefficient aggregation. It checks both ciphertext polynomial contexts, converts
the caller-derived public plaintext, preserves every modulus/coefficient and binds
the complete original request bytes. Each operation retains its encoding, public
mask/kernel packing and request metadata checks; proof acceptance remains external.
This adapter retains no requests, rows, keys or proof results.

The indexed SELECT operation freshly encrypts original age/amount lanes and an
encrypted projection/active mask. The public-only peer performs one ciphertext
multiplication and relinearization; it returns encrypted projected lanes and presence
markers. Client completion checks the operation, keyset, context, geometry, projection,
active slots, value bounds and zeroed unrequested/reserved lanes. An in-bounds forged
answer can still pass: `UnverifiedSelectedRows` is explicitly not a computation proof.
The exact-index contract belongs to the caller, as for exact-index aggregates; this
operation does not conceal or re-evaluate an arbitrary SQL predicate.

`Owner::prepare_indexed_insert_for_experiment` independently encrypts the original
contiguous relation and an incoming batch at public append positions. The incoming
operand contains no existing rows, and the existing operand contains no incoming
rows. The public-only `PeerEvaluator::evaluate_indexed_insert_for_experiment` adds
these ciphertexts, including encrypted presence markers. No rotation is required:
the request exposes `existing_rows` and nonzero `incoming_rows`. This is input
placement for genuine encrypted addition, not owner assembly of the complete answer.
The append request version is 3; earlier single-row/staging requests are rejected
rather than interpreted under different arithmetic semantics.
`decrypt_indexed_insert_unverified_for_experiment` returns only decoded peer output
after binding, lane and value checks. This operation requires Rows256 and a complete
old-plus-incoming relation of at most 256 rows. Empty/oversized batches reject before
encryption. It retains the original parameters and public rotation keys.
`PublicUpdateEvaluator::{evaluate_insert,insert_circuit_request,restore_insert_circuit_output,insert_metadata}`
expose the same operation without rotation/relinearization keys. Canonical circuit
outputs match both full and minimal upstream evaluator bytes exactly. `insert_metadata`
validates both original ciphertexts before exposing the public counts and query heads;
it supplies neither an arithmetic proof nor a freshness decision.
Storage growth, authorization and validation against authenticated originals belong
to the caller. It does not provide a succinct computation proof.

`Owner::prepare_exact_select_for_experiment` is a separate path for a complete,
authenticated exact matching set in which every supplied row is active. It rejects
private-active holes. Original age/amount fields, encrypted presence bits and zero
padding are encrypted before projection; it never prepares a projected answer.
`PublicUpdateEvaluator::evaluate_exact_select` then performs real upstream
ciphertext-by-plaintext multiplication. Its mask contains only the already public
`RowProjection`, covering all 256 possible slots even for Rows16 or an empty result.
No count, row predicate, active pattern or original field appears in that mask.

For this all-active exact-set domain, the decoded output equals the original
encrypted-mask path: the public mask agrees on every present slot, and zero input
padding remains zero regardless of mask values there. Presence bits distinguish
zero-valued rows from padding and remain encrypted. Request shape and mask are
independent of selected count; fresh same-length BFV ciphertexts hide contents and
count under the original encryption assumption. This is a conditional equivalence
argument, not a new cryptographic security proof. The original private-active
ciphertext-by-ciphertext API remains available and cannot be substituted by this
path. The operation mode and column projection remain public in both contracts.

`select_circuit_request` converts the exact original ciphertext and public encoded
mask into [bfv-product-circuit](../bfv-product-circuit/README.md)'s complete NTT
products. `restore_select_circuit_output` reconstructs the normal upstream response
without repeating the multiplication. Conversion and restoration validate all
original ciphertext representations and bind the complete original request digest,
including query ID, both heads, geometry, projection and keyset. Restoration is not
proof verification. An external proof consumer must independently derive the same
canonical inputs, verify a real proof and separately establish authenticated index
completeness and the fresh agreed head before any live acceptance or mutation.

Private modules are canonical, kernel, exact_index, indexed_select, indexed_update and indexed_insert.
Direct project dependencies are bfv-linear-circuit and bfv-product-circuit. External
dependencies are pinned fhe/fhe-traits0.1.1, rand0.9.2, serde/bincode1.3.3, SHA256 and zeroize;
it has no storage, SQL, PIR, GUI, fixture or deployment dependency. Complete exact
selection, trusted heads/freshness, global transaction policy and resource accounting
belong to its caller. Original public setup must be retained for same-key recovery;
secret serialization is currently exposed as a COUNT only, not a recovery image.

Parameters stay native/unfused/level0 N8192/Q218/t114689, CBD variance10. The full
evaluator retains the unchanged keyset; indexed addition can omit keys unused by
that circuit. Independent security/noise/CCA and malicious arithmetic proof gates remain
open. The inherited37 tests/2 compile-fail doctests move with this implementation;
crate imports change only. Extraction validation passed all 37 runtime tests and
two compile-fail doctests in release/locked/offline mode, plus strict all-target
Clippy. Those measurements describe the extracted baseline. Indexed SELECT adds a
depth-one projection operation with the same parameters and public key material;
the existing aggregate/update circuits retain their contracts.
Rust 1.99 is retained from the measured baseline; lower MSRV is not claimed.

With indexed SELECT, release/locked/offline validation passed 45 runtime tests and
three compile-fail doctests. Controls include all 256 slots at maximum unsigned
values, every projection mask, inactive/zero rows, fresh ciphertexts, forbidden echo,
wrong operation/keyset/query/heads/geometry/projection and lower-level/wire rejection.
An accepted in-bounds forged value remains explicitly unverified.

With encrypted INSERT and the generic owner-keyset completion guard, owning
release/locked/offline validation passes 53 runtime tests and three compile-fail
doctests. INSERT controls cover empty and 255-row targets, zero/max values, real
addition of separate operands, fresh ciphertexts, unchanged public setup, full/unsupported
geometry, wire/binding/shape rejection and in-bounds malicious output.

The owning storage consumer is [compact-query](../compact-query/README.md), whose
explicit BFV module establishes the owner-built exact-index and compact writeback
contract. Headless GUI uses that module; no owner secret enters a peer evaluator.

Owning validation commands (Rust 1.99):

```sh
cargo test --release --locked --offline -p bfv-query-core -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-query-core --all-targets -- -D warnings
```

`PublicSetup::relinearization_material()` returns a borrowed
`PublicRelinearizationMaterial` after the existing fixed parameter check.
`parameters()` and `relinearization_key()` expose the exact original public byte
slices; `geometry()` exposes the existing geometry. `keyset_id()` is the existing
SHA256 identity of the COMPLETE setup encoding, including untouched rotation-key
bytes. It does not decode/reorder key blobs or assemble a parameter-only subset.
The view borrows one immutable setup and retains no cloned component buffers;
computing its identity uses the unchanged full setup encoder. It has no secret-key,
mutable-key, evaluator, serialization or accepting-proof API.

Native owning validation passes all 93 runtime tests and the three existing
compile-fail doctests, with zero failures or ignored cases. Strict all-target
Clippy and explicit rustfmt also pass on Rust 1.99.0 in release/locked/offline mode,
using a fresh `.local/target-public-relinearization-view-r1`. All existing lock
files, setup wire and operation profile implementations remain unchanged.
The three new public API tests cover a real non-secret Owner-generated setup and upstream key roundtrip, exact
original/roundtrip bytes, identity changes for geometry, either key blob and
rotation order, and opaque invalid bytes that remain inspectable while the full
evaluator rejects them. Getters borrow component buffers; constructing the view
temporarily encodes the complete setup to compute its existing identity, so this
is not an allocation-free constructor or a whole-process resource guarantee.
The caller must already trust the expected owner/setup provenance. A setup decoded
from an untrusted sender can have a perfectly matching self-derived identity;
that comparison supplies no owner authorization, same-secret/evaluation-key
consistency, computation proof or fresh agreed state. The
[public seeded-key adapter](../bfv-relinearization-key-source/README.md) consumes
this view at a separate boundary; PB-to-NTT proof links remain necessary.

## Optional owner key evidence

The `key-proofs` feature adds `Owner::key_anchor`, an opaque borrowed
`OwnerKeyAnchor`, its public `BfvKeyAnchor`, and
`PublicSetup::verify_key_transform`. Default core dependencies do not enable this
feature. The direct optional [key-transform](../bfv-key-transform/README.md) and
[hiding suite](../bfv-hiding-stark/README.md) dependencies own the reusable circuit
and proof implementation; core never depends on an experiment.

The actual Owner checks its original complete setup identity, fixed parameters and
geometry before copying SDK coefficients. It mints a stable prequery input root and
uses fresh output salt/prover randomness on each proof. The private handle has no
Clone, Debug, serialization, import, callback or private-data getter. Explicit wide,
narrow and stored salt buffers are zeroizing; native field vectors, FFT/trace and
SDK scratch are not securely erased. Public verification requires the original
setup and an independently owner-pinned anchor, never metadata chosen by the sender.
The full setup association is trusted owner-local metadata; the unchanged AIR
parameter descriptor does not prove evaluation-key same-secret consistency.

There is no durable anchor/private-salt recovery, and standalone output openings
are discarded. A future combined Basis producer must own a newly matching private
opening and real Key proof. Executed owning tests include actual Owner proof
generation, an independent full 8192-coefficient native oracle, fresh public
verification and hostile frames. No ciphertext formation,
SQL answer acceptance, client freshness or composed-security claim follows.

Native validation of the optional owner-key API is recorded in
[Owner key validation](../bfv-key-transform/OWNER-KEY-VALIDATION.md). It covers
actual generated keys, independent fresh verification, rejection boundaries and
observed resource limits; it does not grant live SQL acceptance.


## Sequential owner Key and five Basis

The optional `basis-proofs` feature includes `key-proofs` and adds
`OwnerKeyAnchor::basis_job`, `OwnerBasisJob`, `BasisJobStage` and
`PublicSetup::verify_basis_convolution`. The new direct optional
[bfv-basis-convolution](../bfv-basis-convolution/README.md) dependency owns the exact
reusable relation and bounded one-component codec; Core owns the actual Owner mint.
No experiment dependency is introduced.

Job construction rechecks the ORIGINAL complete setup identity, geometry and fixed
parameters, then the COMPLETE canonical public ciphertext BEFORE a single guarded
SDK coefficient copy. It derives one private Shat outside the actual proof trace,
retains one fresh output salt/CsHat, and emits a newly matching real Key proof.
Standalone Key evidence's discarded salt is never recovered. AwaitingKey then
Basis0..4 then Complete is a local synchronous sequence; failures do not advance,
repeated/completed/cancelled calls reject, and cancel is between calls only. No
completed prefix is a ciphertext-formation or SQL acceptance token.

After Key success the guarded coefficient witness is dropped. The job retains
only its borrowed owner anchor, one public Key frame, public ciphertext, private
64 KiB canonical Shat and tiny guarded salts. Each call returns ONE public Basis
component; no aggregate proof vector/frame or parallel backend cache exists.
Cancel/drop clears guarded private storage; native Gold/FFT/trace/LDE/PCS buffers
are NOT promised securely erased. No private getters, Clone, Debug, serialization,
import, callback or persistence/recovery API is added. The original setup and
independently owner-pinned anchor remain required for fresh public verification.

Executed owning tests spool public components sequentially, drop Owner/job before
fresh independent verification, and compare all8192 outputs of each basis against
actual SDK-key/native-prime/CRT plus independent Poseidon streams. The
[validation record](../bfv-basis-convolution/OWNER-BASIS-VALIDATION.md) reports the
executed rejection boundaries and sampled resources. These proofs do not establish
formed BFV encryption, evaluation-key consistency, Source/Registry200 linkage,
controller authority, fresh agreement, live SQL or a composed128-bit claim.

## Ciphertext formation continuation

The optional `formation-proofs` feature includes `basis-proofs` and the reusable
[formation relation](../bfv-ciphertext-formation/README.md).
`OwnerKeyAnchor::encrypt_encoded_coefficients` accepts caller-owned scaled W, checks
the complete original setup and fixed shape before SDK work, then uses actual
Owner encryption. `OwnerBasisJob::into_formation` consumes only a complete job and
an explicit private `EncodedOpening`. The opaque non-Clone/non-Debug/non-Serialize
OwnerFormationJob rechecks actual Key/five Basis, derives common bounded noise,
and emits one bounded component. No private getters, callbacks or import exist.
The retained Shat/opening/salts are released on successful proof, cancel or drop;
SDK/native field scratch is not promised erased. Cancellation is between synchronous
calls. No owner-private persistence/recovery is added. This mathematical input is
not Source/SQL authority, and the feature does not enable network answer acceptance.
The [executed validation](../bfv-ciphertext-formation/OWNER-FORMATION-VALIDATION.md)
covers actual Owner formation, hostile components and sampled process resources.


## Exact public projection completion

`Owner::decrypt_public_select_unverified_for_experiment(request, response)` decodes
an existing exact public-projection response using the original Owner. It checks
full keyset/context/projection/geometry/operation and complete canonical ciphertext
before actual SDK decryption, then returns all 8192 caller-owned SIMD slots. It
creates no pending token, re-encrypts no fields and performs no proof, freshness,
SQL or authorization check. Generic Core has no Journal or experiment dependency.

The strict raw ciphertext boundary is owned by
[bfv-ciphertext-wire](../bfv-ciphertext-wire/README.md), a direct dependency used by
`checked_ciphertext` before SDK allocation. The completion codec and public encoder
reuse its unchanged fixed ciphertext cap. Native/SDK scratch is not securely
erased by this API; returned plaintext belongs to the client. The new owning codec
example and composed peer job passed the owning checks; see
[executed peer validation](../../experiments/hiding-fri-sha256-gate/src/opening/registry_lifecycle/formation/job/PEER-PROJECTION-VALIDATION.md).
This does not grant proof, freshness or SQL authority to the completion method.

## Private coefficient-predicate prototype

The separate [coefficient-predicate module](src/coefficient_predicate/README.md)
keeps all four original rows and WHERE/constants encrypted using query-independent
weighted onehot source lanes and a separate encrypted query polynomial. One actual
SDK ciphertext product and original relinearization produce per-row masked
presence/age/amount coefficients; the original Owner performs decryption only.
Completion returns UnverifiedPrivateCoefficientPredicate, with no Source,
computation/completeness, freshness or SQL admission. The existing fixed-geometry
and ciphertext-wire dependencies own constants and borrowed canonical preflight;
no public mask or plaintext SQL hash, new proof/profile, peer role or dependency
is introduced. That stage has no input provenance proof; the separate experiment
below now links those inputs. Complete output MulRelin and live integration remain
open. The [executed validation](PRIVATE-COEFFICIENT-VALIDATION.md)
records all eight new actual FHE tests within 70 Core tests, affected-consumer
regressions and the limits of the measurements. It does not grant SQL authority.

## Shared Key opening for two operands

The existing `formation-proofs` feature adds the opaque
[two-operand Owner scope](src/key_anchor/two_operand_job/README.md). It proves one
Key followed by two ordered Basis5 + Formation chains, keeping the same private
Shat/CsHat and binding each complete original ciphertext and public encoding
commitment independently. `PreparedPrivateCoefficientPredicate::operand_ciphertexts`
borrows the exact existing request operands after pending digest/label checks;
the scope never encrypts a substitute input. Input0/Input1 are generic local
positions, not SQL/Registry authority. Complete clears explicit private material
and retains one borrowable public Key frame; terminal cancel clears it too.
The [executed input validation](../../experiments/hiding-fri-sha256-gate/PRIVATE-COEFFICIENT-INPUT-VALIDATION.md)
covers the actual13-component scope, native oracles, lifetime gates and a separate
Source/hidden-query sixteen-proof chain. No aggregate wire, raised caps or SQL
admission is introduced; old single-job APIs remain separately tested.

`EvaluatedPrivateCoefficientPredicate::ciphertext_for_experiment` borrows the
complete proposed ciphertext through the existing response validator, allowing
the standalone [full multiplication graph](../../experiments/bfv-mul-relin-proof/README.md)
consumer to bind exact encrypted output bytes. It grants no SQL/proof authority
and introduces no dependency from Core to that experiment.

## Reusable in-memory proof epoch

The existing `formation-proofs` feature also provides an opaque
[OwnerProofEpoch](src/key_anchor/proof_epoch/README.md). One actual Key33/CsHat
opening and genuine Key proof serve exclusive sequential operand jobs, each
with its own exact request, complete ciphertext and encoding commitment.
`OwnerEpochOperandJob` emits ordered Basis5 plus Formation using the existing
real prerequisite verifiers. Job completion/cancel/Drop clears only its own
guarded W/salts; epoch cancellation/Drop clears the retained Key opening.
The old single-operand and fixed two-operand APIs retain their semantics and
owning assertions. Their shared private operand implementation contains no SQL
or Source policy. That in-memory stage introduced no new dependency, profile,
frame, cap, secret getter, serialization, trusted marker or recovery path.

The [producer/epoch validation](../../experiments/hiding-fri-sha256-gate/PRIVATE-INPUT-PRODUCER-EPOCH-VALIDATION.md)
records the executed native stage. It enables
private opening reuse; it does not make existing query-specific Source proofs
reusable across SQL requests or change full-product provenance checks. Persistent
Source certification, origin/query composition, evaluation-key same-secret
proofs, fresh agreed heads and live SQL acceptance remain separate obligations.

## Public anchor claim codec

With `key-proofs`, `BfvKeyAnchor::encode_claim` and
`PublicSetup::decode_key_anchor_claim` encode/decode the fixed 140-byte
`BFVKAC01` public metadata format. It binds database/key domain/epoch, the full
original setup identity, parameter-only digest and canonical Gold coefficient
commitment. Decoding checks exact grammar and the supplied setup association;
it performs no polynomial transform or evaluation-key decoding. A decoded
anchor is an untrusted mathematical claim, with no Owner provenance, secret
possession or proof authority. Clients must keep their original independently
authenticated anchor. The codec exposes no secret/opening getter and does not
alter the genuine `verify_key_transform` prerequisite. Both new owning codec
tests passed with `formation-proofs`; the
[peer validation](../../docs/private-where-peer.md) also covers the borrowed
complete-request view and exact encrypted-response binding.

## Owner-authenticated private backup

The separate [owner-state module](src/owner_state/README.md) adds encrypted,
bounded Owner/anchor/ReadyEpoch backup and lexical restore. The caller supplies
an owner-custodied wrapping authority and independently pinned full original
setup/scope/record/anchor/Key33. Restore validates all secret coefficients before
the SDK boundary, reopens both commitments and verifies the genuine stored Key
frame before returning Ready. The implementation uses the existing pinned
XChaCha20Poly1305 and official prost encoder; it exposes no plaintext secret,
salt or Shat getter. Old generation and proof APIs retain their behavior.
The [native validation](../../docs/owner-key-recovery.md) passed 132 runtime
tests and 35 compile-fail contracts, including actual restored Key/Basis/Formation
after the original private objects were destroyed. It adds no durable OwnerVault,
rollback protection, Source Ckey/pending transaction recovery, same-secret RK
theorem, finality or SQL admission.

## Protected N4096 owner inputs

The optional `gold-owner` feature adds the separate [Gold owner family](src/gold/README.md).
It generates a key with fresh OS/ChaCha20 coins or imports an independently pinned
guarded SDK key, opens its actual Cs, generates original DATA/query ciphertexts
through actual SDK encryption with owner-controlled
ChaCha20 error coins and an exact phase-preserving A remask, then checks the complete
conditional public arithmetic certificate before client decryption. Protected AEAD
origination restore rechecks the original input equations; it never re-encrypts or
adopts a stored success flag. The supplied DATA expectation is mathematical metadata,
not Source/current-head admission. Old N8192 Owner/public profiles remain separate.
No production SQL, finality, lattice/noise or composed-security assurance is added.
The [sampler contract](src/gold/SAMPLER.md) records the precise randomness/phase
argument and unresolved imported-key/DATA assumptions. The
[executed validation](src/gold/VALIDATION.md) distinguishes the original four
SDK/custody cases, new sampler cases, compile-fail contracts and separate
default/all-feature compilation. The [generated lifecycle](src/gold/GENERATION.md)
adds bounded authenticated key restoration and prepares real native DATA/fused
Query proofs while retaining the secret key inside Owner.
