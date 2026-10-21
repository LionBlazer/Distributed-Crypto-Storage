# Generated owner, key custody and native private preparation

The v3 protected-owner family supplies an executable private lifecycle for the
existing N4096/Q2/t65537/CBD20 mathematics. It creates actual SDK keys, encrypts
original DATA and queries with owner-controlled randomness, and prepares the
original native DATA/fused Query relations without exporting a secret key.
This is not enrollment, Source/Word admission, current finality or SQL authority.

## Key lifecycle

`Owner::generate(scope,context)` requires a nonzero owner scope and canonical
Gold Cs context. One fresh fallible OS seed initializes ChaCha20 stream2 for
the SDK's actual CBD20 secret and stream3 for four uniform Gold salt elements.
Both start at counter0. Salt sampling uses the prebuilt unbiased Uniform path.
All4096 secret coefficients are packed into the original512 six-bit words;
the existing528-field Cs sponge computes their root. The independently retained
KeyExpected fixes the complete scope, parameters, context and root. The generated
SDK bytes/salt pass through the same complete private opening/import checker.
No seed/provider argument, raw secret getter, Clone or Debug is available.

This provides a normal honest generation path under the OS/multi-stream ChaCha20
assumptions. `from_sdk` remains an explicit guarded import, whose bounded/Cs
consistency check cannot establish honest random sampling. Neither construction
authenticates who may enroll or use the key in a database. Such authorization
and Source key binding belong to the upper application.

`seal_key(identity,custody_key)` returns an exact4315-byte EncryptedKey record:
168-byte header,4131 encrypted SDK/salt bytes and16-byte AEAD tag. The header
binds GOKCST01/profile, independent record identity, full KeyExpected binding,
fresh fallible24-byte OS nonce, exact payload length and zero reserved fields.
The payload contains4099 canonical SDK-key bytes and four little-endian u64 salt
words. It contains no generated/verified/admitted flag. XChaCha20Poly1305 uses
the same closed custody-key primitive as the existing query-origin custody.

`restore_key` takes independently retained KeyExpected, identity and custody key.
It rejects the wrong exact shape/profile before allocation, compares the full
expected header, authenticates/decrypts, then reopens the complete actual key/Cs
through `from_sdk`. Valid AEAD alone cannot accept a different bounded key or
salt. Untrusted EncryptedKey parsing creates no Owner. The caller must protect
CustodyKey separately from the record and pin KeyExpected from its trusted state.
No filesystem persistence, fsync/WAL, anti-rollback, writer exclusivity, nonce
lifetime accounting or enrollment policy is implemented here.

## Original DATA

`Owner::originate_data` consumes exactly4096 canonical unscaled private words.
The shared private SDK/remasking producer uses fresh ChaCha20 streams4/5; queries
retain streams0/1. Each operation has its own fresh OS seed. The final original
ciphertext is canonical unseeded CT2. Move-only OriginatingData retains the
private words and complete owner-key binding, exposes only ciphertext, and can
compute a salted Cw commitment for independently selected public context/salt.
It has no raw-ciphertext constructor, private-word getter or serialization.

The upper Source encoder must supply the actual original database encoding and
independent Source-derived DATA expectation. Caller-supplied polynomial words
or a commitment are not proof of that connection. `prepare_data` requires the
literal original ciphertext, same complete key binding and exact Cs context/root.
It scales the SAME private words once, opens the independently pinned Cw and
consumes a guarded copy of the SAME key/Cs opening into `data::Prepared`.
That prepared input proves nothing by itself: original `prove_dense` and cold
`verify_dense` still execute. Borrowing the original permits retry without
substituting a newly encrypted request; no prior verification result is cached.

## Original Query and composition

`PublicRequest::formation_request` constructs the lower original ordered
[DataCt,QueryCt] endpoints with a nonce hashing the entire protected request.
It derives metadata, without converting any profile or accepted capability.
The receiving upper composition must independently bind the same endpoints to
Source, Word/Stmt96, caller intent, authorization and current agreed state.

`query_commitment` commits this SAME private mask under caller-selected public
Cw context and private salt. `prepare_query` requires the original QueryCt and
derived nonce, same Cs/context, canonical full96 statement words, exact original
packed mask and actual Cw opening. It returns the existing fused Query Prepared
using the privately retained SDK key/salt. Native proving and cold verification
remain mandatory. A caller-selected statement/header may satisfy the low-level
formation relation without satisfying Word semantics: only the separate original
Word/Source composition can establish that application claim.

All lower DATA/Query/product profiles and native verifiers are unchanged. The
protected-owner v3 digest records generation, six fixed stream domains, key
custody and private preparation. Existing upper bindings carry that digest;
no v1/v2 migration, legacy fallback or profile conversion is provided.

## Evidence and remaining boundaries

The owning normal-client test creates a key through `generate`, encrypts DATA,
destroys/restores the Owner, generates and independently verifies genuine dense
DATA and fused Query proofs, then performs ciphertext-only SDK multiplication,
checks its full arithmetic certificate and decrypts before a separate4096-word
plaintext oracle. It uses no SDK-secret getter, supplied verifier, accepted-DATA
fixture or simulated FHE work. Additional cases reject failed entropy, invalid
context, wrong key/record/custody key, malformed or damaged records, repaired-AEAD
wrong secret, substituted original DATA, wrong Cw salt/mask/nonce and bad proofs.
Test custody keys and fixtures are explicitly public/nonsecret. Actual results,
component timings and process resources are in [VALIDATION.md](VALIDATION.md).

The test's DATA/Stmt metadata is a mathematical example. It supplies no native
Source-version or Word proof, fresh weighted head, lock or SQL result. Existing
imported key/DATA entropy, honest sampling across untrusted network producers,
whole-system confidentiality and concrete composed security remain separate.
Private SDK/salt/word/AEAD buffers have scoped guards; complete erasure of RNG,
SDK, allocator, compiler or OS copies is not promised. This capability remains
an owner-side core consumer, with no registry, consensus, GUI or fixture dependency.
