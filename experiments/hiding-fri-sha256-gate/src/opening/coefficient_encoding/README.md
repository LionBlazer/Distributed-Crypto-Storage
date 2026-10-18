# Source and private-query coefficient evidence

This non-admitting consumer proves the two distinct private-main relations in
[registry200-proof::coefficient_encoding](../../../../../crates/registry200-proof/src/coefficient_encoding/README.md).
Every original row is encoded before any WHERE filtering. The hidden query is
independently encoded as a reversed256-bit coefficient polynomial. No mask,
threshold, SQL text, private blind, source plaintext or salt is serialized.
This is not a peer SQL handler, Formation, complete MulRelin or agreed-head grant.

| Direct owner/dependency | Responsibility |
| --- | --- |
| [compiler](compiler.rs) / sql-plan | Privately compile fixed-schema WHERE, exact blinded SQL binding and acyclic pre-Source q |
| [trace](trace.rs) | Own guarded caller plaintext/mask/salts, complete main trace and optional mathematical EncodedOpening |
| [library wire](../../../../../crates/registry200-proof/src/coefficient_encoding/wire/mod.rs) | Original two-component bounded canonical frame and real Source-first verification |
| [fixture](fixture.rs) | PUBLIC NONSECRET Source/blind vectors and genuine actual Owner public Key statement; never runtime authority |
| [registry200-proof](../../../../../crates/registry200-proof/README.md) | Single shared Source and new coefficient AIR/statement/profile implementations |
| [bfv-hiding-stark](../../../../../crates/bfv-hiding-stark/README.md) | Existing fixed hiding proof configuration, actual assessment and bounded topology/codec |
| [bfv-key-transform](../../../../../crates/bfv-key-transform/README.md) | Typed fullKey33 and exact vector root ABI |
| [bfv-ciphertext-formation](../../../../../crates/bfv-ciphertext-formation/README.md) | CLI mathematical opening validation and separate linked-test Formation proofs |
| [bfv-query-core](../../../../../crates/bfv-query-core/README.md) | Actual Owner/setup/Key fixture and linked-test two-operand scope/Prepared FHE inputs |

## Client compiler contract

CompiledPrivatePredicate accepts ONLY a plain QueryPlan::Select with AgeAmount
projection and normalized default window(offset0,limitNone). SELECT * is equivalent;
LIMIT ALL/NULL and OFFSET0/NULL normalize to the same window. Other projections,
effective LIMIT/OFFSET, all locking SELECT, aggregates, updates and inserts reject.
ORDER BY is unsupported by the current parser. This stage binds predicate encoding;
it does not claim full SELECT projection/window/locking execution.

The caller supplies a high-entropy private32-byte blind and separate public nonce.
The compiler rejects zero blind or a blind equal to the public nonce, but cannot
certify entropy. It hashes length-delimited exact SQL with that PRIVATE blind;
this is not SHA(SQL||publicNonce). The blind is guarded and dropped after compile;
mask remains guarded compiler metadata and is never a peer field. Public fixture
blinds are explicitly nonsecret examples, not confidentiality or entropy evidence.

q32 hashes the new intent domain, blinded SQL identity, public nonce, full original
setup-id, BOTH original heads, Source C_key and stable KeyExpected29(profile8/
descriptor17/C_s4). It excludes fresh C_sHat4 to avoid the current basis-job q
cycle. It also excludes C_open/C_mask/C_w. bind recomputes and compares ALL q bytes.
After Source, BOTH encoding PV/context/Expected retain ALL KeyPV33 including C_sHat;
a changed transformed root must change the child context even when q stays equal.
The old parameter-only descriptor semantics stay unchanged. These labels do not
prove evaluation keys share a secret or establish controller possession.

The library README freezes PV append order752/772, private source field offsets,
Cmd48, the full scaled coefficient equations and exact Formation8208 root. All
source values and the complete packets compare before child construction. The
consumer genuinely verifies Source before analyzing/allocating a child backend or
invoking its trace factory. Factory callbacks only create explicit experiment
traces; they receive no Owner/key getter and cannot replace verification.

## Evidence and lifecycle

DCSCEP01 has a184-byte header:magic8,role1/zero7,originalSourceProfile32,
newRoleProfile32,encodingContext32(eight u32),C_mask32(zero for Source),C_w32,
SourceLength4,childLength4. Exactly Source proof then encoding proof follow.
Role/profile/context/command/canonical roots/exact lengths are checked before decode.
Source is capped20MiB; child12,578,091B; the WHOLE pair32MiB. Sequence cap16384;
Source/child total decoded-container budgets24Mi/16Mi elements. Element budgets
are not byte/RAM caps. Existing framing, seven operations, domains, profiles,
production proof caps and allowlists remain unchanged. The pair is not a signed
Journal Body or a transport registration/aggregate-fit claim.

Source-first bounded decode verifies and drops its decoded proof/backend before
allocating the child verifier. Framing and verification now live in the library;
the CLI, adversarial examples and input16 integration call it directly, with no
local verifier adapter. Its read-only result retains the full Statement/C_w.
Typed BfvBinding is ONLY independently pinned
public context; this pair contains NO Key proof. Downstream Formation must verify
its actual Key/fiveBasis prerequisites and compare the complete independently
expected encoding Statement INCLUDING C_w. New salt legitimately changes C_w;
Expected-only input equality is insufficient. Statement::producer_identity hashes
all public values including C_w under its fixed domain; fresh consumers can build
public EncodedCommitment metadata without a private witness. This label is not
verification authority. EncodedOpening remains a caller-owned
mathematical opening; constructing it grants no SQL or Source authority.

The CLI proves Source once, sequentially generates/verifies the two child frames,
drops their decoded proof buffers between roles and checks their exact Formation
root opening. The genuine fixture separately creates/proves/verifies an actual
Owner Key statement then drops Owner/private handle/setup; the exported pair still
contains only two proofs. Security mode analyzes three PUBLIC shape statements
without Owner generation, trace or proof; source fixture setup uses nonsecret AEAD
bytes/commitments. No secure erasure of native field/trace/FFT/SDK buffers is promised.

## Candidate verification and usage

The [executed native validation](../../../PRIVATE-COEFFICIENT-INPUT-VALIDATION.md)
records all nine encoding tests and the separate linked-input test. Tests cover
full8192 actual SDK Encoding::poly parity, complete private
mask shapes, coherent data/identity/scaling/gap/tail/salt attacks, genuine foreign
Source/context proofs, both-role replay, compiler rejection, canonical nested
proof bombs and fresh-salt complete-statement controls. The shared library also
pins the existing Formation digest ABI at the last coefficient. Actual degree4,
individual128-bit assessments,32MiB pair fit and selected process resources were
measured; source review alone was not used as a native PASS.

The separate [input integration](input_formation.rs) proves one actual Key,
Source, both encodings, ten Basis and two Formation components against exactly
the Prepared request operands. It runs actual private FHE on those same bytes and
freshly rebuilds public expectations after private drop. It has no output MulRelin
proof, fresh agreed head or SQL grant. The CLI pair still contains only Source+child.

~~~text
hiding-fri-source-primitives security private-coefficient-encoding
hiding-fri-source-primitives prove private-coefficient-encoding
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::coefficient_encoding::tests:: -- --test-threads=1
~~~

The prove JSON stage is verified_private_coefficient_encodings. setup_and_key_ms
includes fixture preparation: genuine Owner/setup/Key proof and fresh Key
verification, Source encryption/commitment, compiler binding and private witness
construction. Source proving and verification have a separate timer. Each child timer includes trace/proof/
self-verification and encoding; each fresh timer includes Source+child bounded
verification, complete-statement comparison and mathematical opening validation.
generation_through_drop_ms ends after public/private fixture and source buffers
are dropped, but excludes process startup and printing. Root must measure whole
process RAM/time and actual frame sizes. The standalone CLI pair alone establishes
no Source/query Formation; the separate linked test supplies those input proofs.
No fixed latency cutoff, whole128, output MulRelin proof, freshness, live SQL,
lock or writer permission follows from either path.

The [library extraction validation](../../../COEFFICIENT-WIRE-EXTRACTION-VALIDATION.md)
covers the preserved DCSCEP01 bytes, both genuine roles, Source-before-child-bomb
rejection, mutable Source encoder checks and fresh input16 verification.
