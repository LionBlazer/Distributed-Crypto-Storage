# Word mathematical proof API

Fixed State208/Cmd160/Stmt96 mathematics, backed by the existing complete native
Word AIR. This module makes its guarded inputs, independently retained public
expectations and actual native receiving usable in ordinary library builds.
It does not register SQL, authenticate Source/OldRoot or establish history,
key/lattice security, current weighted head, durable locks or finality.

`Expected::checked` derives original headers, complete Source scope and context100
from the sealed SourceVersion metadata, genesis/parent/enrollment and complete
transition `Claims`. All309 public values remain constrained. Metadata is not a
verified proof. Read-only public context/scope/header access supports caller-owned
serializers; these getters provide no private opening or authority. Control claims
require a zero statement root. `SourceOpening` consumes the complete2348-byte private source and
opening salt. `RegistryOpening` owns both full banks and controllers. The public
`CommandInput`/`WalkInput` preserve their exact existing fixed fields and clearing
on drop. `PrivateInputs` consumes them, the private mask and three salt banks;
it has no getter, Clone, serialization, callback or fixture constructor. Buffer
clearing remains best effort, not a stack/compiler/allocator erasure guarantee.
Owners must supply their own fresh secret blinding salts; default values and the
explicitly public constants in unit fixtures are not production salt generation.

`Prover::new(Role)` owns immutable public role preprocessing only. Each
`produce` consumes private inputs and uses fresh OS private proof randomness.
`Verifier::new(Role)` independently constructs its own public preprocessing and
retains no prover-only data. Each `verify` binds the complete current expectation,
performs bounded canonical decoding and actual native verification before
constructing the private move-only `VerifiedWord`. The cold free functions are
convenience entry points; cold receiving checks original bounds/header before
allocating setup. Producer bytes are explicitly unverified.

Direct dependencies are the [internal fixed Word backend](../word_inventory/README.md),
this crate's [SourceVersion metadata](../../source/version/README.md), existing
hiding/P3 libraries and bounded-postcard. Internal serializer/golden checks are
normal library code; owner cases, source fixtures, diagnostic writers and attack
helpers are test-only. No consumer supplies an AIR, plan, CommonData, verifier,
randomness or checked flag. Original profiles, complete native equations, all
public preprocessing pins, canonical frame and security/resource gates remain
unchanged. No old production protocol or accepting result is reinterpreted.

Typical use retains independent complete metadata, constructs a prover and a
separate receiving setup for one fixed role, consumes owner inputs into unverified
evidence, then verifies the evidence against the receiver's original expectation.
Higher layers must independently join Source/DATA admission, authorized prior
state and fresh weighted finality before accepting an SQL/locking result.

The normal [conditional read composition](read/README.md) joins complete immutable
DATA, this Word Predicate, fused original Query Formation and a real FHE product.
It retains only an actual immutable DATA theorem and freshly checks per-query
arguments. BFV/product security and fresh weighted SQL/lock admission remain
separate obligations.

The [EMPTY208 bootstrap](bootstrap/README.md) separately proves the original empty
Word registry against an actual SourceVersion certificate and fixed enrollment.
It does not authorize that enrollment or establish a current network head. Its
distinct frame/profile cannot be substituted for a Word transition or the old
Bootstrap803 role.

`command_header` and `result_header` expose the exact original five-field
Cmd160/Result160 prefixes for independent owner serializers. They add no generic
hash namespace or alternate profile. `statement_header` remains the original
thirteen-field Stmt96 prefix. The actual graph, field order and all pins are unchanged.

`PrivateInputs::statement_opening(StatementDomain)` now serializes that exact
original Stmt96 in normal code. It checks original actor identity/controller/
snapshot/enrollment, field bounds and query policy, and returns a move-only
`StatementOpening` with a public root and consuming guarded96-word export. It
computes no query answer or proof. The full Source, Word, input equations and
currentness obligations remain. Public `Expected::{genesis,parent,statement_domain}`
getters retain the exact independent metadata used by the original constructor;
they grant no authorization. Existing profiles, canonical words and native graph
are preserved. The optional [client compiler](../../../../storage-client/src/word_query/README.md)
uses this boundary without exporting Source plaintext or a secret key.

## Producing a transition from current private state

`CurrentRegistry::new` consumes a guarded canonical208-word current opening,
controllers and next-bank salt. `prepare_transition(Expected, TransitionMaterial)`
uses the same closed Word instruction graph to derive the next bank and the
original Cmd160/Stmt96/Result160 commitments. The caller supplies no next bank,
selected-row outcome or result opening. BEGIN, all four locking strengths,
WAIT/SKIP LOCKED/NOWAIT, original WAIT continuation, savepoint targeting,
rollback/release and stable END compaction use the existing native formulas.
Done/Error automatically clear the candidate progress salt; Parked retains it.
Owner-supplied source, enrollment, parent and current OldRoot remain pinned;
noncanonical old headers/padding, forged continuation and counter overflow fail.

Producer-only directions point from existing constrained fields to their existing
expressions. They add no AIR node, equation, public input, hash or preprocessing
change. All original assertions still execute. These directions are never used
by the ordinary proof trace writer or independent verifier. Immutable role setup
does not retain owner source/state. The bounded140/136-entry direction map fits
the existing per-node recipe reserve; synthesis scratch remains bounded by the
original10000-node/209-permutation limits.

`PreparedTransition::into_parts` returns the proposed expectation, original
protected inputs and a move-only `TransitionOpening`. Its consuming export is
guarded private plaintext for the owner's later state lifecycle. It is **not**
an accepted bank or SQL result: there is no commit/install/lock-grant method.
The owner must produce the original native proof and independently receive the
actual DATA/FHE composition, authenticate rights and prior state, and require
fresh weighted finality before applying a candidate. Private witness production
does not replace the peer's homomorphic computation or client result check.

Focused owning checks:

```text
cargo test --release --locked -p registry200-proof --features owner-read registry_progress::word::transition:: -- --test-threads=1
```

The examples compare complete next-bank/result words and all public commitments
with independently retained public WAIT, SKIP, zero-limit, resume, NOWAIT and END
cases. A separate six-step control lifecycle generates and independently checks
real native proofs, rejecting a changed NextRoot on every step. Rejection cases
include a different old root/controller, forged resume prefix, nonzero old padding
and overflowing revision/sequence. These are component correctness checks, not
a complete500ms SQL observation or cryptographic security assessment.

### Native validation on 2026-10-22

The final bounded native captures passed all13 selected tests. Registry build279
and client build280 used locked/offline release Rust1.99 MSVC, native CPU,
Cargo/Rayon2 and the established project-local target. Each capture pinned its
exact executable image/held handle/creation time, checked sources before/after,
sampled every20ms and retained the120s/1792MiB process limits. All exited0
without observer faults or cleanup. The6 inventory tests retained the original
literal full semantic graph and public preprocessing pins for both roles.

| Capture | Owning checks | Test interval | OS peak working set | Peak private bytes |
| --- | --- | --- | --- | --- |
| 276 | 3 current-state cases, including the6 native control proofs | 1.87s | 131,944,448 | 123,723,776 |
| 278 | 6 complete graph, preprocessing, resource and refusal checks | 0.11s | 14,032,896 | 6,422,528 |
| 281 | 4 client compiler/original DATA/Word/FHE composition checks | 7.30s | 560,910,336 | 555,024,384 |

The final client capture logged2362us for owner current-state preparation alone.
The7.30s figure includes cold cryptographic preparation and rejection assertions;
neither interval includes real peer I/O, current weighted quorum, durable state
installation or accepted SQL. This is not a full-query latency or security claim.

Ignored native report SHA256 pins, respectively:

- `863C29E9A1F3518C6E48978E0A60DEA22997EAC9DE122F70A759DD5BD1CAE445`
- `72C6D2D140C87C0DA8575A138AC190E0AAA05471B1DA107BAC56CA67EC33B57A`
- `BE3C11336DC5B099969E81F18C6D5ADD5771E99A8EAE75FEC68455AE040F0C06`

The registry image was12,414,976 bytes, SHA256
`3475BFF51FD1576843100298F8BD83923484FA5F96FC31F0E2851F1E3D69EE19`;
the client image was26,721,280 bytes, SHA256
`3A4C58D84F60921995C81396A5B48C28A725B191C550D71436336ECA4D9179B2`.
Only this evidence note was appended after those captures; production/test Rust
and manifest hashes were rechecked before publication.
