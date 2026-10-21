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
