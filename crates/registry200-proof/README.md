# Registry200 proof verification

This library owns the single fixed Source-opening and Registry200 lifecycle
circuits previously owned by the hiding-FRI experiment. It verifies actual
hiding STARKs; a profile match, owner signature or public claim is insufficient.

| Dependency | Responsibility |
| --- | --- |
| [bfv-hiding-stark](../bfv-hiding-stark/README.md) | Fixed hiding suite, actual SDK assessment/verification, Poseidon gadget and bounded canonical Postcard |
| [compact-store](../compact-store/README.md) | Complete original encrypted image/root and fixed geometry checks |
| [version-journal](../version-journal/README.md) | Existing Body ceiling used by the original wire reservation |

Pinned p3-air/field/goldilocks/symmetric/uni-stark provide the AIR, field,
permutation and proof types; sha2 computes the preserved profile/context identities.

admission::CanonicalSource::checked checks complete original images and
independently supplied heads, q, C_key and C_open. These checks alone do not prove
the private plaintext or index. admission::Expected retains an immutable checked
Source and independently pinned G/parent/enrollment, plus actual old registry and
command commitments for a transition. wire::verify accepts these independent
expectations and the exact DCSLFPW1 frame. It constructs the fixed actual
AIR/config/assessment locally, checks the analytical floor and bounded canonical
topology, genuinely verifies Source first, drops that decoded proof, then decodes
and verifies the lifecycle child. VerifiedOutputs has private fields and exposes
only verified next/result roots. It is not SQL, authorization, freshness,
lock-ownership or finality authority.

The public source and lifecycle namespaces are a low-level circuit ABI.
Their mutable public mathematical claims, finite legacy modes, columns and
caller-owned row helpers support existing experiment producers and adversarial
tests. A low-level claim, supplied public-values vector or AIR constructor is
never an admission token. The peer frontend accepts only Canonical Source and
Bootstrap/Transition, reauditing complete images. Invalid shapes can violate
low-level row-helper preconditions; the bounded frontend rejects them first.

There is one Source AIR for Bytes, Canonical, Packed, Factorized and State layouts.
Old profiles, kind names, arithmetic and wire limits retain their exact bytes.
Witnesses, private keys/salts, native Registry.step, trace producers, fixtures and
CLI deployment remain outside this crate. wire::decode_and_verify_claim exposes
actual verified proof objects for downstream mathematical composition; it does
not grant application permission.

Source uses width 11521/PV691; Bootstrap width 1082/PV104; Transition width 6741/PV116.
DCSLFPW1 retains Source 20 MiB, child 12,578,091 B, sequence 16384, Source 24 Mi and child 16 Mi
decoded-element budgets and the original 32 MiB signed-Body reservation. Element
budgets are not bytes/RSS. Each original proof has its individual fixed security
floor; no composed 128 or whole-protocol security claim follows.

The extraction, preserved profiles and real two-peer control consumer are covered
by the [validation record](../../experiments/hiding-fri-sha256-gate/REGISTRY200-PEER-CONTROL-VALIDATION.md).
Its operation/process observations do not establish a whole-peer resource guarantee.


## Separate WriteImage relation

[write](src/write/README.md) defines fixed AddAmount eligibility and a complete
ordered logical image. It shares the original canonical Registry200 opening,
range and predicate equations; old profiles and operations remain unchanged.
The control wire and application do not admit it or form a new encrypted Source
or BFV result. Actual native analysis, proofs, framing and affected tests are
recorded in the [WriteImage validation](../../experiments/hiding-fri-sha256-gate/REGISTRY200-WRITE-IMAGE-VALIDATION.md).

## Non-admitting private coefficient encoding candidate

The new [coefficient encoding module](src/coefficient_encoding/README.md) owns
separate SourceAllOriginal and PrivateMask AIRs. Both retain full Source691,
setup identity and allKey33 as public context while original rows, masks and
salts stay private main witnesses. The new direct dependency
[bfv-key-transform](../bfv-key-transform/README.md) owns that typed statement and
the Formation-compatible vector root ABI. Key context is not Key proof authority.
The [experimental consumer](../../experiments/hiding-fri-sha256-gate/src/opening/coefficient_encoding/README.md)
owns private compilation/proving and Source-first pair verification. The
[executed validation](../../experiments/hiding-fri-sha256-gate/PRIVATE-COEFFICIENT-INPUT-VALIDATION.md)
records actual degree4, individual128-bit assessments, proofs and input linkage.
These roles do not change Registry admission or any original profile/cap/operation.
