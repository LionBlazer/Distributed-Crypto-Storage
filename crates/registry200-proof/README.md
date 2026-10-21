# Registry200 proof circuits and evidence

The separate [Registry progress module](src/registry_progress/README.md)
adds separate Source-first Bootstrap803, Control815 and Predicate896 AIR/proof
frontends with fixed Registry208/Statement96/Progress48/Result160. Genuine
Source/Encoding SKIP-before-OFFSET/LIMIT, prefix-WAIT, proved End-compaction,
fresh-blind Resume and genuine NOWAIT failure passed the owning native gates
recorded in [validation](../../docs/registry-progress-validation.md).
The v2 step profile uses width 8266 and the distinct v2 Statement96 profile; no
old proof profile is reinterpreted. This module does not activate SQL or finality;
existing profiles and admission remain unchanged.

The [public Word mathematical API](src/registry_progress/word/README.md) uses the
separate bounded H512 backend and actual hiding proof/cold verification. Its
original literal graph/PP/commitment pins remain mandatory in ordinary builds.
Fixtures and attack helpers remain test-only. It grants no Source/OldRoot,
freshness, finality or SQL admission; component timings exclude the complete DCS
query composition.

This library owns the single fixed Source-opening and Registry200 lifecycle
circuits previously owned by the hiding-FRI experiment. It verifies actual
hiding STARKs; a profile match, owner signature or public claim is insufficient.

| Dependency | Responsibility |
| --- | --- |
| [bfv-hiding-stark](../bfv-hiding-stark/README.md) | Fixed hiding suite, actual SDK assessment/verification, Poseidon gadget and bounded canonical Postcard |
| [bfv-key-transform](../bfv-key-transform/README.md) | Typed full Key33 context and exact coefficient-vector digest ABI |
| [bfv-ciphertext-formation](../bfv-ciphertext-formation/README.md) | Caller-owned encoded opening handoff and the separate actual CoreGold Formation prover/verifier; neither infers Key or SQL authority |
| [compact-store](../compact-store/README.md) | Complete original encrypted image/root and fixed geometry checks |
| [version-journal](../version-journal/README.md) | Existing Body ceiling used by the original wire reservation |

Pinned p3-air/field/goldilocks/matrix/symmetric/uni-stark provide the AIR, field,
trace, permutation and proof types; sha2 computes the preserved profile/context
identities. zeroize guards explicitly owned byte/integer witness buffers.

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
The [Source circuit](src/source/README.md) owns the one mathematical trace writer
for all five layouts and a fixed Canonical-only typed producer. The coefficient
module likewise owns its guarded private witnesses and typed producer. The
[lifecycle module](src/lifecycle/README.md) owns the original native prover-input
model, trace writer, guarded witness and fixed Source-first producer. SQL
compilation belongs to storage-client; fixtures and CLI deployment remain in
their consumer layers. The [producer validation](../../docs/lifecycle-producer.md)
records actual byte verification, durable Journal reopen and unchanged reports.
wire::decode_and_verify_claim exposes
actual verified proof objects for downstream mathematical composition; it does
not grant application permission.

Original Canonical Source uses width 11521/PV691; Bootstrap width 1082/PV104;
Transition width 6741/PV116.
DCSLFPW1 retains Source 20 MiB, child 12,578,091 B, sequence 16384, Source 24 Mi and child 16 Mi
decoded-element budgets and the original 32 MiB signed-Body reservation. Element
budgets are not bytes/RSS. Each original proof has its individual fixed security
floor; no composed 128 or whole-protocol security claim follows.

The separate [Source version capability](src/source/version/README.md) owns an
immutable independently derived StateCertificate expectation, an explicitly
unverified producer and a move-only mathematical result created only after fresh
native verification. It uses the existing packed width 7161/PV691 relation and
original codec/security policy. The four new runtime cases and two ownership
examples passed; [validation](src/source/version/VALIDATION.md) records actual
1930.865 ms proving and 527.465 ms cold verification. It supplies no application
cache, current-head, key, Formation, SQL or finality authority and preserves the
original Canonical-only APIs. The 500 ms complete-query target remains unmet.

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
The module's `wire` frontend owns bounded DCSCEP01 framing and actual Source-first
pair verification, returning the complete verified Statement including C_w.
The [experimental consumer](../../experiments/hiding-fri-sha256-gate/src/opening/coefficient_encoding/README.md)
owns private compilation and fixtures, and calls the typed Core producers and
byte verifier directly. The
[producer/epoch validation](../../experiments/hiding-fri-sha256-gate/PRIVATE-INPUT-PRODUCER-EPOCH-VALIDATION.md)
records executed producer regressions and input16; the reports below preserve
their historical boundaries. The
[executed validation](../../experiments/hiding-fri-sha256-gate/PRIVATE-COEFFICIENT-INPUT-VALIDATION.md)
records actual degree4, individual128-bit assessments, proofs and input linkage.
These roles do not change Registry admission or any original profile/cap/operation.
The [extraction validation](../../experiments/hiding-fri-sha256-gate/COEFFICIENT-WIRE-EXTRACTION-VALIDATION.md)
records the library frontend's native regression checks.

## Separate private predicate / Acquire linkage

[predicate_acquire](src/predicate_acquire/README.md) adds a distinct success-only
relation opening the same hidden mask in the existing Cmd48 and Acquire Cmd160,
and the exact successful Result144. Its detached verifier requires genuine
Source/Query and Source/Lifecycle pairs before the new link proof. This does not
change Journal admission, prove SQL compilation or grant freshness/finality.
All eight new owning tests passed in the
[native validation record](../../docs/private-predicate-acquire.md). The measured
unique proof payload exceeds the unchanged 32MiB Body cap before headers; this
detached relation is not yet an admitted composite transition. Existing validation
records above retain their original scope.

## Separate private Control-kind linkage

[control_kind](src/control_kind/README.md) adds a new detached fixed relation
opening the original Cmd160 commitment and proving its hidden opcode belongs to
the six existing non-Acquire operations. It requires the genuine original
Source-first Lifecycle pair and pins full Source691/Lifecycle116 before child
work. Bootstrap remains separate. The full library's 21 runtime cases and four
ownership examples passed; see the [native record](src/control_kind/README.md#executed-validation).
It changes no old AIR/profile/opcode/cap, Journal allowlist or SQL capability.
A future composite Control application must actually require this link rather
than trust a caller-supplied lane tag.


## Separate two-lane encoding mathematical candidate

The new [two-lane module](src/two_lane_encoding/README.md) owns distinct all-4096
Source/mask AIRs for N=4096 with two ciphertext moduli and plaintext modulus65537,
two lanes per original row and the exact SDK lift multiplier16389. It genuinely
verifies the original Source691 proof before
every new child prove/verify call; Source bytes are supplied separately and are
never duplicated into the child frame. The new 29-field candidate key binding is
public metadata only, without Key33, CsHat, a same-secret Formation proof or a
security grant. It changes no old profile, SQL/runtime admission, protocol/G,
proof-consumer or current-head policy. Its fixed backend branch uses the same
actual hiding suite and mandatory individual assessment. Nine owning tests,
including genuine proof cases, passed in 35.62 s, plus nine existing boundary
tests and strict all-target
Clippy; see the [executed validation](src/two_lane_encoding/VALIDATION.md).
The all-or-nothing pair frontend verifies the common Source once before both
children. On identical proofs, its observed 1595.910 ms compares with 2674.165 ms
for two independent single-child calls; the 500 ms complete-query target remains
unmet.

The additive `two_lane_encoding::formation` consumer now connects the original
Source and both encoding children to the actual lower N4096/Q2 Formation proof.
Its producer consumes the SAME final Witnesses and salts after fresh prerequisite
verification; its receiver repeats actual Source/pair and cold Formation
verification before returning a move-only mathematical result. The
[native validation](../bfv-ciphertext-formation/src/gold/VALIDATION.md) covers one
real full chain and hostile native arguments under the unchanged resource fuses.
It supplies no installed-key, current-head, SQL or finality grant. Fresh receiving
took1800.541ms in that run; the complete-query500ms target remains unmet.


The additive `two_lane_encoding::product` consumer now binds the same raw
Formation inputs and nonce to a genuine unrelinearized encrypted product.
Complete arithmetic checking and fresh Source/children/cold Formation checking
are mandatory in the same call. Its sealed result grants conditional arithmetic
only. The [executed product validation](../bfv-unrelinearized-product/VALIDATION.md)
covers the actual full chain, four privacy examples, hostile receiving cases
and the extracted library/experiment consumers. Fresh receiving took
1730.017 ms, so the 500 ms complete-query goal remains unmet. No installed-key,
SQL, current-head or network-finality grant follows from this candidate.


The new `two_lane_encoding::Role::VersionSourceAllOriginal` binds all 4096 DATA
coefficients to a genuine request-independent StateCertificate. Its constructor
retains the full immutable SourceVersion expectation; both producer and receiver
freshly verify that actual prerequisite. Old Source/mask, pair and Formation
contracts remain separate. [Executed version encoding validation](src/two_lane_encoding/VERSION-VALIDATION.md)
covers fourteen owning cases, the unchanged full product consumer and two
privacy examples. This is an input-encoding proof, without DATA ciphertext
Formation, current-head authorization or SQL admission.


The separate `two_lane_encoding::data_formation` composition now consumes the
immutable-version encoding with an actual single-DATA ciphertext Formation.
Both producer and receiver freshly verify State/Role3; the producer consumes
the same final W/salt and original SDK secret. [Executed DATA validation](../bfv-ciphertext-formation/src/gold/DATA-VALIDATION.md)
records one genuine collection, strict cryptographic rejections, two encrypted
products reusing the same checked DATA ciphertext, and the preserved Pair path.
It grants mathematical association only; SQL/current-head/key authorization
and network lock finality are not supplied by this new result.
## Word mathematical API

The [registry_progress::word](src/registry_progress/word/README.md) facade now
exposes the fixed State208/Cmd160/Stmt96 Word relation in ordinary library builds.
Public expectations derive their original headers and complete Source context;
guarded move-only owner inputs feed the existing closed native prover. Independently
constructed public receiving setup always runs bounded canonical/native checking
before returning the privately constructed mathematical result. Role-only public
preprocessing can be retained; private inputs, randomness and verdicts cannot.
The exact original profiles, full graph/PP pins and codecs are preserved. This is
not Source/OldRoot authentication, current weighted finality or SQL/lock admission.
