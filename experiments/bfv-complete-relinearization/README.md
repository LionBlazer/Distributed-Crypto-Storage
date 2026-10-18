# Complete fixed public relinearization composition

This standalone experiment composes **all 32 query-dependent proofs** for
level 0/0, log-base 0 relinearization. The relation is three complete canonical
native-NTT Q5 vectors to two complete native-NTT Q5 vectors, each with 8192
coefficients per modulus. It is not a codec for SDK ciphertext protobuf: the SDK
serializes PowerBasis values even when its representation tag says NTT.

The complete stream has been compiled and executed with fresh public-key
verification and an independent actual SDK oracle. See [executed validation](VALIDATION.md)
for the seven runtime tests, complete timings, component sizes, process observations
and primitive analytical reports. Existing primitive validation remains owned by
its unchanged consumers. No SQL, predicate, completeness, source formation,
same-secret evaluation-key validity, writer permission or agreed freshness is
established by this mathematical composition.

## Ownership and dependencies

| Dependency | Owned responsibility |
| --- | --- |
| [bfv-query-core](../../crates/bfv-query-core/README.md) | Original PublicSetup encoder, borrowed public material and complete setup identity |
| [bfv-relinearization-key-source](../../crates/bfv-relinearization-key-source/README.md) | Bounded seeded-only level0/0 key parsing and exact public c1 seed expansion |
| [bfv-fixed-geometry](../../crates/bfv-fixed-geometry/README.md) | Original N8192/Q5/t114689 constants |
| [bfv-ntt-circuit](../../crates/bfv-ntt-circuit/README.md) | Exact public setup NTT evaluation and canonical query request/output codecs |
| [bfv-relinearization-circuit](../../crates/bfv-relinearization-circuit/README.md) | Existing Embed/MAC integer relations/codecs and shared pure complete-vector routing |
| [bfv-ntt-witness-proof](../bfv-ntt-witness-proof/README.md) | Actual complete native NTT main-witness proof and bounded verifier |
| [bfv-relinearization-multilinear-proof](../bfv-relinearization-multilinear-proof/README.md) | Actual Embed/MAC public-Aux proofs and bounded verifier |

The direct SDK dependencies are only the independent actual-Owner demo/oracle. Core and the existing primitive libraries do not depend
on this experiment. Its private workspace has its own lockfile, generated only by
the Root orchestrator. No existing primitive profile, AIR, proof cap or test body
is changed.

`key.rs` owns immutable private-field `PreparedKey`. `input.rs` owns complete
public `Input`. `state.rs` owns exact32 ordering and delegates Embed/MAC request
assembly, digit-row selection and complete output transposition to the Core
[routing module](../../crates/bfv-relinearization-circuit/src/routing/README.md).
`prover.rs` owns sequential proof production; `verifier.rs` owns actual
cryptographic admission. `component.rs` owns one bounded public frame. `demo.rs`
and `spool.rs` are the explicit local measurement consumer and owned public-file
lifecycle, with no networking, deployment discovery or SQL acceptance policy.

## Setup work and independent pins

`PreparedKey::from_original(&PublicSetup, independent_keyset_id32)` checks the
independently supplied complete original setup ID through `decode_seeded` before
parsing or coefficient allocation. It then hashes the COMPLETE original setup
bytes with SHA512, including rotation keys, and derives all 50 ordered K0/K1 rows.
The existing canonical seeded-only key source rejects unsupported keys/levels,
malformed envelopes/counts/lengths/defaults and every noncanonical packed residue
before allocation. No arbitrary peer NTT array or key-probe result can construct
`PreparedKey`.

The 25 forward NTTs of public c0 are fixed setup preprocessing: existing pure
NTT evaluation runs once per row and drops each public auxiliary before the next.
The original public c1 seed chain is expanded by the existing key-source library.
These are not query proofs or query re-execution. The verifier owns these constants;
it never accepts a serialized prepared-key or checked-prefix receipt. The retained
constants occupy exactly 50*8192*8 = 3,276,800 bytes, excluding Vec/struct overhead
and setup temporaries. There is no global or persistent key cache.

`PreparedKey::component(component_index, decomposition_index)` borrows one
immutable complete Q5 native-NTT array; component0/1 and decomposition0..4 identify
all 50 rows. Invalid indices return None. This readonly metadata API neither
changes setup provenance nor verifies same-secret key consistency.

The local SHA512 label does not upgrade the authority of an untrusted PublicSetup
or the caller-supplied SHA256 setup pin. The trusted original owner/application
must supply that pin independently. Setup byte identity and the KeyTransform
coefficient commitment are separate from proving that evaluation keys were
generated from the same secret. No secret getter, callback or private Owner state
enters the composition.

## Exact stream and endpoints

`Input::new(query32, [c0,c1,c2])` requires exactly three complete component-major
Q5 native-NTT arrays, each 40960 canonical u64 values. It hashes the complete
query and all values with SHA512. This accepts public mathematical operands;
it does not certify their storage, encryption or SQL origin.

| Ordinal | Genuine primitive | Exact next input |
| --- | --- | --- |
| 0..4 | Inverse NTT, basis i | Original c2_i, all 8192 |
| 5 | Embed | All five proven c2 PowerBasis rows |
| 6+5*i+j | Forward NTT, basis j | Proven Embed block 5*i+j, all 8192 |
| 31 | AccumulateAndAdd | Target-j block: O0,O1,D0..4,K00..04,K10..14 |

Every request is built by the consumer from its original pins and preceding
admitted complete outputs. No peer-supplied request, Boolean, VK or stage digest
can replace those edges. Query-dependent inverse/forward transforms, embedding
and MAC are never evaluated by `Verifier`. The final MAC output order 2*j+c is
transposed by exact copying to SDK component-major order 5*c+j.

`Prover::prove_next` produces one component and releases its primitive generated
object/backend before another call. A producer prefix has no checked-result API.
`Verifier::accept` verifies the exact expected primitive proof before advancing
once. A rejected candidate leaves verified arithmetic state unchanged, while
consuming the lifetime attempt/byte budget. `finish(self)` constructs sealed
`CheckedRelinearization` only after all 32 genuine admissions. Its output contains
both complete native-NTT arrays; `matches` rebinds the complete independent pins.
Cancellation is terminal and happens only between synchronous calls. It releases
owned public intermediates; this is not SDK mid-proof interruption or secure RAM
erasure. Missing components, duplicate/out-of-order frames and incomplete finish
never become a completed operation.

## Canonical framing and resource boundary

A component has a fixed 192-byte header: magic8 at0, complete composition profile64
at8, independent Expected SHA512 identity64 at72, ordinal/kind/source/target at136,
output length u32 at140, proof length u32 at144 and zero44 at148. It is followed by
the exact existing canonical primitive output and unchanged bounded primitive
proof. The composition profile binds every used original proof profile, fixed
geometry, seed role, ordering, endpoint conventions and these stream policies.
The old primitive binding32 field remains unchanged and is independently derived
from the complete outer identity and exact stage metadata; it is not a new
512-bit primitive context field.

The fixed new component cap is 20 MiB, while each original primitive cap remains
16 MiB. The largest analytical frame is 18,415,952 bytes (Embed output plus its
worst proof cap and header). The exact worst-cap sum for all 32 is 541,140,544 bytes;
this is a byte budget, not an aggregate wire frame or RSS claim. A verifier charges
both failed and successful candidates against that one byte budget and at most 64
attempts. There is no retry budget reset. Header/profile/identity/ordinal/exact
lengths and canonical output validation bound allocation before a child proof
backend is used. Decoded proofs/backends are not retained between admissions.

The local demo writes CreateNew public component files to one exclusively created,
canonical checked temporary child. Each read uses a capped Read rather than
metadata followed by unbounded fs::read. Write/sync failure is terminal for that
spool; a partial ordinal is not silently retried. Normal `finish` checks the exact
owned child and propagates cleanup errors before reporting success; Drop makes
only a best-effort cleanup on failures. No complete proof Vec, aggregate
serialization, networking or remote component stream is implemented. Existing
64 MiB transport, 32 MiB Body and 256 MiB Journal policies are unaffected.

## Actual owning gate and measurement contract

```powershell
cargo run --release --locked --offline --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- security
cargo run --release --locked --offline --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- prove
cargo test --release --locked --offline --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- --test-threads=1
```

These reproduction commands correspond to the executed validation linked above.
The prove demo creates one actual Core Owner/original setup, uses the documented
public ciphertext payload tuple of genuine encrypted rows, and performs actual
upstream ct-by-ct multiplication to obtain native three-component input. Actual
SDK `RelinearizationKey::relinearizes` supplies a separate test oracle only; no
oracle value constructs a proof or verifier request. The private Owner and SDK
key drop before composition proof generation.

After sequential production/spool writes, the Prover and its PreparedKey drop.
A fresh verifier reconstructs its own public key constants from original setup
bytes, reads one public component at a time, verifies all 32, and compares both
full outputs with the independent SDK oracle. The sole prove JSON stage is
`verified_complete_relinearization_stream`. It reports all 32 component sizes;
Owner/input/SDK-oracle generation, fixed public key preprocessing, proving plus
spool writes, fresh setup/spool reads/verification, and total time are separate.
Total time also includes checked normal spool cleanup. Full process peaks, proof
sizes and latency require actual Root observation; the source makes no fit claim.

`security` emits 12 actual primitive analytical reports with no Owner, key
preprocessing, query arithmetic, witness or proof: five inverse, five forward,
Embed and MAC. Forward reports each occur five times in the32 proof chain;
inverse and the two arithmetic reports occur once each. An unweighted sum of12
reports is not composition security. Existing 144-bit per-primitive floors imply
a conservative 139-bit union floor for32 only under appropriate composability
assumptions; existing primitive numeric estimates give a conditional proof-only
union estimate around152.4413 bits. Neither statement certifies the whole
composition's adaptive Fiat-Shamir, outer identities, setup trust or SQL security.
The code intentionally reports `composed_128_claim:false`.

The [full graph validation](../bfv-mul-relin-proof/VALIDATION.md) records the shared
routing extraction and readonly key accessor regressions: seven owning tests
under retained unchanged R3 source and the genuine old32 CLI prove under final
R4. The historical executed validation above is retained; this refactor adds no
arithmetic, profile, frame, cap or shortened proof path.
