# Fixed BFV basis convolution

This reusable crate owns the unchanged experimental one-basis relation:
H512/W9452/PV62, the original profile and salted raw-Goldilocks commitment streams.
It depends directly on [bfv-key-transform](../bfv-key-transform/README.md),
[bfv-hiding-stark](../bfv-hiding-stark/README.md) and
[bfv-fixed-geometry](../bfv-fixed-geometry/README.md), plus the pinned public
fhe/fhe-math/fhe-traits 0.1.1 codec. It never depends on Core, experiments or apps.
The [Owner Basis validation](OWNER-BASIS-VALIDATION.md) records executed real proofs,
malformed-wire rejection, complete old regressions and observed process resources.
Historical measurements remain scoped to the old adapter.

`CanonicalCiphertext::decode` checks fixed parameter bytes and a borrowed exact
protobuf envelope before SDK polynomial allocation or NTT. Exactly two unseeded
polynomials or one polynomial plus seed32 are accepted. Each polynomial must have
Ntt representation, degree8192, exactly 223232 packed bytes and canonical optional
variable-time bool; every packed residue in all five qi is checked before SDK math.
Unknown/duplicate/default/overlong fields, wrong level/seed/degree/count and trailing
bytes reject. Both omitted-false and true metadata remain valid. After this gate,
the original SDK checks, dimensions, representations, residues and exact canonical
roundtrip remain mandatory. The complete original parameter/ciphertext bytes are
retained, including c0/B and seed; callers cannot submit an independent A or Ahat.
The byte limits remain 1024 for parameters and 512 KiB for a ciphertext.

`Expected` independently pins the complete Key statement (all 33 public values),
complete canonical public ciphertext, request32 and one basis 0..4. `ProverWitness`
borrows an explicit caller-owned canonical Shat vector and guards its salt copies;
it has no Owner access or private-data getters. `circuit` is the exact low-level
mathematical writer/AIR used by the old adapter and rebuilt tests. The input opens
KeyTransform's original role1 root/context. It then proves pointwise multiplication
by verifier-derived Ahat, bit reversal, 13 inverse DIT stages, normalization/untwist,
and the complete salted output root. Native field vectors and SDK scratch are not
securely erased.

`prove` verifies the actual supplied Key evidence and compares all 33 public values
before the child claim oracle/AIR/trace. It analyzes the same immutable child AIR,
requires the individual fixed-suite floor, proves and genuinely self-verifies, then
encodes one bounded component. `verify` repeats actual Key verification under exact
Expected. `PublicInput` plus `verify_with_key` is the compound path: verify the Key
once under independently pinned KeyExpected, derive the full Key statement, then
privately check the fixed Basis component. Those standalone paths always verify
the supplied prerequisite bytes. A `VerifiedBasis` checks only one mathematical
component; it carries no Owner authority, complete-five admission or freshness.

`verify_scoped(full_setup_id, &VerifiedTransform, &Expected, bytes)` verifies the
actual Basis child after matching the borrowed genuine transform's full setup
label and ALL33 against the complete Expected. Its opaque `ScopedBasis` borrows
that exact transform instance, retains the checked full statement, and cannot
outlive the transform or be constructed from claims. `require_same_scope` rejects
mixing components borrowed from distinct transform objects, even if their public
claims agree. The caller still owns setup provenance and fresh-call policy:
the closed MulRelin input verifier creates its own fresh transform on every call
and accepts no caller-supplied capability. No SDK proof/backend is retained by
these mathematical results. The old raw-evidence verifiers are unchanged.

The genuine Input16 gate and both ownership compile-fail examples passed native
checks. See the [validation record](../../docs/joint-query-fast-path-validation.md).
Whole-operation speedup remains unmeasured for this revision.

The new DCSBCP01 header is 308 bytes: magic8/profile32/full-setup-label32/unchanged
descriptor68/Cs32/CsHat32/request32/canonical-public-input-binding32/basis4/result32/
payload-length4. The public-input binding uses a fixed domain and u64 lengths before
both original parameter and ciphertext bytes. The 20 MiB payload, 16384 sequence and
24 Mi element nested limits passed actual emission and hostile validation.
Dimensions/chunks are verifier-derived from the actual fixed AIR, never selected
by an incoming frame. Canonical decode/reencode and all nested topology
checks precede SDK verification. The full setup label is external owner-pinned
metadata; the preserved legacy descriptor still identifies PARAMETERS ONLY.

The [optional Core job](../bfv-query-core/README.md) owns actual Owner key material,
shared fresh CsHat and sequential production. Arbitrary canonical CT input has no
authenticated keyset label: a new valid Basis proof for a different CT can exist.
Replay of the old proof under different full CT or independent pins must reject.
This relation does not prove short-noise encryption, B/plaintext formation,
evaluation-key same-secret consistency, Registry200 encoding linkage or live SQL.

Only mandatory main openings already require14,525,952 bytes per Basis. Key plus
five Basis require at least87,892,992 bytes, exceeding the existing 64 MiB transport
and 32 MiB Journal limits. No aggregate frame, network registration or quota widening
is added here. Sequential process resources remain empirical. Six individual 128-bit
floors imply only a 125.415-bit union floor; composed 128 is not claimed.


## Complete component verification and digest words

`verify_five` verifies one actual Key and exactly five ordered Basis components
against independently pinned full claims, including every Key public value,
request, complete canonical parameters/ciphertext and result. Each decoded proof
is dropped before the next. An incomplete prefix is never sufficient.

`words` exposes the existing canonical digest encoding: eight consecutive
little-endian u32 words from a 32-byte digest, represented exactly in Goldilocks.
The formation library reuses this public encoding; no profile, context, equation
or verification policy changes. Neither entry point grants SQL authority.


## Shared ciphertext preflight

The borrowed protobuf gate and its fixed ciphertext byte limits now belong to
[bfv-ciphertext-wire](../bfv-ciphertext-wire/README.md), a pure dependency on
fixed geometry. Basis maps that gate into its existing Shape error and retains
its actual SDK decoding, complete residue/context checks and exact roundtrip.
The accepted grammar, proof profile, mathematical relation and old test bodies
are unchanged. The extraction, Core shape gate and actual-process rejection
coverage passed the [recorded release validation](../bfv-ciphertext-wire/README.md#executed-validation).
Earlier validation records remain historical measurements.
