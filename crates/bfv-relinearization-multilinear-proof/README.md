# Public-Aux relinearization arithmetic proof

This library owns the genuine proofs of the two complete N8192 public arithmetic
roles: `Embed` maps five PowerBasis rows to 25 source/target rows;
`AccumulateAndAdd` maps 85 native-NTT rows to ten target/component rows, including
original c0/c1 and all five ordered digit/key terms. The existing `BFVRLM01`
implementation moves here with unchanged profiles, domains, arithmetic, limits
and individual security policy. The library boundary keeps CLI fixtures outside the proof contract.

Both roles expose their arithmetic and Aux as public preprocessing. They do not
prove private execution, key authority, NTT provenance, complete relinearization,
MulRelin, SQL completeness, authorization or freshness.

## Public contract and ownership

- `prove(&Request)` evaluates the canonical circuit certificate and returns an
  owned `Generated` output/frame/timings result.
- `verify(&Request, &Output, frame)` bounded-decodes the role-sized public Aux and
  SDK proof, rebuilds its own AIR/preprocessing/VK and verifies the actual proof.
  It does not run reduction, NTT, key switching, MAC or quotient/carry evaluation.
- `CheckedStage::matches` binds full SHA512 request/output digests, role and exact
  external context32. The opaque marker retains the verifier-rebuilt
  `SecurityReport`; that report is not supplied by the frame or caller.
- `analyze(&Request, &Output, &Aux)` builds actual public preprocessing and SDK
  assessment for a supplied canonical claim, without arithmetic evaluation or a
  main trace/proof. A report does not establish that the claim is true.
- `profile_digest(Role)` and `role_name` expose fixed metadata. `SecurityReport`,
  `PcsSchedule` and `Term` are public report data. Backend, prepared AIR, SDK
  configuration/proof types and PK/VK are private.

Context32 is an ordinary mathematical label. Callers must independently bind
their trusted full setup and all producer/key/digit/output edges. Verification
drops proving preprocessing before the actual SDK verification. Public table
encoding/commitments remain real verifier work included in timings.

The [standalone consumer](../../experiments/bfv-relinearization-multilinear-proof/README.md)
owns CLI parsing and public nonsecret fixtures. Library fixtures, native SDK
oracles and hostile AIR adapters compile only under `cfg(test)`.

## Fixed proof policy

`BFVRLM01` retains its 144-byte header, full profile64, binding32, key-context32,
role/representation/count tags, exact public Aux and canonical SDK payload. The
16 MiB cap includes Aux. Sequence and total decode limits remain 16,384 and 8 Mi
elements. Full envelope SHA512 seeds, canonical reencoding, strict topology,
WHIR query bounds, trailing-byte and SDK panic rejection are unchanged.

The fixed backend uses Goldilocks EF5, full SHA512, collision cap256,
UniqueDecoding, zero PoW, phase target160 and an actual complete individual-stage
floor144 with no unassessed component. This makes no composed security or
whole-process memory claim.

## Direct dependencies

| Dependency | Responsibility |
| --- | --- |
| [bfv-relinearization-circuit](../bfv-relinearization-circuit/README.md), `plonky3` | Sealed Request/Output/Aux, integer bounds and exact public arithmetic AIR |
| [bfv-multilinear-stark](../bfv-multilinear-stark/README.md) | Shared serial SHA512/WHIR configuration and complete SDK assessment |
| [bounded-postcard](../bounded-postcard/README.md) | Fresh caller-owned typed allocation budget |
| `vendor/p3-multi-stark`, exact 0.8.0 | Reviewed SDK setup/prove/verify implementation through an explicit path dependency |

Other pinned P3 dependencies provide AIR/symbolic operations, fields, matrices,
sumcheck and WHIR/Merkle proof types. `serde`, `postcard` and `sha2` implement the
fixed report, wire and digest contracts. Actual native BFV SDK and hostile
program helpers are dev dependencies only. Core never imports an experiment.

## Owning verification

All twenty existing tests move with the implementation, preserving their genuine
proofs, every last input/output row, integer/range attacks, canonical decoder
limits, transcript challenges and weaker/foreign programs that verify under
their own AIR/VK before honest rejection. Native SDK tests compare every output
coefficient for actual arbitrary and encrypted products; these remain independent
test oracles, not verifier authority. Only the report test's analyze call changes
to pass its existing zero claim/Aux.

Run the owning gate with
`cargo test --release --locked --offline -p bfv-relinearization-multilinear-proof --lib -- --test-threads=1`.
Historical results remain in the unchanged [validation report](../../experiments/bfv-relinearization-multilinear-proof/VALIDATION.md)
and do not certify this extraction's performance or resource use.

The [proof-library extraction validation](../../experiments/bfv-mul-relin-proof/LIBRARY-EXTRACTION-VALIDATION.md) records the current
relocation, owning native tests and preserved proof policy.
