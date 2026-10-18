# Compact RNS scaling AIR

The optional `multistark` feature represents the existing complete scaling
relation with main-trace auxiliary limbs and mandatory range lookups. It reuses
the private `air_equation` kernel also used by the older public-auxiliary
`plonky3` adapter. Default math, old profiles, canonical request/output/auxiliary
bytes and the older public adapter's 32 public values retain their existing
contract. The new machine has no peer, SDK, transcript, proof codec or backend
configuration dependency.

## Trusted preparation and prover witness

`shape(role, namespace)` exposes bounded table metadata before coefficient or
support allocation. `prepare_public(&request, &output, namespace)` checks the
sealed public codec identities, hashes and extension's copied Q5 rows, then
splits all canonical public coefficients into limbs. It does not evaluate a
scaler, auxiliary, rounding quotient or remainder. A false public arithmetic
claim can therefore be prepared and must fail the actual proof.

`PreparedMachine::witness(&aux)` is prover-only. It checks the existing sealed
auxiliary binding and ranges, splits it into main limbs, and counts range
messages. No auxiliary values enter preprocessing or public values. The
certificate is derived from public ciphertext residues and carries no secrecy
or zero-knowledge claim. `PreparedMachine`, `ProgramAir`, histogram and witness
objects are not checked proof results.

The verifier must reconstruct prepared AIRs from its trusted complete request,
output, role and namespace. Every table has PV0; the consumer must bind the exact
ordered canonical Request and Output, namespace and new profile into its initial
transcript. The module's distinct SHA-256 `profile_digest` identifies this
mathematical layout, not a backend security profile or an upgrade to an old proof
profile. Analysis-only unprepared AIRs must never enter proof admission.

## Exact layout

Every arithmetic table has height 8192 and main width 160:

| Main columns | Meaning | Range |
| --- | --- | --- |
| 0..4 | v, four little-endian limbs | R16 |
| 4..12 | remainder_v, eight limbs | lower seven R16; top R15 for extension or R13 for downscale |
| 12..15 | W + 2^45, three limbs | lower two R16; top R14 |
| 15..23 | remainder_e, eight limbs | lower seven R16; top R15 |
| 23..48 | five biased quotients, five limbs each | lower four R16; top R2 |
| 48..104 | low halves of 56 shifted carries | R16 |
| 104..160 | high halves of those carries | R9 |

Public width is 40 for extension and 60 for downscale: four limbs per input
residue followed by 20 limbs for the five computed outputs. The copied extension
Q5 prefix is checked by public preparation. Row order is the original coefficient
order; there are no next-row constraints or omitted tail rows.

The private shared kernel enforces all 63 digit equations: 12 for the Garner
rounding, 11 for signed correction rounding, and 8 for each of five output
moduli. Reconstructing each carry as low + 65536*high proves its original 25-bit
bound. Each chain retains both zero endpoint carries through the fixed shifted
endpoint 2^24. Together with remainder_v < 2^h, remainder_e < 2^127,
Wb < 2^46 and U < 2^66, the original integer residual bounds remain below
Goldilocks. Every main column has exactly one unit range query: 96 R16, 56 R9,
5 R2, 1 R14 and two top-remainder queries. Extension uses two R15; downscale
uses one R15 and one R13. The declared arithmetic degree is 1; actual SDK
analysis remains a validation gate.

## Shared supports and example

[limb-range-air](../../../limb-range-air/README.md) owns the exact fixed support
and checked histograms. `into_traces` returns one standalone arithmetic trace
followed by providers in `shape().tables()` order. For a batch, use `into_parts`,
merge histograms and include each `(namespace, range)` provider exactly once.
Namespaces may deliberately share range support across Scale and Tensor, but
must not collide with unrelated or dataflow buses. This relation has no dataflow
lookup: the future consumer must bind exact graph-edge vectors separately.

```rust
use bfv_scale_circuit::{Role, decode_request, encode_request, evaluate_with_certificate};
use bfv_scale_circuit::multistark::{Namespace, prepare_public, shape};

let role = Role::Extend5To10;
let namespace = Namespace::new([0x41; 32]);
let metadata = shape(role, namespace);
let input = vec![0; role.input_coefficients()];
let request = decode_request(&encode_request(role, [0x42; 32], &input)?)?;
let evaluation = evaluate_with_certificate(&request)?; // Prover computation.
let prepared = prepare_public(&request, &evaluation.output, namespace)?;
let traces = prepared.witness(&evaluation.aux)?.into_traces()?;
assert_eq!(metadata.tables().len(), traces.len());
# Ok::<(), bfv_scale_circuit::Error>(())
```

## Validation

Owning tests cover independent zero/minus-one output controls, full
rows and high limbs, symbolic layout/range declarations, coherent last-output
claims, both carry halves, shared histogram accounting and, with both features,
exact reconstruction of the older public kernel input. A split-carry alias
intentionally passes local equations but is outside its mandatory range support;
local debug checks are not lookup proof verification. All four feature
configurations and strict Clippy passed. The separate arithmetic consumer passed
actual SDK oracles, complete three-phase proofs and genuine hostile programs;
see its [executed validation](../../../../experiments/bfv-arithmetic-batch-proof/VALIDATION.md).
Its bounded frame, security estimate and sampled resources apply to that
standalone public arithmetic consumer, without linked MulRelin, SQL, provenance,
freshness or whole-peer resource authority.
