# Compact BFV tensor AIR

The optional `multistark` feature moves the existing tensor certificate into
range-checked main columns. A private shared `air_equation` kernel owns the same
24 digit residuals used by the older public-auxiliary `plonky3` adapter. Default
math, canonical codecs, old profiles, old public preprocessing and its 32 public
values retain their existing contract. No proof backend, peer or SDK dependency
enters this module.

`shape(basis, namespace)` provides small metadata without coefficient/support
matrices. `prepare_public(&request, &output, namespace)` checks sealed public
codec identity and hashes, then splits all four complete inputs and three
complete outputs into public limbs. It never multiplies inputs, divides by a
modulus or evaluates an auxiliary. `PreparedMachine::witness(&aux)` is only the
prover's sealed binding/range check and main-limb/histogram conversion. Neither
method returns proof authority. No auxiliary values are public preprocessing or
public values, and no zero-knowledge claim is made for these public-derived
certificate values.

## Fixed mathematical layout

The arithmetic table has 8192 rows, public width 28 (input16/output12), main
width 54 and no next-row access. All columns are little-endian:

| Main columns | Meaning | Range |
| --- | --- | --- |
| 0..12 | three unsigned u64 quotients, four limbs each | R16 |
| 12..33 | low halves of three seven-carry chains | R16 |
| 33..54 | high halves of the same chains | R9 |

All three eight-digit equations are enforced, including d1's two asymmetric
cross terms and both zero endpoint carries per chain. Reconstructed shifted
carries have exactly 25 bits. Every local residual remains below Goldilocks.
Canonical public operands/output and all eight complete integer digit equations
force k0,k2 < p and k1 < 2p: their numerators are respectively below p^2 and
2p^2, the output is in [0,p), and the unsigned quotient has a complete u64
representation. No quotient comparator, host modular multiplication or verifier
quotient recomputation is substituted for those equations. Every main column has
one unit range query: 33 R16 and 21 R9. The declared arithmetic degree is 2;
actual SDK analysis remains a validation gate.

Every table has PV0. The trusted consumer must reconstruct the exact basis,
namespace and complete canonical Request/Output, require prepared AIRs, and bind
their ordered bytes plus the new profile into its initial transcript. The new
SHA-256 `profile_digest` describes this mathematical layout; it is not a backend
security profile or an upgrade of an old profile. Arbitrary unprepared shape
objects are analysis only.

## Support ownership and usage

[limb-range-air](../../../limb-range-air/README.md) owns complete fixed supports
and checked prover histogram aggregation. `into_traces` yields the arithmetic
table followed by standalone R16 and R9 providers. Batch consumers instead use
`into_parts`, merge histograms, and include exactly one provider for each trusted
`(namespace, range)` pair. Deliberate sharing with Scale is allowed only for these
identical range supports; unrelated/dataflow bus collisions must be excluded by
the consumer. This module does not prove graph-edge linkage.

```rust
use bfv_tensor_circuit::{Basis, DEGREE, decode_request, encode_request, evaluate_with_certificate};
use bfv_tensor_circuit::multistark::{Namespace, prepare_public, shape};

let basis = Basis::new(0)?;
let namespace = Namespace::new([0x51; 32]);
let metadata = shape(basis, namespace);
let input = vec![0; 4 * DEGREE];
let request = decode_request(&encode_request(basis, [0x52; 32], &input)?)?;
let evaluation = evaluate_with_certificate(&request)?; // Prover computation.
let prepared = prepare_public(&request, &evaluation.output, namespace)?;
let traces = prepared.witness(&evaluation.aux)?.into_traces()?;
assert_eq!(metadata.tables().len(), traces.len());
# Ok::<(), bfv_tensor_circuit::Error>(())
```

## Validation

Owning tests cover all ten bases, independent p-1 product/quotient
controls, both cross terms, high limbs, every component's last coefficient and
both carry halves, coherent output changes, symbolic range metadata, and exact
old/new kernel inputs when both features are selected. A range-alias test
explicitly separates local equation success from its out-of-support mandatory
lookup message. All four feature configurations and strict Clippy passed. The
separate arithmetic consumer passed actual SDK oracles, complete three-phase
proofs and genuine hostile programs; see its
[executed validation](../../../../experiments/bfv-arithmetic-batch-proof/VALIDATION.md).
Its bounded frame, security estimate and sampled resources apply to that
standalone public arithmetic consumer, without complete MulRelin, key/source
authority, freshness, live SQL or whole-peer resource guarantees.
