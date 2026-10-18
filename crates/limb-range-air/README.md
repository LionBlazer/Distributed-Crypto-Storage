# Fixed limb range AIRs

This crate owns complete fixed Goldilocks lookup supports for 2, 9, 13, 14, 15
and 16 bits. It depends only on the pinned P3 0.8.0 AIR, field, matrix,
Goldilocks and lookup packages. It has no application policy, arithmetic-stage
dependency, proof configuration, wire codec or checked-result authority.

`RangeAir::shape` exposes metadata without allocating a support matrix.
`RangeAir::prepare` constructs the complete fixed support as one public column.
Its two main columns are value and multiplicity. The value must equal the public
support, and the interaction uses `Count::provided(-multiplicity)`. Each consuming
limb uses `query`, a unit positive interaction. The 2-bit support has height 16
and repeats 0 through 3 four times; the provided witness uses the first copy for
frequencies and puts zero in the remaining copies. Other heights are exactly
2 raised to the supported width. All AIRs have zero public values, no next-row
access, and one linear base constraint. A real consumer must verify the global
lookup argument as well as the base constraint.

## Composition contract

The trusted composition chooses `Namespace`, includes it in its full transcript,
and reconstructs the intended support set. Bus names are the fixed prefix
`dcs/limb-range-air/v1/`, all 32 namespace bytes as 64 lowercase hexadecimal
characters, a slash, and the decimal width. This encoding has no variable-length
namespace ambiguity. It does not prevent an unrelated AIR from deliberately
emitting the same bus name; avoiding such collisions is the composition owner's
responsibility.

Several arithmetic instances may deliberately share these identical supports.
Merge their histograms, and include exactly one provider for each chosen
`(namespace, range)` pair in the actual union. Do not concatenate standalone
provider tables under the same bus. Arithmetic/dataflow buses must use separate
domains. The crate does not connect one arithmetic output to another input.

`Histogram` is prover-side frequency accounting. It accepts only supported
values, checks addition without field reduction, and merges subsets atomically:
a missing range or multiplicity overflow leaves the destination unchanged.
`trace` returns the two main columns in the exact provider order. Host histogram
validation does not replace cryptographic lookup verification, and an arbitrary
provided field multiplicity is not an authorization token.

```rust
use limb_range_air::{Histogram, Namespace, Range, RangeAir};

let namespace = Namespace::new([0x31; 32]); // Chosen by trusted composition.
let mut combined = Histogram::new(&[Range::R16, Range::R9])?;
let mut instance = Histogram::new(&[Range::R16, Range::R9])?;
instance.add(Range::R16, 65535)?;
instance.add(Range::R9, 511)?;
combined.merge(&instance)?;
let provider = RangeAir::prepare(namespace, Range::R16);
let main = combined.trace(Range::R16)?;
// Supply provider and main to the consumer's actual multi-AIR proof machinery.
# Ok::<(), limb_range_air::Error>(())
```

## Validation

The owning tests cover complete support construction, namespace separation,
provided-count metadata, checked/atomic histogram accounting, repeated support
layout and local fixed-value rejection. Local constraint debugging ignores lookup
messages; those checks are not genuine LogUp proofs. All three owning tests and
strict Clippy passed. The separate arithmetic consumer also passed genuine
positive and hostile lookup proofs over all six supports; its
[executed validation](../../experiments/bfv-arithmetic-batch-proof/VALIDATION.md)
records the actual SDK analysis, bounded frame and sampled process resources.
These checks establish no SQL admission, source completeness, key authority,
freshness or whole-peer resource guarantee.
