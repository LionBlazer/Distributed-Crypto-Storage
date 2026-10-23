# Query opaque INPUT forest

This test-only child of the [native Query research harness](../README.md)
constructs four opaque private INPUT commitments and their real native MMCS
multiproofs. It supplies the Merkle component needed by a future public sampler;
it does not construct a complete native proof or evaluate the Query AIR.

## Fixed ownership and geometry

Every tree has 32768 combined leaves and a cap containing one root. The sealed
`PrivateInput` roles fix the matrix widths below, before per-matrix salts:

| Role | Matrices | Base-field columns per matrix |
| --- | ---: | ---: |
| `Random` | 1 | 10 |
| `Main` | 1 | 421 |
| `Quotient` | 8 | 10 |
| `Aux` | 1 | 425 |

Public PP remains ordinary native public setup/ProverData and is absent from
this role enum. A future five-round PCS assembly must preserve
`[Random, Main, Quotient, normal public PP, Aux]`.

The constructor samples one opaque 32-byte label per combined leaf. All internal
binary NODE hashes run normally, bottom-up, through the same shared oracle;
no internal node is programmed. Opening a new index programs only its canonical
salted LEAF to the saved label. Each matrix row has its own four Gold salt
fields; the native stream interleaves each matrix row and its salt block.

Caller indices are native bit-reversed MMCS row indices. For the actual Query
coset their physical points are `7 * omega^reverse_bits(index, 15)`. The forest
does not convert coefficient indices or certify the caller's row/point relation.
Values and salts retain caller query order, including duplicates. The pruned
frontier follows native level, ascending parent, then missing-child order over
sorted unique indices.

## Direct dependencies and entry points

[research_ro](../research_ro.rs) owns the shared `Programmer`/query-only `Oracle`,
canonical leaf encoding and conflict rejection. [research_config](../research_config.rs)
fixes genuine P3 0.8.0 hiding Merkle MMCS, binary trees, raw 32-byte digests and
salt4. The [Query layout](../../layout.rs) owns the AIR profile. This module uses
`bfv_hiding_stark::Val`, native P3 dimensions/caps/pruned paths/`BatchMultiOpening`,
`rand-public-pp` sampling and standard owned collections.

The private parent entry points are `OpaqueInputs::new(programmer, rng)`,
`commitment(role)`, `dimensions(role)` and `opening(role, indices, rows, rng)`.
Rows have shape `[query][matrix][column]`; the result is exactly
`BatchMultiOpening<Val, research_config::Mmcs>`. Native `verify_multi_batch`
checks the returned values, salts and paths, without a verifier callback.

The Query entry point requires exactly 192 indices, including duplicates;
cumulative distinct disclosures are limited to 192 per tree. The private tree
helper permits shorter batches only for isolated native-path checks. Shape, contradictory-row and disclosure-limit failures precede
new salt sampling/programming. Repeated rows reuse their exact salts and labels.
A programming conflict never overwrites an oracle answer and permanently disables
further openings on the entire forest. Cross-role aliases and collisions remain
visible shared-oracle events; they are not resampled away.

## Validation boundary

Authored tests cover a literal eight-leaf example, independent comparison with
genuine native `open_multi_batch`, all four actual 32768/192 geometries, replay,
disclosure limits, conflicting programming, and hostile rows/salts/frontiers.
All three checks passed under the [owning observer](../../RESEARCH-VALIDATION.md),
including 24 hostile native checks at the full geometry. A test-only RNG wrapper
counts every delegated call to the actual generator to verify that replay and
preflight failures consume no new randomness. The forced-conflict case uses an
explicit public seed for an independent salt preview; it never clones private
production RNG state. Seeded test randomness is not an ideal-oracle or concrete
PRG theorem. The full public sampler, native FRI/proof-frame assembly,
privacy reduction and production admission remain outside this module.
