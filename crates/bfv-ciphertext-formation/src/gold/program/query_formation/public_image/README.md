# Public Query quotient image arithmetic

This test-only module evaluates the actual owning `FullAir` and automatically
packed LogUp constraints over a finite polynomial quotient ring. It depends on
the fixed Query prescreen/layout, native public PP, the SDK symbolic builder,
Gold/EF5 arithmetic, DFT, and its private `ring` implementation. It retains no
private configuration, witness, original trace, `Prepared` or secret RNG.

`QueryFoldProgram::from_expected` derives the genuine expression DAG and global
emission order. Public PP is interpolated after the native zero interleaving
from 2048 to 4096 rows. `DisclosureDomain::checked` constructs squarefree target
and enlarged moduli from the input locations, OOD point and required rotations.
`PublicResidues::checked` takes 416 MAIN and 420 separate AUX base residues.
`fold` uses exact selectors, bus challenges, terminal zero and Horner order,
then returns all five coordinate polynomials of the folded quotient image.
The coefficient extension and residue indeterminate remain distinct.

Outputs are public arithmetic data. Arbitrary residues are not asserted to form
a valid original AIR trace. The conditional distribution interpretation needs
the honest-AIR, degree, divisibility and ideal-cell premises in
[QUOTIENT-IMAGE](../../../../../../bfv-hiding-stark/src/hash/QUOTIENT-IMAGE.md).
This module alone does not sample the full disclosure law or construct proofs.

Owning checks compare literal small-ring products and the actual Query fold
with the independent SDK field folder, plus projection/Frobenius framing. These
checks passed in the [bounded owning runs](../RESEARCH-VALIDATION.md). The small
folder case has an empty query set and base OOD point 49; it is not a full
192-location test or a privacy/Fiat-Shamir theorem.

```sh
cargo test --release --locked -p bfv-ciphertext-formation gold::program::query_formation::public_image:: -- --test-threads=1
```
