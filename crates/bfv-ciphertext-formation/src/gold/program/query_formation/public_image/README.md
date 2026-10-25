# Public Query quotient image arithmetic

This test-only module evaluates the actual owning `FullAir` and automatically
packed LogUp constraints over a finite polynomial quotient ring. It depends on
the fixed Query prescreen/layout, native public PP, the SDK symbolic builder,
Gold/EF5 arithmetic, DFT, and the shared test-support [coefficient ring](../../../../../../proof-research-support/src/ring.rs). It retains no
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

The shared Ring example runs at its test-support library owner; Query checks compare its fold
with the independent SDK field folder, plus projection/Frobenius framing. These
checks passed in the [bounded owning runs](../RESEARCH-VALIDATION.md). The small
folder case has an empty query set and base OOD point 49; it is not a full
192-location test or a privacy/Fiat-Shamir theorem.

The separate opt-in full-profile case now compares every coordinate at 192
physical locations and five coefficient-Frobenius embeddings at fixed nonbase
z. Its negative control detects a nonzero tensor error invisible to all base
locations and the first scalar embedding. This checks the complete degree<197
coordinate residues for one public fixture against the actual SDK folder;
it is not a separate reconstruction of the public PP commitment. The
[owning observations](../RESEARCH-VALIDATION.md) record its executed scope.

```sh
cargo test --release --locked -p bfv-ciphertext-formation gold::program::query_formation::public_image:: -- --test-threads=1
```

The shared arithmetic example is selected separately after its ownership move:

    cargo test --release --locked -p proof-research-support -- --test-threads=1

The full-profile case is ignored by the ordinary filter above. Execute its exact
target under the owning held-process resource observer:

```sh
cargo test --release --locked -p bfv-ciphertext-formation gold::program::query_formation::public_image::tests::full_locations::all_five_query_coordinate_polynomials_match_native_folder_on_192_rows_and_five_ood_embeddings -- --ignored --exact --test-threads=1
```

The private [joint disclosure sampler](public_disclosures/README.md) draws
enlarged MAIN/AUX residues, evaluates this actual fold with the same coins, and
samples the normalized correlated quotient fiber plus wrapper/R disclosures.
Its output is fixed-coin public arithmetic, without an original trace or proof.
Oracle/FRI composition and operation admission remain separate boundaries.
