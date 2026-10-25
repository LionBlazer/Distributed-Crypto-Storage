# Proof research support

This unpublished library owns the existing pure coefficient arithmetic shared by
owning proof research tests. It is a workspace member outside default-members;
its consumers use dev-dependencies from
[BFV ciphertext formation](../bfv-ciphertext-formation/) and
[Registry200 proof](../registry200-proof/) for owning Word arithmetic checks.
Normal proof facades and production dependencies do not import it.

The [ring module](src/ring.rs) exposes `Poly`, `Tensor`, `Result`, free polynomial
operations and `Ring`. Coefficients use the fixed Gold field and EF5 basis from
[bfv-hiding-stark](../bfv-hiding-stark/); `p3-field = 0.8.0` supplies their existing
arithmetic traits. Neither dependency points back to either consumer crate.

`Ring::checked` takes ownership of a monic modulus with 2..=395 coefficients
(degree 1..=394). `modulus` borrows that stored value; arithmetic returns owned
coefficient vectors. Quotient-ring inversion rejects nonunits. A `Tensor` keeps
five base-polynomial coordinates in the existing EF5 basis, with the residue
indeterminate X separate from the extension indeterminate u. No field trait is
implemented for the quotient ring.

Consumers bound their input polynomial lengths and workload. The modulus guard
does not establish a whole-process memory or timing limit. The library owns no
witness, randomness, oracle dictionary, native proof configuration, Expected,
AIR, preprocessing factory, verifier or application-admission capability. Its
arithmetic alone does not establish cryptographic privacy or soundness.

The extraction preserves all existing algorithms, errors, the modulus guard and
the independent literal polynomial/tensor regression test. Only the former
owner-restricted item visibility becomes public for the new library boundary.
BFV's cfg(test) import keeps its existing `public_image_ring` consumer name.

Run the owning arithmetic regression with:

```sh
cargo test --release --locked -p proof-research-support
```

Existing Query/DATA image, disclosure, DEEP and native-session tests remain with
their respective owning adapters. Registry imports only this arithmetic; no
shared oracle, native-frame or cross-crate research adapter is supplied.
