# BFV product circuit

Canonical arithmetic for exact ciphertext-by-public-plaintext BFV multiplication.
The [linear circuit](../bfv-linear-circuit/README.md) supplies the unchanged N8192,
five ordered coefficient moduli and two-component geometry. This crate has no other
dependencies and owns no keys, SQL planning, storage, consensus or proof system.

`encode_request` binds all 81,920 residues of each operand to an opaque original
request digest. `evaluate` computes every `a*b mod q` using a full u128 product.
The plaintext polynomial is repeated across both ciphertext components by the
owning [BFV core](../bfv-query-core/README.md) adapter. `decode_output` checks only
canonical representation. None of these APIs proves or accepts a SQL answer.

Input is exactly 1,310,760 bytes with domain `BFVPMUQ1`; output is exactly 655,400
bytes with domain `BFVPMUR1`. Both contain the 32-byte original request digest.
Residues must be below their fixed ordered modulus. The proof consumer must
independently derive the canonical inputs and check an actual multiplication proof
before reconstructing or consuming a result.

```sh
cargo test --release --locked --offline -p bfv-product-circuit
```
