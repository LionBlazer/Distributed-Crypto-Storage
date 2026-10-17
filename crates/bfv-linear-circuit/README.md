# Canonical BFV addition circuit

This library owns the fixed, level-zero BFV ciphertext-addition
relation for the unchanged N8192, five-prime Q218 profile. It adds all residues of
both ciphertext components in NTT representation, with canonical range checks.
It is ordinary homomorphic ciphertext addition, not a new cryptographic primitive.

`encode_request` binds the two complete operand arrays to an opaque caller-supplied
request identity. `evaluate` executes the full addition; `decode_output` validates
its output representation. The input/output contain public ciphertext residues,
never row plaintext or a secret key. Shapes are fixed independently of selected
row count: 1,310,760 input bytes and 655,400 output bytes. These transient buffers
are not the compact persistent database format.

Its only dependency, [bfv-fixed-geometry](../bfv-fixed-geometry/README.md), owns the
unchanged ring degree and ordered coefficient moduli. This library re-exports
`DEGREE` and `MODULI` with their original values. [bfv-query-core](../bfv-query-core/README.md)
converts actual upstream ciphertexts to/from this representation and tests equality
with the upstream BFV operator. A proof-system consumer can compile this small
relation without constructing general-purpose BFV parameter/key-switch contexts.

This library supplies no proof, authenticated query selection, agreed database head,
authorization, freshness decision or accepted SQL result. A proof verifier must bind
the exact input and output digests and a trusted program identity; a prover-supplied
opaque request identity alone authenticates nothing. Database acceptance remains
owned by the query/protocol layer and is blocked while its required checks are absent.

Run `cargo test --release --locked -p bfv-linear-circuit` from the repository root.
