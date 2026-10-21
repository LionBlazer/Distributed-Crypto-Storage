# Public arithmetic relation and remaining security work

This document describes an experimental arithmetic certificate. The executable
reports `proof_verified=false`, `cryptographic_security_assessed=false` and
`sql_accepted=false`, including after a successful arithmetic check. No DCS
dispatcher accepts this profile. Changing its geometry or challenge count changes
its profile digest; it is separate from existing accepted proof profiles.

## Closed relation

The statement contains the original two unseeded two-component SDK ciphertexts,
an unseeded three-component output, their exact bytes and a nonce. The independent
bounded decoder reads every PowerBasis coefficient despite the SDK's Ntt wire
tag. Degree, level, basis order, component count and canonical residues are fixed.
Seeded, oversized, unknown-field, nonminimal-varint and trailing encodings reject.

Four exact integer certificates extend the original Q components to QP, including
exact copies of both original Q rows. Three exact integer certificates scale the
same certified product components down to the original output Q components.
Every coefficient and every rounding/reduction identity is mandatory. See the
[scaler contract](../../crates/bfv-unrelinearized-product/src/scale/README.md). These deterministic checks do not depend
on a random challenge, a scalar-certificate signature or a caller-supplied hash.

For each of the four prime fields, let the extended inputs be A0,A1,B0,B1. The
certificate contains three degree<N products Y and three degree<=N-2 quotients H.
It must satisfy these ordinary polynomial identities:

```
A0*B0       - Y0 = (x^N + 1)*H0
A0*B1+A1*B0 - Y1 = (x^N + 1)*H1
A1*B1       - Y2 = (x^N + 1)*H2
```

The prover obtains H from the upper half of the ordinary 2N-point convolution.
The verifier evaluates all three identities at eighteen points per field. It
performs no NTT, SDK scaler or ciphertext multiplication. No high coefficient,
cross term, product component or residue basis is omitted.

The only complete checking entry point owns canonical decoding and derives
challenges from the SAME complete frame and original statement. All Y, H,
extended P coefficients, seven integer certificates and exact endpoints are
fixed before any challenge. Each challenge hashes that whole transcript with
explicit basis/sample domain labels. Cloning an unfinalized SHA512 prefix only
avoids hashing identical bytes again. It does not expand a finalized short seed.
Each full 512-bit digest is interpreted big-endian and reduced modulo its prime.

## Conditional root argument

The following is a local algebraic derivation, not an assessment of SHA512 or of
the complete protocol. A false fixed certificate satisfying all exact scalar
checks leaves at least one nonzero identity polynomial F of degree<=8190 in one
field. Choose that first false F before sampling. Acceptance requires all eighteen
points in that field to be roots of F. Sharing those points among three equations
does not require a factor of twelve: acceptance implies this one fixed event.

For independent uniform 512-bit oracle outputs, a particular reduced field
element has probability at most `1/p + 2^-512`. Thus, with the smallest fixed
prime p=1073668097, the fixed-certificate error is bounded by:

```
epsilon_18 <= [8190 * (1/p + 2^-512)]^18 < 2^-305.99
```

Fiat–Shamir lets an attacker choose certificates after hash queries. The fixed
certificate bound alone is therefore insufficient. A classical random-oracle
grinding estimate is `(q+1)*epsilon_18`. The security model must define q and
account for all other assumptions and protocol invocations.

The [Fiat–Shamir QROM analysis](https://arxiv.org/abs/1902.07556) and
[Don–Fehr–Majenz, Theorem 3](https://arxiv.org/html/2003.05207v3#S3)
describe reductions with a quadratic oracle-query loss. They do not assess this
implementation. A proposed model groups the 72 independent component outputs
into one wide random-oracle answer; simulating each component query with at most
two wide-oracle queries suggests a bound `(4q+1)^2*epsilon_18`. That model,
simulation and concrete SHA512 instantiation still require independent review.

Even that proposed bound does not mean a 2^-144 failure probability for a
2^144-query adversary: with eighteen points its upper bound is only below
2^-13 at that budget. Twenty-six points would give a conditional bound below
2^-149.98, using the same model. The current eighteen-point profile deliberately
carries no assessed-security label. A future accepted profile must state a
security metric and oracle budget instead of silently equating a root bound
with a complete cryptographic guarantee.

## Missing DCS composition

The certificate proves no authenticated Source, valid encryption key, formation
of the encrypted predicate, SQL program, row completeness or agreed database
version. Those independently authenticated inputs and program constraints must
be connected to the exact ciphertext statement. No plaintext fixture assertion,
hash, decryption or public scalar equation can replace them.

The N4096/Q2 lattice parameters and the correctness/noise bound for the full
accepted data/query domain remain unassessed. One successful decryption and SDK
conformance tests do not settle either question. Durable mutations, consensus,
locks, failure recovery, memory for the complete peer and full query latency
remain separate obligations. None is granted by this experiment.
