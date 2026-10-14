# BFV verification: bounded source investigation

2026-10-15, research only. This note revisits the existing
[proof investigation](experiment-query-proofs.md) against the actual
[byte-limb core](../experiments/bfv-byte-limb-core/README.md). No new
implementation, build or benchmark was run. The core's forged-echo test is
still decisive: returning the input value ciphertext can yield an in-bounds
wrong (COUNT1,SUM10) instead of(2,30), explicitly UnverifiedAggregate.

Decision: exact ring-product checks are a useful established primitive, but
neither a few committed NTT-coordinate openings nor fifteen abstract products
prove this actual BFV circuit. A complete specialized proof remains plausible
research, with no demonstrated500ms prover+verifier+wire/RAM pipeline here.

## Four primary sources and actual scope

1. Atapoor–Baghery–Pereira–Spiessens, IACR CiC1(1), 2024,
   [Verifiable FHE via Lattice-based SNARKs](https://cic.iacr.org/p/1/1/24/pdf),
   Sections2.7/5, AppendixA. Its dCRT construction covers maintenance, including
   key/modulus switching. The implementation proves BGV, N4096, three30-bit
   primes and two squaring layers approximating a neural network, not our BFV.
   Table2 reports prover116–167s, verifier597–925ms as input width5..100 varies;
   six R1CS instances total3,133,440 gates, proof187kB, CRS11.6GB. CRS size is
   not measured peakRSS. Parameters target128-bit security/soundness with
   amplification rho15. The model explicitly retains CPA instead of CCA1.
   These are published results, not local timings or a transferable BFV budget.
2. Giorgi–Grenet–Perret du Cray,
   [Polynomial modular product verification, arXiv2101.02142v1](https://arxiv.org/html/2101.02142v1),
   Algorithm3/6, Theorem4.1. It verifies H=FG modP over a coefficient integral
   domain in O(N*#P) operations for dense polynomials. Thus P=X^N+1 permits
   O(N) verification when full coefficients are available. Error is bounded by
   (N-1)/|challenge set|; small fields need repetition/extension with stated
   costs. It supplies no committed-trace BFV prover or measured end-to-end
   homomorphic query. Apply it per prime field, not directly to composite Z_Q.
3. fhe.rs0.1.1, release VCSfe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a,
   [parameters.rs](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/parameters.rs),
   lines481–509. At level0, original five Q218 primes are extended with
   ceil((218+60)/62)=5 auxiliary62-bit primes: ten temporary RNS lanes.
   This is public computation workspace, not an enlarged encryption modulus.
4. Same release,
   [ops/mod.rs](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/ops/mod.rs),
   lines259–350. Actual ciphertext multiplication extends components, tensors
   them, converts to coefficient form, applies the down-scaler t/Q and returns
   to NTT. Local release sources also inspected: rns/scaler.rs,
   keys/{key_switching_key,relinearization_key,galois_key}. They implement
   coefficient projection/rounding and key switching, not just field products.

A generic zkVM can trace those integer operations; a field SNARK must encode
modular reduction, canonical ranges/carries and conversions. A specialized
system can exploit the ring/NTT structure, as source1 does. Neither approach
has a compiled relation or published benchmark for our unchanged core. We do
not scale the cited neural-network timings by our product count.

## Actual relation and work inventory

The native/unfused byte-range kernel has15 ciphertext products, depth5,
16/20 rotations for16/256 slots, N8192/t114689/Q218. Each product immediately
relinearizes; each rotation also key-switches. There are therefore31/35 key
switches to cover. The literal2x2 tensor loops alone perform
15*4*8192*10=4,915,200 scalar NTT products across the temporary basis.
This is source execution accounting, NOT an R1CS constraint lower bound.
An algebraically equivalent circuit can optimize it.

A complete relation must bind exact input/output ciphertexts, public keys,
parameter/source/kernel versions, query ID and both independently current
heads. Every wire must connect to the next operation. It must additionally cover:

- All coefficient/NTT transformations and automorphism permutations.
- Basis extension, canonical integer representatives, cross-prime consistency,
  rounded t/Q scaling and any prescribed context reduction. A residue congruence
  alone does not fix an integer lift or its rounding/carry choices.
- Public-key decomposition/products for relinearization and rotations, plus
  constant additions, linear range identity and slot reduction.
- Actual byte/COUNT packing and output slots; the owner already enforces valid
  encrypted inputs and lo<=hi. Selection/authentication stays a separate bound
  owner/retrieval obligation, not a consequence of ciphertext multiplication.

Keeping output level0 removes no internal scaling/basis work. Skipping these
relations proves a different computation. Independent HE-security/noise validation
and malicious decryption/verification-oracle confidentiality also remain open.

## Why post-commit checks require a full protocol

The following arithmetic is an inference, not a proposed secure construction.
For degree<N A,B,C over F_q, a quotient witness D of degree<=N-2 permits the identity

    A(X)B(X)-C(X)-D(X)(X^N+1)=0, degree <=2N-2.

D and all wires must be bound before an unpredictable challenge z. Checking
A(z)B(z)=C(z) at an arbitrary field point is generally WRONG for an honest
quotient-ring product: it omits D(z)(z^N+1). Allowing an uncommitted D(z)
lets the prover fit the equation after seeing z.

For one fixed false degree<=16382 identity and uniform field z, the elementary
bound is16382/q_min≈1.8624e-9, about2^-29, using q_min8796092792833.
Five independent challenges bound that ONE identity by about2^-145.
This is not a full-protocol128-bit claim: batching, all relations, commitments,
openings, adaptivity/Fiat–Shamir and implementation need their own analysis.

A Merkle commitment fixes an array; it does not authenticate a dense polynomial
evaluation outside its stored coordinates. Either the verifier reads the
coefficients and performs the established O(N) check, or an actual polynomial
commitment/IOP proves the requested evaluations and their representation links.
An arbitrary claimed scalar, unchecked inner product, or hash root alone is
insufficient. Dense random linear combinations over a field detect sparse
errors only when their full values are computed or soundly proved; sampling
coordinates is a different experiment. Composite-Q entropy cannot be treated
as218 independent soundness bits when an error occupies only one prime factor.

For a naive transcript, fifteen post-relinearization two-component outputs
alone contain15*2*8192*5*8=9,830,400B in u64 RNS arrays, or6,696,960B ideally
bit-packed to218 bits/coefficient. This omits input/key/rotation/scaling states.
It is an illustrative full-transcript size, not a lower bound on succinct proof
wire: commitments can avoid transmitting the full trace, at additional proved
opening/prover costs. No such cost has been measured for this core.

## Random NTT coordinates can miss almost every sparse error

For f=X^N+1, every NTT root r_j has the Lagrange basis polynomial

    E_j(X)=f(X)/((X-r_j)f'(r_j)), degree N-1.

It equals1 at r_j and0 at every other NTT root. A prover can commit to a wrong
polynomial differing by a nonzero multiple of E_j before the challenge.
A sampled NTT coordinate then detects the error with probability only1/N.
For N8192,100 independent samples miss it with probability0.987866;
with replacement, about726,774 samples are needed just to drive this particular
miss probability below2^-128. Distinct sampling needs essentially every
coordinate. Sampling a random modulus as well can miss a one-modulus error too.
These are direct calculations, not attacks on either cited proof system.

The NTT vector is a rate1 representation: every vector is some degree<N
polynomial, so a Merkle tree alone creates no distance amplification. A real
low-degree extension/IOP must prove consistency and all conversion constraints.
It cannot borrow a field-wide polynomial identity bound for N chosen roots.

## Finite conclusion

The source1 dCRT-with-maintenance construction is the closest verified design
reference found in this bounded investigation. Source2 gives a legitimate
linear-time product-check primitive, not a complete lightweight BFV compiler.
No inspected evidence justifies attaching a custom transcript spot-check and
accepting the present output as proved. Retain ProofStatus::Unavailable and
UnverifiedAggregate. The next prerequisite is a complete formal relation/model
and concrete proof backend, followed by actual full-operation prover/verifier,
wire, setup and native-memory measurements; no prototype is added here.

Audited core source SHA-256: lib.rs6576adf2f81f886d3c6ca0480566e920c8dcadb9f6cf3d4aa0418d5ae9e7dd12;
kernel.rs1d719aa6193470c6f3b8c7d28fbc56a87a90d4d14e152a9ce63e5ff47400ae54.
Frozen source/report packages remain unchanged. The arithmetic in this note was
checked directly. Publication text and local/promotion targets were checked;
release code was read locally with its Cargo VCS record (remote commit links
were unavailable to the browser fetcher). These
are research/documentation checks, not application or cryptographic tests.
