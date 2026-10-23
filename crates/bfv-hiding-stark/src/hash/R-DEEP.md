# Conditional R-DEEP image of the native hiding PCS

This finite algebraic result describes the current fixed SHA suite and its five
owning proof geometries. It assumes ideal independent uniform masking cells,
fixed challenges and locations, and consistent disclosed polynomial values.
It does not establish input commitment hiding, adaptive Fiat–Shamir security,
a simulator for the disclosed values themselves, or live operation admission.
Concrete OS-seeded random streams additionally require a PRG assumption.

## Actual polynomial map

Let F be Goldilocks, p = 18446744069414584321, and E/F its degree-five binomial
extension, q = p^5. Original height N is 512 for Source/Role3/Word and 2048 for
DATA/Query. Each proof's input base polynomials have degree < k = 2N and common
committed coset D = 7 H_(8k). The native R constructor commits ten independent
base columns of degree < k: five extension coordinates and five codewords.
It uses the inner PCS directly, without another trace-height doubling.

R is the first PCS matrix and opens only at z. All ten OOD values are public:
the wrapper moves the last five into the proof and the verifier rejoins them.
Other input columns open at z and may additionally open at h_N z, with h_N of
order N. The PCS absorbs all per-column claims before sampling the mixing
challenge theta. At this common height it constructs one reduced polynomial B:

```text
B(X) = sum_(column j, requested point a) theta^e (f_j(X)-f_j(a))/(X-a).
```

The exponent follows native matrix/point/column order; R receives powers
0 through 9. Let S contain the distinct raw input-row query locations in D,
with s = |S| <= 192. Every base column's values at S and requested OOD points
belong to the fixed view V, including every appended codeword.

## Exact conditional mask image

Fix z outside D. Its monic minimal polynomial m_z over F has degree d = 1 or 5.
Write P_S = product_(x in S)(X-x), M = P_S m_z, m = s+d, A = M/(X-z),
and r = k-m. The factors are coprime and m <= 197 < k. For each R column,
choose any base-polynomial representative R_i^0 consistent with its claims.
Polynomial CRT gives the exact conditional law

```text
R_i = R_i^0 + M u_i,             u_i independent uniform in F[X]_<r.
delta B_R = A sum_(i=0..9) theta^i u_i.
```

Every disclosed residue has p^(k-m) preimages. Per residual coefficient the
map F^10 -> span_F(1,theta,...,theta^9) has constant-size fibers. Since the
extension degree is prime, theta outside F has degree five. Its first five
powers form a basis, giving rank 5r and p^(5r) preimages for the full map.
Consequently delta B_R is exactly uniform on A E[X]_<r. For theta in F,
the image is A F[X]_<r, of rank r and fiber size p^(9r).

At s = 192 and generic z, r is 827 or 3899. A has zeros at S and the four
other Frobenius conjugates of z. Thus this is not uniformity over all reduced
polynomials of degree < k-1; it is uniformity over the required affine fiber.

## Why every remaining input difference lies in that fiber

Compare any two configurations of all non-R base polynomials consistent with
the same V. They may have arbitrary MAIN/AUX/quotient correlations. Every
column difference delta f is divisible by M. Its reduced term at z is therefore
divisible by A. If it also opens at b = h_N z, then delta f(b) = 0.

For nonbase z, b cannot be a Frobenius conjugate of z: iterating that relation
five times would give h_N^5 = 1, incompatible with its power-of-two order N.
Thus delta f is divisible by P_S m_z m_b. Dividing by X-b leaves A. For base
z, A = P_S, and division at either requested point preserves every S zero;
both points lie outside D. Coincident points at z = 0 obey the same algebra.
Every reduced difference has degree < k-1, so the total difference lies in
A E[X]_<r. R is independent of the other polynomial construction in this
fixed-coin ideal experiment. Adding its uniform image therefore removes every
remaining polynomial-choice dependence conditional on V, when theta is nonbase.

An explicit whole-B sampler uses only V:

1. Choose any degree < k base-polynomial CRT representative for each column's
   S and requested OOD claims.
2. Compute B0 in native point/column order with its theta powers.
3. Draw U uniformly in E[X]_<r and return B0+A U.

The representatives need not satisfy AIR or quotient consistency. Every actual
coherent configuration differs by the proven subspace. This samples the entire
conditional polynomial, including unqueried values and coefficients. It does
not sample V; the joint trace/quotient disclosure law is a separate obligation.

All subsequent FRI algebraic arrays, sibling values and final coefficients are
functions of this entire B and fixed folding coins. Fresh FRI commitment salts
can additionally be sampled. Input-MMCS sibling hashes, roots, and correlations
caused by adaptively derived challenges are outside this fixed-location result.

## Exceptional coins and producer aborts

When theta is base, the R image is smaller. If z is also base, all reduced
polynomials have base coefficients and the smaller space suffices. If theta is
zero, only the first R column survives, so B is independent of later inputs.
For nonzero base theta and nonbase z, universal absorption does fail. A later
column with two points can differ by delta f = P_S m_z m_b while keeping its
disclosures zero. With nonzero base native weights a and c,

```text
delta B/A = a m_b + c (X-z) m_b/(X-b).
```

This vanishes at the other four conjugates of b, but its value at b is
c(b-z)m_b'(b), which is nonzero. It cannot have base coefficients. This is an
abstract span obstruction, not an exhibited leak between accepted AIR witnesses.
A conservative fresh-uniform mixing-coin charge is p/q per proof, hence 5p/q
across the five proofs. p/q = p^-4 is approximately, not exactly, 2^-256.

Separately, native adjusted interpolation weights reject z = 0. The original
trace-image argument excludes z in H_N, and PCS denominators exclude z in D.
The union bound per proof is at most (8k+N+1)/q, summing to 95,749/q. Native
LogUp skips zero multiplicity but batch inversion panics on any active zero
denominator. With beta fixed, each denominator is affine in lookup alpha with
slope one. Original-row/message slots bound this fresh-coin event by

```text
(2048*243 + 512*98 + 2048*248)/q = 1,055,744/q.
```

These local events together satisfy the exact integer inequality

```text
(5p + 1,151,493) * 2^253 < p^5.
```

This is only a union bound for the named local ideal fresh-coin events, including
aborted executions. It is not a composed privacy error or an adversarial FS
query budget. Conditioning on successful generation must not silently erase
witness-dependent aborts. Root/MMCS hiding, the law of V, PRG and semantic
assumptions, repeated proofs and decrypt interfaces still need composition.

## Pinned source correspondence

All following SDK files are Plonky3 0.8.0 under the locked local Cargo source.

- `p3-fri/src/hiding_pcs.rs:675-737`: public appended OOD claims and actual
  ten-column R constructor; `332-414`: receiver rejoining claims.
- `p3-uni-stark/src/prover.rs:397-423` and
  `p3-batch-stark/src/prover.rs:562-599`: R first and requested point layout.
- `p3-fri/src/two_adic_pcs.rs:587-778`: OOD absorption, mixing coin, common-height
  grouping, powers and the native reduction sign.
- `p3-fri/src/prover.rs:279-354,454-473`: complete FRI arrays and input raw rows.
- `p3-matrix/src/interpolation.rs:75-80`: zero-point interpolation rejection.
- `p3-lookup/src/logup.rs:716-720,786` and
  `p3-field/src/batch_inverse.rs:24-29`: inactive messages and active-pole abort.
- [Owning native trace geometry](../../../registry200-proof/src/registry_progress/word/read/NATIVE-TRACE-VALIDATION.md)
  records the five actual verifier layouts and common heights.

See [validation](R-DEEP-VALIDATION.md) for actual-field regression coverage and
native constructor/kernel measurements. No proof profile or admission changes.
