# Exact correlated quotient disclosure sampler

This is a fixed-location algebraic lemma for the existing hiding quotient
transformation. It uses independent ideal uniform field samples and independently
fixed public inputs/coins/locations. It proves equality of the stated algebraic
marginal for honest valid original traces. It does not condition on actual Merkle
roots, an actual FS transcript, hash-selected locations, successful FRI checks or
an adversary's auxiliary information. It establishes neither public-proof
confidentiality nor SQL admission.

## Fixed source geometry and premises

Let F be Goldilocks, p=18446744069414584321, and
E=F[u]/(u^5-3), with the **fixed** ordered basis (1,u,u^2,u^3,u^4).
In particular u has coordinates (0,1,0,0,0); it is not an arbitrary element of E.
Let original H=H_N=<h>, Z=X^N-1, and k=2N. Fix the actual closed AIR,
independently owned full Expected, public PP and periodic polynomials, PV,
lookup coins and terminal, constraint-folding coin alpha, and OOD point z in E.
Fix the set S of distinct actual input-LDE positions. Locations are parameters
of this experiment, independent of all fresh ideal masking samples.

The input LDE domain is D=7*H_(16N), S is a subset of D and |S|<=192. Native
quotient interpolation uses U=7*H_(cN), split into c disjoint cosets
U_i=s_i*H_N. **Each original quotient chunk has height N**, and its masked
polynomial has degree<2N. All chunks share the same input-LDE row set S.

| Closed family | N | c | cN | D size |
| --- | ---: | ---: | ---: | ---: |
| SourceVersion | 512 | 16 | 8192 | 8192 |
| Role3 version encoding | 512 | 16 | 8192 | 8192 |
| Dense DATA | 2048 | 8 | 16384 | 32768 |
| Predicate Word | 512 | 8 | 4096 | 8192 |
| Fused Query | 2048 | 8 | 16384 | 32768 |

Thus U=D for Source/Role3; U is an index-two subset of D for the other three.
D is disjoint from H and stable under multiplication by h. The quotient-image
lemma below allows z anywhere. The joint trace/quotient sampler requires z not
in H. Coin selection, abort probabilities and the actual FS bridge are separate.

The following honest-AIR premises are essential:

1. Original MAIN and original AUX satisfy every emitted AIR/lookup equation on
   H, with the fixed public PP, periodic polynomials, PV and terminal. The actual
   AUX generation succeeds; this is not a claim about zero-denominator aborts.
2. For every original private base column f, the fresh committed column is
   P=f+Z*R with deg f<N and independent uniform R in F[X]_<N. This includes
   each of the five flattened base coordinates of an original AUX extension
   column. MAIN and AUX masks use disjoint ideal source cells. Each appended
   trace codeword is independently uniform in F[X]_<2N.
3. The actual emitted/folded polynomial C_alpha uses the original-domain
   selectors and rotation h, with exact native emission order. It obeys
   Z|C_alpha and deg(C_alpha/Z)<cN. Native quotient interpolation on U is
   consequently the polynomial Q=C_alpha/Z, not merely the interpolation of
   a rational expression at cN points.
4. Quotient masks and quotient appended codewords use fresh ideal samples,
   independently of all trace masks and of each other as specified below.

Original-row validity implies divisibility after masking: P and f agree on H,
and h*H=H preserves next-row values too. It does not by itself prove the degree
bound. Under the source-associated certificate of nontransition degree a and
at most one transition factor per term, a conservative bound is

    deg C_alpha <= a*(2N-1)+(N-1),
    deg Q <= a*(2N-1)-1.

First/last selectors have degree N-1 and are already counted; transition has
degree one but cached symbolic degree zero. The extra N-1 slack covers it.
The recorded actual closed profiles give:

| Family | a | deg Q ceiling | cN |
| --- | ---: | ---: | ---: |
| SourceVersion | 3 | 3068 | 8192 |
| Role3 | 4 | 4091 | 8192 |
| DATA | 4 | 16379 | 16384 |
| Word | 4 | 4091 | 4096 |
| Query | 4 | 16379 | 16384 |

These are certificates for these actual sources, not a generic inference from
an arbitrarily normalized degree report. Closed Source uses StateCertificate,
not the separately factorized Source experiment. Its periodics and Role3's
periodics are original-H polynomials with the full 512-row period. A different
AIR, selector schedule or public preprocessing needs its own certificate.

## The exact quotient-mask fiber

First fix one base coordinate of Q. Let q_i in F[X]_<N interpolate that
coordinate on U_i. Define the normalized polynomials and constants

    v_i(X)=(X/s_i)^N-1,
    V=product_i v_i,
    c_i=(product_(j!=i) v_j(s_i))^(-1),
    lambda_i(X)=c_i*product_(j!=i) v_j(X).

All c_i are nonzero. Lambda_i is one on U_i and zero on every other U_j;
sum_i lambda_i=1 as a polynomial. Native sampling is

    r_0,...,r_(c-2) <- independent uniform F[X]_<N,
    r_(c-1)=-sum_(i<c-1) (c_i/c_(c-1))*r_i,
    q'_i=q_i+v_i*r_i.

Since lambda_i*v_i=c_i*V, the correlated masks cancel **polynomially**:

    sum_i lambda_i*q'_i = sum_i lambda_i*q_i = Q.

The last equality is CRT interpolation of degree<cN. Thus the entire
recomposed Q is preserved, including Q(x) at every opened base point, not only
the collapsed value Q(z). At x in U_j, q'_j(x)=Q(x) and lambda_j(x)=1.
This explains the visible structure at every Source/Role3 base opening.

Let M be the squarefree product of the distinct minimal polynomials over F of
S union {z}. Put A=F[X]/M and m=deg M<=|S|+5<=197<N. Equality of points and
Frobenius-conjugacy compatibility are represented by A; there is no claim of
independent E coordinates when z lies in F or coincides with an opened point.
Reduction F[X]_<N->A is onto with p^(N-m) preimages per residue.

All polynomials below are reduced to A. Set

    K={ r in A^c : sum_i c_i*r_i=0 },
    B(r)_i=v_i*r_i,
    J={ y in A^c : sum_i lambda_i*y_i=0 }.

**B:K->J is an isomorphism.** Split A into its irreducible residue fields.
Because the v_i are pairwise coprime, any factor divides at most one of them.

- If it divides none, all v_i and V are units. The inverse is r_i=y_i/v_i;
  the target relation divided by V is exactly sum_i c_i*r_i=0.
- If it divides v_j, lambda_j is nonzero and the other lambda_i vanish.
  The target relation is exactly y_j=0; all remaining y_i are free.
  Recover r_i=y_i/v_i for i!=j, then uniquely recover r_j from the c-weighted
  relation. This also gives B(r)_j=0.

CRT joins these inverses. Therefore the tuple (q'_i mod M)_i is exactly uniform
on the affine fiber

    F_Q={ y in A^c : sum_i lambda_i*y_i=Q mod M }.

Its F-dimension is (c-1)m, and each output has exactly
p^((c-1)(N-m)) native mask preimages. The distribution depends on q_i only
through Q mod M. This holds also for z=0, z in F, z in U and S intersect U.
There is no additional quotient-rank bad event at a root of some v_i.

An explicit sampler needs no original q_i. Because sum lambda_i=1, the vector
(Q,...,Q) is a particular solution. Sample t_0,...,t_(c-2) independently
uniform in A, derive the last t by the c-weighted relation and output
Q+v_i*t_i. The isomorphism proves this is uniform on F_Q.

For each of the five appended quotient codeword columns, the initial q_i are
independent uniform degree<N polynomials. Their residues in A^c are already
fully uniform. Adding the independent correlated mask preserves that full
uniform law, independently of all five original quotient-coordinate columns.
Their image is A^c, with no fixed original-Q recomposition constraint.

## Enlarged trace residues and the two exact rotation maps

Put T=S union h*S union {z,h*z}. Let M_T be the squarefree product of its
distinct minimal polynomials over F, and A_T=F[X]/M_T. Then

    deg M_T <=2*192+10=394<N,
    gcd(M_T,Z)=1 when z is not in H.

Reduction of a uniform degree<N trace mask to A_T is onto. Multiplication by
the unit Z followed by addition of f proves P mod M_T is exactly uniform in
A_T, independently of f. Independent source cells give the product of these
images over original MAIN/AUX base columns. Appended trace codewords have the
same uniform residue law, since their coefficient space has dimension 2N.
The extra h*S samples are internal simulator variables, not extra disclosures.

Use the two well-defined F-algebra maps

    pi_0:A_T->A,  [P] -> [P(X)]_M,
    pi_h:A_T->A,  [P] -> [P(hX)]_M.

The first is well-defined because M|M_T. For the second, every root t of M
has h*t among the roots of M_T, including all conjugates because h is in F.
Thus M(X)|M_T(hX), proving well-definedness. Compute these maps from any
polynomial representative; canonical degree<deg M_T representatives suffice.

Do **not** substitute hX as an endomorphism of A_T. T need not be stable under
h. For example choose S={s}, generic degree-five z and h^2*s not in T or its
conjugate closure. The valid mask perturbation delta P=Z*M_T has degree<2N
and changes neither original H rows nor P mod M_T. Nevertheless
delta P(hX) at X=h*s is nonzero. Therefore the full rotated residue modulo
M_T is not recoverable. Only pi_h into the smaller target A is needed here.

## Keeping all five quotient coordinates

Let B=E_coefficient tensor_F A. Treat it as A[u]/(u^5-3), keeping its five A
coordinates. The fixed coefficient u and residue indeterminate X are different
elements. Embed a fixed extension coefficient a as `a tensor 1` and a residue
t as `1 tensor t`.

Feed pi_0(P) into current-row MAIN slots and pi_h(P) into next-row slots.
For each AUX extension column, reconstruct sum_(b=0..4) u^b tensor P_b from
its five **separately** sampled base-coordinate residues; use the same two maps
for its current/next slots. Use the independently known actual PP/periodic
polynomials, actual original-H selectors, PV, terminals and fixed extension
coins. Evaluate the actual emitted polynomial C_alpha in B, and divide by the
unit 1 tensor Z. Expanding its fixed coefficient basis produces exactly

    sum_(b=0..4) u^b tensor (Q_b mod M).

This follows because the two maps agree with each actual trace column and its
rotation modulo M; ring evaluation and division by a unit preserve that
agreement. No globally valid trace extension of a sampled residue has to be
constructed. Nor is the actual C_alpha mod M_T claimed to be known.

Collapsing the two extension copies loses information. With z equal to the
**fixed basis generator** u, the E-coefficient polynomial Q(X)=X-u has ordinary
Q(z)=0, while its five base-coordinate evaluations are (z,-1,0,0,0).
The multiplication map E tensor_F E->E has F-dimension 25 in its domain and 5
in its image, so its kernel has dimension 20. A collapsed AIR evaluation at z
does not determine the receiver's five individual base-column OOD openings.

## Complete fixed-location algebraic sampler

Here EmitA evaluates a residue at all distinct x in S and at z, retaining the
actual repeated-position/Frobenius consistency. Trace emits only the point
sets actually requested for each matrix (z, and h*z where applicable). Public
PP values are their actual fixed values. No root/hash/FRI message is emitted.

```text
INPUT: independently fixed full Expected/AIR/PP/periodics/PV/terminal/coins,
       N,c,h,z outside H, S subset D with |S|<=192.

M   := product of distinct minimal polynomials of S union {z}
M_T := product of distinct minimal polynomials of S union h*S union {z,h*z}
A := F[X]/M; A_T := F[X]/M_T; B := E_coefficient tensor_F A

For every original MAIN/AUX BASE column:
    Pbar <- uniform A_T, independently
For every appended MAIN/AUX trace codeword:
    Pbar <- uniform A_T, independently

Cbar := actual ordered AIR/fold in B,
        current slots = pi_0(Pbar), next slots = pi_h(Pbar),
        AUX extension slots = sum_b u^b tensor (corresponding base slot),
        remaining inputs = actual independently fixed public polynomials/coins
(Qbar_0,...,Qbar_4) := coefficient_basis(Cbar / (1 tensor Z))

For b=0..4, independently:
    t_0,...,t_(c-2) <- uniform A
    t_(c-1) := -sum_(i<c-1) (c_i/c_(c-1))*t_i
    For chunk i: Y_(i,b) := Qbar_b + v_i*t_i
For every appended quotient codeword j=0..4 and chunk i:
    Y_(i,5+j) <- uniform A, independently

Emit actual trace-coordinate disclosures from Pbar, dropping unused h*S data
Emit EmitA(Y_(i,b)) for all c chunks and all ten base columns
```

The samplers for all five quotient-coordinate fibers use independent ideal
samples. Conditional on any full valid masked trace, actual fresh quotient
masks have exactly this fiber law. Its offset depends on that full trace only
through the Q_b residues computed from the enlarged trace image. Averaging
over full traces proves equality of the complete stated joint trace/quotient
algebraic marginal, independently of the honest original witness under the
fixed public premises. This is an equality of distributions, not just a rank
count or a claim about one collapsed recomposition equation.

Fixing a public lookup terminal does not by itself couple the fresh MAIN/AUX
masks. Actual AUX and terminal are computed from original MAIN/PP rows before
AUX hiding, using fixed lookup coins; they do not read the masked MAIN LDE.
This argument does not establish confidentiality of those public terminals.

## Finite regression evidence

The [validation note](QUOTIENT-VALIDATION.md) records separate checks of exact
F_17 fibers against independent RREF, Gold/EF5 tensor projection at both actual
height classes with the full 192-location budget, and actual native quotient
masking on all three closed geometries. The polynomial AIR fixture is an
algebra example. Actual emitted-AIR/source association and honest degree and
divisibility certificates remain their owning checks.

## Source anchors and precise limits

Pinned SDK prefix:
`.local/cargo-home/registry/src/index.crates.io-1949cf8c6b5b557f/`.

- uni `prover.rs:195-216,278-282,309-316,397-409`: original/hidden domains,
  quotient flattening and actual opening points.
- batch `prover.rs:151-175,209-224,409-410,490-496`: same cN/N geometry,
  flattening, splitting and masking; `574-599`: actual point requests.
- commit `pcs/univariate.rs:157-177`, `domain.rs:263-316`: split order and
  normalized vanishing polynomials; `235-236,326-336`: original rotation and
  selectors.
- FRI `hiding_pcs.rs:489-518,526,542,550-560,757-773`: exact mask correlation,
  normalizers and physical DFT variable X=7Y. The inserted term is
  v_i(7Y)*r_i(7Y), not an unshifted v_i(Y)*r_i(Y).
- uni `verifier.rs:81-107`: exact lambda recomposition and fixed EF5 basis.
- batch `prover.rs:294-301,326,357` and lookup `logup.rs:878-893`: original
  AUX/terminal construction, flattening and fresh independent hiding commit.
- batch `prover.rs:867,871,1036-1063` and uni `prover.rs:742,822-878`: actual
  original-H selectors/rotation, emitted fold and multiplication by inverse Z.
- `crates/bfv-hiding-stark/src/config.rs:28` and pinned Goldilocks
  `extension.rs:131-153`: fixed EF5 power basis u^5=3.

The quotient image adds no exceptional z. The joint trace sampler excludes
z in H, where an original trace row is unmasked. A z in D may separately
cause native PCS denominator failure despite the algebraic image remaining
well-defined. Active zero lookup denominators can abort AUX generation; their
probability/privacy is not analyzed by conditioning on a valid original AIR.

Concrete RNG/OS/PRG assumptions, salted root hiding, programming or simulating
the full-prefix SHA512 transcript, adaptive root-selected S/z, the joint
R/PCS/FRI carried values and privacy of aborted executions are outside this
lemma. The lemma must not be promoted to a whole-proof or live security claim.

This statement incorporates an independent review of the rotation and tensor
maps. The regression checks in `quotient_image_tests.rs` and the native quotient
checks separately test concrete arithmetic and source correspondence; they do
not replace the stated premises or prove the excluded cryptographic bridges.
The separate [R-DEEP image](R-DEEP.md) handles the whole reduced polynomial
conditional on these algebraic disclosures, also at fixed locations and coins.
