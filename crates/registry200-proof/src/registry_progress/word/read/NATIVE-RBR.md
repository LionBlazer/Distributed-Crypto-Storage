# Native RBR correspondence under explicit hypotheses

This research note associates portions of the five fixed native arguments with
the conditional algebraic diagnostic. The owning integer certificates are checked;
the proposed round-by-round derivation remains subject to independent review.
It changes no engine term, proof configuration, wire profile or admission guard
and establishes no composed cryptographic security or SQL/lock authority.

## Fixed native execution

The five closed arguments have a single input-PCS height partition individually:

| AIR | committed k | input LDE n | powers-batch functions F | binary folds |
| --- | ---: | ---: | ---: | ---: |
| Source | 1024 | 8192 | 14502 | 10 |
| Role3 | 1024 | 8192 | 3492 | 10 |
| DATA | 4096 | 32768 | 2622 | 12 |
| Word | 1024 | 8192 | 3024 | 10 |
| Query | 4096 | 32768 | 2327 | 12 |

These are separate PCS/FRI instances. Matching numerical heights between two
arguments does not merge their batching challenges or received words.

Pinned p3-fri 0.8.0 source correspondence:

- `two_adic_pcs.rs:684-778`: accumulate one reduced word per actual LDE height;
  every (column, opening point) advances the powers ladder by one.
- `prover.rs:285-304`: commit the current word as binary rows BEFORE beta, then
  fold it. `two_adic_pcs.rs:103` gives zero extra query-index bits.
- `two_adic_pcs.rs:117-129`: for a pair at s,-s, native `fold_row` equals
  `(u(s)+u(-s))/2 + beta*(u(s)-u(-s))/(2s)`.
- `verifier.rs:995-1045`: replace the selected coordinate with the incoming
  value, authenticate the complete reconstructed pair, shift the index by one,
  and apply the same fold. Single input height means no later roll-in occurs.
- `transcript.rs:351-360,547-575`: bind the final polynomial before drawing all
  192 indices. `verifier.rs:749-818` checks every chain and its terminal constant,
  then authenticates all reconstructed FRI rows.

Condition this lemma on the separately bounded online Merkle extraction event:
every committed row is fixed at its commitment notification, including roots in
potentially canonical raw FS query prefixes. Salt columns are excluded from the
algebraic words; the authenticated EF5 pair is decoded canonically.

## Proposed weighted-prefix RBR invariant

Put a=7/(6*sqrt(8)), n_i=n/2^i, k_i=k/2^i, r=log2(k), and
A_i=ceil(a*n_i). Then k_r=1,n_r=8 and 2*A_(i+1)>=A_i. Use normalized subgroup
coordinates: the initial PCS coset g*H is parametrized by X in H through g*X.
In bit-reversed indexing the ancestor projection is pi_i(j)=j>>i.

Let b be the received reduced-opening word after the powers challenge. Let w_i
be the FRI word committed before beta_i. Define the surviving ORIGINAL positions:

```
K_0 = {j : b[j] = w_0[j]}.
K_(i+1) = {j in K_i :
    w_(i+1)[pi_(i+1)(j)] = Fold_beta_i(w_i)[pi_(i+1)(j)]}.
```

For the last fold replace w_r with the submitted final constant c. K_r is exactly
the set of original indices passing the complete native arithmetic chain, once
the authenticated rows are fixed. Duplicate indices do not change this set.

After a committed w_i, declare a prefix live exactly when some polynomial P_i of
degree <k_i agrees with w_i on at least A_0 ORIGINAL surviving positions in K_i.
Multiplicity matters: several original positions can project to one child point.
After beta_i and before the next commitment, use the same predicate with
Fold_beta_i(w_i), projection pi_(i+1), and unchanged K_i.

A next prover commitment only intersects K_i with a new equality and cannot turn
a dead prefix live. The initial prover commitment also cannot do so when b has
no degree-<k polynomial at agreement A_0.

For one beta transition, write the fixed pair data as received words E_i,O_i on
the CHILD domain, so Fold_beta_i(w_i)=E_i+beta_i*O_i. Suppose a late candidate Q
makes the new prefix live. Its full child agreement set has at least
ceil(A_0/2^(i+1))=A_(i+1) distinct points. Outside the full-common-agreement MCA
exceptional set, Q has witnesses E*,O* of degree <k_(i+1) on that SAME full set.
Then

```
P_i(X) = E*(X^2) + X*O*(X^2)
```

has degree <k_i and agrees with BOTH coordinates of every witnessed fiber. It
therefore preserves all original-position mass that made Q live, contradicting
the prior dead prefix. This works for adaptively chosen later commitments because
the exceptional set depends only on the word fixed before beta_i and covers every
late Q. Existential proximity without the common agreement set would not suffice.

The coding input is the full-agreement-set conclusion of DKT Theorem 5.12
(pp.52-53), not an SDK security assertion. For child dimension >=2, its line
exceptional count is below C_i=343*n_(i+1)^2/[3*(k_(i+1)-1)]. The note's weighted
prefix construction and native association are a proposed derivation, separate
from that published theorem. Primary source:
https://quangvdao.github.io/papers/authored/reed-solomon-codes-beyond-johnson.pdf

For the last k_i=2 -> child dimension1, E_i and O_i must be CONSTANT witnesses.
For any two positions with distinct coefficient pairs, equality after folding
requires a root of a nonzero affine polynomial in beta. Excluding at most
binom(8,2)=28 such roots makes every constant agreement set of size >=2 lift to
constant E*,O* with exactly that full set. Here A_r=4, so the endpoint is covered
without dividing by zero or extrapolating the positive-degree formula.

Every C_i and the constant bound28 are dominated by
C_max=343*n^2/[3*(k-1)]. This bounds each beta round separately. A union over all
folds gives an INTERACTIVE EXECUTION bound; it must not be confused with the
worst-per-round delta required by the FS state-restoration reduction.

## Finite integer certificates in the owning tests

For every actual binary schedule, use its child dimension and n_child=8*k_child.
For k_child>=2 put D=k_child-1 and choose the order-zero support:

```
A = ceil_sqrt(49*n_child^2/288)
M = ceil_sqrt(49*D*n_child/4)
B = ceil_sqrt(49*n_child/(4*D)) - 1
Z = ceil(49*n_child/(12*D)) - 1                 // line degree ell=1
Psi_D(B) = 1+(2D-1)(2B-1)+2*max(B-2D-1,0)
```

Count the monomials and multiplicity equations exactly, require variables >
equations and M<=3*A, and compare Equation (88)'s rational exception bound with
both C_i and C_max using cross multiplication. In particular, the positive-part
Psi tail cannot be dropped at the two smallest positive dimensions:

| child k | n | A | M | B | Z | tail max(B-2D-1,0) | variables | equations | E numerator/denominator |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 2 | 16 | 7 | 14 | 13 | 65 | 10 | 6475 | 6272 | 55887/6 |
| 4 | 32 | 14 | 35 | 11 | 43 | 4 | 8976 | 8320 | 155798/11 |
| 8 | 64 | 27 | 75 | 10 | 37 | 0 | 15290 | 14336 | 548862/20 |
| 16 | 128 | 53 | 154 | 10 | 34 | 0 | 27720 | 26368 | 2189022/38 |
| 32 | 256 | 106 | 312 | 10 | 33 | 0 | 53493 | 51200 | 8830275/75 |
| 64 | 512 | 212 | 629 | 9 | 33 | 0 | 107120 | 102400 | 32189340/149 |
| 128 | 1024 | 423 | 1263 | 9 | 32 | 0 | 207555 | 198656 | 126040649/296 |
| 256 | 2048 | 845 | 2530 | 9 | 32 | 0 | 415050 | 397312 | 506384521/590 |
| 512 | 4096 | 1690 | 5064 | 9 | 32 | 0 | 830040 | 794624 | 2030013225/1179 |
| 1024 | 8192 | 3380 | 10133 | 9 | 32 | 0 | 1660305 | 1589248 | 8129000041/2357 |
| 2048 | 16384 | 6759 | 20270 | 9 | 32 | 0 | 3320550 | 3178496 | 32533761737/4712 |

The actual five shapes visit54 folds,49 positive-degree child cases, five constant
endpoints, and the11 distinct positive child dimensions2..2048. The largest-height
powers-curve test remains intact; its helper now retains the general Psi tail.
All seven owning classical metadata tests passed on 2026-10-23 (capture r605),
including these 54 folds and the unchanged five opening-inventory certificates.
The tests took 2.80s after compilation; strict all-target release Clippy passed
(r606). These tests invoke no native proof, private witness or SQL execution.
Reproduce with `cargo test --release --locked -p registry200-proof --features owner-read --lib registry_progress::word::read::classical::tests:: -- --test-threads=1`.

## Exact low-bit query loss

After the whole pre-query transcript and all oracle words are fixed, a dead
terminal prefix has |K_r|<a*s, where s=n is8192 or32768. The ideal challenge bridge
gives192 independent uniform Goldilocks words with replacement. For
p=2^64-2^32+1, s divides p-1. Write p=s*m+1. Low-bit residue0 has m+1 preimages;
each other residue has m. Thus max_index_probability=ceil(p/s)/p=(m+1)/p and

```
Pr[all192 indices in K_r]
  <= (|K_r|*ceil(p/s)/p)^192
  <= (a*s*ceil(p/s)/p)^192
   = a^192 * (1+(s-1)/p)^192.
```

The multiplicative correction relative to the pure term is exactly bounded in
bits by192*log2(1+(s-1)/p); replacing the small denominator p by p-1 is conservative.
This is the max-bucket bound, not an additive union192*s/p. Deduplicating native
Merkle paths must not replace192 by the number of distinct indices. Adaptive
choice of openings after the indices does not enlarge K_r after online extraction.
The challenger/FS bridge and the Merkle event remain explicit prerequisites.

Do not change the engine's query term from this note alone: the complete native
RBR correspondence still needs review and integration.

## Connection back through DEEP denominators

On the separately charged good OOD event, every native denominator z_j-x is
nonzero for every x in the common input domain. Powers batching combines the
received words g_j(x)=(claim_j-u_column(x))/(z_j-x), using degree F-1 in the batch
challenge. A full common-witness powers-curve certificate gives one Q_j of degree
<k per term on the SAME large agreement set S. The deterministic lift is

```
P_j(X) = (z_j-X)*Q_j(X)+claim_j.
```

It has degree <=k, agrees with its original column on S, and evaluates to the
claim at z_j. Two lifts of one column agree on |S|>=A_0>k base-domain points, so
their degree-<=k difference is zero. A PP lift equals the independently rebuilt
degree-<k public PP polynomial by the same root count. Base-valued columns also
have base-field lift coefficients: interpolate uniquely from k+1 base-valued
samples at base-field points. Therefore this yields a common joint row candidate,
not separate column candidates on unrelated sets, within the early degree-<k+2
list used by the current diagnostic.

The following LogUp implication assumes the recovered candidate equations.
The later same-candidate ALI/DEEP section gives a conditional state-function
derivation for those equations. Its independent review and the total five-proof
security assessment remain open; this lift grants no SQL admission.


## Conditional packed LogUp-to-multiset implication

This lemma starts **after** candidate MAIN/AUX polynomials and receiver-fixed PP
satisfy the actual AIR equations on the original `N`-row domain. It does not
establish that ALI/DEEP or the native transcript yields those candidates.

| AIR | Original slots/row `S` | `N` | Packed fractions | EF5 AUX columns | Base AUX columns |
| --- | ---: | ---: | ---: | ---: | ---: |
| DATA | 243 | 2048 | 81 | 82 | 410 |
| Word | 98 | 512 | 34 | 35 | 175 |
| Query | 248 | 2048 | 83 | 84 | 420 |

AUX column zero is the accumulator; column `j+1` is packed fraction `j`.
The batch verifier recomposes each five base openings into one EF5 opening
(`p3-batch-stark/src/verifier/mod.rs:737-772`); hiding columns are separate.
The original schema and packed setup checks preserve every tuple and count,
contiguous columns, global bus names, widths and absent exclusive flags.

For original slot `s` at row `r`, write its signed count `m_s` and denominator
`d_s=A+(bus_s+1)*B^W-Horner_B(payload_s)`. SDK transcript lines474-533 fix one
width per bus and the maximum width `W`; shorter buses are mathematically
left-padded with zeros, leaving their native Horner value unchanged. Word's
WIRE/POLICY/MASK widths are 2/5/2. The bus coefficient is distinct modulo Gold;
different formal messages have different polynomials in `Gold[A,B]`. This is
formal distinctness, not pointwise injectivity after sampling `B`.

For each additive packed group `G`, the actual constraint is
`U_G*f_G=V_G`, where `U_G=product_G d_s` and
`V_G=sum_G m_s*product_(t!=s) d_t`. Thus, outside denominator zeros,
`f_G=sum_G m_s/d_s`. The constraint is ungated, including the last row;
see [pinned LogUp lines184-231,355-407](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/lookup/src/logup.rs#L184).
First-row `a_0=0`, transition `a_(r+1)-a_r=sum_G f_G(r)`, and
last-row `terminal-a_(N-1)=sum_G f_G(N-1)` telescope to the complete rational
sum (`logup.rs:410-463`). Both closed hash frame decoders require sole terminal
zero. No row, duplicate occurrence or zero-count slot can be dropped.

These selectors use the original domain, reconstructed by batch verifier
lines713-719 and `verifier/data.rs:79-119`. Its next-point rotation is by the
original `N`-row domain generator. Random odd rows in the hidden `2N`-row encoding
are mask rows, not another `N` lookup rows or an extra terminal equation.

Integer interpretation uses actual constraints, not `Count::bounded` alone.
DATA/Query counts are receiver-owned PP and each has absolute value at most 4.
Word first uses WIRE's receiver-owned signed counts and unique producer/consumer
plan. A nonzero integer WIRE imbalance stays nonzero modulo Gold under the
weighted-height bound, and other formal buses cannot cancel its rational part.
If WIRE balances, every consumer equals its unique producer; this links each
POLICY frequency `f` and `Q-f` to their 32-bit range equations. Since
`f+(Q-f)=Q` has integer sum below `2^33<p`, it gives `0<=f<=Q`.
MASK frequencies are directly constrained to `0..4` by same-row bits.
See `word_inventory/{air.rs:61-171,expr.rs:459-473,plan.rs:519-571}`.
The Word weight sum is `76*max_fanout+Q+45`; the owning inventory multiplies
it by `N=512` and checks it below `p`. This first-bad-bus argument does not
assume private POLICY counts are bounded before WIRE consistency.

Put `T=S*N`, counting **all** original slots. Combine identical formal
denominators into coefficients `c_t`. If the required multiset is wrong,
the preceding no-wrap argument gives some `c_t!=0`; distinct bus denominators
give a nonzero numerator
`P=sum_t c_t*product_(u!=t) d_u`. Reducing modulo one `d_t` proves this:
the surviving product of nonzero polynomial differences cannot vanish.
Its total degree is at most `(W+1)*(T-1)`. For independent uniform EF5
`A,B`, Schwartz-Zippel plus `Pr[any d_s=0]<=T/p^5` gives at most
`T*(W+2)/p^5` for a false fixed MAIN candidate. The numerator test already
charges payload collisions after sampling `B`; no extra `T^2` term is needed.
Zero-count slots remain in the pole union because a zero packed denominator
can otherwise leave a fraction unconstrained.

The respective numerators `T*(W+2)` are 1,990,656 / 351,232 / 2,031,616.
A frozen joint MAIN list of size at most `L` pays their union multiplied by
`L`; the diagnostic's `S*k*(W+2)*L`, with `k=2N`, is conservative.
This sampling statement is conditional on the separate actual FS interpretation.

This lemma establishes only the conditional algebraic consequence of the
candidate equations. The next section associates them with the actual ALI/DEEP
claim order and the reported RBR terms. Independent review of that derivation
and Merkle/FS/binding/hiding composition remain open; admission is unchanged.

## Same-candidate ALI/DEEP transition

This is a finite algebraic correspondence for the actual pinned 0.8.0 verifier,
conditional on online fixed-row extraction and the full-common-witness MCA
statement already used above. The ideal verifier challenges in this argument
are uniform and fresh. No assumption named "complete native RBR" is used.

Let `H=<g_N>`, `|H|=N`, `k=2N`, `|D|=n=8k`, and
`A=ceil(7*n/(6*sqrt(8)))`. Freeze row-distance lists of vectors of polynomials
of degree `<k+2`, with at least `A` simultaneous row agreements. PP is the
independently rebuilt singleton, not an adversarial list. Merkle salt fields
are excluded; the five hiding codeword columns of each private matrix remain.

These lists have width-independent bounded size. If `M` distinct vectors each
choose `A` agreement positions, their pairwise overlap is at most `k+1`:
some component of their difference is a nonzero polynomial of that degree.
Cauchy on the per-position incidence counts gives
`M <= n*(A-k-1)/(A^2-n*(k+1)) < 7 < L=3*n/(k-6)` for both fixed heights.
The exact owning integer certificate checks `A=3380,13517`, denominator
positivity and those rational inequalities. It does not construct lists.

The actual challenge/message order is:

1. Bind MAIN and receiver-fixed PP; draw the lookup pair if present.
2. Bind AUX and the sole terminal, then draw the constraint challenge `alpha`.
3. Bind quotient chunks before the OOD point `zeta`.
4. Bind every claimed opening before the PCS powers challenge `theta`.
5. Commit/fold the native FRI words, bind the terminal constant, then draw indices.

For the uni arguments omit the lookup/AUX steps. A separate R randomization
matrix may occur in the PCS opening list. Neither early list below needs R,
so its generation time is not an extra premise.

Freeze the joint MAIN+AUX list `Mlist` before `alpha`, including the hiding
columns of both matrices. Each projection lies in the earlier frozen MAIN
list. After quotient commitment freeze the joint chunk list `Qlist` before
`zeta`; it includes each chunk's hiding columns. Do not multiply one list size
per column or per chunk. Full-common-MCA later supplies the same agreement set
for the projections into these two lists, even when an additional R word is late.

For `m in Mlist`, substitute its local columns `P(X)`, next columns
`P(g_N*X)`, fixed PP, public values and fixed periodic polynomials into the
actual emitted constraints `C_i(X)`, including the lookup fraction equations.
The pinned verifier's two-adic selectors are the polynomials
`Z_H/(X-1)`, `Z_H/(X-g_N^-1)`, and `X-g_N^-1`.
The first two have degree `N-1`; they are nonzero at their selected row.
Thus vanishing of the selector-weighted constraint on `H` is exactly the
corresponding original-row equation. Rotation uses `g_N`, not `g_(2N)`.

The verifier's `assert_zero` and `assert_zero_ext` both use Horner order:
`C_alpha(X)=sum_(i=0..C-1) alpha^(C-1-i)*C_i(X)`.
Freeze the concrete constraint emission order, not the symbolic collector's
base/extension grouping. If `m` violates any original-row equation, choose
a row with some nonzero `C_i(h)`. Then `C_alpha(h)` is a nonzero polynomial
in `alpha` of degree at most `C-1`. A union over `Mlist` shows that
a dead prefix can obtain a candidate with `Z_H | C_alpha` with probability
at most `L*(C-1)/q <= L*C/q`, exactly the included ALI charge.

Let `H_j` be the actual original quotient-chunk domains, each of size `N`.
The native recomposition is
`lambda_j(X)=product_(t!=j) Z_Ht(X)/Z_Ht(first(H_j))` and
`Qrec(X)=sum_j lambda_j(X)*q_j(X)`.
Its denominators are fixed nonzero constants from disjoint cosets, and
`deg(lambda_j)=(c-1)*N`. This is Lagrange recomposition, not a power split.
Base-flattened chunk candidates are recomposed into EF5 with the same fixed
basis as the verifier. Allowing the enclosing-list degree `k+1`,
`deg(Z_H*Qrec)<=c*N+k+1`.

For any pair `(m,qchunks)` after a dead alpha prefix, the polynomial
`E_mq(X)=C_alpha(X)-Z_H(X)*Qrec(X)` is nonzero: otherwise
`Z_H | C_alpha`, contradicting that prefix's state. With the actual symbolic
constraint degree `d`, fixed selectors/periodics and original-domain model,
a conservative degree ceiling is
`Dstar=max{d*(k+1)+(N-1),c*N+k+1}`.
The cached symbolic degree treats a transition selector as degree zero,
although its polynomial degree is one. The actual emitted constraints have
at most one transition factor. The explicit `N-1` slack covers that factor;
first/last selectors are already counted, so double-counting them is safe.
The current diagnostic uses the larger
`D=max{d*(k+1)+(k-1),(c+1)*k+1}`.
The five exact pairs `(Dstar,D)` are
`(9217,17409),(9217,17409),(20481,36865),(5121,9217),(20481,36865)`.
Consequently the `zeta` dead-to-live transition costs at most
`L^2*Dstar/(q-|D union H|) <= L^2*D/(q-(n+k))`.
In this ideal challenge model, whole-field sampling also incurs the separately
included `(n+k)/q` event.
Both `zeta` and `g_N*zeta` avoid D on that good event because D is
stable under the rotation; there is no second factor of two for the opening.

Finally suppose full-common-MCA at `theta` yields quotient witnesses of degree
`<k` on the same `S`, `|S|>=A`, for every function
`(claim-u_column(x))/(point-x)`. Lift each by
`P_point(X)=(point-X)*Q_point(X)+claim`; its degree is at most `k`.
For two openings of one column these lifts agree on S and therefore coincide,
since `A>k+1`. Their evaluations supply the actual local and rotated claims
of this SAME polynomial. Interpolation at `k+1` base points makes base-valued
column lift coefficients base-valued. PP's lift equals its fixed degree-<k
polynomial by the same root count. AUX groups of five base polynomials yield
exactly the verifier's EF5 columns. These projected candidates lie in
`Mlist` and `Qlist`, fixed before alpha and zeta respectively. The MAIN
projection also lies in its pre-lookup list. Later witnesses may select members
but cannot enlarge those frozen lists.

After zeta, retain only pairs matching every submitted opening and the native
OOD equation. A prover message only removes possible pairs. Outside the MCA
exception, a low-degree reduced opening word yields one such pair, so a dead
prefix cannot become live at theta without the already charged powers-curve
exception. The later weighted-prefix FRI invariant supplies the remaining
fold/query transitions. This constructs the ALI/DEEP portion of that invariant,
rather than inferring all row equations from one OOD equality.

Pinned source associations: batch transcript lines881-963; batch verifier
lines122-246,713-823; uni verifier lines73-113,117-205,347-395,651-709;
uni folder lines374-402; `p3-commit/src/domain.rs:318-341`;
`p3-lookup/src/protocol.rs:50-79`; inner PCS lines684-778. The actual symbolic
degree association is `p3-air/src/symbolic/builder.rs:118-158` together with
the owning full-lookup assessors. For Source/Role3, fixed periodic polynomial
degrees are handled by that trace-size-aware symbolic pass; they are not free
constants in the OOD equation.

This derivation is analogous to the frozen-list state functions in
[ethSTARK v1.2, Theorem 5 and its proof](https://eprint.iacr.org/2021/582);
its single-alpha powers adjustment matches Remark 6. The published
[DEEP-ALI Theorem 2](https://cic.iacr.org/p/3/2/38/pdf) supplies the conservative
squared-list structure, not automatic native-code correspondence.

The owning certificate checks the actual metadata inequalities and
quotient geometry only; it observes no runtime candidate or native AIR
constraint evaluation. Independent review of this state function and the
earlier weighted-prefix/full-common-MCA derivation remains required before
describing the whole native algebraic argument as established. The separate
actual FS/Merkle instantiation, hiding composition and live authorization/
freshness/locking assessment still grant no SQL admission from this note.

Validation on 2026-10-23: all eight owning classical metadata tests passed
(capture r619; 4.09 s test execution after compilation), including the new
five-instance list/degree certificate. Strict all-target release Clippy passed
(r620). The tests run no native proving, SQL or protocol-admission decision.
