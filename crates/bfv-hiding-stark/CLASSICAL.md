# Conditional classical algebraic diagnostics

`classical::analyze(parameters, committed_log, original_logup)` calculates a finite
algebraic error bound from trusted caller-associated metadata. It allocates at
most seven term records and the bounded FRI schedule; it creates no trace, witness,
proof, RNG, preprocessing, configuration or operation authorization. The normal
native proving and verification paths are unchanged.

The caller must derive the parameters from the same immutable complete AIR and
actual proof configuration. For a batch AIR this includes every base, extension,
preprocessed and packed-lookup constraint and every opening. `original_logup` is
the original interactions per row and widest original payload, before packing;
`None` asserts that no lookup argument exists. The calculator cannot detect
omitted constraints, openings or lookups, or authenticate an AIR association.
`AlgebraicBound` has private fields and read-only metadata, FRI-shape, term and
union getters. It is a diagnostic value, never an admission capability.

## Fixed inputs and ownership

The suite remains Goldilocks/EF5, field-size lower bound `q=2^319`, blowup eight,
192 queries, binary folds, final polynomial length one and no grinding. The
existing collision workbit policy must still be 128, but it is not an algebraic
probability term. Only committed log-heights 10 and 12 are supported, corresponding
to the existing original 512-row and 2048-row hiding traces. Analysis uses the
single fixed multiplicity `m=3`; it performs no parameter or regime search.

Constraint and opening counts must be positive and exactly representable within
`2^53`; at least two opening functions are required. The actual degree must be
1 through 8, rotations one or two, and committed quotient chunks a power of two
between the native hiding minimum and sixteen. The minimum is
`2 * next_power_of_two(max(degree+1,2)-1)`; a larger valid count accommodates an
owning AIR's conservative degree hint. Source and Role3 uni-STARKs actually use
degree hint five and sixteen committed chunks. DATA, Word and Query batch AIRs
separately enforce their own eight-chunk gate in their actual owning assessors;
the low-level calculator does not authenticate a native family from its numeric
inputs. Original lookup height-count products and
payload widths must also fit the stated exact-integer range. Unsupported suite
fields, overflow, degenerate probabilities and failed strict proximity
preconditions reject through the existing engine errors.

The module directly uses pinned `p3-uni-stark` metadata, `p3-fri` transcript and
folding shapes, `p3-field` field order, and `p3-security` 0.8.0 term mathematics.
It has no project-module dependency or product policy. Higher owning modules
derive actual Source, Role3, DATA, Word and Query metadata; protocol composition
and PIT/adaptive hashing budgets belong there.

## Counted terms

Put `k=2^committed_log`, `n=8k`, `rho=1/8`, and
`alpha=(1+1/(2m))*sqrt(rho)`. Strict paper and SDK preconditions are checked.
The strict `eta>0` condition is tested with checked integers: for `m=3`,
`alpha>sqrt((k+max_combo)/n)` is exactly `13*k>36*max_combo`.
For conservative ALI and DEEP diagnostics use the paper list bound
`L=m/(rho-2m/n)`, rather than the smaller SDK list-size estimate.

| Term | Conditional probability charged before bit rounding |
| --- | --- |
| `air-composition` | `L * actual_constraint_count / q` |
| `deep-ali` | `L^2 * D / (q-(n+k))` |
| `ood-domain-hit` | `(n+k)/q` |
| `batch-combination` | SDK `SecurityAssumption::prox_gaps_error_jb_at_m` at the actual opening count |
| `ldt-commit-phase` | SDK worst-per-round `fri::commit_phase_error_ldr_m` at the committed height |
| `ldt-query-phase` | biased-index correction to `alpha^192`, described below |
| `logup-fingerprint` | `L *` SDK `N*(W+2)/q`, with `N=original_interactions*k`; omitted only for `None` |

For DEEP, `D=max(d*(k+1)+(k-1), (c+1)*k+1)`, with actual degree `d`
and committed chunk count `c`. Each chunk has degree below `k`; the second factor
also bounds the paper's segment expression with segment degree at most `k` and
two-point expansion `k+2`. This deliberately uses two-point expansion even if the
AIR reads only the current row. Since `|D_eval union H|<=n+k` and the field has
at least `2^319` elements, the denominator is conservative. Its logarithm is
evaluated with `ln_1p` so the small domain-exclusion correction is not lost by
direct subtraction from `2^319`.

That denominator is conditional on sampling outside `D_eval union H`. The native
sampler draws from the whole extension field. Rejecting a pole at a queried row
does not globally exclude the LDE domain, so `ood-domain-hit` separately charges
the full excluded-set upper bound `(n+k)/q`. Smaller input domains are nested in
the largest LDE coset, and the actual next-row rotation preserves these domains;
two opening points do not double this bound. This accounting changes no sampler
or native verifier.

The paper's squared-list and excluded-domain denominator differ from SDK
`deep_ali_error`, which uses a linear list factor and the whole field denominator.
This diagnostic retains the conservative paper form. The primary source is
[Atapoor, Delpech de Saint Guilhem and Kindi, Theorem 2](https://cic.iacr.org/p/3/2/38/pdf).
Its official title is *STARK-Based Signatures from the RPO Permutation*;
the title attached to 2024/1553 in SDK comments is inaccurate.

## Query sampling and numerical policy

The query width is reconstructed through the actual
`TwoAdicFriFolding::extra_query_index_bits` and `FriShape::new`, at the largest
committed LDE height. Binary folding gives the same schedule when smaller
committed matrices join intermediate rounds. Goldilocks
`DuplexChallenger::sample_bits` takes the low bits of a canonical field word;
it does not sample perfectly uniform indices. For `b=FriShape::index_bits`,
`s=2^b`, and Goldilocks order `p`, the maximum bucket mass is
`ceil(p/s)/p`. Each query therefore costs at most
`alpha * s*ceil(p/s)/p`, and the full query term charges its 192nd power.
The ceiling and excess numerator are calculated with checked integer arithmetic.
Using the exactly representable `p-1` in the small relative correction only
increases its bound. The unrounded bias loss is exposed separately.

Every finite term is rounded down to whole minus-log2 bits and then loses one
additional bit. The union uses `p3_security::ErrorBits::sum` on those reported
probabilities, followed by the same conservative rounding. This intentionally
coarse floating-point diagnostic avoids claiming fractional precision from SDK
formula evaluation or tiny denominator/sampling corrections; it is not a
machine-checked real-arithmetic certificate. The union sums reported algebraic
round-by-round contributions and conservatively bounds their worst round; it
does not sum over FRI folds or claim the failure probability of a complete
interactive execution. It does not use the SDK report's minimum workbit cap.
No independence of the error events is assumed. A higher-level conditional BCS
analysis may use this conservative algebraic RBR input only after associating
the actual transcript with the claimed model.

## Frozen MAIN list and lookup association

The list multiplier is needed before AUX exists. After online extraction of the
MAIN commitment, freeze its entire row-distance list at agreement `alpha`, with
candidate columns of degree below `k+2`. Include masked MAIN and the five random
codewords, excluding the four per-row Merkle salts. Packaging a row through a
field-extension basis preserves equality and polynomial degree, so the scalar
Johnson bound also bounds this joint list without a factor exponential in width.
Receiver-reconstructed PP is a fixed polynomial, not another adversarial list.

For each MAIN candidate satisfying MAIN-only constraints and integer multiplicity
bounds, the fixed-message LogUp lemma costs `N*(W+2)/q`. Distinct original bus
denominators are formal polynomials, not a pointwise injective encoding after
sampling. Clearing denominators gives a nonzero numerator for an unbalanced
multiset; `W+2` charges its roots and all zero denominators, including inactive
slots. Union over the frozen list gives `L*N*(W+2)/q`. Later AUX cannot select a
MAIN polynomial outside this list merely because it knows the lookup pair.

The required late-to-early connection is full common-witness MCA, on the same
agreement set for every selected candidate. Native PCS batches the separate
functions `(claim-u_column(x))/(point-x)`. A common degree-bounded quotient
candidate lifts to `P(X)=(point-X)*Q(X)+claim`; its degree is at most `k`. Lifts
from two openings of one column agree on more than `k` domain points, so are
identical. The `k+2` early list is conservative. A joint MAIN+AUX candidate
therefore projects into the pre-lookup MAIN list. Freeze MAIN+AUX before the
constraint challenge, and the separate quotient list before zeta: these give
the existing `L*C/q` and `L^2*D/(q-(n+k))` charges.

The relevant primary statements are DKT Theorem 5.12, Section 7.2 Equation (88),
and Lemma 7.4 in the [author's full paper](https://quangvdao.github.io/papers/authored/reed-solomon-codes-beyond-johnson.pdf).
They distinguish full common-witness agreement from merely existential proximity
and transfer list bounds to interleaved rows without a width multiplier.

This change does **not** certify all five native RBR protocols. A finite owning
check must still derive actual height partitions `(k_h,n_h,F_h)`, certify the
integer powers-curve interpolation support and Equation (88) for
`ell_h=F_h-1`, and show their exception sum is covered by the reported
`(F_total-1)*C_max/q`. Different heights have different agreement sets. It must
also match the native insertion of smaller input words into FRI, and pin each
batch AIR's MAIN-only no-wrap bound plus all fraction, accumulator, last-row and
zero-terminal constraints. These are concrete correspondence obligations; this
numeric API neither authenticates nor executes them. No new public certificate
helper or claim of completed native RBR association is introduced here.

## Full-prefix SHA-512 FS bridge

For the separate SHA suite, an exact classical-ROM bridge is available once the
closed runtime grammar is associated. Each valid raw hash input must uniquely
identify an instance, complete prover-message prefix, logical group, coordinate,
accepted-sample history and retry. A separator snapshot alone does not establish
this runtime association. One EF5 challenge is a five-coordinate Gold group;
the lookup pair is one ten-coordinate group, and all 192 indices are one group.
Source/Role3 have 14 groups, DATA/Query 17 and Word 15, totalling 77.

For each canonical coordinate, obtain its uniform group value from the
state-restoration oracle, independently choose a geometric first-accept retry,
return rejected uniform 64-bit words before it, that value at it, and ordinary
uniform words afterwards. The unused 448 output bits are independent uniform.
Reconstruct ancestor groups before classifying arbitrary claimed histories;
noncanonical inputs use a consistent independent lazy table. This exactly
decomposes the raw random-oracle retry sequence, including reverse retry queries
and guessed future coefficients. A raw query uses at most `s_i` restoration
moves for an `s_i`-group protocol. Full-prefix injectivity prevents a previously
noncanonical input from changing identity later. Fail-closed overflow cannot
increase acceptance.

Thus, **given an actual complete RBR bound** `delta_i`, one final five-proof
tuple satisfies the FS-plus-interactive bound
`(Q512+1)*sum_i(s_i*delta_i) <= 77*(Q512+1)*max_i(delta_i)`.
Here `Q512` counts all prior raw SHA512 queries, including offline and auxiliary
calls; it is not a SQL-attempt count. This exact simulator adds no truncation or
codec error term. It assumes SHA512 is a classical random oracle, not an
unconditional theorem about SHA512. It adds no Merkle, PIT, external-binding or
hiding verdict. Multiple final outputs require explicit additional accounting.
The source framework is [Chiesa--Yogev, Version 1.2](https://snargsbook.org/),
basic full-prefix FS and its state-restoration simulation; the `(t+s_i)*delta_i`
RBR-to-restoration bound is restated in
[Atapoor et al., Theorem 1](https://cic.iacr.org/p/3/2/38/pdf).

## Remaining composition premises

This module does not evaluate Fiat-Shamir attempts, hash/Merkle collisions,
external binding digests, shared Poseidon2 instantiation error or confidentiality.
The fixed-budget BCS reduction and its association to the real field duplex and
Merkle construction remain higher-level obligations; see
[Block and Tiwari, Appendix A.3](https://www.pratyush.site/publication/concsecfri/concsecFri.pdf).
An algebraic number alone cannot authorize a network query.

The SDK batching/FRI terms use Johnson-regime proximity results from
[BCHKS](https://eprint.iacr.org/2025/2055) and
[Dao, Kominers and Thaler](https://eprint.iacr.org/2026/2056).
LogUp additionally assumes committed messages precede the sampled fingerprint,
injective bus encoding, the separately enforced multiplicity bound and the real
packed-lookup constraints; its charged `W+2` includes vanishing denominators.
See [Habock's lookup argument](https://eprint.iacr.org/2022/1530).

Hiding is separate: the existing 404-row opening budget, five random codewords,
fresh independent OS-seeded masking/salt streams and one-use commitment ownership
must hold in the actual proving path. Neither a soundness sum nor these numeric
checks establish their complete zero-knowledge composition; see the
[hiding analysis](https://eprint.iacr.org/2024/1037).

The owning unit tests contain public nonsecret rational-reference examples,
sampling-width and union postconditions, monotonic constraint charging, and
unsupported/overflowing metadata cases. On 2026-10-23 all nine engine classical
tests and five actual closed-read metadata tests passed, including the two new
charges and unchanged transcript geometry. Eight engine transcript tests also
passed; they check adjacent challenge grouping, framing and unsupported shapes.
Strict all-target Clippy passed for engine, Formation and Registry proof crates;
the repository requirements-sync test passed. These are numeric/shape checks,
not evidence of completed RBR association or live admission.
