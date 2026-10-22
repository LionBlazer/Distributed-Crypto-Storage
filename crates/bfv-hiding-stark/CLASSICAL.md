# Conditional classical algebraic diagnostics

`classical::analyze(parameters, committed_log, original_logup)` calculates a finite
algebraic error bound from trusted caller-associated metadata. It allocates at
most six term records and the bounded FRI schedule; it creates no trace, witness,
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
| `batch-combination` | SDK `SecurityAssumption::prox_gaps_error_jb_at_m` at the actual opening count |
| `ldt-commit-phase` | SDK worst-per-round `fri::commit_phase_error_ldr_m` at the committed height |
| `ldt-query-phase` | biased-index correction to `alpha^192`, described below |
| `logup-fingerprint` | SDK `N*(W+2)/q`, with `N=original_interactions*k`; omitted only for `None` |

For DEEP, `D=max(d*(k+1)+(k-1), (c+1)*k+1)`, with actual degree `d`
and committed chunk count `c`. Each chunk has degree below `k`; the second factor
also bounds the paper's segment expression with segment degree at most `k` and
two-point expansion `k+2`. This deliberately uses two-point expansion even if the
AIR reads only the current row. Since `|D_eval union H|<=n+k` and the field has
at least `2^319` elements, the denominator is conservative. Its logarithm is
evaluated with `ln_1p` so the small domain-exclusion correction is not lost by
direct subtraction from `2^319`.

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
unsupported/overflowing metadata cases. This document makes no claim that those
tests have been executed.
