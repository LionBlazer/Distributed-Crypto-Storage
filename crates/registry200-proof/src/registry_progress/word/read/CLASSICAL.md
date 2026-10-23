# Conditional five-AIR classical error accounting

`classical::analyze(&read_expected, log2_query_budget)` derives diagnostics from
the actual closed SourceVersion, Role3 version encoding, dense DATA Formation,
Predicate Word and fused Query Formation AIRs. It accepts no submitted numeric
report, proof, verifier callback or approval flag. Existing symbolic assessors
retain their already derived parameters and original lookup inventory; the
additional arithmetic runs only when this diagnostic is explicitly requested.
No private witness, preprocessing commitment, native configuration or RNG is
created. Actual verification and every mathematical/wire profile are unchanged.

This is an accounting tool with explicit unfinished premises. It is not an
assessment of the concrete cryptographic protocol, an admission token, a
confidentiality argument, a fresh-head check, or an end-to-end SQL measurement.
The real Joint Predicate verifier still rejects after mathematical checking.

## Actual metadata and algebraic terms

Source and Role3 use the same private `FixedAir` dispatch as `fixed::Backend`,
without constructing that backend's random configuration. Predicate uses the
same closed `prescreen_role` plan, goldens, symbolic lookup packing, security
and resource prescreens as the native role setup. DATA and Query construct their
own `MetadataAir` from the independently retained complete expected values and
use the common actual symbolic assessor. None calls `preprocessed_trace`.

Committed log-heights are respectively 10, 10, 12, 10 and 12. Hiding doubles
the original degree. Original lookup inventories are absent for the first two,
and `(interactions_per_row, widest_payload)=(243,2),(98,5),(248,2)` for the last
three. These are original denominators, never compressed packed counts. The
current shared-flag Query PP gives 2327 opening functions.
Source and Role3 retain their real degree-five hint and sixteen committed chunks;
DATA, Word and Query retain their independently enforced eight-chunk batch gate.

The [engine diagnostic](../../../../../bfv-hiding-stark/CLASSICAL.md) fixes the
analysis multiplicity to three and the native suite to Goldilocks/EF5, blowup8,
192 queries, binary folds, final degree one and no grinding. It reports separate
ALI, conservative paper DEEP, OOD-domain hits, batching, FRI commit, FRI query
and original LogUp terms. The lookup contribution includes a union over the
frozen joint MAIN list; the explicit OOD charge covers the whole excluded domain,
not only positions eventually sampled by FRI. The reported sum bounds the
reported algebraic RBR contributions; it is
not the total failure probability across an interactive execution. In particular,
the SDK commit term is a maximum over folding rounds, not a sum over them.
There are five native arguments and one separately analysed product PIT.

## One source-derived PCS height partition per AIR

The five opening inventories are respectively 14502, 3492, 2622, 3024 and 2327.
For each closed AIR, let the original trace height be `N`, the committed height
`k=2N`, and the LDE height `n=8k=16N`. Every input commitment has this same
height within that AIR; this does not merge the domains of different AIRs.

This follows from the pinned SDK constructors and receiver-side opening claims:

- MAIN and lookup AUX begin with `N` rows. Hiding commit doubles them before the
  inner blowup8. PP similarly interleaves zero rows, giving the same height.
- The randomization matrix R already has `2N` rows and calls inner commit
  directly; it is not doubled a second time.
- With base quotient exponent `r`, the quotient domain has `2N*2^r` rows and
  is split into `2^(r+1)` committed chunks. Each starts with `N` rows.
  Hiding `get_quotient_ldes` expands it by `2^(3+1)=16`, also giving `16N`.
- Inner commit and quotient LDEs normalize the coset shift with
  `GENERATOR/domain.shift()` and use the same bit-reversed row order.

Relevant pinned 0.8.0 source locations are `p3-uni-stark/src/prover.rs:117-119,
209-228,281-282`, `p3-batch-stark/src/prover.rs:155-175,219,491-496`, and
`p3-fri/src/hiding_pcs.rs:229-259,427-451,476-569,704-725`.
This is not only an honest-producer property: uni verifier lines535-564 and
batch verifier lines199-229 reconstruct each randomized quotient opening domain
as `2N`; MAIN/R/AUX/PP use that same domain. The PCS verifier in
`p3-fri/src/two_adic_pcs.rs:565-576` derives
and deduplicates `log2(domain.size())+log_blowup`, producing one input-height
partition. No smaller input words are inserted during these five FRI runs.

The owning DKT test pins those five inventories against actual AIR metadata
and the manifested PCS opening counts. Its exact `u128` support count checks
`Nvar>Neq` and Equation(88) against `ell*343*n^2/(3*(k-1))`, with
`ell=F-1`, for that single partition. See the
[primary DKT paper, Equation(88)](https://quangvdao.github.io/papers/authored/reed-solomon-codes-beyond-johnson.pdf).
The height equations are a static source association: the test does not invoke
native constructors or observe runtime matrix heights. Its definition is not
a proof of the underlying MCA theorem or of complete native RBR soundness.

The next finite obligation is the fixed batch-AIR RBR bridge: starting from
full common-witness MCA, derive the native MAIN/AUX candidate polynomials and
singleton receiver-fixed PP, then show that the actual packed fraction,
accumulator, last-row and zero-terminal constraints on the original `N` rows
imply the original lookup multiset equation with the actual no-wrap derivation.
Word's policy frequency range checks are linked through WIRE, so the proof must
first use bounded receiver-owned WIRE counts. A first WIRE imbalance cannot
cancel across distinct formal bus denominators; when WIRE balances, it links
`f` and `Q-f` to their 32-bit range checks and gives the POLICY bound. MASK bounds
come from same-row bit constraints. Do not assume every private multiplicity is
bounded by MAIN-only local equations. Pin the exact native ALI/DEEP identities,
selectors, rotation and claim order. The generic frozen-list argument and this
integer certificate do not themselves execute that correspondence. This step
is distinct from the separate Merkle/FS/binding/hiding composition and does not
change an admission guard.

## Explicit conditional budget expression

For a chosen integer `b` in 0 through 120 put `B=2^b`. This is a hypothetical
upper bound on each complete BCS reduction's classical oracle-query budget.
Separately require `Q_H+V<=B` for the product's adaptive complete-transcript
SHA512 model. Include offline grinding, failed attempts, retries, verification
attempts and shared-primitive queries required by the reduction. The calculator
does not enforce a lifetime limit and operational timeouts do not imply one.

If `delta_i` really bounds the corresponding closed IOP's RBR error, and the
actual transcript has the required classical BCS interpretation with effective
oracle range `R>=2^255`, the included terms obey the conditional expression

```text
epsilon_included <= sum_i=1..5 [B*delta_i + 3*(B^2+1)/2^255]
                    + B*2^-306.
epsilon_system   <= epsilon_included + epsilon_binding + epsilon_instantiation
                    + other relevant protocol failure events.
```

This uses [Block and Tiwari, Appendix A.3, Theorem 2](https://www.pratyush.site/publication/concsecfri/concsecFri.pdf),
conditional on that theorem applying to the concrete transcript. It incurs five
full collision expressions, without assuming independence or dividing a shared
query budget by five. A joint reduction might improve the bound; it has not been
supplied. A further factor for the number of FRI folds is not automatically
required for an RBR theorem; an interactive-execution union is a different claim.

The 255-bit range is an **unproved model premise for this calculation**. Four
Goldilocks words have more than `2^255` possible values, but this cardinality does
not turn the actual sponge/compression/duplex into an ideal bitstring oracle or
prove the BCS correspondence. The SDK's 128-bit collision workbit cap is not
substituted as a probability term. The report's `conditional_error_bits` is minus
log2 of a fixed-budget probability ceiling, not computational workbits or a new
128-bit acceptance policy. A ceiling below128 at budget64 is not by itself an
attack or a contradiction of a128-workbit target.

The calculator sums probabilities using SDK `ErrorBits::sum`. The engine has
already rounded each algebraic term down to an integer bit with an extra bit of
slack; the aggregate displayed sums do the same. This avoids claiming fractional
precision from floating logarithms. It is not certified interval arithmetic.

## Product lemma and separate obligations

The [complete product model](../../../../../bfv-unrelinearized-product/MODEL.md)
fixes every certificate coefficient before all18 SHA512-derived points. Its
largest error-polynomial degree is `d=2*N-2=8190`; the smallest field is
`p=1073668097`. For `t=2^17`, exact integer checks give `d*(t+1)<p` and
`d*t*(t+1)<2^128<2^512`. Thus each reduced512-bit sample has root probability
less than `d/p+d/2^512<1/t`, giving the coarser exact `18*17=306` bit ceiling
for one false complete transcript. Adaptive first-touch accounting pays `Q_H+V`.
It does not multiply the exponent by the number of equations or fields.
The existing PIT profile, sampling, certificate wire and checker are unchanged.

Before the expression can support Predicate admission, the actual shared
Poseidon2 duplex, fixed-length PaddingFreeSponge and truncated Merkle compression
require a quantitative joint model or a justified ideal-oracle instantiation
assumption with the correct query accounting. Framing, fixed leaf lengths,
domain separation and observation order must match the reduction. Collision
resistance alone does not establish this model.

In particular, the native leaf sponge and two-digest compression share a
permutation and agree literally on the same eight-field input. Padding-free
sponge outputs also have known ambiguities across arbitrary input lengths.
The actual MMCS instead checks verifier-derived fixed matrix widths before
salting and hashing; the present audit found no bypass of that geometry. A
valid reduction must use typed, fixed-geometry vector binding and a joint
permutation/duplex model, not independently idealize every hash interface.
The SDK already length-frames its protocol seeds, absorbs protocol names,
versions, pattern fingerprints and shapes, and length-tags partial duplex
absorption. Claiming that those separators are absent would be incorrect.
Pattern fingerprints additionally use Keccak256; fixed closed patterns and
their distinct fingerprint values still need an explicit manifest.

LogUp also needs the actual before-challenge commitment order, injective bus
encoding, original multiplicity bounds, complete packed constraints and
zero-denominator accounting. Inventory/symbolic gates check finite metadata,
but their error number alone is not a complete RBR argument. The full hiding
composition requires independent fresh mask/salt streams, one-use private
commitments and opening budgets; algebraic soundness does not imply privacy.
External SHA256/Poseidon bindings, authenticated source/key ownership, BFV
confidentiality/noise, fresh weighted agreement and locking remain separate.
No requirement or admission guard changes.

The owning tests use explicitly unproved public metadata endpoints. They check
the actual five inventories, original LogUp counts, the integer PIT lemma and
probability-space references at several adaptive budgets. They are never inputs
to live SQL processing or substitutes for native proofs.

## Executed validation

On 2026-10-22 the release/native diagnostic captures r500/r501 passed seven
engine cases and three owning composition cases. This measured diagnostic work,
not SQL execution. Actual metadata from the owning capture was:

| AIR | Committed log | Constraints | Symbolic degree | Chunks | Openings | Reported algebraic RBR sum bits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SourceVersion | 10 | 16133 | 3 | 16 | 14502 | 242 |
| Role3 version encoding | 10 | 6916 | 4 | 16 | 3492 | 242 |
| Dense DATA | 12 | 1332 | 4 | 8 | 2622 | 242 |
| Predicate Word | 10 | 1660 | 4 | 8 | 3024 | 242 |
| Fused Query | 12 | 1184 | 4 | 8 | 2327 | 242 |

The uni-STARK degree-five hints determine their native chunk count even when
the selector-aware symbolic degree is smaller. The diagnostic does not alter
that distinction. At the stated ideal-model hypotheses, the rounded expression
produced the following **fixed-budget error ceiling bits, not workbits**:

| log2 budget | Five algebraic BCS terms | Five BCS collision terms | Adaptive PIT | Included total |
| ---: | ---: | ---: | ---: | ---: |
| 40 | 198 | 170 | 266 | 170 |
| 60 | 178 | 130 | 246 | 130 |
| 64 | 174 | 122 | 242 | 122 |
| 120 | 118 | 10 | 186 | 10 |

The current bound is limited by the conditional joint-hash model expression,
not by the raw algebraic/PIT numbers. This is no claim that the unfinished
concrete instantiation satisfies that expression. Binding and instantiation
failure terms remain outside this table.

The unchanged actual complete read test also passed at r502: genuine Source,
Role3, DATA, Word, Query and product production/receiving, protected client
completion and the existing corruption/association/retained-query assertions.
That whole test process took34951.5588ms, with562720768B OS peak working set;
it includes setup and hostile checks and is not a full network SQL latency.
There was no network quorum, fresh-head certificate or accepted lock in it.

All three captures pinned input sources and exact release opt-level3 test images,
used Rayon2 and independent held-process monitoring, retained the120s and1792MiB
fuses and20ms sampling, and completed without fuse faults or cleanup actions.
The engine image was2205184B, SHA256
`2B2CB1F75281822BD7D4281E34305FE5CBC130F9693F37CAE4472E399BC001AE`;
the owning image was12416000B, SHA256
`50EF0C0735A03C81D2F0E9869A17213423B13587F432E5DC3C423F921ED4CAA5`.
Local receipt SHA256 values are:

| Ignored local result | SHA256 |
| --- | --- |
| `.local/word-cmd-native-r500-bfv-hiding-stark-observe-tests/result.json` | `E7929987874544A37AD659E5F636579F79807A51C778DA9A3D2F813202DAF21B` |
| `.local/word-cmd-native-r501-registry200-proof-observe-tests/result.json` | `D40DD06EAF6AFE23529295BA7DADC1450C6E87AC064B267F8466C6BB7E1D2344` |
| `.local/word-cmd-native-r502-registry200-proof-observe-tests/result.json` | `5D0CBCF8E61E7C811C5ADE4A298DF70CED2A316A5926D5DCD411D3258344B024` |

Generated logs, binary images, proofs and local receipts are not committed.
After these captures only the PIT geometry test's literal constant assertions
were replaced with reads of the actual constants to satisfy strict Clippy;
production arithmetic and all verification paths were unchanged.
The corrected three owning cases then passed again at r512 in661.69ms with
58798080B OS peak working set. That rebuilt test image was12418560B, SHA256
`79AF71F330A9866859F6247C3A611A41789492D31B5EECDBA7FB0799AF0B5627`;
its local result SHA256 was
`0DF5AD3C957285BCE7816E24C668393FE02D6212B5B1C6D128C939BDB5AA8CBC`.
Strict release Clippy with all targets passed for the engine, Formation and
registry proof crates; all12 Word compile-fail interface examples and the
dependency-free requirements mirror test also passed. Final formatting and
documentation-link checks are performed before publication. No500ms full-query
claim follows from these checks.


On 2026-10-23, all six owning classical diagnostic tests passed, including the
exact single-partition DKT support certificate for the actual five opening
inventories. This metadata check invoked no native proof or SQL execution.
Strict all-target release Clippy and the requirements mirror test also passed.
