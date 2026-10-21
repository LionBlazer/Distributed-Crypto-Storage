# Exact sparse coefficient validation

On2026-10-21 all6 standard-library unittest cases passed under local CPython3.11
in0.186s. The coefficient comparison case contains346 complete public series:
180 single-factor combinations,160 deterministic three-factor examples and6
explicit repeated/zero/large-exponent/empty/Gaussian-like shapes. The independent
oracle expands finite binomial factors and convolves them with the original
negative-binomial denominator; it does not use either differential recurrence.

Other cases preserve the strict first-negative rule across an intervening zero
and an excluded precision endpoint; check the original n4096 bounded CBD20
baseline's first negative at41; and calculate all8192 coefficients of the
Gaussian-like zero-sample series with independent binomial checks at selected
positions through8191. Invalid domains, including bool/float/negative values,
zero precision and a forbidden iterator, reject without consuming that iterator.

A separate local diagnostic generated18 full8192-coefficient prefixes for
n4096 and factors[(d,m),(41,4096)], with d in[9,17,33,41,65,8191] and m in
[0,1,2^31]. All147456 coefficients were computed exactly; total observed time
was472.273ms and the slowest prefix53.396ms. This is sparse coefficient generation
on the local CPython runtime, NOT Sage, an attack-cost sweep, FHE execution or SQL
latency. These selected parameter extremes do not establish full estimator runtime
or a universal resource bound. Raw local receipts remain ignored in `.local/`.

The source SHA256 used by the diagnostic and prepared public r7 packet is
`73d90c3abe9f1267adda76ad37b541c2ab20ee77b6ac538713ce1cb48a20f0ab`.
The estimator archive remains pinned at revision
`53da5982597709ba0fdf94ea37a84d822310fd84`; its original gb.py SHA256 is
`d785ee73ad40a470422d1ddc21d76e9f32b8ab1d85d88ae2539590b32bbd7edc`.
No original estimator source byte is changed. The optional in-memory override is
explicitly identified as `exact_integer_sparse_differential_prefix_v2`.

Before installation, the genuine Sage gate compares68 full QQ PowerSeries
cases/1183 coefficients, full Cost/type/item-order/metadata, two original-function
fallbacks and the42-coefficient public bounded prefix. All passed in the actual
authorized r7 Sage10.10/Python3.12.3 run. Its inventory and seven payload/controller/archive pins
were independently checked locally; only the new module/payload hashes,
implementation identity and expected gate counts differ from the reviewed r5
runner. All eight attacks, both classical models, original parameters and
120s/CPU120/2GiB-AS/2GiB-physical/file16MiB guards remained unchanged.

The model then entered the Gaussian-like Arora branch;30/60/90s stack snapshots
still show coefficient generation. GNU SIGKILL ended the child at120.049s,
returncode-9, without any attack-result or completed-model record. ADPS16 was not
launched. The complete official source identity was checked before and after;
kernel absence and server shutdown were confirmed. Child CPU/RSS fields do not
represent aggregate Sage-process-tree usage. No numerical minimum is established.
Sparse individual prefixes do not remove the upstream loop over many degrees,
including runs of prefixes with no negative coefficient. The next optimization
must prove such cases equivalent, retaining the original first-negative result.

The previous v1 recurrence did pass its separate57-case/711-coefficient Sage gate
in the actual r6 run, then hit GNU timeout in the Gaussian-like Arora branch.
That result does not establish a minimum attack cost. The complete eight-attack
MATZOV/ADPS16 results are still required before interpreting numeric estimates.
BFV confidentiality, sampler
entropy, product Fiat–Shamir, whole-system security and the <=500ms complete SQL
goal remain unestablished. Production acceptance paths are unchanged.

## Exact sign criterion, v3

The [algebraic criterion](POSITIVE-PREFIX.md) preserves the original no-negative
Cost using sufficient exact integer inequalities. It neither approximates the
series nor converts a resource failure into infinity. Inputs outside the proved
families retain the complete sparse recurrence. The negative n4096/degree41
example still reaches its independently checked first negative at6615; a
one-variable example still reaches81. Accepted positive families are compared
with independent complete finite-binomial products.

All9 local unittest cases passed in0.435s. A separate CPython diagnostic covered
all4092 odd degrees from9 through8191 with each multiplicity0,1,2^31 at n4096 and
precision8192. Of12276 prefix decisions,12251 were certified nonnegative and25
used the complete recurrence; total observed time was561.390ms. These selected
multiplicity bounds test the sign algorithm, not actual Sage tail/sample choices,
a cost model or SQL performance. Raw receipts stay in `.local/`.

The v3 source SHA256 is
`188a1e011c9841bda5aa8b894d2cdfdb6a616fc9e2d7874332d703786372141a`.
The authorized r8 run used actual Sage10.10/Python3.12.3 and passed all74
QQ PowerSeries/Cost/type/order/metadata cases,2047 coefficients, two original
fallbacks and the42-coefficient public baseline before installing the explicit
`exact_integer_sparse_positive_prefix_v3` override. All original estimator files
and public script pins were checked before and after. Archive and official gb.py
identities are unchanged from above; all admission/security flags remain false.

This time30s stack sampling reached BKW's N/ntop/ntest/t1 functions;60s and90s
samples reached primal-hybrid GSA/beta/cost_zeta/scipy optimization. Thus the run
advanced past Arora–GB, without dropping it or changing its returned cost rule.
GNU SIGKILL still stopped the whole model at120.063s, returncode-9. There was no
completed result-map/attack_result record, model completion or ADPS16 execution.
Kernel absence and server shutdown were confirmed. Partial progress is not a
numeric minimum, and waited-child CPU/RSS is not aggregate process-tree usage.
Further profiling/bounded execution of the remaining full attacks is needed;
neither parameter security nor the <=500ms complete SQL goal is established.

## Complete classical numerical gate and exact dual rounding

The [fixed public driver](estimate_n4096.py) now records the original sequential
attack starts/returns before requiring the complete eight-result map. Seven
hermetic observer tests cover exact argument/object preservation, ordered maps,
missing/extra/substituted results, original exceptions, absent results, unexpected
inputs/exception swallowing and exact function restoration. All16 local tests
(9 coefficient/sign cases and7 observer cases) passed in0.427s under CPython3.11.
The dependency-free release requirements_sync test also passed. No Rust behavior,
Cargo dependency, product parameter, SQL timeout or production admission changed.

R9's larger explicit offline600s wall/CPU budget completed all8 MATZOV attacks,
but its ADPS16 child died by SIGSEGV during BKW. R10 removed asynchronous stack
sampling and completed ADPS16; its later MATZOV child failed at the original
dual-hybrid scalar conversion with a Sage infinity SignError. Both paired jobs
were rejected, retaining completed individual maps and original failed evidence.
The native SIGSEGV cause is still unknown. No failure became an infinite cost.

The [exact dual-scalar rounding proof](DUAL-ROUNDING.md) certifies the original
30-bit scalar as1 on a strictly checked RR domain, with original lazy evaluation
outside it. The pinned original classmethod AST changes exactly one expression.
In each actual r11 Sage child,17 original scalar/type and directed-interval
comparisons,2 fallback cases and8 complete Cost/type/order/metadata comparisons
passed before installation. The existing exact-GB74-case/2047-coefficient gate
also passed unchanged in both children. These are genuine Sage gates, separate
from the hermetic observer test markers.

R11 completed both8-attack maps with exit0 and empty stderr, using the original
full factory, all attacks/options and the explicit two in-memory overrides.
ADPS16's minimum was2^227.76 operations and MATZOV's2^250.68787454. Local review
checked both complete maps field-for-field against the earlier successful
original maps, including dominated/infinite results and full-precision costs.
All records matched exactly; source identities, byte hashes and resource receipts
matched, kernel absence and server shutdown were confirmed. Both models ran in
one245.955s research job. No latency-distribution or whole-process-tree memory
claim follows from these individual observations.

The complete [estimate/provenance record](ESTIMATE.md) identifies the published
r11 driver SHA256, official sources, all attack costs/times, original failures,
unchanged limits, reproduction and unresolved cryptographic obligations. This
completes the classical numerical gate only. It neither establishes a BFV
confidentiality theorem, quantum security, assessed Fiat–Shamir composition,
network SQL/locks nor the <=500ms complete-query target. The goal remains open.
