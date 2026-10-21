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
