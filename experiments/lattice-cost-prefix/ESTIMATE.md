# N4096/Q2/CBD20 classical attack-cost estimates

On2026-10-21 the complete eight-attack MATZOV and ADPS16 classical calculations
finished together in r11 under genuine Linux Sage10.10/Python3.12.3. The smallest predicted cost
across these two models is approximately2^227.76 word operations (ADPS16 uSVP);
MATZOV's minimum is approximately2^250.688 (BDD). These are heuristic costs of the
implemented attacks, not proven security lower bounds, quantum security, a full
BFV confidentiality assessment or SQL admission.

## Fixed inputs and method

The exact inputs are n4096, scalar modulus1152789568982753281, ordered Q bases
1073692673/1073668097, and `ND.CenteredBinomial(20)` for BOTH secret and error.
Each distribution has support[-20,20] and exact variance10. The sample count is
infinity in the independent-LWE heuristic. The underlying ring is
`Z_Q[X]/(X^4096+1)` and the plaintext modulus65537. The two P extension primes
are not included in the encryption modulus. Ring rotations are not independent
random samples. No relinearization or rotation keys are part of this profile.

The [original full attack factory](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe.py)
is called with GSA, one job, empty deny/add lists and `catch_exceptions=False`.
The [published driver](estimate_n4096.py) checks the complete63-file/11-directory
official source identity before and after execution. The101555-byte archive's
SHA256 is `4236adc38031c139c8a2721804d8962d6cacd015fae37f6f5215d2ac7f011060`.
Revision provenance is an exact official archive, with `git_clean=null`.

The source files are unchanged, but this is explicitly NOT a vanilla execution:
`exact_integer_sparse_positive_prefix_v3` replaces only `gb.gb_cost` in memory,
using the same exact coefficients, strict first negative and original Cost rule.
Its [sparse recurrence](README.md) and [sign criterion](POSITIVE-PREFIX.md) avoid
the failed dense series allocation. Before installation, each actual Sage child
passed74 complete QQ PowerSeries/Cost/type/order/metadata cases,2047 coefficients,
two original-function fallbacks and the42-coefficient public baseline. The
optimization module SHA256 is
`188a1e011c9841bda5aa8b894d2cdfdb6a616fc9e2d7874332d703786372141a`.

The published r11 driver additionally uses the [exact dual-scalar rounding](DUAL-ROUNDING.md)
adapter to remove a later Sage symbolic conversion failure. For the supported
RR sigma in[3,4], the original30-bit scalar is provably exactly1. Only that
expression is replaced; all other Cost arithmetic and search parameters remain
original. Other inputs use the lazy original expression. Before each installation,
17 actual Sage original-scalar/type and directed-interval cases,2 original-branch
fallbacks and8 full Cost/type/order/metadata examples must pass. This second
override has its own required provenance record before the model starts.

## Complete returned maps

Values below are log2(rop), rounded only for this table. Every configured result
was retained, including dominated hybrid attacks and the original BKW infinity.
The latter is the upstream function's actual returned Cost, not an omitted
attack or a timeout converted into infinity.

| Attack | MATZOV classical | ADPS16 classical |
| --- | ---: | ---: |
| arora-gb | 655.571302 | 655.571302 |
| bkw | +Infinity | +Infinity |
| usvp | 251.710140 | 227.760000 |
| bdd | 250.687875 | 228.268322 |
| bdd_hybrid | 250.695986 | 228.268322 |
| bdd_mitm_hybrid | 594.536407 | 570.583020 |
| dual | 255.175308 | 229.804000 |
| dual_hybrid | 253.632933 | 229.220008 |

The MATZOV BDD minimum uses beta776, eta807 and dimension8262. The ADPS16 uSVP
minimum uses beta780 and dimension8245. Full-precision minimum log2 values are
250.6878745397801448842344750325994011556170563593277075658005537458962187603 and
227.7599999999999908979776195979946295903747447949948070927365072197091275263.
Extra printed digits preserve the recorded estimate; they do not improve the
underlying model's numerical precision or uncertainty.

## Observed research runtime and failure handling

The r9 MATZOV full model took243.660s internally, CPU241.649s; the bounded child
terminated at248.056s with exit0. Its per-attack wall times were33.563s Arora–GB,
41.862s BKW,0.163s uSVP,3.834s BDD,57.748s hybrid,102.360s MITM hybrid,0.136s dual
and3.989s dual hybrid. Thus the old120s whole-model fuse interrupted a legitimate
unfinished calculation. No symbolic square-root or hybrid-cost optimization was
needed for this completed numerical gate.

The r9 ADPS16 child later exited by SIGSEGV11 at63.426s inside Sage while BKW
was active. Its Arora result was retained diagnostically, but NO ADPS16 minimum
or completed sweep was accepted. Periodic30s faulthandler snapshots were active;
the exact cause of the native fault is not established.

The r10 driver removed asynchronous stack sampling and ran ADPS16 first with the
same mathematics, source pins,8 attacks and resource guards. ADPS16 completed in
113.222s internally, CPU112.381s; bounded child116.406s, exit0. Per-attack times
were15.226s,15.036s,0.065s,1.671s,25.617s,54.625s,0.039s and0.940s in table order.
Binder hosts were not CPU-pinned; these observations do not establish a speedup
from disabling diagnostics or a runtime distribution.

R10's later MATZOV repetition returned the first seven attacks but failed in
dual_hybrid at the original `tmp_a` numerical conversion, with Sage's
`SignError: cannot add infinity to minus infinity`, exit1 at117.920s. No partial
minimum was accepted for that repetition. Both r9 and r10 paired controllers
therefore terminated incomplete, although r9 retained one complete MATZOV map
and r10 one complete ADPS16 map. The exact rounded scalar adapter addresses this
separate finite-expression conversion; it does not explain the r9 SIGSEGV.

R11 then completed both full maps in one authorized free Binder session. ADPS16
took111.513s internally/CPU110.796s, bounded child114.584s; MATZOV114.109s
internally/CPU113.383s, bounded child116.832s. Both children exited0, stderr was
empty, all source identities matched, and the controller completed in245.955s
including setup/artifact handling/cleanup. Kernel absence and server shutdown
were confirmed for r9, r10 and r11. Whole-job OS descendant cleanup after an
abrupt kernel death is not attested by these receipts.

| Attack | R11 ADPS16 seconds | R11 MATZOV seconds |
| --- | ---: | ---: |
| arora-gb | 14.578 | 14.598 |
| bkw | 14.935 | 14.997 |
| usvp | 0.047 | 0.048 |
| bdd | 1.715 | 1.705 |
| bdd_hybrid | 25.930 | 29.415 |
| bdd_mitm_hybrid | 53.808 | 52.602 |
| dual | 0.038 | 0.050 |
| dual_hybrid | 0.459 | 0.690 |

Independent local review compared ALL8 complete returned records, including
every field/finite flag/full-precision log2 cost, against successful original
r9 MATZOV and r10 ADPS16 maps. Both match exactly. This is in addition to the
17-scalar/8-full-Cost gate executed in each new genuine Sage child; no partial
minimum from either failed repetition participates in acceptance. The two
successful r11 stdout SHA256 values are
`333640fee9e9f50b1512ec036826d5379e71f1008d29fdf697be911e4edb6cf7` (ADPS16) and
`a20762456a28e6c0df241909882146595aa7e655e080e4c2e02f3b446580849d` (MATZOV).

Each child used an independent GNU timeout9.4 SIGKILL wall bound600s, CPU600s,
per-process address-space2147483648 bytes, core0 and output-file16777216 bytes.
The runtime separately reported the operator's aggregate physical2GiB cgroup.
The complete checked maps above each have exit0, no outer group kill, unchanged
source identities and stdout/stderr hashes matching their terminal receipts.
Per-attack starts/returns preserve original arguments and result objects, and
their field snapshots match the final returned map. Child CPU/RSS fields are
not an attestation of aggregate process-tree resource usage or DCS peer usage.
The600s bound is for offline parameter research, not a changed SQL timeout.

The r9 MATZOV stdout SHA256 is
`12b90fff73bc2dbb3d44b1988a7e835378b708c9bf0ee9a96795d95d694f4f38`;
r10 ADPS16 stdout SHA256 is
`10b0f1788093b286ee68d23336e85129f48121005f16f0d85567ae68363eaad6`.
The published driver is byte-identical to r11, SHA256
`3229841a308795d856e1c0529e8d5adf75056ab6f6d0c3b70423e412155476e6`.
R10 used driver SHA256
`99efb2ddaf8ecbe5bc33e3f4eff3c22fd040934ec29f2823540696b364e641ae`.
R9 used driver SHA256
`3c5aa400fcbd441043ed8f280a1d337b3da93913989f80abb90802aa767e1913`.
Reviewed runtime receipts and all frozen controller/supervisor/helper pins stay
in ignored `.local/lattice-runtime-archive-{controller-source,run}-r9`, `-r10`
and `-r11`;
generated raw outputs, external-session credentials and runtime artifacts are
not committed. The public script and reproduction requirements are in the
[module README](README.md).

## Remaining obligations

Independent-LWE attack estimates do not settle ring-specific attacks, sampler
entropy/PRNG quality, side channels, chosen-ciphertext/protocol composition,
concrete Fiat–Shamir hashing or quantum attacks. The conditional
[product model](../../crates/bfv-unrelinearized-product/MODEL.md) and native
Formation/Source joins retain their exact original scope. All security, SQL and
full-query500ms flags remain false. Fresh weighted-head verification, durable
Predicate completion, real network SQL/locks and the complete client latency
still have to be joined and measured.
