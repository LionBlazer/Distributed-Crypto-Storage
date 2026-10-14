# BFV parameter-security gate: exact inputs, estimator pending

Status: input mapping and a pinned official estimator invocation are prepared.
**No numerical security estimate ran and the independent >=128-bit gate remains
open.** Windows Python3.11.9 and bundled Python3.12.14 have no sage module; no Sage
command was found. The earlier inventory recorded Ubuntu WSL2 and Docker as
stopped; they were not started by this work, and no tools/packages were installed. This missing runtime concerns
this estimate, not progress on the wider storage/query goal.

The measured [BFV SIMD experiment](experiment-bfv-simd.md) supplies the exact
profile. Its successful decryptions and upstream about128 name do not establish
parameter security. This note does not substitute the SEAL ternary-secret table.

## Exact profile and distributions

Pinned fhe=0.1.1 uses VCS commit fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a.
N=16384 is the degree of Z_Q[x]/(x^16384+1), with cyclotomic index32768;
t=33292289. At level0, all nine ciphertext primes are public:

~~~text
0xfffffffd8001, 0xfffffffa0001, 0xfffffff00001,
0x1fffffff68001, 0x1fffffff50001, 0x1ffffffee8001,
0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001
~~~

Their exact product Q is
709803428473824464899716522243808726188912609449487857793115029420083157504007498781933901411951056604199361914151348163758737883137,
with bit_length438 and log2(Q)=437.99999997312773. Use the complete product,
not one48/49-bit RNS prime, the plaintext t, or a rounded2^438 modulus. The
[parameter source](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/parameters.rs)
and an actual N16384 setup record match these inputs exactly.

The CLI names this unchanged default `n16384-plain25`. Explicit
`--profile n8192-byte17` describes N8192, t114689 and these five unmodified
official ciphertext primes:

~~~text
0x7fffffd8001, 0x7fffffc8001, 0xfffffffc001,
0xffffff6c001, 0xfffffebc001
~~~

Their exact product is
421249101157150430150591791601812858371395928330411389778873040897
(bit_length218, log2(Q)=217.99999977561694). The new t exceeds the maximum
individual byte-limb SUM65280; low+256*high is reconstructed after decryption.
The default t still accommodates full SUM16776960 directly. Manifests and future
attack records identify the selected profile. There is no silent substitution of
N8192 for the original default, and both profiles use the exact distribution below.

The variance10 sampler consumes40 random bits per coefficient: popcount of20
minus popcount of20. Consequently both secret and error are exactly
**ND.CenteredBinomial(20)** in lattice-estimator notation: mean0, variance10,
standard deviation sqrt(10), support[-20,20]. CenteredBinomial(10) would have
variance5 and is wrong. The input script checks the exact rational mass, mean and
variance of binomial(40,20+k)/2^40; this is an input check, not cryptanalysis.
See the pinned
[fhe sampler](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe-util/src/lib.rs#L22),
[secret/error path](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/secret_key.rs),
and estimator
[CenteredBinomial constructor](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/nd.py#L276).
Poly::small uses the same sampler for ciphertext and switching-key error.

BFV's fresh phase is -a*s+e+embedded_message: e has that distribution directly.
Do not multiply it by t as in a BGV convention, or divide it by the message scale.
A same-variance Gaussian is not the exact bounded CBD law. If only documenting
Gaussian conversions, estimator DiscreteGaussian takes standard deviation, while
DiscreteGaussianAlpha(alpha,Q) uses alpha*Q/sqrt(2*pi); same standard deviation
sqrt(10) would require alpha=sqrt(20*pi)/Q. The prepared invocation uses CBD20
and avoids this approximation entirely.

## Ring model, sample count and evaluation keys

The generic LWE input dimension is the selected N:16384 for n16384-plain25 or
8192 for n8192-byte17. It is not N/2 SIMD-row slots,16/256 selected rows or the
2N cyclotomic index. A known-plaintext symmetric ciphertext gives one
RLWE polynomial relation and N scalar coefficient equations. Its rows are
negacyclic shifts of one public a polynomial, not N independent random LWE row
vectors. Fresh public a values are seed-expanded with ChaCha8; the estimator's
uniform-matrix model does not audit that PRNG or the implementation.

Use m=oo as the primary **independent-LWE heuristic** because this owner has no
ciphertext-query lifetime cap. Finite m=N,3N or4N are one-polynomial/one-EQ-GE-query/
one-range-query sensitivity models only. Within the independent-LWE abstraction,
unlimited samples avoid relying on an optimistic finite query bound. They do not
remove ring correlations, prove a reduction for this CBD distribution, or cover
all ring/algebraic attacks. Report the interpretation, not just a bit count.
The official estimator explicitly defines
[m as scalar samples](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_parameters.py#L13).

At level0 each rotation or relinearization key has one RNS pair per ciphertext
prime. The16-row shape uses7 rotations plus relinearization; the256-row shape11+1:

| Profile | Primes/key | Polynomial pairs,16 /256 rows | Coefficient relations,16 /256 rows |
| --- | ---: | ---: | ---: |
| n16384-plain25 | 9 | 72 /108 | 1179648 /1769472 |
| n8192-byte17 | 5 | 40 /60 | 327680 /491520 |

These are **exposure inventories**, not an IID sample count: messages contain
Gi*s(x^j) or Gi*s^2 under the same secret. The
[key-switch generator](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/key_switching_key.rs)
adds fresh small error to -a*s plus those key-dependent terms. The ordinary LWE
estimator does not establish their circular/KDM security. No extra public P
modulus appears in these level0 key contexts; temporary multiplication extension
bases are computational scratch, not another published ciphertext modulus. This
needs a separate scheme/security argument before a full BFV claim.

## Pinned models and prepared execution

Official lattice-estimator revision **53da5982597709ba0fdf94ea37a84d822310fd84** was
resolved with git ls-remote and cloned into the experiment's ignored .local tree;
HEAD and clean status were checked. The
[official project](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)
requires Sage; installing its Python package alone supplies no Sage runtime.
The upstream Dockerfile uses mutable latest/main plus apt operations, so it was
not used as a reproducible or authorized runtime shortcut.

The new [script](../experiments/bfv-security/estimate_bfv.py) defaults to a stdlib
input manifest, with no estimator import or computation. Explicit --estimate
requires a clean exact-pinned checkout and Sage. It calls the full
[LWE.estimate API](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe.py#L88)
with jobs1, no denied attacks and catch_exceptions=False. Its configured attacks
are Arora-GB, coded BKW, primal uSVP, BDD, BDD hybrid, BDD MITM hybrid, dual and
MATZOV dual hybrid. The full API may omit dominated hybrid results; failures must
not be silently treated as high-security results.

Run two explicit classical reduction-cost models with GSA shape: RC.MATZOV
(the pinned default, classical list-decoding model) and RC.ADPS16 (classical mode).
The [pinned configuration](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/conf.py)
and [cost models](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/reduction.py)
define them. Do not use estimate.rough as a complete sweep: it limits attacks and
uses a different reduction-cost configuration. Neither classical run is a quantum
security estimate or a rigorous lower bound. Record every finite cost, optimized
sample use, lattice/block dimensions, memory, model and minimum; do not cherry-pick
a model above128 while ignoring a cheaper one.

Prepared invocation from a project root in an existing Sage environment:

~~~sh
git clone https://github.com/malb/lattice-estimator.git .local/fhe-research/estimator-53da598
git -C .local/fhe-research/estimator-53da598 checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
python3 experiments/bfv-security/estimate_bfv.py
python3 experiments/bfv-security/estimate_bfv.py --profile n8192-byte17
python3 experiments/bfv-security/test_manifest.py
# Only after a CPU lease and a version-recorded Sage runtime is available:
sage -python experiments/bfv-security/estimate_bfv.py --profile n8192-byte17 --estimate --model both --samples unlimited --estimator-root .local/fhe-research/estimator-53da598 > .local/fhe-research/bfv-lwe-byte17-estimates.jsonl
# Use --profile n16384-plain25 explicitly for the original profile.
~~~

The source records Sage/Python versions, exact inputs, estimator commit, cost-model
state, configured attacks and results; threads are limited in that process only.
The Sage execution path is prepared and statically API-checked, **not runtime
validated**. Its runtime version remains unpinned because no Sage runtime was run.

## Checks performed and remaining action

Windows stdlib execution passed: syntax, exact CBD probability moments, constants
against pinned fhe source and measured profile, clean estimator revision, and
constructor/full-estimate argument checks via AST. An explicit --estimate attempt
stopped with exit1 and “Missing Sage runtime” before importing the estimator or
running attacks. This is a negative runtime check, not a security result.

Local evidence in compact-fhe-query/.local/fhe-research:
bfv-security-inputs.json and bfv-security-runtime-check.stdout.jsonl/.stderr.txt.
Pinned local file SHA-256: sampler lib.rs
688EEA292BE729EE75B682678B6A9A4DDB9C18FF8E4B757EEABE1AFF434CF173;
fhe parameters.rs
7F6B1D364CBC8547B3F381551EC14F1EC0272C07B3C8A4EE03C4DF1FC9AECE30;
estimator nd.py
099264D65B6610BDAA6B632C8B0CD33648FEB00177D1E99BE2B30AE3D5DB1EAC.
The original single-profile script SHA-256 was
EE4572BBC7A4544AD83665DD5165578A147ABAD52FB4EC336039C5AD9EF448C6;
the explicit-profile script is
D0C96E9F0F45345DCDC3EBFAD9243FA0F4FC82EEBB27A4C633988084B4D9A9EC.

This extension starts from published f80065e. All existing default JSON values
except the source hash remain equal to that published script; additional fields
only label profile/packing/component bound. Five stdlib CLI tests cover unchanged
defaults, byte17 modulus/exposures, exact CBD/unlimited-model caveats, finite samples
using the selected dimension, and rejection of an unknown profile. Both prime
sets/products and batching primes match the locked library constants/generator;
pinned estimator API signatures were checked statically. BOTH explicit --estimate
requests stop at the missing-Sage guard before estimator import. No attacks ran.
New local evidence under .local/fhe-research/bfv-security-profiles/ contains one
manifest and runtime-failure stdout/stderr pair per profile, plus checks.json.

Separate root-reported runtime-probe evidence: two version-only requests to
SageCell /service returned HTTP520. They supplied neither a Sage version nor an
estimate and are not alternative security evidence. This extension made no remote
requests or messages.

The next runtime stage needs a version-recorded Sage environment and saved full
output under the experimental CPU/resource limits. An existing Ubuntu distribution
is one candidate for read-only runtime inspection; it was not started in this
stage. If no Sage runtime exists, a pinned isolated runtime is needed before
executing the estimator. No VM startup or global installation was performed here.

Even a completed generic-LWE estimate leaves implementation audit, ring/KDM and
PRNG assumptions, leakage/side channels, exactness/noise-failure probability,
authentication and malicious-peer query proofs as distinct gates. A numeric LWE
attack estimate must not be reported as closing those boundaries.
