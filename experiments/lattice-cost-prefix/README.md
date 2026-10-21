# Exact Hilbert-series prefixes for lattice cost research

This research candidate removes a numerical-estimator bottleneck before any BFV
confidentiality assessment can be completed. It computes exactly the original
coefficients of H(z)=prod(1-z^d)^m/(1-z)^n, below the original precision, and stops
only at the original first strictly negative coefficient. It is not a lattice
security estimate, DCS proof, SQL operation or production admission mechanism.

`exact_gb_cost.coefficients(n,factors,precision)` and `first_negative` use Python
standard-library integers only. `test_exact_gb_cost.py` independently computes
finite binomial products/convolutions; it never supplies production ciphertexts
or proof answers. Run the hermetic checks with:

```sh
python -m unittest discover -s experiments/lattice-cost-prefix -p "test_*.py" -v
```

The optional `install()` adapter requires an already available Sage runtime and
the exact official lattice-estimator revision
`53da5982597709ba0fdf94ea37a84d822310fd84`. It verifies the original gb.py bytes and
function identity, then compares all gate coefficients and Cost metadata against
the original Sage QQ PowerSeries expression BEFORE changing `gb.gb_cost` in memory.
Unsupported inputs fall back to that exact original function. Source files are
never modified. Calling this explicit adapter requires the surrounding research
runner's time, address-space, physical memory and cleanup guards; this module
neither installs a runtime nor launches a network job. Sage equivalence and full
eight-attack/two-model execution are separate, non-hermetic gates.

`estimate_n4096.py` is the fixed public Linux/Sage10.10 CLI for that separate
numerical gate. It checks all63 official archive files/11 directories before
and after evaluation, installs the explicit exact-GB adapter only after its
Sage equivalence gate, then calls the original full `LWE.estimate` with all8
attacks, GSA, one job, no deny/add list and no swallowed exceptions. The temporary
`install_attack_progress` observer forwards every original call argument and
returns the original result object; it records individual starts/returns before
the final complete map. Missing, extra, reordered or substituted results reject.
The original batch function is restored even on an attack failure. This CLI is
an offline research consumer of `exact_gb_cost`, not a DCS library dependency.

A second explicit adapter, `install_exact_dual_rounding`, handles one bounded
30-bit scalar in the original dual-hybrid Cost. The [rounding proof](DUAL-ROUNDING.md)
certifies its exact value and original-expression fallback outside the proved
domain. Seventeen real Sage interval/scalar comparisons and8 full Cost/type/
order/metadata comparisons must pass before that classmethod is changed in
memory. The full original parameter search and all8 attacks remain required.

Prepare the exact official revision above in an otherwise untouched source tree.
Run each model in a fresh Linux supervisor with a600s GNU SIGKILL wall deadline,
CPU600s, address-space2147483648 bytes, core0 and per-file16777216 bytes; the
operator must separately enforce an aggregate physical-memory2GiB cgroup. With
those external guards in place, the child commands are:

```sh
sage -python experiments/lattice-cost-prefix/estimate_n4096.py --estimator-root /path/to/exact-official-tree --model adps16-classical --max-seconds-per-model 600
sage -python experiments/lattice-cost-prefix/estimate_n4096.py --estimator-root /path/to/exact-official-tree --model matzov-classical --max-seconds-per-model 600
```

The CLI's Python alarm alone cannot enforce those OS limits. Both complete
eight-attack maps, successful terminal receipts and unchanged source identities
are required for a two-model numerical conclusion. Partial records are diagnostic
evidence only. Research limits do not change the DCS peer or full-query targets.
The hermetic `test_estimate_progress.py` checks observer behavior with explicit
public test markers; it supplies no Sage runtime or estimated attack costs.

For distinct active degrees set Q(z)=prod(1-z^d), P(z)=(1-z)*Q(z), and
R(z)=n*Q(z)-(1-z)*sum(m*d*z^(d-1)*prod_other(1-z^other)). Then P*H'=R*H and P(0)=1,
so, writing H=sum A[k]z^k:

```text
k*A[k] = sum((R[i-1]-(k-i)*P[i])*A[k-i], i=1..k), A[0]=1.
```

Only nonzero P/R shifts are visited and every division checks zero remainder.
Equal degrees combine multiplicities. Zero multiplicities and degrees beyond the
precision are exact identities for the requested prefix. Huge multiplicities
do not require dense polynomial powers. For the actual two-degree Gaussian-like
branch, P has at most8 sparse terms; coefficient generation avoids the previous
quadratic convolution over all earlier coefficients. Many-factor inputs can
still be expensive; this is not a universal resource bound. No attack is omitted,
no cost is approximated and resource failures must remain incomplete results.

The later [exact nonnegative-prefix criterion](POSITIVE-PREFIX.md) proves that no
negative coefficient exists for two precisely checked families. It preserves
the original infinity Cost instead of expanding those series. All other inputs
still use the complete sparse recurrence. Its sufficient inequalities use only
integers; no floating-point tail or attack cost is substituted.

Direct dependencies are Python's standard library, with optional Sage and the
[pinned official GB implementation](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/gb.py)
for the explicit adapter. There is no dependency on DCS application modules,
secret keys, owner data or fixtures. Previous actual public-runtime evidence and
remaining security obligations are in the
[product model](../../crates/bfv-unrelinearized-product/MODEL.md).
The [classical numerical record](ESTIMATE.md) contains every attack, source pins,
the native failures and the scope of the accepted maps.
Executed local/Sage checks and the numerical sweep status are recorded in
[VALIDATION.md](VALIDATION.md).
