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
Executed local/Sage checks and the incomplete full sweep are recorded in
[VALIDATION.md](VALIDATION.md).
