# Exact rounding of the dual attack's bounded scalar

The pinned official [MATZOV.cost](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_dual.py)
constructs `alpha=pi^2*Xs.stddev^2`, then
`tmp_a=exp(8*alpha*exp(-2*alpha)*tanh(alpha)).n(30)`. The rest of its original
Cost calculation and parameter search consume that30-bit scalar. During r10,
Sage raised `SignError: cannot add infinity to minus infinity` at this numerical
conversion; the complete model was rejected. The argument is finite for this
profile. Its earlier successful evaluation is not a reason to accept the failure
as infinity or skip the attack.

For a finite53-bit Sage RR sigma in[3,4], its rounded RR square is in[9,16]:
round-to-nearest is monotone and both endpoints are exactly representable.
Using3<pi and pi^2<10 gives81<alpha<160, including that initial rounded square.
Set delta=8*alpha*exp(-2*alpha)*tanh(alpha). Since0<tanh(alpha)<1 and e>2,

```text
0 < delta < 1280*exp(-162) < 2^11*2^-162 = 2^-151.
0 < exp(delta)-1 < 2*delta < 2^-150.
```

The second inequality follows, for0<delta<1/2, from the exponential series
`exp(delta)<=sum(delta^k)=1/(1-delta)`. At1 the30-bit binary spacing toward2 is
2^-29, so its half-ulp is2^-30. Consequently the correctly rounded original
30-bit value is EXACTLY `RealField(30)(1)`, with no tie. This is not a small-term
approximation or a constant attack cost. All other expressions and every search
candidate still execute in the original implementation.

`install_exact_dual_rounding(params)` in the [driver](estimate_n4096.py) checks
the full official lwe_dual.py SHA256 and original function identity. It clones
the original classmethod AST, requires exactly the expected `tmp_a` assignment,
and substitutes only that value with a bounded helper and a lazy original
expression fallback. The helper applies only to the actual RR field and
3<=sigma<=4. Other types, precisions and values evaluate the original expression.
No official source file is modified, no error becomes an infinite Cost, and the
original full LWE factory still invokes all eight attacks.

Before installing the classmethod, genuine Sage must pass17 original-scalar/type
comparisons for sigma=3+i/16, i=0..16; directed256-bit interval checks of the exact
represented-sigma expressions must round to the same1 at both endpoints.
The analytic bound above also covers the intermediate RR square's rounding.
Two out-of-range cases must take the original-expression branch. Eight full
Cost/type/item-order/global-impermanent-metadata comparisons use both classical
models at beta776/781 and guessed dimensions0/20. Source and original function
identity are checked again before installation. A distinct
`dual_rounding_provenance` record is required before each full model starts.

This numerical adapter does not assess lattice, hash, sampler, protocol or SQL
security. It addresses an offline Sage expression evaluation only. The
[estimate record](ESTIMATE.md) distinguishes completed maps, rejected attempts,
actual source identities and remaining obligations.
