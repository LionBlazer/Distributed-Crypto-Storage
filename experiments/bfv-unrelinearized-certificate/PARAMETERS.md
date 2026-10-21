# Fixed-pair parameter analysis, pending admission

This is a conditional analysis of one fresh N4096 product. It is separate from
the public arithmetic certificate and does not enable a proof or SQL dispatcher.
The executable's `noise_certified=false` and `lattice_security_assessed=false`
flags remain correct. The complete SDK rounding argument and a faithful pinned
lattice attack estimate still require validation. No estimator was run.

## Exact implementation and semantic domain

The pinned fhe0.1.1 parameters are N=4096, Q0=1073692673, Q1=1073668097,
Q=1152789568982753281, and t=65537. Thus Q mod t=16389 and
Q/(2t)=8794952232958.125. These are the Q ciphertext parameters; the auxiliary
62-bit P primes are deterministic public computation intermediates, not fresh
encryptions under a larger modulus.

Both the secret and fresh encryption error use `sample_vec_cbd` with variance10.
The implementation subtracts the population counts of two independent groups
of twenty bits. Its ideal distribution is CBD(eta20), support[-20,20], mean0,
variance10 and fourth moment295. The MGF is cosh(u/2)^40<=exp(5u^2), with
sub-Gaussian variance proxy10. It is neither ternary nor a Gaussian with sigma10.

The domain is four rows with age in0..255 and amount in0..65535, together with
any256-bit truth table over age. Each source lane has one nonzero coefficient:
presence/age has value256+age, and the other lane has the amount. Each lane has
stride512; the mask puts bit(age) at255-age. The largest product degree is4094.
Lanes do not overlap and no negacyclic wrap occurs in the plaintext product.
Every product coefficient is zero or the original lane value, strictly below t.
The target coefficient255 of each lane implements the exact truth-table lookup;
zero amounts and age0 remain distinguishable through the presence/age lane.

For centered plaintexts m,n, uniformly over this domain:

```
||m||_1 <= 133116; ||m||_2 < 65544; support(m) <= 8
||n||_1 <= 256;    ||n||_2 <= 16;    support(n) <= 256
```

This covers the finite age/amount schema and one product only. It does not cover
additional multiplication depth, amount predicates, arbitrary SQL or larger tables.

## Honest fixed pair and required rounding premise

The argument assumes independently sampled ideal CBD key/error coins, public
second ciphertext components independent of the secret, and both plaintexts
chosen before the pair's fresh error coins. It does not justify adaptive queries
that reuse a source ciphertext: a later mask could depend on its earlier error,
invalidating the independence used below. The concrete RNG and public-seed
expander also need their computational assumptions stated separately.

The SDK plaintext lift is floor(Q*m/t), including centered representatives. Its
implementation first forms W=(Q mod t)*m mod t and multiplies by -t^-1 mod Q.
Writing alpha=Q/t, the fresh phase is alpha*m+eta_m, where eta_m=e_m+d_m,
-1<d_m<=0 and |eta_m|<=21. The embedding bias is zero off the plaintext support.

The remaining rounding premise is precise: the fixed Q2 extension must select
the true centered representative; the honest tensor must remain centered in QP;
the component downscale and final decryption must equal nearest(t*x/Q).
For this geometry the SDK Garner shift is127. The proposed error bounds are
<2^-97 for Q2 centering, <2^-65 for honest Q2P2 centering, and <2^-96 for the
fractional downscale/decryption term. The latter depends only on the two30-bit
Q rows: GammaTheta and the P-row theta terms are zero. These errors are below
the corresponding half-boundary gaps; honest tensor coefficients are also far
below QP/2. Independent source review found no numerical contradiction, but
complete implementation conformance is still an admission prerequisite. Random
SDK tests alone do not prove these statements for the full accepted domain.

## Conditional coefficient error bound

Condition on any fixed centered public component a, |a_j/Q|<=1/2. Each
coefficient of a*s/Q has variance proxy at most10*N/4=10240. Across two
ciphertexts and every coefficient:

```
Pr[max |a*s/Q| > 3000] <= 4N*exp(-3000^2/(2*10240)) < 2^-619
```

On that event, the noiseless centered wraps K0,L0 have magnitude at most3001.
Adding fresh noise changes each wrap by a correction D,D' of magnitude at most1.
Those corrections may depend on their own errors and are bounded deterministically.
With actual wraps K=K0+D, L=L0+D', retaining all component-rounding terms gives:

```
E = m*eta_n + n*eta_m + (t/Q)*eta_m*eta_n
    + t*(K*eta_n + L*eta_m) + rho0 + rho1*s + rho2*s^2
```

The wrap terms cannot be omitted. Products in this formula are negacyclic.
The independent random linear part has weights m+t*K0 and n+t*L0, each with
Euclidean norm below12588000000. A union bound gives failure below2^-314.7
for its maximum coefficient to exceed1200000000000. The remaining terms have
the following conservative coefficient bounds:

| Term | Upper bound |
| --- | ---: |
| Embedding bias | 51922739140 |
| D,D' corrections | 11274461184 |
| Component rounding, with ||s||_1<=81920 | 3355484161 |
| Scaled eta product | 1 |

Consequently |E|<=1266552684486, with the exact positive margin
Q-2*t*1266552684486=986777442416435317. Under the stated rounding and ideal-coin
premises this gives one-pair failure below2^-314, uniformly for each allowed fixed
pair. It is not an absolute guarantee for all coins or an adaptive/lifetime bound.
It establishes neither valid sampling by a malicious party nor key authority.

## Confidentiality and outstanding work

A faithful attack estimate must use n4096, q=1152789568982753281 and
Xs=Xe=CenteredBinomial(20), with a stated key-lifetime sample bound (infinity is
a conservative starting point). Pin the estimator, its runtime/dependencies and
cost model, run the applicable primal, dual, hybrid and BKW attacks, then report
the conservative minimum and the ring/seed-model limitations. Generic Gaussian
or ternary parameter tables cannot serve as an estimate for this exact instance.
Public arithmetic, successful decryption and the error bound above cannot replace
the confidentiality assessment. Same-secret Formation and authenticated inputs,
program, version and consensus remain separate requirements.

The analysis was derived from the pinned local SDK sources and independently
reviewed as source/mathematics only. The original 15-file research receipt is
`.local/unrel-cert-noise-confidentiality-research-r1/pins.json` in the research
worktree; its SHA256 is
`91128A28701D41FC6A822A2915AAC33C547715739E27E939EA082F11C380910B`.
The source note SHA256 is
`C102B930B16240CB29364D0A1059F8EF1B53830B630FDE827B5F5DFAEC65F188`;
the independent review SHA256 is
`EA2EA15824AA79804D01AC686AC9D04B21646609579F8B0EE4E7C121D8C51C66`.
Those records contain no native assessment or security flag. The exact SDK
sources are `fhe-util0.1.1/src/lib.rs`, `fhe0.1.1/src/bfv/{plaintext,parameters}.rs`,
`fhe0.1.1/src/bfv/keys/secret_key.rs`, and
`fhe-math0.1.1/src/{rns/scaler,rq/scaler,zq}.rs` in the locked Cargo registry.
