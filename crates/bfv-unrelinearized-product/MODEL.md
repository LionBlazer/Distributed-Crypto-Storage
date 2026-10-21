# Conditional arithmetic and noise model

This is a conditional model for the existing **UNASSESSED** product profile,
not a security approval. It changes no bytes, parameters, admission rules or
flags. `proof_verified`, `cryptographic_security_assessed`, `noise_certified`,
`lattice_security_assessed` and `sql_accepted` remain false in the experiment.
A sealed `ArithmeticCheckedProduct` records only the library's mathematical
checking result under these assumptions; it supplies none of those authorities.

## Fixed public relation and transcript
The geometry is N=4096, t=65537 and the ordered prime bases
Q=[1073692673,1073668097], P=[4611686018427322369,4611686018427289601].
Here Q denotes their product1152789568982753281 when used as a scalar;
M=Q*P0*P1. The P primes are computation intermediates, not a larger
encryption modulus. Primality and this fixed order are geometry premises.

[Expected](src/statement.rs) retains both original unseeded CT2 byte strings,
the unseeded CT3 output and an independent nonce. Canonical decoding covers
every natural PowerBasis coefficient despite the SDK wire's Ntt tag.
Four exact integer certificates extend the original components Q2->QP,
preserving the original Q rows; three scale the product components QP->Q2.
[The complete checker](src/certificate.rs) binds all seven certificates and
all endpoints, verifies every scalar equation, and checks for each basis:
```text
A0*B0       - Y0 = (X^N+1)*H0
A0*B1+A1*B0 - Y1 = (X^N+1)*H1
A1*B1       - Y2 = (X^N+1)*H2
```

Inputs and Y have N coefficients; H has N-1. Each error polynomial F therefore
has degree<=8190. The verifier performs Horner evaluations, not NTT or query
execution. The producer obtains H from ordinary2N convolution and Y=low-high.

[PIT sampling](src/pit.rs) hashes the full prefix-free transcript: fixed domain,
LE64 length plus literal request, output and complete canonical frame.
Each point appends a distinct fixed domain plus LE32 basis and sample index.
All P extensions, Y, H and scaler witnesses are fixed before any point.
Cloning an **unfinalized** SHA512 prefix computes the same full-message hash;
it is not a finalized short-seed expander. All512 digest bits are interpreted
big-endian and reduced modulo the field. The exact frame/EOF/canonical rules
are mandatory; caller-supplied hash prefixes or challenge lists are not APIs.

## Deterministic SDK rounding lemmas
Use R(x)=floor(x+1/2), U=2^127. For CRT modulus m let
G_i=(m/p_i)*inverse(m/p_i modp_i), T_i=R(U*G_i/m).
The SDK selects v=R(sum(r_i*T_i)/U). Its error from the exact Garner sum is
at most sum(p_i-1)/(2U), or the sharper exact constant-derived error.

1. For every canonical Q2 input, the Garner error is<2^-97, below the
   odd-Q half-boundary gap1/(2Q)>2^-61. Factor1 extension thus represents
   the exact centered integer in every P basis, with Q rows copied.
2. Every coefficient of the genuine depth-one tensor obeys
   |T0|,|T2|<=N*Q^2/4 and |T1|<=N*Q^2/2<M*2^-51.
   This includes arbitrary canonical input ciphertexts and negacyclic signs;
   no honest-noise assumption is used. QP centering is therefore far from a
   half boundary. The generic Garner bound<2^-64 suffices; the actual pinned
   constants sharpen it to<2^-65 (approximately2^-66.74235).
3. For downscale t/Q, Gamma=t*P0*P1 is integral and P-row theta terms vanish.
   Only the two30-bit Q rows have directed theta error, totaling<2^-96.
   Odd denominator Q gives a half gap>2^-61, so downscale equals R(t*T/Q)
   modulo each Q prime. The Q2->t decrypt scaler has Gamma=t and the same
   gap/error argument for the full c0+c1*s+c2*s^2 phase.
4. The SDK lift W=(Q modt)*m modt and delta=-t^-1 modQ give exactly
   floor(Q*m/t) modulo Q, including centered negative m.

[Scaler constraints](src/scale/math.rs) enforce unique v/w intervals and exact
checked-I256 reduction equations, not finite-field aliases. The pinned SDK's
positive and negative w branches both implement floor((Etheta+2^126)/2^127).
For these roles the Garner sum is<2^191 and signed theta magnitude<2^157;
the U256 operations, sign test and final u128 sums do not overflow.
SDK lazy Shoup permits any u64 first operand; only its second operand must<p.
These lemmas require the **genuine tensor relation**, not just valid scalar
certificates. A useful counterexample is the arbitrary QP input x=(M-1)/2,
with residues [536846336,536834048,2305843009213661184,2305843009213644800].
The exact SDK algorithm returns Q residues [1072594946,513385678], whereas
ideal R(t*x/Q) gives [1097726,560282418]. Its Garner v differs by1.
It is outside the bounded tensor domain. The actual-SDK midpoint contrast
and full4096 coefficient checks live in [scale tests](src/scale/tests.rs);
testing alone does not establish the universal rounding lemmas.

## Conditional classical random-oracle bound
Assume a classical512-bit random oracle with independent outputs for distinct
complete messages. Collision resistance alone is insufficient to justify this
model for SHA512. For one fixed false canonical certificate satisfying all
scalar checks, choose one nonzero F in one field **before** its challenges.
A degree8190 polynomial has at most8190 roots. Each reduced digest residue has
mass<=1/p+2^-512, so with18 independently domain-separated points in that field,

```text
epsilon <= max_p [8190*(1/p+2^-512)]^18 < 2^-306.
```

Q1 is worst (approximately306.00456 bits before budget loss).
Points are shared among the three component equations. A false certificate
may fail in only one component/basis: do not multiply the exponent by3 or4.
Acceptance implies all18 roots for the selected F; no factor12 is needed.

For adaptive grinding, enumerate complete transcripts at their **first**
domain-relevant oracle query. All coefficients of that transcript are then
fixed, and its18 selected outputs remain independent of earlier different
messages. Abandoning candidates early does not increase the event bound.
A transcript first submitted to the verifier is another first-touch event.
A union bound, without independence between attempts, gives

```text
Pr[any false arithmetic acceptance] <= min(1,(Q_H+V)*epsilon).
```

Q_H counts all adversarial component-oracle queries, including offline work;
V counts verification attempts. Under the explicit classical budget
Q_H+V<=2^128, the bound is<2^-178, conditionally exceeding a144-bit arithmetic
error floor. Operational timeouts do not enforce the offline budget.
This is not a system security level or SHA512 theorem. Quantum queries require a
separate QROM reduction; halving306 is not one. The profile remains UNASSESSED.

## One reused source: finite adaptive-mask noise theorem
Assume ideal independent CBD(eta20) coefficients for s,e0,e1,... and public
A0,A1,... independent of the secret **and** errors. The actual SDK variance10
sampler subtracts two20-bit popcounts: support[-20,20], variance10 and
MGF<=exp(5u^2). Public A need not be statistically uniform for this bound.
Concrete public-seed ChaCha8/DRBG/RNG behavior remains a computational premise.

There is ONE reused source ciphertext with coins(A0,e0), and at most T=2^64
fresh query encryption/product attempts. Count retries, resumes and failed
attempts, not only terminal SQL calls. Four ordered rows have age8bit/amount16bit
(at most2^96 plaintexts). Masks are arbitrary256-bit age truth tables.
Eight512-stride lanes have source presence256+age and amount, mask[255-age].
The plaintext product degree is<=4094, with no lane overlap or plaintext wrap.
For centered source m and mask n:
```text
||m||1<=133116; ||m||2<65544; support(m)<=8
||n||1<=256;   ||n||2<=16;   support(n)<=256.
```

Put eta=e+d, with floor(Q*m/t)=(Q/t)*m+d, -1<d<=0.
Retain centered phase wraps K,L; they cannot be dropped from the error:
E=m*eta_n+n*eta_m+(t/Q)*eta_m*eta_n
  +t*(K*eta_n+L*eta_m)+rho0+rho1*s+rho2*s^2, |rho_j|<=1/2.
On the common wrap event G, noiseless wraps have magnitude<=3001.
Its complement is bounded by2N(T+1)*exp(-3000^2/20480).
G depends only on s/public A and holds simultaneously for all plaintexts;
it pays no mask/source-domain factor.

For each fixed m,n, the random linear part
Z=ei*(m+t*K0)+e0*(n+t*L0) has both weight norms<U0=12588000000.
Conditioning only on s/public A gives tail2N*exp(-lambda^2/(40U0^2)).
The remaining terms have uniform bound R=66552684486.

For analysis only, couple every mask at each attempt to the same fresh query
coins, and optionally every source plaintext to the same ONE source coins.
A uniform good event then covers any history-dependent selected mask;
do not condition on that selected mask and assert error independence.
No production coins are reused or changed by this analysis. Union gives
```text
Pfailure <= 2N(T+1)*exp(-3000^2/20480)
          +2^96*T*2^256*2N*exp(-lambda^2/(40U0^2)).
```

The optional2^96 means counterfactual plaintexts with ONE source coins,
not2^96 fresh source ciphertexts. For a fixed source chosen before its errors
that factor is unnecessary. At lambda=2400000000000, the wrap exponent
is556.99684 bits and the all-source/mask/lifetime linear exponent882.06300:
Pfailure<2^-556 in this ideal model. Emax=lambda+R=2466552684486 satisfies
Q-2*t*Emax=829488642416435317>0, so |E|<Q/(2t)=8794952232958.125.
This covers one product depth and the stated finite domain, not maliciously
chosen errors/secrets, arbitrary predicates, many-source lifetimes or RNG failure.

## Source references and remaining obligations
Repository anchors: [geometry](src/geometry.rs), [codec](src/certificate.rs),
[PIT](src/pit.rs), [scalar constants](src/scale/constants.rs) and
[integer verifier](src/scale/math.rs). The historical
[fixed-pair parameter note](../../experiments/bfv-unrelinearized-certificate/PARAMETERS.md)
has the smaller original nonadaptive tail; the stronger finite theorem is above.
Pinned SDK package-relative anchors are fhe-math0.1.1/src/{rns,rq}/scaler.rs
and src/zq/mod.rs; fhe0.1.1/src/bfv/{parameters,plaintext,ops/mod}.rs and
keys/secret_key.rs; fhe-util0.1.1/src/lib.rs::sample_vec_cbd.
Exact source hashes accompany this documentation's source packet.

Primary background: [Thaler, sections3.4 and5.3](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)
for polynomial testing and Fiat-Shamir query accounting;
[Bellare–Rogaway](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf) for the distinction
between ROM proof and concrete hashing;
[Don–Fehr–Majenz–Schaffner](https://arxiv.org/abs/1902.07556) for separate QROM reductions.
The implementation-specific derivations above are not theorems of those papers.

A faithful lattice/confidentiality estimate for n4096,q=Q,CBD(20) is pending.
On 2026-10-21 the numerical runner reached genuine Linux Sage 10.10/Python 3.12.3
with a 2 GiB operator cgroup and GNU timeout 9.4. After the Git prerequisite was
removed, the [official exact-commit archive](https://codeload.github.com/malb/lattice-estimator/tar.gz/53da5982597709ba0fdf94ea37a84d822310fd84)
was staged without changing any estimator byte. All 63 files/11 directories and
the six original RAW pins were independently checked before and after the run.
The saved 101555-byte archive SHA256 is
`4236adc38031c139c8a2721804d8962d6cacd015fae37f6f5215d2ac7f011060`;
archive provenance reports `git_clean=null`, never a fabricated Git checkout.

A startup diagnostic measured Sage virtual size 1602277376 bytes and
RSS 204087296 bytes before NumPy. The original 1536 MiB address-space fuse left
8335360 bytes and NumPy mapping failed. The offline research child now has an
explicit 2048 MiB virtual limit; the aggregate physical 2 GiB cgroup, GNU 120s,
CPU 120s and file 16 MiB guards are unchanged. This does not change a DCS peer cap.
Actual MATZOV evaluation then started, but independent GNU timeout stopped it
after 120.05s before any attack-result or model-completion record. ADPS16 was
not launched. Setup and source checks passed, and kernel/server cleanup was
acknowledged; `.local/lattice-runtime-archive-run-r3` retains the raw evidence.
Waited-child CPU/RSS after this group SIGKILL does not account for all Sage
descendants and must not be presented as whole-estimator resource usage.

The ordinary estimator remains pinned at
`53da5982597709ba0fdf94ea37a84d822310fd84`, with exact CBD20 secret/error,
full Q, m=infinity, all eight attacks and separate classical MATZOV/ADPS16 models.
No sweep or minimum cost has been established. The next diagnostic samples the
Python stack under the same deadline to locate the slow stage. All eight attacks
remain required for a numerical claim. Full confidentiality assessment remains
an explicit receiving blocker.
Smallness does not prove sampler entropy. The certificate does not establish
same-secret Formation, authenticated Source/hidden-program completeness,
authorization, current agreed head/QC, durable locks or SQL admission.
No serialized checked flag, owner signature or successful decryption substitutes
for those obligations. Cold verification remains real checking of the original
bytes; this document introduces no cache lease. Neither standalone timing nor
these bounds establishes <=500ms COMPLETE query or whole-peer memory targets.
