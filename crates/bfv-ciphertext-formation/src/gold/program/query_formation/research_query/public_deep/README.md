# Public Query R-DEEP sampler candidate

Private child of the owning Query `research_query` tests. It builds the entire
reduced polynomial B from PUBLIC disclosures V and fixed public preprocessing;
it has no original trace, original R, private witness, verifier callback or
accepted-proof conversion. Every algebra object uses native Gold/EF5 types and
ordinary coefficient `Vec`s. This is fixed-location algebra, not a RO/FS theorem.

`prepare(PublicView)` validates the fixed native matrix/point/column inventory:

| PCS round | Base columns | Points | Theta exponents |
| --- | ---: | --- | --- |
| R | 10 | z | 0..9 |
| MAIN | 421 | z, hz | 10..430; 431..851 |
| Quotient | 8 matrices of 10 | z | 852..931 |
| Public PP | 545 | z | 932..1476 |
| AUX | 425 | z, hz | 1477..1901; 1902..2326 |

Each `Column` has base-field values at the unique S locations, a complete EF5
value at z and optional EF5 value at hz. The view borrows these objects and the
actual 545 PUBLIC PP coefficient vectors. `QueryFoldProgram`'s independently
source-associated public PP getter can supply those vectors directly. The
sampler checks their complete disclosed S/z values, not just a profile digest.
Authentication of that public factory association remains the owning caller's
source contract; arbitrary caller-chosen PP is not an admission capability.

All non-PP columns use base-field CRT representatives. Lagrange interpolation
handles S, then small base-polynomial completions handle the minimal polynomials
of z and hz. The five-coordinate evaluation-basis inverse retains Frobenius
consistency; it does not identify the polynomial variable X with the EF5 basis
element u. PP uses its actual known coefficients. Native weighted sums are
accumulated separately for z/hz before just TWO exact synthetic DEEP divisions.
Their sum is B0 in physical X, with the native positive DEEP sign.

Let M=P_S*m_z, m=deg M and A=M/(X-z). `Prepared` owns B0, A and r=4096-m.
`instantiate(U)` returns B0+A*U for exactly r EF5 coefficients. A 4096-point native
base-field DFT convolution transports all five coordinates. `sample(CryptoRng)`
draws five native uniform Gold cells per EF5 coefficient and applies that map.
The ideal independent-cell/actual CSPRNG premise remains explicit. No production
RNG, Config or proof is created by this module.
The coefficient source must be independent of V, FS coins and MMCS salts;
the public deterministic test seed establishes no randomness/security claim.

The output has exactly 4095 coefficient slots, degree<4095. A is not M: it has
zeros at S and the OTHER conjugates of z; it need not vanish at z. At192 distinct
locations and nonbase z, deg M=197, deg A=196 and r=3899. B0 need not itself be
an honest witness polynomial; the conditional R-DEEP image absorbs differences
between all coherent representatives when theta is nonbase.

Policy is explicit: S may be empty or at most 192 unique values in7*H32768.
Duplicate locations reject even with equal rows; a native192-index stream must
deduplicate consistent rows BEFORE constructing this typed view. Arbitrary
unique S order is retained. Reject z=0, z in original H2048, z in7*H32768, or
theta in the base field. Base z elsewhere is supported, but then each OOD value
must also be base. hz is derived internally with the original 2048th root, not a
caller point; a minimal-polynomial collision rejects. Missing/extra next claims,
wrong widths, inconsistent PP and coefficient containers longer than4096 reject.
Zero padding within that cap is allowed. Byte canonicality belongs to the
typed-value producer/actual wire decoder; this module does not parse proof bytes.

Direct dependencies are `bfv-hiding-stark` field aliases, pinned `p3-field`
Frobenius/base arithmetic, native `p3-dft`, the already present rand0.10 alias
`rand-public-pp`, and standard collections. It does not depend on a custom ring
API, the original private witness factories or the new Query evaluator's types.
PP validation streams one column's LDE when needed. Private CRT representatives
retain at most one matrix (425 by at most 202 coefficients); PP is borrowed.
These scratch bounds do not establish a whole-process RAM guarantee; the owning
component observations are linked below.

Eight owning checks passed in the [bounded validation](../../RESEARCH-VALIDATION.md):
literal hand interpolation/DEEP;
all-five Frobenius coordinates at both points; independent literal native weight
boundaries; full4096/192 whole affine image with FFT versus coefficient product
and a direct coherent polynomial oracle; PP tampering; base-OOD/duplicate policy;
and exceptional coin/location/shape/resource cases. The additional source
association case uses all 545 actual public Query PP polynomials and compares
all 2327 native DEEP terms at every one of the 192 physical locations. Its
non-PP columns remain explicit public algebra fixtures, without an original
private trace or a valid Query AIR/proof/SQL answer.

No result from this module proves the law of V, correlated quotient sampling,
input-MMCS privacy, causal FS programming, native accepting frame simulation,
soundness, BFV/Poseidon composition, freshness, consensus or live SQL admission.
