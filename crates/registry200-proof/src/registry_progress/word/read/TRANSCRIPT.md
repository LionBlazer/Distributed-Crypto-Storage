# Fixed-five native transcript manifest

`read::transcript::inspect(&expected)` derives the actual SourceVersion, Role3,
dense DATA, Predicate Word and fused Query metadata in that order. It constructs
the pinned SDK `StarkShape`, `BatchShape`, `PcsShape` and `FriShape` descriptions,
then captures their actual `DomainSeparator::seed` observations through the
[engine tap](../../../../../bfv-hiding-stark/src/transcript.rs). It does not
reimplement the seed encoding. The report contains protocol IDs, Keccak pattern
fingerprints, delimited instance labels, exact field-packed seed observations,
opening groups and salted matrix geometry. Its SHA256 snapshots are diagnostics.

No trace, preprocessing commitment, RNG, proof or accepted result is constructed.
Source and Role3 use the same private FixedAir dispatch as native checking.
Word uses the same complete closed role plan and resource/security prescreens.
DATA and Query each use their own immutable AIR and original native assessment.
The additional diagnostic is invoked explicitly, never on a production proof or
admission path. Existing mathematical profiles, frames and rejection guards are
unchanged. These snapshots cover the public seed and shape, **not every message
of an actual proof transcript**. Source/session public claims are absorbed later
by the real SDK driver; inspecting a separator alone does not check them.

## Fixed native geometry

The common low-level engine helper requires caller-associated actual AIR,
parameters, already BASE-flattened AUX width and STARK separator. It validates
the fixed suite and exact total opening count; it cannot authenticate that
association itself. The higher owning functions accept only their closed
Expected/role and derive those inputs internally.

Opening groups are in the actual native order: randomization, MAIN, quotient,
then PP and AUX when present. Private matrices have five additional base-field
hiding codewords; preprocessing has none. Every input matrix has four base-field
Merkle salt columns. Equal-height quotient rows are concatenated in one tree,
with salts added to each matrix separately. AUX is flattened once by the native
batch prover, so multiplying the assessor's width by five again is incorrect.

| Argument | LDE log | Salted input leaf widths in opening order | Original AUX base columns |
| --- | ---: | --- | ---: |
| SourceVersion | 13 | 14, 7170, 224 | absent |
| Role3 | 13 | 14, 1665, 224 | absent |
| Dense DATA | 15 | 14, 521, 112, 672, 419 | 410 |
| Predicate Word | 13 | 14, 577, 112, 718, 184 | 175 |
| Fused Query | 15 | 14, 425, 112, 549, 429 | 420 |

The quotient widths are16*14 and8*14 for uni and batch respectively. Binary FRI
leaf rows are two EF5 values plus four base salts, width14. Matrix log-heights
run from LDE log minus one down through three. The native comparison reconstructs
the actual inner PCS counts from the proof's public opened values and separate
hiding-codeword openings, then checks MMCS row/salt widths and FRI shape after
the complete independent native proof verification. It does not replace that
verification with shape checks.

Protocol IDs, versions, pattern fingerprints and length-framed instance chunks
are already seeded by the pinned SDK. Shape data that leaves a pattern unchanged
is bound in the instance label. For example DATA and Query share a batch pattern
but have different main/PP widths and different instance labels. The manifest
records both; comparing only the pattern hash would lose this distinction.

## Shared-permutation boundary

The leaf sponge, internal compression, duplex challenger and semantic Poseidon
commitments share the same permutation. `Hash8` is literally the compression of
two four-field digests. Padding-free hashing also preserves an unoverwritten
rate tail in its last partial block. For the actual Query salted lengths425 and
429, a public example can append four previously retained rate words and obtain
the identical final permutation input. Tests exercise these actual interfaces.
They demonstrate cross-width correlations, not a same-width Merkle forgery or a
valid false SQL proof. They rule out independently idealizing each interface as
a separate random oracle. Checking fixed dimensions before salting remains
necessary; it does not by itself prove a joint extraction theorem.

The relevant target is a joint ideal-permutation construction with one common
budget for direct/inverse permutation calls, long leaf absorption, semantic
commitments, proof attempts and reduction work. The verifier must extract the
typed committed vectors before dependent challenges, and simulate the actual
duplex challenge tree in a state-restoration game. Plain collision resistance
and an informal unpredictable-challenge assumption are insufficient substitutes.

[Chiesa and Orru](https://eprint.iacr.org/2025/536.pdf), Theorem 6.1, gives a
state-restoration-to-duplex reduction with explicit capacity and codec terms.
It does not directly establish this native variant: its construction initializes
capacity with an independent `h(x)` and overwrites rate, while the pinned Plonky3
challenger initializes to zero and adds an absorption-length tag to capacity
when clearing a partial rate tail. A variant lemma must account for both.
The [Chiesa--Yogev Merkle extraction analysis](https://raw.githubusercontent.com/hash-based-snargs-book/hash-based-snargs-book/main/snargs-book.tex)
also cannot be transplanted by treating every present configuration as an
independent random oracle. No unspecified big-O constant is used as a numerical
security level. The [existing conditional expression](CLASSICAL.md) remains an
abstract BCS calculation whose concrete joint-model correspondence is unproven.

FRI queries can be modelled as raw uniform Goldilocks challenges followed by the
actual low-bit map inside the IP verifier. The identity field codec then adds
no artificial statistical-distance penalty; the existing algebraic query bound
already accounts for the largest nonuniform index bucket. This choice changes
neither the native sampler nor the transcript.

## Finite LogUp lemma and remaining RBR association

For committed MAIN/PP messages fixed before lookup challenges, use original
message slots, including inactive zero-count slots. Formal denominators have
the form `A+(bus+1)*B^W-Horner(payload)`. Equal widths inside a bus and distinct
bus coefficients make these formal polynomials distinct. This is not pointwise
injectivity after sampling: `B=0`, for example, erases bus offsets.

If signed multiplicities have a genuine nonzero imbalance over these formal
messages, the cleared rational numerator is nonzero. Its degrees are bounded
by N-1 in A and W(N-1) in B. Schwartz--Zippel bounds its roots by N(W+1)/q;
the union of all denominator-zero events adds N/q. Thus the charged bound is
N(W+2)/q. Payload-compression collisions are inside this polynomial bound, so
an additional pairwise N-squared collision term is unnecessary. If an inactive
denominator is zero, its fraction can be unconstrained even though the honest
producer skips it; those slots therefore remain in N. Packing has the same
denominator-zero set and preserves all original fractions and multiplicities.

The pinned SDK binds MAIN, public values and PP before the lookup pair, then
AUX and terminals before its separate constraint challenge. Complete fraction,
accumulator, last-row and terminal equations are included in the actual symbolic
AIR/ALI/DEEP/FRI calculation. The closed native frame also requires the sole
terminal to be zero. Word policy frequencies are bounded by f and r-f unsigned
range constraints; mask frequencies have their bit constraints. Their total
weighted heights remain below the characteristic. A separate probabilistic
terminal term is not needed.

This finite fixed-message lemma still needs the online/list-decoded committed
MAIN association in the full RBR proof. Neither the manifest nor the fingerprint
number alone supplies it. Predicate admission, confidentiality composition,
external bindings, fresh finality, locks and full-query500ms remain unfinished.

## Executed validation

On 2026-10-22 six release/native engine tests passed at r517, including independent
seed framing/field packing and the two concrete shared-interface correlations.
Four owning diagnostic cases passed at r518. Their five reviewed public manifest
SHA256 snapshots were then pinned in the regression test:

| Argument | Manifest snapshot SHA256 |
| --- | --- |
| SourceVersion | `406e2791ce0b1198980fda765c99e528903723aa3b8977a9ce7e2cb333fe933a` |
| Role3 | `378d90a66c4e82ec06b8dbe84b7b3d6538bc6aafc3a50d1393f1428ee3ff1977` |
| Dense DATA | `8536f9022089addb76a956eaefdcdf269b3cd01e4a004d6692739c840925699e` |
| Predicate Word | `9eab76dfbb11338eb63ff875189798ce1d3768d60bc96c5e3d6984db5e3d7119` |
| Fused Query | `7884b9c9949e5ce746cc46f482928d87d1fef2b142c8b84322b3d64242e2d742` |

The complete actual six-proof read case passed at r519, including independent
verification, protected client completion and all original rejection/retained
query assertions. After verification, the new native comparison decoded each of
the five genuine STARK frames, matched its separate hiding openings against
the manifested PCS counts, and checked every input row/salt width and FRI
round/query/salt shape. The product PIT was still checked by its original full
checker. No proof was replaced by this comparison. The test process took
29799.8311ms with 562343936B OS peak working set. It includes setup and hostile
checks, not a complete network SQL operation, fresh quorum or lock acquisition.

These captures pinned exact sources and release opt-level3 images, used Rayon2,
and retained the 120s/1792MiB/20ms independently held-process fuses. They completed
without fuse faults or cleanup actions. Engine image 2252288B SHA256 was
`57DB9AC5F80FC084682AC6E3A38418C7D2624E9C369E90DED891373065261F96`;
owning image 12475392B SHA256 was
`F475534C236139CD8381F3828D7E51725DF8CE8A9A08FBCAA0AEE4FA20F2C93E`.
Ignored local receipt SHA256 values were:

| Local result | SHA256 |
| --- | --- |
| `.local/word-cmd-native-r517-bfv-hiding-stark-observe-tests/result.json` | `C2E73D75D42A9565D9DEA9CA377DB6F1EA17469042BD97E8EEA102DA956A65A6` |
| `.local/word-cmd-native-r518-registry200-proof-observe-tests/result.json` | `11C7E87E9D9D6F2ACC6DAB84EEC593AFB65248416F223FE86E17E2D0DE38991B` |
| `.local/word-cmd-native-r519-registry200-proof-observe-tests/result.json` | `F74B43174DA8F769FAEF6D8541747B61756BF5D7A750F5FE5765551865AEC241` |

Only public expected snapshot assertions were added after those captures;
production code and the native chain test were unchanged. All four diagnostic
cases passed again at r526 with those pins. Strict all-target release Clippy
passed for engine, Formation and registry proof crates; all 12 Word compile-fail
interfaces and the requirements mirror test passed. Generated proofs, logs and
binary/receipt artifacts remain ignored. This establishes finite transcript
correspondence coverage; it does not establish the remaining joint model or 500ms.

The final pinned diagnostic image was12488704B, SHA256
`2E09B806138635FF94BD6E3EA19E55BE0FE48CA8F60B4A05F2341AF8F6EB41E4`;
its r526 result SHA256 was
`01E0BBFC43C961F611DBCEE76268417B32B2B16BA1B34E28EE06196F55A10331`.
