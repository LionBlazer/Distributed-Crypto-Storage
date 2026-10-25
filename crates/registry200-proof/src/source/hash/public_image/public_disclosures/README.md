# Source public joint disclosures

This private owning cfg(test) module samples a fixed-coin PUBLIC arithmetic image
for SourceVersion. Its native layout is R10, MAIN7161+5 and sixteen ordered Q5+5
matrices. No PP or AUX is present. The result is unverified arithmetic, with the
complete Expected691 retained and checked; it creates no proof or admission token.

The sampler directly calls the existing [SourceFoldProgram](../mod.rs), whose
actual OpeningAir DAG, full Expected, plain H512 periodic IDFT, source-derived
cache bound and five-coordinate quotient evaluator stay unchanged. The existing
[domain](../domain.rs) owns target/enlarged projections. Pure coefficient
arithmetic comes from the dev-only
[proof-research-support ring](../../../../../../proof-research-support/src/ring.rs).
The SDK PolynomialSpace supplies actual native domains and normalized factors.
The [independent consumer](../tests/joint_disclosures.rs) is a child of the
existing Source tests so the original private NativeOracle needs no API change.

`sample(program, expected, alpha, z, S, rng)` is visible only inside the owning
public_image module. Expected, alpha, z and ordered unique physical S are fixed
before all ideal-cell draws. Preflight rejects a full-public mismatch, more
than192 locations, duplicates/nonphysical points, and the explicitly unsupported
zero, H512 and physical-domain OOD cases. These named failures leave the supplied
cell RNG untouched. This is not a rollback promise for an unexpected later fold
error, or a claim that public-fixture setup performs no other randomness.
A driver must retain the separate raw192 index stream to reuse duplicate rows.

The actual quotient split is7H8192 into16 domains s_i H512, s_i=7*omega8192^i.
The sampler derives normalized v_i=(X/s_i)^512-1 and
c_i=(product_(j!=i) v_j(s_i))^-1 from the real SDK. They happen to satisfy
c_i=-1/16 here; construction does not hardcode that value. For each original
quotient coordinate it samples fifteen free target residues and sets

    t_15 = -sum_(i<15) (c_i/c_15)*t_i,
    q_i = q + v_i*t_i.

Every physical Source row lies in exactly one chunk where its v_i vanishes.
These zero divisors are supported: no all-v_i-units precondition is imposed.
Five appended Q columns per chunk are free final target residues. Native hiding
also masks those wrapper columns after creating random baselines; equivalence of
this free-cell recipe with their conditioned native distribution remains open.
The original five Source-coordinate recomposition constraint is NOT imposed on
those five unrelated wrapper columns.

The explicit cell stream is7161 enlarged MAIN polynomials,15*5 target mask
polynomials,16*5 target Q wrapper polynomials,5 enlarged MAIN wrapper polynomials,
then10 target R polynomials. With m=deg(M), m_T=deg(M_T), its Gold-cell inventory
is (7161+5)*m_T+(15*5+16*5+10)*m. This counts algebraic cells, not raw RNG draws,
rejections, RAM or cryptographic security. The small16 positions7*omega^j,
j=0..15, meet each chunk once and have disjoint hS; nonbase z gives m21/m_T42
and304437 cells. MAIN's hS values remain latent fold inputs, not new native rows.

Three math tests compare the actual split/normalization, normalized polynomial
values and all16 active zero-divisor cells; independently row-reduce the15-mask
map at all16 cells and nonbase z; reconstruct all five coordinate copies and
native SDK images; and reject a wrong last mask, wrong sign, mixed monic/native
normalization and chunks0/15 swap. The wrong-last/sign controls deliberately pass
ALL base-row recompositions and fail OOD. Fully consistent monic rescaling is an
equivalent parameterization and is not described as an invalid affine law.

The independent consumer replays the complete explicit cell stream, checks all
7161 original MAIN columns plus every MAIN/Q wrapper and R column by scalar
Horner, and invokes the UNCHANGED NativeOracle on16 base rows and five OOD
coefficient embeddings at the same z. Only coefficient alpha is conjugated;
MAIN(z,hz) and periodic512 stay fixed. It checks80 base-coordinate equalities,
actual native quotient recomposition, complete C_state association with the SAME
public images, a corrupted V OOD value and preflight RNG preservation. Cache
counts are compared with the actual live graph; no fixture's numeric node count
becomes a universal cap.

The consumer also retains every sampled quotient mask. All 1,280 individual
chunk/base values and 80 chunk/OOD coefficient embeddings are checked against
the SAME public cells and unchanged native references. Independently derived
native factors and the correlated last mask prevent a sampler that consumes
but ignores its free masks from passing. The original 21 native-folder calls
are reused; no extra native setup or call is added.

The three isolated math cases and preflight case are ordinary unit tests. The
actual Source sampler/native replay is opt-in under the existing held-process
resource observer and unchanged process fuses:

```sh
cargo test --release --locked -p registry200-proof source::hash::public_image::public_disclosures::tests:: -- --test-threads=1
cargo test --release --locked -p registry200-proof source::hash::public_image::tests::joint_disclosures::source_joint_preflight_preserves_rng_for_named_public_association_and_geometry_failures -- --exact --test-threads=1
cargo test --release --locked -p registry200-proof source::hash::public_image::tests::joint_disclosures::source_joint_small16_replays_all_main_cells_and_matches_native_rows_and_five_ood_embeddings -- --ignored --exact --test-threads=1
```

The five cases passed the [owning validation](VALIDATION.md), which records
exact coverage, process measurements and the test-only compile fixes.
The owning public fixture seals public constants with a public key and fresh
OS-random page nonces; it is not RNG-free. No witness, trace, actual native
quotient production, FHE query or Source proof is requested. Arbitrary sampled
MAIN residues need not extend to an honest witness or globally divisible
constraint polynomial. The q_i=q affine baseline is an algebraic solution, not
a claim about genuine native unmasked chunks. Honest-source/divisibility,
conditioned native-mask/baseline association (including wrappers), ideal-cell
independence, adaptive privacy, shared RO/FRI, whole-B, native Source frames,
freshness, application admission and the500ms full SQL/FOR UPDATE target remain
unproved. This module changes no production facade, guard, config or profile.
