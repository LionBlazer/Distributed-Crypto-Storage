# Public-V-only DATA whole-B arithmetic

This private `cfg(test)` child constructs the coefficient-side affine B image
from explicit public DATA disclosures. Its fixed layout is R10, MAIN517(z,hz),
Q8x10(z), PP668(z), AUX415(z,hz):2622 complete terms in native round/matrix/point/
column order. The public PP theta exponent begins at1124.

`prepare(PublicView)` validates raw extents and next-claim shape before
interpolation; requires<=192 distinct S in7H32768; rejects base theta, z=0,
z inH2048/7H32768 and intersecting OOD minimal polynomials. CRT reconstruction
retains all five Frobenius coordinates at nonbase z/hz. Base OOD claims must be
base; duplicate S never merge. Each PP polynomial has<=4096 coefficients and is
checked against every disclosed row and complete z claim. Native DFT streams
large PP row checks; PP has no next claim or wrapper.

The accumulator preserves all2622 theta powers with separate local/next banks.
Exact division by X-z and X-hz gives the origin, with weighted OOD remainders
checked. Mask direction is P_S*m_z/(X-z). At generic192 S, B has4095 coefficients,
direction197 and3899 free EF5 coefficients. `Prepared::instantiate` uses a
native4096-point base-field DFT convolution transporting all five EF5 coordinates;
`sample` draws explicit coefficient cells through caller-owned CryptoRng.

## Ownership and dependencies

The [shared coefficient ring](../../public_image_ring.rs) supplies pure base
product/evaluation, and pinned P3 DFT/field and rand0.10 supply native arithmetic
and caller randomness. Local CRT and synthetic division retain owning utilities;
no Ring or FRI implementation is duplicated. The reviewed Query affine algorithm
is adapted to DATA's fixed dimensions/order, without reusing its statements.

Tests obtain actual DATA Expected, PP and joint V from the owning
[public image](../public_image/README.md) and
[joint sampler](../public_image/public_disclosures/README.md).
They explicitly copy unverified values into this raw arithmetic interface.
No private trace, original R, DATA Prepared, secret key, proof or oracle enters.

## Executed checks

Seven algebra cases verify literal linear CRT, five-coordinate reconstruction,
every native matrix boundary, exact4096/192 mask divisibility, native FFT versus
schoolbook product, PP row/OOD/degree attacks, base/duplicate/exceptional points,
malformed next claims, wrong widths and mask degree. Their zero-polynomial
fixtures describe raw arithmetic, not honest DATA witnesses.

The real-DATA base-z case uses z=49 and overlapping hS. It compares native2622-term
reductions against B origin/sample, checks smaller affine dimensions and rejects
tampered last PP row, PP OOD and a nonbase claim at base z.

The opt-in real-DATA full192 case draws383953 cells, binds Expected and actual668
PP, constructs and instantiates B, and compares every row with both literal2622
terms and the genuine packed SDK kernel. It verifies four other Frobenius roots
and an independent mask-product evaluation at a non-disclosed probe.

All nine cases passed in optimized observed runs r879..880. Full jointV->B with
its comparison controls took2842.9390ms, OS peak116965376B. This includes setup,
sampling and independent assertions; it is not isolated proving or SQL latency.
The [owning validation table](../public_image/README.md) records executable,
source/handle pins,120s/1792MiB limits and other exact gates.

Reproduce ordinary cases:

    cargo test --release --locked -p bfv-ciphertext-formation gold::program::dense_data_inventory::public_deep::tests:: -- --test-threads=1

Select the explicitly ignored full192 case by its exact name under the owning
held-process observer.

## Remaining boundary

PublicView cannot authenticate that supplied PP coefficients belong to Expected.
The real-DATA consumer supplies independently derived factory values. A future
encapsulated native assembly must preserve that association; consistency checks
alone give no Source/key/version or admission authority.

Affine distribution claims retain honest AIR, degree/divisibility, ideal-cell
and public-conditioning premises. The owning [DATA research receiver](../research_data/README.md) now checks full
native frame assembly in the programmed proof-ROM. Mixed-family prior-state
coupling and adaptive/auxiliary/abort handling, concrete crypto/PRG,
application bindings and production admission remain separate work. Network SQL,
fresh consensus and finalized locks are neither implemented nor timed by these
tests; the complete500ms goal remains unmet.
