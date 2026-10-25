# Fixed-coin public dense DATA disclosures

This private child of the owning `cfg(test)` DATA public image samples joint
trace/quotient disclosures from the actual `DataFoldProgram`, fixed public
`DataCoins`, OOD z, ordered unique physical S and a caller-owned `CryptoRng`.
DATA Expected and all 668 zero-interleaved PP coefficients come from the owning
program. No Query statement, private trace, DATA Prepared or accepting type enters.

`sample` returns unverified `Column` values: base rows, complete EF5 z
claims and optional hz claims. The DATA-only layout is R10(z), MAIN517(z,hz),
Q8x10(z), PP668(z), AUX415(z,hz). The actual fold retains512 original MAIN,
410 separate AUX base polynomials,81 packed lookups and all five quotient
coordinate copies under the same lookup/folding coins.

For A=F[X]/M and enlarged A_T=F[X]/M_T, original MAIN512, AUX410 and ten appended
wrapper columns are sampled in A_T. Each of five quotient coordinates uses seven
uniform A masks and an eighth fixed by the native c-weighted relation. Chunks
are Q_b+v_i*t_i with normalized v_i=(X/s_i)^2048-1. Native H4096 extension,
disjoint7H16384 quotient domain and ordered eight H2048 chunks determine shifts
and weights. There is no inverse v_i; rank remains seven at its roots. Forty
appended quotient columns and R10 use independent A draws. Generic192-point
geometry consumes932*394+85*197=383953 Gold cells, excluding rejection draws.

## Ownership and dependencies

The owning [DATA image](../README.md) supplies `DataFoldProgram`,
`DisclosureDomain` and `PublicResidues`. Its shared
[coefficient ring](../../../public_image_ring.rs), pinned P3 domain/DFT traits and
rand0.10 CryptoRng supply arithmetic. Types/functions are visible only in the
DATA test subtree. No Cargo or normal-build API/configuration changes are needed.

Preflight requires ordered distinct S of length<=192 in7H32768 and rejects z=0,
H2048 or7H32768 before any cell draws. Base z elsewhere and S/hS overlaps are
supported. PP geometry is DATA-owned. A later driver must deduplicate raw native
indices in original order and reuse disclosed rows for duplicates.

## Executed checks

Four unit cases verify normalized chunk geometry, all five correlated fibers
at192 locations, kernel rank at all eight roots and rejection with no RNG advance.
The fifth case changes only constraint_alpha with identical cell tapes: all
original quotient chunks shift by the same offset; other disclosures stay equal.
It uses base z=49 and h-overlapping S.

The opt-in full192 case pins every edge of native round/matrix/point/column order:
R0..9, MAIN10..1043, Q1044..1123, PP1124..1791, AUX1792..2621.
It computes two weighted row banks through the actual P3 packed Gold/EF5
dot-product kernel, compares all192 reductions with literal2622-term arithmetic,
and detects substituting Query's incorrect PP exponent932.

All six tests passed in observed optimized runs r876..878. The full192 process
took2131.0380ms with OS peak117207040B. Detailed common build, fuse, timing and
scope evidence is in the [owning validation table](../README.md).
A downstream [whole-B consumer](../../public_deep/README.md) also passed.

Reproduce ordinary cases:

    cargo test --release --locked -p bfv-ciphertext-formation gold::program::dense_data_inventory::public_image::public_disclosures:: -- --test-threads=1

The full192 case is explicitly ignored by this command; select its exact name
under the owning held-process observer with --ignored.

## Remaining boundary

This is a fixed-public-input algebraic image under the original honest AIR,
degree/divisibility and ideal independent-cell premises. CSPRNG sampling alone
does not establish those premises. Residues need not form a globally valid
original trace. The owning [DATA research receiver](../../research_data/README.md) now checks
complete native frame acceptance in the programmed proof-ROM. Mixed-family
prior-state coupling, adaptive Fiat-Shamir/auxiliary/abort analysis, concrete PRG and
cryptography, Source/key/current-version association and admission remain open.
Network SQL, finalized locks and the complete500ms request are unmeasured here.
