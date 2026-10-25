# Dense DATA public image arithmetic

This private cfg(test) child evaluates the actual DATA FullAir and automatically
packed LogUp constraints in a finite polynomial quotient ring. It derives
DATA's own MAIN512/PP668/PV32, 243 original messages packed into 81 lookups,
82 extension AUX columns retained as 410 separate base polynomials, and the
native global stream of 1248 base plus 84 extension constraints.

DataFoldProgram::from_expected, DisclosureDomain::checked, PublicResidues::checked
and DataFoldProgram::fold retain only public Expected, public PP, supplied public
residues and public fixed coins. They return all five coordinate quotient
residues modulo M. Source M_T permits X and hX projection into M without assuming
rotation is an endomorphism of M_T. Degrees are bounded by 197/394 for at most
192 physical 7H32768 points and one EF5 OOD orbit.

## Ownership and dependencies

| Dependency | Role |
| --- | --- |
| [native.rs](../native.rs), [layout.rs](../layout.rs) | Actual DATA FullAir, prescreen, bus and fixed dimensions |
| [hash_wire.rs](../hash_wire.rs), [hash_setup.rs](../hash_setup.rs) | Existing closed frame checks and sealed PUBLIC native PP factory |
| [Shared coefficient ring](../../public_image_ring.rs) | Private cfg(test) program-owned pure Gold/EF5 polynomial arithmetic; also used by Query |
| Pinned P3 0.8 | Actual symbolic emission, packing, independent concrete folder, DFT and MMCS |

The common arithmetic implementation and its small test were moved byte-for-byte
from Query into the shared test-only owner. DATA and Query keep their own AIR,
Expected, profile, residue domains and dimensions. Normal builds acquire no
research API, configuration, new dependency or changed acceptance rule.

## Executed checks

The small DATA folder case compares every coordinate at base z=49 and rejects
wrong source-domain association, missing AUX coordinates and invalid locations.
The projection case checks both maps and Frobenius-orbit preservation. The
shared Ring example and existing Query native-folder example also pass after
the ownership move.

The first opt-in full case compares 960 coordinate values at 192 base points,
then all five coefficient-Frobenius embeddings at fixed nonbase z. The actual
SDK folder is called 197 times. A nonzero P_S*((X-2)-u) control is invisible
to the base points and first OOD map but detected by the other four.

The second opt-in case checks every 4096*668=2736128 zero-interleaved PP cell.
Naive H2048 interpolation differs at nonbase z. A full bit-reversed 7H32768 LDE,
committed with genuine native MMCS and unchanged public stream label0, has
exactly the cap from the sealed native public factory. The first factory's
prover-only storage is dropped before the second full matrix is made.

| Run | Exact case | Harness | Process wall | Sampled OS peak |
| --- | --- | ---: | ---: | ---: |
| r861 | DATA native folder, base z | 0.21 s | 236.7913 ms | 75,386,880 B |
| r862 | DATA projections and Frobenius framing | 0.00 s | 7.6976 ms | 5,435,392 B |
| r863 | Shared Ring example at its new owner | 0.00 s | 7.6869 ms | 5,410,816 B |
| r864 | Existing Query native-folder regression | 0.20 s | 206.8094 ms | 62,996,480 B |
| r865 | DATA full192/five-coordinate native folder | 2.54 s | 2547.6160 ms | 136,462,336 B |
| r866 | All DATA PP cells and actual native cap | 0.18 s | 185.2442 ms | 210,931,712 B |

All six exact cases report one passed and zero ignored; the two heavy ignored
targets were explicitly selected. Optimized build r859 executable SHA256:
`1C06DBACF5163C0E122BE2D6ACBF3F1711C945D293383069589173AAE34D5AC2`.
The existing held-process 120-second/1792-MiB fuse and Rayon8 were unchanged.
Source/image pins matched and no observer fault or cleanup occurred. Strict
Clippy r858 passed after removing duplicate module loading and correcting two
constant-chunk iterator calls. Independent source review found no blocking defect.
A cache-node count alone is not an analytical whole-process memory guarantee.

Ordinary owning checks can be run with:

    cargo test --release --locked -p bfv-ciphertext-formation gold::program::dense_data_inventory::public_image:: -- --test-threads=1
    cargo test --release --locked -p bfv-ciphertext-formation gold::program::public_image_ring:: -- --test-threads=1

The first filter leaves the two heavy cases ignored. Select each exact target
under the owning held-process observer for the complete measured checks.

## Remaining boundary

Arbitrary public residues are not claimed to be a valid DATA witness. This module
does not sample joint V, construct B/FRI or produce a DATA proof. Source/key/current
version authority, adaptive privacy, concrete cryptography, production admission,
network SQL, locks and the complete 500-ms request remain separate requirements.
These test durations are not full SQL latency measurements.
