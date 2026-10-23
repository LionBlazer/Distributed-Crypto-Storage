# Fixed-coin public Query disclosures

This private child of the owning `cfg(test)` Query image module samples the
joint algebraic view V from independently fixed public Expected, lookup/folding
coins, z, and unique physical S. It creates no original trace, private witness,
Query `Prepared`, configuration, proof, commitment or acceptance result.

`sample(QueryFoldProgram, QueryCoins, z, S, CryptoRng)` returns unverified native
Gold/EF5 columns with base rows, complete z claims and optional hz claims. The
fixed layout is R10(z), MAIN421(z,hz), Q8x10(z), PP545(z), AUX425(z,hz). Its types
are visible only inside the owning Query test hierarchy. A research consumer
may explicitly copy them into `public_deep::Column` or native frame structures;
this conversion supplies no production proof authority.

The actual image/fold and private ring arithmetic are its direct owning
dependencies. Native P3 domain splitting derives the eight normalized quotient
vanishing polynomials on 7H16384, each original chunk height 2048. The module
also uses native public-PP DFT, fixed Gold/EF5 aliases and rand0.10 `CryptoRng`.
It has no dependency on the research oracle, opaque tree or FRI assemblers.

For M from S/z and M_T from S/hS/z/hz, original MAIN416/AUX420 and their ten
appended columns are sampled uniformly in F[X]/M_T. The actual program computes
all five Q coefficient residues in F[X]/M using the SAME sampled originals and
lookup/folding coins. Seven independent masks per coordinate determine the
eighth by the actual c-weighted relation; chunks are Q_b+v_i*t_i. Five appended
quotient codewords are independently uniform across all eight chunks. R's ten
columns are uniform in F[X]/M. PP is evaluated from the actual zero-interleaved
public factory coefficients. At full disjoint192/genericz geometry this uses
846*394+85*197 = 350069 Gold cells. This count excludes raw RNG rejection draws.

These are the fixed-coin ideal-cell laws in
[QUOTIENT-IMAGE](../../../../../../../bfv-hiding-stark/src/hash/QUOTIENT-IMAGE.md)
and [R-DEEP](../../../../../../../bfv-hiding-stark/src/hash/R-DEEP.md), with their
honest original AIR, degree/divisibility, independent public inputs and source-
cell premises. Supplying a concrete RNG is a recipe, not proof of those premises.
The sampled residues need not form a globally valid original trace.

S must be unique, ordered, of length at most192 and in7H32768. Duplicate raw
native query indices must be deduplicated by the driver, with their original
order retained separately for repeated-row emission. z=0, z in H2048 and z in
the input coset reject before cell draws. Base z elsewhere and overlaps between
S/hS are supported. There is no quotient-rank exception at any zero v_i.
No mixing coin is used here; the whole-B consumer owns its nonbase-theta guard.

Four owning unit cases cover native normalized geometry, complete five-coordinate
fibers at192 locations, seven-dimensional kernel rank at all eight roots, and
preflight errors without RNG advance. Two research consumer cases compose
actual joint V with whole-B arithmetic and check same-coin coupling. These
six checks passed in the [bounded owning observations](../../RESEARCH-VALIDATION.md).
Their seeded public fixtures are not statistical distribution tests or private
participant data.

Full native proof/FRI assembly, salted-root/shared-oracle coupling, adaptive
Fiat-Shamir, abort and auxiliary-information conditioning, concrete PRG/security,
semantic application bindings and operation admission remain separate work.
