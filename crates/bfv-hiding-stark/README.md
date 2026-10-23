# Fixed hiding STARK suite

The separate [`hash`](src/hash/README.md) module owns the extracted SHA-256
Merkle/full-prefix SHA-512 candidate. Closed consumers use distinct profiles and
result types; this does not replace the original suite or enable admission.

[`classical::analyze`](src/classical.rs) provides a separate fixed-multiplicity
diagnostic over trusted actual AIR metadata. The [classical note](CLASSICAL.md)
defines its conservative algebraic terms, original lookup inputs, numerical
policy and remaining composition premises. This report is not a proof or an
operation capability and is not evaluated on native proof paths.

[`transcript::inspect_separator`](src/transcript.rs) records the actual SDK
`DomainSeparator<FieldUnit<Val>>::seed` field observations alongside its protocol
identifier, pattern hash and delimited instance label. This public diagnostic
snapshot creates no RNG, configuration or proof; callers retain responsibility
for associating the supplied SDK separator with their actual protocol instance.
`SeedBinding::challenge_group_base_draws` inspects that same SDK pattern and
groups consecutive draws between observations. It preserves both the ten Gold
draws in a lookup challenge pair and all 192 index draws; zero grinding and hints
cannot create a fictitious observation boundary. Unsupported sampling shapes
reject. These counts support transcript analysis and supply no security verdict.

`transcript::inspect_argument` adds the fixed one-AIR hiding-PCS opening geometry
and actual SDK PCS/FRI seeds. It checks widths, salts and the total opening count,
using the owning assessor's already BASE-flattened AUX width. Its snapshots are
public diagnostics; they authenticate neither the supplied AIR association nor
the shared-permutation security model. It uses no batch-STARK dependency.

This crate owns the existing private-witness Goldilocks hiding-FRI implementation
previously held by the source-primitive experiment. The
[Owner validation](../bfv-key-transform/OWNER-KEY-VALIDATION.md) records actual
proofs, complete old regressions and observed resource limits.

The fixed suite uses pinned Plonky3 0.8.0, Goldilocks/EF5, Poseidon2 width 12,
HidingFriPcs, parallel Radix2Dit, height 512, committed degree 1024, 192 queries,
blowup 8, five random codewords, four field salt elements, and no grinding.
Input-tree salts, FRI-tree salts and polynomial masks use separate OS-seeded
StdRng 0.10.3 streams. Both analytical bounds must reach the existing individual
128-bit floor. This does not claim composed protocol security.

`config` constructs that suite. `analyze` derives the actual symbolic AIR bound
without a trace or proof; unsupported preprocessing, Boolean/boundary declarations
and unrepresentable metadata reject. `prove_with_config` and
`verify_with_assessment` are low-level SDK helpers: the trusted caller must retain
the same immutable AIR, public values, matching fixed configuration and analytical
parameters. They check shape and the actual proof-derived bound, but do not certify
that a caller-supplied configuration/assessment belongs to an AIR. They are not
admission tokens or a plugin policy.

Within one `analyze` call, a private symbolic-only view collects the actual base
and extension equations once and passes those same expressions to the SDK's
count and periodic-degree passes. It forwards the original AIR metadata and
degree hint. The view dies with that assessment; actual proving/verification
still evaluates the original immutable AIR. No proof result or cross-call
authority is cached. The [executed analysis validation](ANALYSIS-VALIDATION.md)
records full SDK-parameter parity and the measured component costs.

`poseidon::{write,evaluate}` owns the exact native-equivalent 248-column gadget.
`codec` owns the canonical bounded typed-proof mechanism and the existing fixed
next-row hiding proof topology. A caller constructs its topology from a trusted
operation policy; dimensions, roles, profile allowlists and byte/slot limits are
not selected by an incoming message. Current-row-only AIRs can use the engine,
but are outside this specific codec topology. The direct
[bounded-postcard](../bounded-postcard/README.md) dependency charges nested sequences
before reservation. Codec success must still be followed by real SDK verification.

The [key-transform library](../bfv-key-transform/README.md) and the historical
[source experiment](../../experiments/hiding-fri-sha256-gate/README.md) consume this
implementation. Operation profiles, Owner keys, SQL, request framing and lifecycle
ownership remain in those consumers. No process RAM bound follows from the array
allocation estimator. Goldilocks vectors, FFT/trace/LDE, PCS and SDK scratch buffers
are not securely erased by this crate.
