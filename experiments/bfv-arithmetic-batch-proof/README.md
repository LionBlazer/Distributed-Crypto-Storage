# Atomic seventeen-relation public arithmetic batch

This standalone source candidate proves one fixed ordered batch of public BFV
ciphertext-residue relations: four `Extend5To10`, ten tensors in exact Q0..Q4,
P0..P4 basis order, then three `Scale10To5`. Each relation covers all 8192
coefficients and every output component. Inputs to different relations are
independent public vectors. There is no DAG edge, complete multiplication,
relinearization, source provenance, setup authority, completeness, freshness or
SQL admission claim. In particular, arranging the roles in this order does not
prove that one role consumes another role's output. Three mandatory proof units
cover exact ranges `[0,4)`, `[4,14)` and `[14,17)`. Acceptance is atomic across
all seventeen relations; there is no partial checked result or receipt API.

The cryptographic backend is non-hiding. Public non-secret fixtures represent
ciphertext-derived residues; no plaintext, secret key or private predicate witness
belongs in this experiment. The new main columns contain arithmetic certificates
derived from those public values. Aux bytes are never in the frame, public
preprocessing or public values, and the verifier never recomputes an auxiliary,
tensor multiplication, scaler, modular quotient or native SDK operation.

## Ownership

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-scale-circuit](../../crates/bfv-scale-circuit/README.md) | Complete fixed scaling equations, sealed public codecs and prover certificate conversion |
| [bfv-tensor-circuit](../../crates/bfv-tensor-circuit/README.md) | Complete three-component tensor equations and sealed codecs |
| [limb-range-air](../../crates/limb-range-air/README.md) | Exact fixed supports and checked prover histogram aggregation |
| [bfv-multilinear-stark](../../crates/bfv-multilinear-stark/README.md) | Fixed serial SHA512/WHIR configuration, generic actual-union assessment and whole-proof floor |
| [bounded-postcard](../../crates/bounded-postcard/README.md) | Per-decode nested sequence/aggregate allocation budget |

`statement` owns the immutable complete ordered frontend. `machine` delegates
all equations to the Core arithmetic owners and joins their histograms. `backend`
owns the distinct operation profile, actual per-unit SDK reports and conservative
whole-operation union bound. `proof` owns strict framing, canonical decoding and
genuine SDK proving/verification. `fixture` and
the CLI are public non-secret research consumers, never production admission.
Only this standalone manifest patches `p3-multi-stark` to the reviewed sibling
[streaming SDK experiment](../p3-multi-stark-streaming/README.md), with its
`streaming-lookups` feature. Each producer explicitly selects
`LookupMaterialization::Streaming` for its own batch; enabling the feature no
longer changes other callers' resident default. Integration adds the core-only `limb-range-air`
member and Scale/Tensor optional range dependencies to the root workspace and
lockfile. The root SDK still comes from the published registry package; existing
arithmetic profiles and frame caps remain unchanged.

## Complete expected statement

The independent caller supplies `Context { query32, setup32 }`, both nonzero,
and all seventeen exact canonical requests/outputs to `Expected::new`. Setup is
an identity label and does not prove same-secret evaluation keys or owner origin.
Each position's request binding is SHA256 of a fixed instance domain, complete
query/setup bytes, its u32 index and fixed role/basis tag. Repeated scaler roles
therefore have distinct bindings. The private range namespace derives from complete
query/setup bytes and the fixed phase ordinal under a new v2 domain. The global
instance-binding domain and all original request labels remain unchanged. These
hashes do not replace any missing source, key or SQL proof.

Request envelope header144 is magic8 `BFVABRQ2`, profile64, query32, setup32,
count17 as u32, zero4. Output header144 is magic8 `BFVABRO2`, profile64,
SHA512 of the complete request envelope, count17, zero4. Every ordered record
has length u32, role u8, basis u8 (255 for scalers), zero2, then the complete
unchanged Core canonical frame. Lengths and tags are fixed independently from
the position. Outer exact sizes precede child allocation; child codecs enforce
all canonical residues, roles, high bits and fixed vector lengths. Full copied
Q5 extension outputs are checked against their original inputs. `from_wires`
also requires exact canonical re-encoding and rejects trailing bytes. A caller
must pin these whole expected envelopes independently of an adversarial proof;
decoding an adversary's chosen statement establishes no external authority.

The distinct profile retains all 64 SHA512 output bytes and pins all old math
profiles, new compact layouts, supported ranges, bus names, ordered roles,
protocol descriptor and codec/resource policy. Shared configuration seeds
each unit's preprocessing setup and proof with its statement domain, a full64
component profile binding the outer profile plus count3/ordinal/exact range,
SHA512(full request envelope), SHA512(full output envelope). The fixed leaf,
node, Fiat-Shamir and statement domains are pairwise prefix-free.

## Actual AIR union and policy

Each unit includes its arithmetic tables followed by exactly one provider for
each required range. Extend4 uses R2/R9/R14/R15/R16 (nine tables total), Tensor10
uses R9/R16 (twelve tables), and Down3 uses all six ranges (nine tables). Provider
heights for R2/R9/R13/R14/R15/R16 are respectively16/512/8192/16384/32768/65536.
Both scalers' main width is160, with
public width 40/60 and 63 linear digit equations. Tensor main/public widths are
54/28, with 24 degree-two equations. All are PV0 and current-row only. Provider
main/public widths are 2/1, with one linear fixed-value constraint and
`Count::provided(-multiplicity)`. Exactly one histogram union supplies each
support within each phase; standalone duplicate providers never enter a unit.

The trusted analytical phase shapes are:

| Unit | Main cells / padded variables | Public cells / padded variables | Lookup atoms / padded variables | Main/public initial claims |
| --- | --- | --- | --- | --- |
| Extend4 | 5,473,312 /23 | 1,425,936 /21 | 5,358,096 /23 | 650/165 |
| Tensor10 | 4,555,776 /23 | 2,359,808 /22 | 4,489,728 /23 | 544/282 |
| Down3 | 4,178,976 /22 | 1,597,968 /21 | 4,055,568 /22 | 492/186 |

Range-query count weight across all units remains13,598,720. Provider leaves
also count toward actual lookup atoms, including zero multiplicities. All MAIN
and PP next-column lists are empty and PV count is zero. `Backend::new` derives
all constraints/degrees/interactions, claims and schedules from the SDK, checks
the exact phase shape, then requires actual finite per-proof security at least144
with no unassessed component. Before any main trace or proof, the prover assesses
all three units sequentially and requires `min(actual component bits)-2 >=144`.
The loss2 is `ceil(log2(3))`, a conservative union bound. Fresh verification
rebuilds all three reports and repeats that gate before constructing the sealed
result. No submitted report or prover-selected key participates in acceptance.
Outer sumcheck widths are derived from the maximum constraint and lookup
field/count degree plus the equality weight:2 for Extend,3 for Tensor,2 for Down.
The shared backend fixes Goldilocks/EF5, full SHA512 binary Merkle
hashes, serial PrefixProver, WHIR UniqueDecoding, phase target 160, folding 4,
zero PoW/OOD and collision evidence 256. These settings are not themselves an
executed security result; actual SDK assessment must succeed.

## Proof frame and lifecycle

Frame header320 is `BFVABP02` at0, profile64 at8, query32 at72, setup32 at104,
SHA512(full request) at136, SHA512(full output) at200, role count17 at264,
unit count3 at268, total payload length u32 at272, three u32 component lengths
at276, fixed phase boundaries `(0,4),(4,14),(14,17)` at288, and zero26 at294.
The payload is one canonical Postcard fixed `[Proof;3]`, which adds no count
prefix. One bounded deserialize call shares the nested budget across all three
proofs before Vec reservations. Per-component re-encoding checks the header's
exact byte boundaries; EOF rejects a fourth proof or any suffix. Missing,
duplicate, reordered or transplanted units cannot produce `CheckedBatch`.

The complete frame cap remains16 MiB; per-sequence and aggregate decode limits
remain16,384 and8 Mi container elements. Elements are not RAM bytes. No old cap
or profile changes. A component also must fit the conditional ceiling2,649,168
serialized bytes and1,675,589 decode elements. All three plus header are at
most7,947,824 bytes and5,026,767 elements under those guards.

`resource_bound` computes tighter bounds from each actual returned schedule.
The accepted folding is4, derived rates are4/7/10/13, and query ceilings are
`386,176,162,161,161` for MAIN23, or the first four values for MAIN22 and PP21/22.
Each actual query count must be positive and below its ceiling. Canonical
binary cap-zero authentication frontiers use the distinct-leaf bound
`2 + sum(level=1..d-1,min(q,2^(d-level))) - q`; repeated queries cannot increase
it. Layout checks enforce that bound, the exact row widths/counts, one commitment
root, zero PoW/OOD, current-only openings and exact sumcheck/GKR lengths.
The decode calculation deliberately uses the looser `q*26` siblings and counts
all Gold/EF5/array/struct containers. At the query ceilings with each phase's
exact claims, the formula gives:

| Unit | Conditional serialized bytes | Conditional decode elements |
| --- | --- | --- |
| Extend4 | 2,480,948 | 1,589,781 |
| Tensor10 | 2,554,948 | 1,593,229 |
| Down3 | 2,186,400 | 1,414,998 |
| Sum plus frame header | 7,222,616 | 4,598,008 |

These are source-derived conditional ceilings, not emitted proof lengths or RSS
measurements. A different SDK schedule or unexpected layout fails rather than
silently inheriting a bound. The full public Request and Output envelopes are
independent caller inputs; they are not duplicated in this proof frame.

The verifier checks the complete header before nested decoding, uses a fresh
bounded decoder and exact re-encoding, reconstructs each trusted public AIR/VK,
checks actual schedules/columns/rounds/lookup layers/WHIR topology and requires
the actual whole144 SDK verifier three times, then the conservative union floor.
It retains no Aux or main witness. Prover-selected
keys/preprocessing are not accepted. Panics from adversarial proof verification
become rejection. `CheckedBatch::matches` compares the entire independent
request/output envelopes and profile; it attests only these arithmetic relations.

`prove(context, requests)` obtains complete public outputs, assesses all three
real backends sequentially, then regenerates certificates and proves one phase
at a time. Each proof passes its own actual SDK verifier. The heavy phase scope
drops AIR/PP/PK/VK/PCS and raw proof storage before the next phase; only serialized
public proof bytes and reports escape. Fresh verification decodes the bounded
array and consumes its proofs sequentially, retaining one phase backend at a time.
`generation_ms` starts after request-shape/binding validation and includes public
arithmetic, all phase setup/assessment, trace construction, proof generation,
producer self-verification and frame encoding. It excludes fixture/request
construction and subsequent fresh verification. The CLI `prove`
prints a security report and a result record; its fresh-verification timer starts
inside `verify`, after reconstruction of the canonical public `Expected` from
saved envelopes. Public fixture objects and buffers are not a peer RAM budget.

## Validation and remaining integration

The owning tests cover actual upstream RnsScaler and Poly multiplication/addition
oracles for all 8192 outputs of all seventeen roles, prime-generation provenance,
a genuine three-unit full-batch proof/fresh verifier, full last-word/role/order binding,
canonical cap/topology rejection and coherent repaired-frame failures. Three
test-only attacker programs must each produce and pass their own genuine SDK
proof before the fixed consumer rejects them: an omitted range query hiding a
field-valued carry alias, omitted tensor component equations hiding a canonical
wrong quotient, and foreign complete public preprocessing. Local constraint
debugging is used only to identify which obligation an attack violates; it is
never credited as cryptographic lookup verification. The original nine test
names and their meaningful assertions remain. Three additional owning tests
cover each genuine phase's independent verification, repaired swaps/duplicates/
missing/extra units, full q/setup/last-outer-output transplants, and an actual
nested proof whose individual decode fits but three copies exceed the shared
aggregate budget. Test mutation obtains owned SDK proofs by codec roundtrip;
the backend Config does not need to implement Clone.

The [executed validation](VALIDATION.md) records 103 runtime invocations over 101
test configurations, strict Clippy, the default core graph and genuine full17
generation/fresh verification. Its measured frame was 6,505,688 bytes; generation
took 172,380.3214 ms and fresh verification 1,531.3598 ms in the recorded standalone
run. These measurements do not establish a SQL latency target. A fully linked
MulRelin proof, same-secret relinearization-key provenance, complete graph linkage
and all input/output source/privacy/freshness proofs remain separate open obligations.
This standalone batch and its measurements cannot establish that a
complete operation fits the unchanged 32 MiB Body, 64 MiB transport or 256 MiB
history limits, nor that the whole process fits the RAM target.

The standalone lockfile and reviewed sibling SDK are included. Reproduce with
`cargo test --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --lib -- --test-threads=1`,
and `cargo run --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml -- security` / `prove`.

`CheckedBatch::security_report()` borrows the verifier-owned
`backend::SecurityReport` formed by the existing `summarize` over all three
successfully verified phases. It retains their actual component reports and the
existing conservative whole bound `min(component bits)-2`; it does not use
`Generated.report` or submitted report data. Consumers can compose this whole
bound without counting its three phases a second time. This adds no graph, SQL,
setup-authority or freshness guarantee. The [full graph validation](../bfv-mul-relin-proof/VALIDATION.md)
includes all twelve owning tests, the explicit per-batch streaming mode and
actual aggregation of this report after successful verification.
