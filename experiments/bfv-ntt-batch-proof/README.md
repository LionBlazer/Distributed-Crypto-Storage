# Atomic ordered NTT batch proof

This standalone experiment proves the complete ordered outer batch of 2, 4 or 8
independent native N8192 NTTs. Native validation passed numerical SDK parity,
genuine complete proofs, hostile frames and altered-program rejection; the
[validation record](VALIDATION.md) gives exact evidence and resource observations.
Every proof unit contains exactly two complete operations: outer2 uses one unit,
outer4 uses two, outer8 uses four. Mixed
directions and Q5/P5 bases remain explicit. The unchanged
[semantic NTT machine](../../crates/bfv-ntt-circuit/src/multistark/README.md)
supplies the arithmetic, private certificates and verifier-owned public IO. Its
original single-operation buses, profiles and tests remain separate.

The unit boundary limits simultaneously retained PCS/prover state. It does not
reduce the full eight-operation statement or permit a partial result. All three
measured CLI sizes passed the per-process soft resource gate. This does not
establish a whole-peer RAM bound or application-query latency. The separately
reviewed scoped `streaming-lookups` SDK remains required. Its public contracts,
the shared SHA512/WHIR config and the root workspace policy remain unchanged.

## Ownership and dependencies

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-ntt-circuit](../../crates/bfv-ntt-circuit/README.md) | Complete semantic NTT machines, private certificates and verifier-owned public IO |
| [bfv-multilinear-stark](../../crates/bfv-multilinear-stark/README.md) | Fixed SHA512/WHIR config and actual SDK security assessment |
| [bounded-postcard](../../crates/bounded-postcard/README.md) | Shared nested allocation accounting before deserialization reservations |
| [Scoped SDK](../p3-multi-stark-streaming/README.md) | Opt-in streamed counted-lookup proving with the unchanged verifier |

`Context` and `Expected::new` define the independent complete statement. `prove`
owns witnesses, setup and proof generation; `verify` owns reconstruction,
canonical decoding and all proof checks. Only `verify` can return `CheckedBatch`.
`backend::analyze` reports actual SDK schedules, terms and union accounting.
The public fixture module and CLI contain explicitly non-secret measurement
inputs; they are not a live SQL evaluator. The local SDK patch and lock belong to
this standalone workspace; no root manifest, lock or default graph was changed.

## Independent statement and atomic result

`Expected::new` takes q/setup labels and ALL ordered canonical Request/Output
vectors independently of the frame. Zero labels, missing/duplicate claims and
wrong global instance bindings reject. The v2 length-delimited full byte envelopes
include every coefficient after the legacy SHA256 headers. The outer SHA512
profile fixes all target roots/twiddles, component/framing policy and limits.
Each unit gets a distinct full SHA512 component profile containing that full outer
profile, component count, ordinal and exact range. Its fresh challenger absorbs
the FULL outer request and output envelopes. A unit for instances6..8 keeps the
original globally labelled Request bytes; it never retags them as instances0..2.
Only that unit's trusted private data buses use local0/1 namespaces.

The prover computes full outputs, drops each evaluation's Aux, then assesses every
unit's actual SDK report and the complete union floor before private trace
generation. It regenerates only the current pair's Aux, builds its trace, proves,
checks the strict layout and actually verifies with its own VK. The unit scope
drops raw proof, AIRs, PK, VK and PCS data before the next unit. Only serialized
public proof bytes and small diagnostic reports remain.

The verifier decodes one fixed proof array selected from Expected, reconstructs
each exact pair's IO/machine/config/VK and invokes actual SDK verification in order.
It does not evaluate NTTs, generate Aux or accept prover VKs/reports. Each actual
complete SDK report must be finite, fully assessed and satisfy144 bits. Before
creating the sealed `CheckedBatch`, it also requires the conservative union
`min(actual component security bits) - log2(component count) >=144`.
The report includes the actual terms, geometry, schedules and union loss0/1/2.
These terms are fixed-protocol assumptions, not a proof of hiding or a global SQL
composition theorem. No checked component or partial grant API exists.

## Frame, decoder and conditional bounds

This distinct v2 frame uses magic `BFVNTB02`, a 320-byte header, full
profile64, q32/setup32 labels, SHA512 of both full envelopes, outer count, total
payload length and four canonical u32 component lengths. Unused lengths and the
remaining reserved bytes must be zero. The opaque32 labels confer no setup/key
origin or freshness. Canonical Postcard payloads are the fixed arrays
`[Proof;1]`, `[Proof;2]` or `[Proof;4]`; arrays have no submitted length prefix.

Before deserialization, lengths must be nonzero exactly where independently
required, each at most the derived2,649,168-byte unit ceiling, and sum exactly to
the received payload. One bounded Postcard call shares sequence16384 and total
8Mi container-slot limits across ALL nested proofs before Vec reservations.
EOF, canonical re-encoding and every actual serialized component boundary must
match. The total frame cap stays16MiB. No old frame or v1 migration is accepted.

The following are conditional source bounds, enforced against schedules derived
by the unchanged shared config. Each pair must have main arity23/PP arity22,
fold4, rates4/7/10/13, zero OOD/PoW and query counts no larger than
main386/176/162/161/161 and PP386/176/162/161. The full current-only claim maxima
are990 main and330 PP, including inverse/inverse pairs. Outer/GKR rounds are23;
the outer count is derived from the largest actual table/lookup height.

For one binary cap-zero query phase of depth d and q queries, the canonical
pruned-frontier upper bound is
`2 - q + sum(min(q, 2^(d-i)), i=1..d-1)`.
Repeated queries only reduce distinct leaves. The checked phase depths are
main20/19/18/17/16 and PP19/18/17/16. They give at most19,790 sibling digests per
unit; layout checks this stricter bound, and the original SDK still checks the
actual query indices, frontier consumption and repeated-opening consistency.
Each digest has8 u64 words, at most80 serialized bytes. Gold binary values use8
bytes and EF5 uses40; all query rows, GKR/outer/WHIR values, opening evaluations,
cap roots, zero PoW scalars and finite structural metadata are separately counted
in `backend::resource_bound`. The derived sum must be <=2,649,168 bytes per unit.
Four ceilings plus the header are10,596,992 bytes, below16MiB.

Decoder accounting counts container slots, not bytes or RAM. Gold needs9 slots;
50 conservatively covers EF5 and its parent containers. Row lengths, loose
`q*26` authentication slots, all non-row field values, caps and structural slots
are counted separately. One outer array slot per unit is included exactly once.
The derived unit count must be <=1,675,589 slots, hence all four <=6,702,356 slots,
below8Mi. These analytical ceilings do not replace actual emitter/decoder gates
or whole-process resource sampling. The signed Body32MiB, transport64MiB and
Journal256MiB policies are unchanged; this experiment builds none of those
envelopes and grants no network admission.

## Owning gates

Public non-secret fixtures compare every coefficient against the actual native
CPU SDK for all20 direction/basis targets. Separate mandatory genuine tests for
outer2/4/8 keep independent process/time/resource evidence possible. Full8 hostile
cases repair outer headers after swapping, duplicating, omitting, extending or
transplanting genuinely produced components, and after q/setup/full-outer
last-coefficient changes. A nested hostile array fits individual component/frame
byte caps and each individual decode, but must fail the ONE shared total budget.
The four genuine weaker/foreign AIR cases first prove and verify under their own
altered programs/VKs, then fail the honest verifier.

Reproduction with Rust 1.99.0 and the reviewed lock:

```powershell
cargo run --release --locked --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml -- security 8
cargo run --release --locked --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml -- prove 8
cargo test --release --locked --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml -- --test-threads=1
```

Generation timing includes output evaluation, security/setup passes, regenerated
pair witnesses, actual proofs, own verification and serialization. Verification
timing includes one shared decode/canonicality pass, sequential trusted setup,
layout/security assessment, actual SDK verification and final union. CLI's
separate security analysis occurs before generation timing. The candidate proves
independent arithmetic only: no causal MulRelin chain, hidden WHERE, Source/key
authority, agreed head, finality, SQL grant or whole-peer1–2GB guarantee.
