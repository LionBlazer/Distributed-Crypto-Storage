# Full N8192 NTT main-witness proof candidate

Native experimental validation passed: all twenty actual security reports,
full upstream SDK parity, all twenty genuine serialized proofs and thirteen
unignored owning tests. The standalone CPU smoke and full test process were
measured; see [the exact results and limits](VALIDATION.md). This experiment certifies one public, nonsecret NTT stage
for one of ten fixed Q5/P5 bases. It provides no MulRelin, SQL, freshness, key
ownership or production acceptance capability. The main trace is not hiding.

The consumer owns its SHA-512 transcript, WHIR configuration, security floor,
framing, bounded decoding and checked stage marker. The optional `multistark`
module in `bfv-ntt-circuit` owns fixed arithmetic, native routing, canonical codecs,
public preparation and witness layout. `bounded-postcard` owns allocation-budget
accounting. This consumer does not depend on an older proof consumer or change an
existing operation, profile, proof cap or decoder policy.

## Statement and verification

`prove(&Request)` evaluates the existing sealed arithmetic certificate and creates
one multi-AIR proof for all thirteen forward layers or fourteen inverse layers,
the input/output table and four range tables. `verify(&Request, &Output, frame)`
receives no auxiliary certificate. It constructs all fixed routing, roots,
weights, range domains and expected complete input/output preprocessing itself,
then derives its own VK. No prover-selected VK is accepted. Verification does not
run the BFV NTT, butterfly, quotient or carry evaluator. The PCS still encodes and
commits the verifier's public tables; this is real work, included in timings.

Every copy message carries the original index and all four radix-2^16 limbs.
Ordinary output multiplicity is two, the inverse pre-normalization output and
final output have multiplicity one, and expected input/output are bound through
the IO table. Outputs and their slack have three 16-bit limbs and a 14-bit top
limb, with `z + slack = q - 1`. Quotients are 66-bit unsigned values biased by
2^64; seven internal carries are 25-bit values biased by 2^24, with both endpoint
carries fixed to the bias. Eight complete integer digit equations have sides
below 2^42, below the Goldilocks modulus. R16/R14/R9/R2 lookups enforce every
specified digit; x/y inherit their canonical limbs through the complete copy
arguments. Range table multiplicities are committed histogram witnesses, not
values trusted from a peer.

| Direction | Main cells / raw bytes | Public cells / raw bytes | Lookup atoms | Static count weight |
| --- | ---: | ---: | ---: | ---: |
| Forward | 3,900,448 / 31,203,584 | 1,327,632 / 10,621,056 | 3,293,712 | 3,317,760 |
| Inverse | 4,187,168 / 33,497,344 | 1,417,744 / 11,341,952 | 3,531,280 | 3,555,328 |

The atom count pads to 2^22. Static count weight is a different LogUp accounting
quantity; provided range entries contribute zero to that weight. Stage main
width is 35, public width 11; IO is 1/9. Range tables are 2/1 at heights
65,536, 16,384, 512 and 16 (the last repeats 0..3 four times). All AIR public value
vectors are empty. The complete SHA-512 statement seed binds every canonical
request and output byte, direction, basis, root, native order and full layout.
The old codec's SHA-256 fields remain byte-compatible but are not the sole new
cryptographic statement binding.

## Backend and security gate

Plonky3 0.8.0 at commit `a21e3ed42905040ad49c519e402f018381c12d0c` supplies
multi-STARK, global LogUp, fractional GKR, sumcheck and WHIR. This candidate uses
Goldilocks with a degree-five extension, full 512-bit SHA-512 Merkle leaf/node
outputs and full 512-bit Fiat-Shamir output, each under its own fixed domain.
Its declared hash collision cap is 256 bits. HashChallenger is initialized with
fixed version/domain bytes, the complete 64-byte consumer profile, and SHA-512
of each COMPLETE canonical request/output wire; no half hash or digest-of-old-
SHA256-header shortcut is used.

Main and public PCS stacked arities are 22 and 21. WHIR starts at rate 1/2,
constant folding four, UniqueDecoding, per-term target 160 and zero PoW. Empty
`round_log_inv_rates` invokes the published derived-rate schedule
(`p3-whir/src/parameters/whir.rs:540`); UniqueDecoding returns zero required OOD
samples (`p3-security/src/whir/mod.rs:94`). The SDK stops folding at at most six
variables (`p3-whir/src/parameters/folding.rs:9`), so the actual 22/21 schedules
leave six/five final variables. These are checked SDK-derived values, not omitted
soundness work. A fresh challenger is created for setup and separately for each
proof/verification; setup's challenger state is discarded.

`backend::analyze(direction, basis)` constructs actual job-specific public setup
but no main trace or BFV NTT evaluation. Its report is the SDK's complete union
accounting, including lookup, AIR, opening and collision terms. Missing,
unassessed, nonfinite, or below-144-bit whole-statement bounds reject before
proving and again during verification. Requested per-term target 160 is not a
measured or inferred whole bound. All twenty reports must be reviewed before
native proof gates. No old per-stage 128-bit result is relabeled as this bound,
and no single-stage result is extended to a chain or the full SQL system.

## New frame and allocation policy

`BFVNTW01` frames have a fixed 256-byte header: full profile64, binding32,
direction/basis and representation tags, SHA-512 of COMPLETE canonical input and
output bytes, payload length, table count and zero reserved fields. There is no
auxiliary certificate on the proof wire. The new frame cap is 16 MiB, sequence
cap 16,384 elements and aggregate decode cap 8 Mi elements. Existing proof
consumers retain their own policies. Bounded Postcard decoding precedes SDK
verification, rejects trailing bytes and requires byte-identical canonical
reencoding. Fixed proof topology and bounded WHIR opening shapes are checked
before SDK evaluation. SDK panics on adversarial verification input are caught
and rejected.

The source envelope allows at most six query phases, 512 queries per phase,
16 values per row, Merkle depth 22 and a final polynomial of at most 64 extension
values; actual derived schedules must meet those bounds. An unpruned phase has
at most `512*22 = 11,264` sibling digests, below the sequence cap. Conservatively,
both PCS together use at most
`2*6*(512*16*40 + 512*22*80) = 14,745,600` wire bytes for query values and full
SHA-512 digests. Typed decoding charges at most 48 slots per extension value and
9 per full digest, giving 5,941,248 slots for those parts; the remaining GKR,
sumcheck, evaluations and metadata have more than 1 Mi slots/bytes of headroom.
These are allocation-policy derivations, not actual proof sizes or RAM bounds.
The frame/decoder reject if actual serialization exceeds policy.

Raw main plus public tables are about 40/43 MiB. They exclude the extension-field
lookup reduction, WHIR codewords, trees, transposes, temporary copies and allocator
overhead. Peak process RAM is much larger: the measured forward-0 CLI had an OS-reported
peak working set of 867,315,712 bytes, and the complete thirteen-test process
reached 917,577,728 bytes. These are sampled observations with a soft fuse, not a
hard RAM bound or the memory of a complete peer/SQL operation. No latency SLA or
speedup is established.

## Owning examples and reproduction

The source tests compare every coefficient for all ten Q/P bases and both
directions against the actual feature-selected `fhe_math::ntt::native::NttOperator`.
A real SDK impulse pins root, native ordering and inverse normalization. Twenty
genuine serialized proofs are mandatory and unignored, generated sequentially;
only four public representatives remain for independent negative examples.
Test-only hostile AIR adapters create actual SDK proofs of weaker or foreign
programs and positively verify each proof under its attacker-owned AIR/VK before
honest rejection. Range and address attacks preserve every local integer equation
and isolate the missing global link. Other attacks weaken carries, quotients,
normalization, the final butterfly, multiplicities or complete IO preprocessing.
All thirteen examples executed successfully, with zero ignored cases.

Reproduction uses the reviewed standalone lock, a separate target,
pinned Rust 1.99, `--locked --offline`, bounded build/Rayon threads and the exact
reviewed P3 feature graph. No network/download behavior is part of these commands.
After compilation and strict Clippy, complete all twenty security commands and
the real SDK oracle before genuine and negative proofs under the process fuse:

```powershell
cargo build --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml
cargo test --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml --no-run
cargo clippy --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml --all-targets -- -D warnings
# Invoke the built executable directly for all directions x basis 0..9:
bfv-ntt-witness-proof security forward 0
bfv-ntt-witness-proof prove forward 0
cargo test --release --locked --offline --manifest-path experiments/bfv-ntt-witness-proof/Cargo.toml --lib -- --test-threads=1
```

The CLI `security <forward|inverse> <0..9>` emits one actual report; `prove` emits
that report followed by an experimental verified-stage record. Initial CLI
security setup and fixture construction precede the library proving timer.
Prover timing separately includes certificate arithmetic, public setup, then
trace/proof/encoding; verifier total includes bounded decode, public setup and
SDK verification. An outer owned-process timer additionally includes startup,
initial CLI report/setup and fixtures. No timer is a whole SQL or MulRelin timer.
