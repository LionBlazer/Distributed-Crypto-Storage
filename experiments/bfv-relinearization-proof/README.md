# Public BFV relinearization arithmetic STARK experiment

This standalone consumer proves either complete N8192 arithmetic stage
used by the pinned level 0/0, log-base 0 Q5 relinearization path. `Embed` maps five
PowerBasis residue vectors to 25 reduced vectors. `AccumulateAndAdd` maps 85
native-NTT vectors to ten vectors by adding all five digit/key products to each
original component. Native compilation, strict Clippy, actual security analysis,
SDK parity, both genuine serialized proofs and all 16 owning tests pass. See the
[validation report](VALIDATION.md) for measurements, reproduction and limits.

## Ownership and public contract

| Direct project dependency | Responsibility |
|---|---|
| [bfv-relinearization-circuit](../../crates/bfv-relinearization-circuit/README.md) | Fixed Q5 geometry, canonical sealed request/output/auxiliary, exact prover arithmetic and optional ArithmeticAir. |
| [bfv-arithmetic-stark](../../crates/bfv-arithmetic-stark/README.md) | Shared fixed linked SDK configuration, actual symbolic analysis and complete ProfileAir delegation. |
| [bounded-postcard](../../crates/bounded-postcard/README.md) | Fresh per-decode container budgets with the original Postcard encoding. |

The consumer owns its distinct transcript profile, frame, role caps, error mapping,
independent public preprocessing, proof lifecycle, CLI and tests. It uses the
shared `ProfileAir<ArithmeticAir>` to append eight consumer-profile words to the
library's 32 public values. It introduces no configuration or decoder visitor
copy. Its manifest has a private `[workspace]`; integration owns lock resolution.

Public entry points are `backend::analyze`, `prove`, `verify`, and the explicitly
PUBLIC NONSECRET `fixture::request`. `CheckedStage` has private role, context and
request/output digest fields and matches one full request/output. It cannot be
converted into CheckedOperation, authorize a mutation or accept a SQL answer.

Both roles bind independent binding32 and keyset-context32 values. The latter is
an external identifier, not proof of key generation, key ownership, same-secret
authority or registry admission. All inputs and outputs are public; these proofs
provide no hiding of their coefficient vectors or auxiliary certificates.

## Complete relation and verifier boundary

For embedding, source i, target j and coefficient k are ordered as
`(i*5+j)*8192+k`; the input is source-major. All 25 equations are
`r_i = E_ij + q_j*t_ij`. The quotient may be two and is not assumed boolean.
The public matrix has 55 columns: five inputs, 25 outputs and 25 quotients.

For accumulation, each target modulus has 17 input polynomials ordered
`original0,original1,D0..D4,K00..K04,K10..K14`. Outputs are target-major then
component. Each output satisfies `original_c + sum(D_i*K_ci) = out_c + q*quotient`
using all five terms. The 365-column matrix contains bounded limbs for all 85
inputs, ten outputs, ten quotients and their complete carry chains. Every final
carry endpoint is fixed by the library relation. No row, last coefficient or
outer component is omitted.

The proof frame starts with 112 bytes: magic `BFVRLP01`, consumer profile32 at 8,
binding32 at 40, keyset-context32 at 72, role at 104, representation at 105,
input/output counts at 106/107 and four zero bytes. It then contains the exact
role auxiliary and canonical SDK proof. Embed auxiliaries are 204976 bytes;
accumulation auxiliaries are 2130096 bytes. Headers and hashes bind the complete
request, output and auxiliary in their fixed ordering.

`prove` evaluates the public arithmetic/certificate, prepares the public matrix
and prover key, and generates a genuine linked SDK STARK. `verify` checks the
role cap and header, canonical auxiliary, bounded Postcard payload, no trailing
bytes, canonical re-encoding and exact log-height 13 (8192 rows). It then prepares its own complete
public matrix and verifier key and calls the actual SDK verifier. It does not
repeat embedding reduction, multiplication, division, carry generation, NTT or
relinearization, and accepts no prover-supplied verifier key.

The shared configuration fixes Goldilocks/Poseidon2-12, extension degree 5,
blowup 8 and 192 queries. The actual SDK analyzer must infer each wrapped AIR and
both individual security models must reach 128 bits. Main width 1, public values 40,
public width 55/365, declared degree bounds 1/2 and at most eight quotient chunks
are enforced. Actual analysis reports 26/61 constraints, degrees 1/2, one quotient
chunk and 61/371 batched functions for Embed/AccumulateAndAdd. Both individual
models report 128 bits. A sequence of separate stage reports does not establish
a composed 128-bit guarantee.

## Independent decoder policy and resource estimates

Embed uses an 8 MiB frame cap and 1048576 decoded container slots; accumulation uses
16 MiB and 2097152 slots. Both cap each container at 4096. Existing production,
RNS, NTT and tensor caps are unchanged. Binary Goldilocks charges eight byte-array
slots plus its parent field slot; extension and digest objects cost at most 48/37
including their parent slots.

At height 8192/blowup 8, binary depth 16 and 192 queries, a pruned sibling vector is
bounded by `sum(min(192,2^j),j=0..15)=1791`. Conservatively allowing three input
commitments, 16 FRI rounds, eight five-column quotient chunks and 65536 extra slots
gives 932087 slots for 55 public columns and 1482647 for 365. These source estimates
fit the distinct budgets; genuine serialized proofs for both roles pass bounded
decoding. The estimates are neither measured proof lengths nor RAM limits.

Public field arrays alone are 3604480/23920640 bytes, with blowup 8 arrays of
28835840/191365120 bytes. Main arrays are 65536/524288 bytes. These omit SDK
intermediates, keys, copies, buffers and allocator costs. No process RAM or latency
claim follows from these arithmetic sizes.

## Owning gates and upstream provenance

Two unignored SDK tests cover actual complete upstream behavior. Embedding uses
the real short `Poly` PowerBasis constructor to reduce every source row into all
five target moduli. The relinearization oracle creates one actual level 0/0 key,
uses five RNS-row constant spikes with zero c0/c1 to expose the ordered public
K_i through the public `RelinearizationKey::relinearizes` API, and compares all
ten output polynomials of both arbitrary three-component inputs and a genuine
encrypted two-by-two SDK product. Expected outputs come only from that SDK call.
The actual encrypted-product case also generates and verifies both full stage
proofs from those exact c2/key vectors, comparing their checked outputs with the
same independent SDK results. The intermediate 25 native transforms are
oracle-only checks, not proven links.
The test's parameters/key hash is explicitly local oracle context, not a complete
PublicSetup identifier or proof of same-secret authority. Secret keys in these
tests are explicitly PUBLIC NONSECRET fixtures and are never verifier inputs.

A separate unignored case generates, serializes, verifies and drops both full
stage proofs sequentially. Two public representative proofs are cached only for
rejection examples. Canonical attacks rebuild output digests and auxiliary data
before checking every output, omitted digit term, source order, outer component,
all ten MAC quotients and all five internal carries of the final output's chain.
Range aliases reject before field conversion. Raw SDK
adversaries prove chosen equations or a foreign public preprocessing statement;
the normal verifier must reject them. Decoder cases cover length, sequence/total
budgets, Goldilocks byte slots, truncation, trailing bytes and foreign headers.

Run with the pinned native Rust 1.99 toolchain, reviewed standalone lock, offline
cache and a fresh target. From the root:

```powershell
$ErrorActionPreference = 'Stop'
function Invoke-Checked { & cargo @args; if ($LASTEXITCODE -ne 0) { throw "Cargo failed: $LASTEXITCODE" } }
$manifest = 'experiments/bfv-relinearization-proof/Cargo.toml'
Invoke-Checked build --release --locked --offline --manifest-path $manifest
Invoke-Checked test --release --locked --offline --manifest-path $manifest --no-run
Invoke-Checked clippy --release --locked --offline --manifest-path $manifest --all-targets -- -D warnings
Invoke-Checked run --release --locked --offline --manifest-path $manifest -- security embed
Invoke-Checked run --release --locked --offline --manifest-path $manifest -- security accumulate-and-add
Invoke-Checked test --release --locked --offline --manifest-path $manifest --lib sdk_tests::complete_embedding_matches_actual_sdk_poly_reduction_in_every_source_target_and_last_word -- --exact --test-threads=1
Invoke-Checked test --release --locked --offline --manifest-path $manifest --lib sdk_tests::actual_sdk_ordered_key_probes_and_full_relinearization_match_arbitrary_and_encrypted_product_inputs -- --exact --test-threads=1
Invoke-Checked test --release --locked --offline --manifest-path $manifest --lib -- --test-threads=1
Invoke-Checked run --release --locked --offline --manifest-path $manifest -- prove embed
Invoke-Checked run --release --locked --offline --manifest-path $manifest -- prove accumulate-and-add
```

`security <role>` emits one actual report without a matrix or trace. `prove`
emits that report and one verified-stage JSON. Initial analysis and PUBLIC
NONSECRET fixture construction precede the proving timer. Proving includes exact
arithmetic/certificate, configuration, preprocessing, genuine proof and encoding;
verification includes bounded decoding, public setup and actual SDK verification.
The validation report also records an external observer's complete owned-process
time and sampled memory; neither those observations nor the CLI timers measure
a whole SQL query.

The [canonical key-source adapter](../../crates/bfv-relinearization-key-source/README.md)
now exposes the original c0 PowerBasis rows and exact seeded c1 NTT values. This
experiment has not yet linked that material into a complete operation.
Full relinearization still requires all digit/key/producer/output NTT links,
complete setup/request/stage binding and an explicit same-secret authority
decision. Full MulRelin additionally needs all tensor/scaling/NTT links and a
sound composition-security argument. Source formation, private custody, SQL
completeness, freshness, writer fences and decentralized agreement remain outside
this stage. It grants no production or network SQL acceptance and establishes no
practical query latency.
