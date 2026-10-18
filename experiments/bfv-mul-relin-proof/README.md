# Exact fixed BFV multiplication and relinearization graph

This standalone research consumer connects two complete original BFV ciphertexts
to the exact two-component ciphertext produced by the actual SDK multiplication
and relinearization. N8192, Q5, P5, t114689, level0/0 and log-base0 remain fixed.
It accepts public encrypted polynomials, never plaintext rows or a public WHERE.
The separate client compiler keeps the predicate, constants and mask private.
Full PostgreSQL, locks, completeness against agreed storage and freshness remain
unimplemented by this mathematical composition.

## Ownership and direct dependencies

| Entry/module | Responsibility and direct owners |
| --- | --- |
| `Provenance`, `provenance.rs` / `Verifier::verify_inputs` | Constructor pins original [PublicSetup/anchor](../../crates/bfv-query-core/README.md), full [encoding statements](../../crates/registry200-proof/src/coefficient_encoding/README.md), original ciphertexts and query; input admission actually verifies Key, Source, both encodings, ten [Basis](../../crates/bfv-basis-convolution/README.md) and two [Formation](../../crates/bfv-ciphertext-formation/README.md) proofs |
| `GraphClaims`, `claims.rs` | Complete canonical typed proposed vectors; [NTT](../../crates/bfv-ntt-circuit/README.md), [Scale](../../crates/bfv-scale-circuit/README.md), [Tensor](../../crates/bfv-tensor-circuit/README.md) and [Relin](../../crates/bfv-relinearization-circuit/README.md) codecs |
| `Expected`, `PreparedGraph`, `graph.rs` | Derive every request from immutable original endpoints and fixed full-vector edges; borrowed [ciphertext wire](../../crates/bfv-ciphertext-wire/README.md); immutable [PreparedKey](../bfv-complete-relinearization/README.md) and shared pure Relin routing |
| `Prover`, `prover.rs` | Evaluate public encrypted polynomials, then sequentially produce actual proofs; no checked result constructor |
| `Verifier`, `verifier.rs` | Actual [NTT](../bfv-ntt-witness-proof/README.md), [Relin](../bfv-relinearization-multilinear-proof/README.md) and [atomic arithmetic17](../bfv-arithmetic-batch-proof/README.md) verification; bounded admission and output-only SDK report aggregation |
| `profile.rs` | Bind the exact schedule, primitive profiles, grammar and lifetime limits; SHA512 graph/node domains |

The fixed geometry crate owns parameter constants. `fhe`, `fhe-math` and
`fhe-traits` decode public input ciphertexts in the prover and independently
expand original public seeds during preparation. The graph edge verifier does
not re-evaluate an NTT or the query. The existing Basis input verifier separately
performs public ciphertext decoding/representation conversion and public
preprocessing; this is not a claim of transform-free input admission.
SHA256/SHA512 and the existing p3 field ABI
retain their original purposes. The private workspace pins the reviewed local
streaming p3-multi-stark dependency; core/default members have no new dependency
on this experiment. The existing primitive AIRs and profiles are unchanged.

## Complete graph and endpoint bindings

| Node IDs | Operation |
| --- | --- |
| 0..19 | Inverse Q transforms for all four original native components |
| 20..23 | Extend each complete PB Q5 component to QP10 |
| 24..43 | Forward P transforms for the four extended components |
| 44..53 | Tensor product at every Q/P modulus |
| 54..83 | Inverse QP transforms for all three tensor components |
| 84..86 | Scale each complete QP10 component down to Q5 |
| 87..96 | Forward Q transforms of downscaled c0 and c1 |
| 97 | Embed downscaled PB c2 directly into all25 digit rows |
| 98..122 | Forward Q transforms of all25 digit rows |
| 123 | Full MAC with both originals, all25 digits and all50 pinned key rows |
| 124..133 | Inverse Q transforms of both final components to exact SDK PB wire |

This removes the cancelling forward/inverse c2 conversion in the SDK operator
route; the resulting PB c2 follows the SDK Multiplicator route. There are115 NTT
nodes (55 forward,60 inverse),17 arithmetic relations and2 Relin relations.
Output transport uses118 records: one atomic arithmetic frame containing3 SDK
proofs,115 single NTT proofs and2 Relin proofs, totaling120 output SDK proofs.
The16 unique input proofs are separately mandatory; shared prerequisites are
actually reverified rather than accepted as serialized receipts.

All8192 coefficients at every modulus participate. Original stored components
match their complete PB bytes; seeded c1 matches the exact original SDK NTT seed
expansion. Both final PB components must equal every canonical output coefficient.
The output is unseeded and carries the actual SDK key-switch variable-time flags.
Preparation parses the fixed wire without SDK deserialization or query transforms.

Raw coefficients of all claims, original complete setup identity, full Encoding
PV/Cw, Source packets/heads, query, original ciphertexts and proposed output define
one SHA512 graph identity. Child headers are excluded from that raw identity and
then independently derived, avoiding a binding cycle. Every request digest and
binding is checked; peer-provided requests cannot replace edges. Claims and
prepared requests remain unverified until actual proof admission finishes.

## Limits, security and lifecycle

Claims are exactly16,727,920 bytes, within the16 MiB claims cap. Each proof record
has a160-byte fixed header and at most16 MiB inner proof. Input evidence has its
existing per-frame caps and a348,130,800-byte aggregate ceiling. The complete
session charges every failed and successful call against240 attempts and
`MAX_SESSION_BYTES`; cancellation and exhausted lifetime limits reject finish.
These are research collection limits, not network frame or process RAM promises.
No existing Body32 MiB, transport64 MiB or historical stream cap is enlarged.

Admission order is claims, actual input evidence, the atomic arithmetic block,
then ascending remaining node IDs. Missing, duplicated, reordered or substituted
records cannot produce `CheckedProduct`. One decoded proof/backend is dropped
before the next output proof. Preparation retains the complete bounded graph;
there is no persistent/global cache or externally minted checked-prefix receipt.

Each actual rebuilt primitive verifier returns its local SDK assessment. The
output union sums115 NTT reports,2 Relin reports and the arithmetic report once;
the latter already accounts for its3 phases. Every report must be finite, have
no unassessed term and meet144 bits, and the output union must also meet144.
Input proofs retain their original individual128 policies. `CheckedProduct`
therefore makes no whole-protocol128/144, fresh-head, authorization or SQL grant.
An original owner/application must supply the setup anchor independently; same-
secret public relinearization-key validity is still an explicit unmet requirement.

## Verification entry points

The package tests check the full claim codec, strict record grammar and complete
proof-obligation coverage. The actual private-drop integration lives at the
consumer that owns the Source, private predicate and Formation witnesses:
[full product test](../hiding-fri-sha256-gate/src/opening/coefficient_encoding/input_formation/full_product.rs).
It compares the exact result to the independently executed actual FHE operation,
rejects a genuine foreign NTT proof with a repaired outer envelope, tests final-
coefficient and lifetime failures, then rebuilds and verifies from public frames
after the prover and old decoded graph have been dropped. The
[executed validation](VALIDATION.md) records exact source/receipt identities,
1013 configuration invocations over553 distinct owning cases, full output
verification, measured bytes/time/resources and the remaining integration limits.

```text
cargo test --release --locked --manifest-path experiments/bfv-mul-relin-proof/Cargo.toml
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::coefficient_encoding::input_formation::input16_and_all134_product_nodes_verify_exact_ciphertext_after_private_drop -- --exact --test-threads=1 --nocapture
```
