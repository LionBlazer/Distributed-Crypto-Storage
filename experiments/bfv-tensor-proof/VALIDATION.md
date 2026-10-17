# Native tensor-stage and shared-backend validation

Validated on 2026-10-17 against parent `1ee70c4d2a3359b367ae3b548dc7f9b42ef60a93`.
This proves one public ciphertext-derived tensor stage, not full MulRelin, source
formation, selection completeness, same-secret-key authority or SQL acceptance.
The full PostgreSQL objective, including live row locks, remains open.

## Implementation and boundaries

The pure [tensor circuit](../../crates/bfv-tensor-circuit/README.md) covers all
8192 native-NTT positions of one fixed Q5/P5 modulus: four complete operands
a0,a1,b0,b1 yield d0=a0*b0, d1=a0*b1+a1*b0 and d2=a1*b1 modulo p. Each result has
eight base-2^16 digit equations with canonical public quotients and seven bounded
shifted carries; both endpoint carries are zero. No high product limb is omitted.

The consumer creates genuine serialized Plonky3 proofs. Verification rebuilds
preprocessing and its own key from the complete trusted statement and bounded
auxiliary; it does not recompute tensor products or quotients. `CheckedTensor`
attests this stage only and cannot issue a production operation or SQL grant.

The [shared backend](../../crates/bfv-arithmetic-stark/README.md) now owns the
identical linked configuration and actual AIR security analysis used by RNS, NTT
and tensor consumers. Role wrappers, hashes, framing, decoder policy, public data,
keys, errors and lifecycle remain with each consumer. Existing RNS/NTT profile
function bodies are byte-exact; their 22 numeric report dictionaries are unchanged.
All prior owning tests were executed again, including all twenty genuine NTT cases.

## Environment and execution

Windows x86_64 MSVC; Rust/Cargo 1.99.0; pinned Plonky3 0.8.0; offline locked
dependencies; `RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two Rayon threads.
The fresh target is `.local/target-tensor-proof-r1`. Rust/DCS/Cargo-profile/target
environment overrides were cleared before setting the recorded environment.
Actual resolved `fhe-math` features are empty; `tfhe-ntt` has no nightly feature.
Root default members remain core libraries only. No existing root package record
changed; only the local backend package was added. Existing leaf registry records
are unchanged; new leaf registry checksums and resolved edges match/subset root.

| Gate | Observed result |
| --- | --- |
| Explicit rustfmt; strict all-target Clippy for backend and three consumers | All pass |
| Actual security analysis | RNS2 + NTT20 + tensor10 pass; old22 reports exact |
| Upstream polynomial oracle | All8192 coefficients of all3 outputs across all10 bases match actual SDK Poly multiplication/addition |
| Shared backend suite | 1 passed |
| RNS suite | 14 passed |
| NTT suite | 15 passed, including all20 genuine serialized stages |
| Tensor suite | 14 passed, including all10 genuine serialized stages, dropped sequentially |
| Standalone CLI | Bases0 and9 create, serialize and independently verify genuine proofs |

All 44 suite cases pass with zero ignored, failed or filtered cases. The focused
SDK oracle also ran separately before proof suites. Rebuilt canonical attacks
cover every output component, all quotients and all seven carries at the final
row, both missing middle terms, component ordering and range aliases. Raw SDK
adversaries construct real proofs under chosen equations or a foreign preprocessing
key; normal verification rejects them. Framing, context, profiles, complete-vector
binding, trailing bytes and resource guards have owning rejection cases.

The first focused-oracle driver selected the CLI test target, which contains zero
tests. Its count guard rejected the attempt; no oracle credit was assigned. The
corrected driver selects Cargo JSON artifacts with `target.kind == ["lib"]` and
checks the exact test name and count. Compiled source and binaries were unchanged;
the failed attempt is retained separately. No safety limit was widened to pass tests.

## Security and decoding

All ten tensor AIRs report height8192, main width1, public width61, PV40,
25 constraints, degree2, one quotient chunk and67 batched functions. The unchanged
fixed configuration uses Goldilocks/ext5, Poseidon2-12/rate8/digest4, binary MMCS
cap0, blowup8, 192 queries and zero grinding. Both individual SDK models report
128 bits. These figures do not establish a composed128 security claim.

The new consumer uses an8MiB frame,4096 elements per container and1048576 total
Serde container slots, including Goldilocks byte arrays. All ten genuine proof
decodes pass. [The policy derivation](README.md#bounded-stage-policy) gives a
conservative942743-slot allowance. Production2MiB, RNS8MiB and NTT16MiB frame
policies and their existing decoder budgets are unchanged. Container budgets and
array sizes do not prove a whole-peer RAM bound.

## Observed public-fixture process measurements

| Basis | Prove ms | Verify ms | Proof bytes | Outer process ms | Observed OS peak working set bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Q0 | 157.8382 | 95.1757 | 1396376 | 307.3250 | 73883648 |
| P4 | 149.8086 | 92.6196 | 1391992 | 307.7688 | 73879552 |

Rust proving includes public arithmetic/certificate, configuration, preprocessing,
proof and encoding. Verification includes bounded decoding, independent public
preprocessing/key and actual SDK verification. Those timers exclude initial CLI
analysis, fixture construction and startup. The observer includes complete owned
process time but its100ms polling adds completion-detection granularity.

The tensor14 suite took4.54s in its test harness; outer observation was4635.9298ms
over46 samples. Maximum observed OS peak working set was100618240B and sampled
private bytes95002624B. Actual sample gaps were100.0969–109.6688ms. The two CLI
children each yielded only three samples; their sampled private maxima were
51769344/54042624B. No1792MiB sampled soft fuse or timeout fired. Sampling can miss
short peaks and excludes other processes; these observations are not hard RAM
bounds, throughput results, a whole-query SLA or a distributed SQL measurement.

## Reproduction and retained evidence

The [README](README.md#owning-validation-gates) gives build, analysis, oracle,
suite and CLI commands. Run all ten security analyses before proof execution.
The ignored local evidence contains command arguments, environment/tool hashes,
exact source snapshots, logs, results, binary hashes and per-child memory CSVs:

| Receipt under `.local/tensor-proof-validation-r1/` | SHA256 |
| --- | --- |
| `source.json` | `EFBA15CE2F1DF48F9C94B054B985317E50CCF9C4634B728F912EF4DBA32DD057` |
| `compile/success.json` | `5CF41F8F9EABBDA868EA193AB1734334850E7EE0C909F7E717BEEEA4BA59FB2C` |
| `numeric/success.json` | `8EF7847F62BC4344CC4F1631A7102FB4CAD6EAF2EC6BF3B9ECECCB0C06FD055A` |
| `sdk-r2/success.json` | `B639FB07C74B77A3CC50964F0C06901A253D6425949F20698DB88DB746A30F6D` |
| `tests/success.json` | `074F91B4CF1F129BB02C4DA1C99271A80277EA12483D1A896EFA194ECCE02218` |
| `cli/success.json` | `B77F0B92811441C43BF32A3315B1462E929021623516B7DDF68E0FDB9724242E` |

These receipts locate inspectable artifacts, not cryptographic query evidence.
Donor manifests B2218C8C…/74445904… are source provenance only; all numerical,
SDK, proof, rejection and process observations above come from actual execution.
Requirements text and its AGENTS mirror remain identical and unchanged.
