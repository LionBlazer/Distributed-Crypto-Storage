# Native relinearization-stage and profile-wrapper validation

Validated on 2026-10-17 against parent `64f83c1b8eda5ceb25713c2905b45ab0f25364a3`.
This covers two complete public arithmetic stages, not linked relinearization,
full MulRelin, private SQL computation or SQL acceptance. The full PostgreSQL
objective, including live `FOR UPDATE` and `SKIP LOCKED`, remains open. There is
no fixed 500 ms target; these are measurements of the stated stage boundaries.

## Relation and ownership

The [pure circuit](../../crates/bfv-relinearization-circuit/README.md) owns exact
N8192/Q5 arithmetic. Embed consumes all five PowerBasis rows and produces all
25 source/target reductions, including reachable quotient two. AccumulateAndAdd
consumes all 85 native-NTT polynomials and produces ten outputs using every
original component and all five digit/key terms. Its integer limb equations
cover every quotient, shifted carry and both zero carry endpoints.

The consumer creates genuine serialized Plonky3 proofs and verifies them with
independently reconstructed public preprocessing and verifier keys. Verification
does not repeat reduction, multiplication, division, carry generation, NTT or
key switching. `CheckedStage` attests only the supplied public stage; its context
identifier establishes no key origin, same-secret authority or SQL permission.

The [shared backend](../../crates/bfv-arithmetic-stark/README.md) now also owns
`ProfileAir<A>`. It forwards the inner AIR evaluation and all 14 pinned `BaseAir`
hooks, including explicit periodic overrides, and declares eight additional
public values. Its helper encodes the consumer digest; consumers append those
words after the existing 32 values. Consumers retain profiles, prepared-data admission,
role/shape checks, frame and decoder caps, independent keys, errors and lifecycle.
All three existing profile digest functions and 43 existing consumer test bodies
are unchanged; their complete suites ran again. All 32 preceding numeric report
dictionaries are exact matches.

## Environment and actual gates

Windows x86_64 MSVC; Rust/Cargo 1.99.0; pinned Plonky3 0.8.0; locked offline
dependencies; `RUSTFLAGS=-C target-cpu=native`; two Cargo jobs and two Rayon
threads. Validation used a fresh `.local/target-relinearization-proof-r2` after
clearing Rust/DCS/Cargo-profile/target environment overrides. Actual `fhe` and
`fhe-math` feature sets are empty; `tfhe-ntt` has no nightly feature. Root defaults
remain core only. Root and existing leaf registry package records are unchanged;
only the local backend's direct edge to already-pinned `p3-matrix` was added.
The new leaf's registry checksums and dependency edges match/subset root.

| Gate | Actual result |
| --- | --- |
| Explicit rustfmt and five strict all-target Clippy checks | Pass |
| Actual symbolic/security analysis | 34 pass: RNS2, NTT20, tensor10, relinearization2 |
| Focused SDK gates | Both exact libtest cases pass separately |
| Shared backend suite | 2 pass |
| RNS suite | 14 pass |
| NTT suite | 15 pass, including all 20 genuine serialized stages |
| Tensor suite | 14 pass, including all ten genuine serialized stages |
| Relinearization suite | 16 pass, including both SDK cases and both genuine stages |
| Standalone CLI | Both roles create, serialize and independently verify genuine proofs |

All 61 suite cases pass with zero failed, ignored or filtered cases. Each focused
SDK invocation runs one named test with the other 15 deliberately filtered.
The embedding oracle uses the actual short upstream `Poly` constructor and
compares all five sources, five targets and 8192 coefficients. The second oracle
uses five public ordered-key probes through `RelinearizationKey::relinearizes`,
then compares all ten output polynomials for arbitrary three-component inputs
and an actual encrypted two-by-two SDK product. Expected results come only from
the SDK. For the encrypted-product inputs it also creates and independently
verifies both complete arithmetic proofs. All 25 intermediate transforms remain
oracle-only checks; this does not prove their links.

Rejection examples rebuild canonical output hashes and certificates before
attacking every output polynomial, all ten MAC quotients and all five internal
carries of the final output's chain,
embedding quotient two, missing digit terms, source/key order and outer component
order. Actual raw SDK adversaries prove chosen equations or foreign preprocessing;
the consumer rejects them. Other examples cover residue aliases, exact full-vector
binding, foreign profiles/contexts, canonical framing, truncation, trailing bytes,
container limits and Goldilocks byte-slot charging.

The initial R1 attempt stopped at new-consumer compilation with E0284: two
`try_encrypt` results needed explicit `Ciphertext` types to distinguish BFV from
RGSW. Only those two type annotations changed. Failed logs and ten preceding
compiled artifacts remain preserved; no R1 proof or security result is credited.
R2 uses a fresh source snapshot and target. No arithmetic, profile, cap, oracle
or test name changed to obtain the passing result.

## Individual security and decoding policy

| Role | Main / public width | PV | Constraints | Degree | Quotient chunks | Batched functions | Both individual models |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Embed | 1 / 55 | 40 | 26 | 1 | 1 | 61 | 128 bits |
| AccumulateAndAdd | 1 / 365 | 40 | 61 | 2 | 1 | 371 | 128 bits |

Height8192, Goldilocks/ext5, Poseidon2-12/rate8/digest4, binary MMCS/cap0,
blowup8, 192 queries and zero grinding are unchanged. These SDK reports are
individual bounds, not a composed 128-bit guarantee.

Embed uses an 8 MiB frame and 1048576 total decoded container slots;
AccumulateAndAdd uses 16 MiB and 2097152 slots. Both limit one container to4096.
The [source derivation](README.md#independent-decoder-policy-and-resource-estimates)
gives conservative allowances of932087/1482647 slots. Both actual proof decodes
pass these independent policies. Existing production/RNS/NTT/tensor frame and
container budgets are unchanged. Array sizes and container limits establish no
whole-peer RAM bound.

## Observed public-fixture process measurements

| Role | Prove ms | Verify ms | Proof bytes | Outer process ms | Observed OS peak working set bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Embed | 143.9946 | 86.0340 | 701672 | 307.5897 | 71118848 |
| AccumulateAndAdd | 489.6170 | 420.1497 | 3121753 | 1011.5389 | 260866048 |

Proving includes exact public arithmetic/certificate, configuration,
preprocessing, actual proof and encoding. Verification includes bounded decoding,
independent public preprocessing/key and SDK verification. CLI timers exclude
initial security analysis, fixture construction and process startup; the observer
includes complete owned-process time with completion-detection granularity.

The 16-case relinearization suite took8.76s in its harness and8844.3174ms in the
observer, with88 samples, observed OS peak516427776B and sampled private
maximum511152128B. Actual sample gaps were100.1226–100.8914ms. The focused
encrypted-product SDK case took1311.5100ms externally, with13 samples, OS
peak341807104B and sampled private331956224B. The two CLI children had3/10
samples and sampled private maxima52506624/233746432B. No sampled1792MiB soft
fuse or timeout fired. Sampling can miss short peaks, excludes other processes
and does not prove a hard RAM bound, throughput or distributed query latency.

## Reproduction and retained evidence

The [README](README.md#owning-gates-and-upstream-provenance) gives locked build,
analysis, oracle, suite and CLI commands. Analyze both roles before proof execution.
Ignored local evidence retains exact commands, environment/tool hashes, source
snapshots, logs, results, per-child memory CSVs and compiled binary hashes:

| Receipt under `.local/relinearization-proof-validation-r2/` | SHA256 |
| --- | --- |
| `source.json` | `8DD633F60B0A6C97CCD61E8FCA10FADA8A5D56CE60A971E46E20B966DD1188A2` |
| `compile/success.json` | `E14646DC3915D9A15B6BF102FF5538F93855EFA9A978C1117981D933F46C6552` |
| `numeric/success.json` | `50788E261E01A55F47712078932100926F3CC2F23BF54DDCE6E19FFF84B8CA48` |
| `sdk/success.json` | `19739D8DD9CBFDF684A85EE00A5B9F4F943D63759385E17EF71B36D862CE0164` |
| `tests/success.json` | `87E8F354946028955A6548E1DB41D4AA48234BD59C139C0C25565009E95C42D3` |
| `cli/success.json` | `6D4C67C882886A0CDF8141C11499F3655D257D8212DF4F8F2F933F197079FCCD` |

These receipts locate artifacts; they are not network computation evidence.
Frozen B486C22A… and D9E77543… bundles establish source provenance only. All
numerical, SDK, genuine-proof, rejection and resource results above come from
actual R2 execution. Requirements and their AGENTS mirror remain identical.

Canonical original-key extraction, independently trusted complete setup identity,
all digit/key/producer/output NTT links and composition security remain necessary
for full relinearization. Full MulRelin, hiding of public stage vectors, private
source/index formation, completeness, freshness, writer fences and decentralized
agreement remain separate requirements. No SQL answer or mutation is accepted
by this experiment.
