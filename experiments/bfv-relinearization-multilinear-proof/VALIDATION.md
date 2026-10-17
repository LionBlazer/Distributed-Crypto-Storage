# Multilinear relinearization arithmetic validation

Validated on 2026-10-17 with pinned Rust 1.99.0, release optimization,
`-C target-cpu=native`, two build jobs and an offline reviewed lock. This
standalone serial consumer uses Plonky3 0.8.0 at SDK commit
`a21e3ed42905040ad49c519e402f018381c12d0c`. Existing core libraries, the older
univariate consumer, their profiles/caps and all existing lock files are unchanged.

## Actual security and statement coverage

Both actual SDK complete reports contain six finite terms and no unassessed
component. Their whole-statement estimate is **157.824854488013 bits** each,
above the enforced floor 144. Main/public PCS terms are 159.39154596171863 and
158.41904001390932 bits; the commitment/transcript collision cap is 256. These
conditional SDK estimates are not a complete Relin, SQL or key-authority guarantee.

| Actual property | Embed | AccumulateAndAdd |
| --- | ---: | ---: |
| Rows / main width / public values | 8192 / 1 / 32 | 8192 / 1 / 32 |
| Public width | 55 | 365 |
| Constraint count / degree | 26 / 1 | 61 / 2 |
| Main / public PCS arities | 13 / 19 | 13 / 22 |
| Main current claims / final variables | 1 / 5 | 1 / 5 |
| Public current claims / final variables | 55 / 3 | 365 / 6 |

Main folding is [4,4], rate [4], queries [386,176]. Public folding is [4,4,4,4],
rates [4,7,10], queries [386,176,162,161]. Actual setup keys and verifier instances
were used for both reports; a target or a PCS-only estimate was not substituted.

Strict Clippy/rustfmt, release CLI/test builds and all **20 owning tests** passed,
with zero failures, ignored or filtered tests. Before any proof, two pure upstream
SDK oracles checked every Q5/8192 embedding coefficient and complete original
ordered-key relinearization on arbitrary three-component and encrypted-product
inputs. The full suite additionally generated, serialized and independently
verified both full stage proofs, including both requests from the actual encrypted
product. Expected results came from upstream relinearization.

Eight genuine weakened/foreign programs first verified against their own AIR/VK,
then rejected against honest verifier-built preprocessing. Other checks covered
all last input/output polynomials, quotient 2, all ten MAC quotients, every final
carry chain, all five terms, component/key order, rebuilt canonical bindings,
full 64-byte hashes/envelopes, malformed bounded decoding and exact proof topology.
The verifier performs canonical preparation and SDK verification without repeating
the embedding/MAC/NTT arithmetic.

## Owned-process observations

The CPU CLI includes startup, numerical analysis/public setup and a nonsecret
fixture, followed by actual proof generation and independent verification.
The reported frame includes the fixed public auxiliary and canonical SDK proof.

| Observation | Embed | AccumulateAndAdd |
| --- | ---: | ---: |
| Frame bytes | 1197590 | 3342861 |
| Outer process ms | 409.2548 | 2921.3669 |
| Library prover total ms | 181.6952 | 1778.2107 |
| Library verifier total ms | 62.2382 | 510.5257 |
| Observed OS peak working-set bytes | 86753280 | 608370688 |
| Memory samples | 4 | 29 |

The full 20-test process took 25221.9405ms externally (harness 25.20s), with 251
samples and observed OS peak working set 689123328 bytes. Its actual 250 sample
intervals ranged 100.1504–101.5538ms (mean 100.4559ms). No sampled memory/runtime
fuse fired. Sampling was nominally 100ms; the experimental safeguards were 1792MiB
sampled memory and 1200 seconds per child, not a hard resource guarantee or SQL SLA.
Short-lived peaks after the last observation can be missed.

These are individual public-Aux arithmetic stages, not a hidden main computation,
source/key consistency proof, trusted setup admission, whole 72-stage Relin,
MulRelin, network query, agreed freshness, writer fence or complete-peer RAM
measurement. Full canonical setup and all producer/digit/key/output edges still
need their own checked composition. Stage error bounds must be combined explicitly;
separate reports are not a complete-operation proof.

See the [owning README](README.md) for exact protocol, byte-budget derivation and
reproduction commands.
