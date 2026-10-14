# FHE storage and indexed query performance

The targets remain canonical encrypted storage at most 2x the logical plaintext
size and 100 ms indexed queries, preferably 50 ms. Full scans and arbitrary SQL
remain separate workloads.
The current TFHE representation does not meet the storage target; a faster scan
alone does not provide an index. Both observable-access and concealed-access index
designs remain candidates. Neither privacy model has been selected.

## Measured storage expansion

Measured on 2026-10-14 with TFHE-rs 1.8.1, Rust 1.99, Windows x86_64, and two Rayon
threads, using the prototype's existing parameters and image encoder. Rows contain
`age:u8` and `amount:u16`; the denominator is 3 logical bytes per row.

| Rows | Logical bytes | Compressed image bytes | Expansion |
| ---: | ---: | ---: | ---: |
| 4 | 12 | 2167 | 180.58x |
| 16 | 48 | 3055 | 63.65x |
| 64 | 192 | 9879 | 51.45x |
| 256 | 768 | 38811 | 50.54x |
| 1024 | 3072 | 154539 | 50.31x |

These are fresh encrypted images, including image metadata, excluding keys,
indexes and replicas. The empty image is 151 bytes. Removing the 28-byte project
header cannot explain the expansion. The 1024-row storage probe peaked at
894.36 MiB of whole-process resident memory while encrypting/compressing; it does
not measure an isolated peer, query workload, or GUI.

The pinned compression parameters use 256 two-bit plaintext blocks, GLWE dimension 4,
polynomial size 256 and 12-bit stored coefficients. A full cryptographic packet has
`(4*256+256)*12/8 = 1920` bytes for 64 bytes of plaintext: 30x before high-level
serialization/type metadata. This is specific to the current preset, not a lower
bound on all FHE. [Pinned parameters](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_8/list_compression/p_fail_2_minus_128/mod.rs)

TFHE supports compression after computation and recommends filling shared lists.
The current encoder already puts all table values into one list. Seed-based input
compression does not automatically represent evaluated ciphertexts as one seed.
[TFHE compression documentation](https://docs.zama.org/tfhe-rs/fhe-computation/data-handling/compress)

## Measured scan optimization

The current evaluator compares each encrypted age and accumulates 32-bit COUNT/SUM
serially. A comparison experiment replaces scalar COUNT muxes with boolean-to-integer
casts, uses 12 bits for COUNT, masks amounts before widening, and applies TFHE's
specialized multiple-input `sum` instead of repeated addition. SUM stays 32 bits:
`1024*65535=67107840` requires 26 bits. The library evaluator is unchanged.

| Threads | Rows | Baseline query | Optimized query |
| ---: | ---: | ---: | ---: |
| 2 | 4 | 2354–2760 ms | 889–1129 ms |
| 2 | 16 | 10020–10784 ms | 3339–3819 ms |
| 8 | 4 | 952–1589 ms | 329–603 ms |
| 8 | 16 | 5163–6720 ms | 1442–2005 ms |

Ranges cover three standalone paired trials plus one Cargo reproduction per case,
with generated keys and encrypted input
already resident. They include comparisons, accumulation and owner decryption;
exclude encryption, disk restoration, routing, consensus and query proofs. All
answers matched the public fixture. These are microbenchmark ranges, not p95/p99
or an end-to-end SQL SLA. Additional Cargo examples reproduce the computation and
record whole-process peak memory (360–362 MiB for these small query cases).
Changing thread count changes the resource budget.

The specialized sum and narrower COUNT provide 2.1–3.6x in these paired trials,
but still miss 100 ms. Widening a clean unsigned ciphertext can append trivial zeros;
it must not be treated as an inherently expensive bootstrap. Parallel high-level
row operations need a server-key context on every Rayon worker.
[Pinned multiple-input sum implementation](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/high_level_api/integers/unsigned/ops.rs)

## Candidate storage and query designs

| Candidate | Useful capability | Condition affecting this project |
| --- | --- | --- |
| Packed BFV/BGV | Exact modular arithmetic over many packed values | Bounds must prevent modular wraparound; comparison, repeated updates and ciphertext expansion still need measurements |
| Compact symmetric pages with PASTA conversion | Peer converts selected compact input to HE without learning plaintext or key | Conversion adds computation; evaluated results remain HE ciphertexts |
| Compact pages and searchable authenticated index | Index selects a small candidate set; owner keeps decryption keys | Access positions, repetition or result sizes may leak; not yet a selected privacy model |
| Compact pages and ORAM/PIR index access | Conceals accesses under the chosen protocol | Additional client state, bandwidth, rebuilds or server work; assumptions must tolerate the specified collusion |

[Microsoft SEAL](https://github.com/microsoft/SEAL) supports BFV/BGV exact modular
arithmetic; CKKS approximations do not directly supply exact SQL comparison and
overflow semantics. [PASTA](https://eprint.iacr.org/2021/731) supplies compact
symmetric inputs and their HE conversion. Homomorphically encrypting an evaluated
result symmetrically still produces an HE ciphertext containing that symmetric
ciphertext. A practical compact rewrite with current key placement requires the
owner's application to verify, decrypt and re-encrypt the changed pages. This makes
that application necessary for completing this form of UPDATE.

Published reverse conversion uses distributed FHE decryption with active secret-key
share holders. Giving key shares to peers changes the current model.
[Transciphering for FHE-based MPC](https://eprint.iacr.org/2024/1702)
Theoretical rate 1 FHE supports highly compact evaluated outputs, so 2x is not ruled
out by a universal impossibility claim. A usable repeated-update format and concrete
resource/performance budget remain separate questions.
[Rate 1 FHE](https://eprint.iacr.org/2019/720)

## Indexed latency and privacy

[Arx](https://www.vldb.org/pvldb/vol12/p1664-poddar.pdf) measured index traversal near
3 ms and effective range queries near 15 ms at low load with 10 ms RTT, the top
1000 index nodes cached at the client (88 KB), and deferred repair. Its model is
semi-honest and exposes accesses, result counts and some
search relations. Data expanded 1.9x in one workload, but three range indexes used
8.4 GB and total server storage grew about 16x. It is evidence for an indexed direction,
not a ready implementation of our FHE, malicious-peer or RAM requirements.

Packed arithmetic benchmarks must cover complete queries. For example,
[NSHEDB](https://arxiv.org/html/2602.24271v1) reports submillisecond aggregate
primitives but a 590-second TPC-H Q6 and reports about 27–28x storage: 0.27 MB raw
to 7.4 MB encrypted for 32768 elements in its tested BFV configuration. That raw
baseline differs from our 3-byte logical row denominator. Its semi-honest model
and 128 GB host do not validate our deployment.
[CSHER](https://www.usenix.org/conference/usenixsecurity23/presentation/akavia)
offers compact storage and HE retrieval with two noncolluding services; this is an
extra trust assumption for our peer-collusion model.

An authenticated lookup can return ciphertext and a proof against a committed
index root. Membership proofs for individual returned rows do not establish that
all matching rows were returned. Unique-key absence, complete postings groups and
range boundaries require their own proof structure. The index must also be proven
consistent with the table. Owner construction or verified update transitions can
establish that invariant. These are proposed components, not implemented guarantees.
[Relational answer completeness](https://ink.library.smu.edu.sg/sis_research/778/)

Freshness requires a confirmed version root independently of the responding peer.
New FHE aggregation or arithmetic requires a computation proof in addition to index
proofs. Materialized aggregates can shift computation/proof work to verified writes,
but cannot cover arbitrary ad-hoc SQL. A 100 ms budget must include proof generation,
transmission, verification and version checks, not just FHE arithmetic.
[Verifiable FHE](https://arxiv.org/abs/2301.07041)

## Next acceptance experiments

1. Compare both privacy models for an authenticated point lookup over one million
   records, including absent keys, duplicate-key groups and cold/warm caches. Keep
   row size, shard size, selected rows and response bytes fixed and reported.
2. On the selected candidate set, compare TFHE and packed BFV/BGV COUNT/SUM and
   overflow-safe UPDATE. Separately measure cold compact-to-HE conversion, cache
   maintenance and compact rewrite by the owner. Retrieval alone is not FHE SQL.
3. Exercise 10000 UPDATE/INSERT/DELETE cycles, indexed-field changes, compaction and
   restart. Count every persistent HE cache, overlay and retained version; report
   base data, indexes, keys and replicas separately. Do not classify an expanded
   persistent copy as an index to hide its storage cost.
4. Reject omitted rows, forged emptiness, corrupt data/proofs, stale indexes,
   mixed roots and replayed transitions. Include proof costs in the query budget.
5. Measure p95/p99 whole-peer latency under declared CPU, RAM, load and RTT.
   At 30 ms RTT, two sequential round trips already cost 60 ms. Snapshot reads and
   reads requiring a new confirmed head need separate budgets.

An implementation can claim at most 2x storage only after the read/update lifecycle
preserves it. The 100 ms/50 ms targets need a declared indexed query family, result-size
bound, privacy model and network profile. Online-owner requirements, proof design
and strict versus snapshot freshness remain unresolved.

## Reproduction

Public fixtures and ephemeral in-memory keys only; neither example opens a GUI or
writes database data or keys. Output is JSON lines; generated reports belong in
ignored `.local/fhe-research`.

```sh
cargo run --release --locked -p fhe-prototype --example storage_size
cargo run --release --locked -p fhe-prototype --example query_layout -- 2 3
cargo run --release --locked -p fhe-prototype --example query_layout -- 8 3
```

The scan example compares algorithms on identical inputs and alternates execution
order between rounds. It demonstrates local correctness against a public fixture,
not a cryptographic proof of a peer's answer.
