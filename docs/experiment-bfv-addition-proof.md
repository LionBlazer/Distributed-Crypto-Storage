# Actual proofs of BFV ciphertext addition

2026-10-15. This is a bounded arithmetic-proof experiment, not a completed SQL,
consensus, freshness or performance implementation. The live storage client still
rejects unproved SQL answers and does not commit INSERT/UPDATE.

## Statement and verification boundary

The [canonical circuit](../crates/bfv-linear-circuit/README.md) adds two genuine
level-zero BFV ciphertexts using the unchanged N8192, Q218, t114689 profile. All
81,920 residues of both components and all five moduli are covered. The
[upstream bridge](../crates/bfv-query-core/README.md) is tested byte for byte against
the original BFV operator for both row geometries, carries and overflow cases.

For each residue, the AIR constrains a Boolean carry `k` and
`a + b - c - q*k = 0`. The trusted-input and claimed-output parsers require
`0 <= a,b,c < q < 2^44`. The integer expression has magnitude below 2^45, far below
the Goldilocks field modulus, so a field equality cannot hide an integer wrap.
Eight independent additions occupy each AIR row; none are sampled or omitted.
The padded trace has 16,384 rows, 8 witness columns and 32 public columns.

The verifier independently commits the complete expected ciphertext operands and
claimed ciphertext output. It never accepts a verifier key supplied by the prover.
Exact input/output SHA-256 digests are public transcript values. The input also
binds the complete original request digest: operation, keyset, geometry, query ID
and both supplied data/index heads. A different nonce/head cannot reuse the old
proof. This binding does not establish that a supplied head is agreed or current.

The [standalone proof consumer](../experiments/bfv-addition-proof/README.md) uses
pinned Plonky3 0.8.0, Goldilocks extension degree 5, 192 FRI queries, blowup 8,
binary folding and the standard Poseidon2 width-12 constants. No testing FRI
configuration or reduced BFV parameters is used. The SDK model reports 128 bits
in its two analyzed regimes; this is not an independent security assessment of
the full storage protocol. Witness carries depend only on already public
ciphertext coefficients; this experiment needs no secret key on the prover.

See the primary [Plonky3 framework](https://docs.rs/p3-uni-stark/0.8.0/p3_uni_stark/)
and its [preprocessed-column implementation](https://docs.rs/p3-uni-stark/0.8.0/src/p3_uni_stark/preprocessed.rs.html).
The framework itself cautions that malformed-input panics have not all been ruled
out. A successful finite test suite is not a hostile-network safety audit.

## Bounded measurements

Initial measurements used ciphertext-only public fixtures produced by the actual
BFV owner; keys stayed in memory. Release/offline builds, two Rayon threads, one
run per configuration, concurrent development load. Times start after loading
the ciphertext files. These are descriptive measurements, not p95/p99 or an SLA.

| Phase | One addition per row | Eight per row | Eight, CPU-specific build |
| --- | ---: | ---: | ---: |
| Prover public preprocessing | 1,353 ms | 507 ms | 80 ms |
| Proving after preprocessing | 5,158 ms | 668 ms | 150 ms |
| Independent verifier preprocessing | 1,449 ms | 536 ms | 83 ms |
| Proof check only | 37 ms | 30 ms | 23 ms |
| **Full verification, including preparation and decode** | **1,553 ms** | **607 ms** | **110 ms** |
| Measured proof workflow | 8,399 ms | 2,027 ms | 362 ms |
| Serialized proof | 749,892 B | 553,301 B | 553,301 B |
| Whole isolated proof-process peak working set | 499.2 MiB | 107.9 MiB | 108.6 MiB |

The last column explicitly uses `-C target-cpu=native` on this AVX2/AVX-512 host.
The portable build remains the default. All three retain the same cryptographic
settings; the altered row geometry is included in the SDK security calculation.
The CPU-specific full verification still exceeds 100 ms. Proving, input creation,
network transfer, complete SQL/index selection, durable writes, consensus and
confirmation add further cost. The local proof-process peak excludes the separate
fixture producer and does not establish a complete peer's memory bound.

The canonical input/output occupy 1,310,760 / 655,400 bytes. These and the proof are
transient protocol costs, not compact persistent data size. No new 1-2x whole-system
storage claim follows from this experiment.

The checked-in eight-lane CLI also completed a fresh-owner round trip with genuine
encryption, a serialized proof and client decryption to the public expected values
`[25, 35]`. In that portable run, the complete prover took 1,085 ms; full verification
took 504 ms, including 474 ms of independent preprocessing and 29 ms of final proof
checking. The frame was 549,469 bytes. Fresh keys and the complete diagnostic round
trip took 1,953 ms. Proof sizes vary with the committed instance and sampled paths;
the earlier table and this CLI run are separate measurements. Six boundary tests
exercise this same full cryptographic profile, without reduced test parameters.

A seventh integration test seals 6,040 public records into a real compact encrypted
table and index, authenticates all 242 matching records across posting/data pages,
and proves the unchanged opaque `PreparedUpdate` request. The preparation remains
alive through serialized verification. Replay against a fresh request, a different
delta or a genuinely different pair of table/index heads fails cryptographically,
including when both canonical binding headers are rewritten to match. No owner-local
sum recheck or mutation application is used as the proof verifier.

Earlier local RISC Zero 3.0.6 trials returned no verified receipt within the tested
CPU/time/virtual-address limits, including 16/17-bit execution segments. An 18-bit
trial hit a 1.75 GiB address-space guard; that is stricter than an RSS limit and is
not evidence that every RISC Zero configuration exceeds 2 GiB RAM. Those trials
do not establish an impossibility result. The native AIR is the functioning
candidate carried forward here.

## What remains mandatory

The serialized proof boundary must reject missing, truncated, extended, corrupt,
rebound and wrong-output proofs, including changes at the last real residue.
Verification includes independent public preprocessing; quoting only the 23 ms
inner check would misstate its cost. Reproduction commands and actual boundary
tests live with the standalone crate.

This proves the complete **addition relation**, not the completeness of SQL's
matching row set, a valid `old_root -> new_root` storage transition or current
decentralized agreement. Those obligations, authorization and the
[selected consensus model](consensus-model.md) remain separate. No arithmetic
marker alone authorizes a network SQL result or a database mutation.

The existing owner-built index can authenticate a complete bounded selection
relative to its exact data/index heads. Connecting that selection to the addition
proof does not establish a network-wide query contract: the canonical SQL plan,
complete shard set, per-shard proofs, ordering/LIMIT semantics and global overflow
outcome must be bound before accepting a SQL result. SELECT additionally requires
proof of the real ciphertext multiplication, BFV scale-and-round and key switching.
INSERT also rotates its encrypted incoming row; addition evidence alone cannot
prove that placement. Existing owner-side diagnostic rechecks of every updated sum
must not be renamed succinct verification.
