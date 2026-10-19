# Retained private-WHERE evidence

The [public product store](../crates/bfv-product-evidence/README.md) retains the
existing real private-WHERE input16 and full134 output graph in bounded immutable
CAS blobs. Its small catalog supplies untrusted content references. Every replay
requires independent setup, object, complete Provenance and request pins and
freshly verifies all original cryptographic premises. There is no verified flag,
application receipt or substitute proof callback.

The actual [peer client](../crates/peer-runtime/README.md) records through its
existing TLS verifier: actual bound END, clean EOF, full verifier finish and a
final live cancellation/deadline check precede catalog publication. Failed
recording leaves accounted public prefix blobs; there is no garbage collection.
The depot belongs to the client in this scenario. The daemon has no durable
product spool. The live client keeps its caller-borrowed fifteen input frames
until RPC completion; the server and retained replay drop their materialized
input frames before output proof processing.

## Actual native gates

```sh
cargo test --release --offline --locked -p bfv-product-evidence -p peer-runtime -- --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test private_product private_product_success::retained_stored_product_replays_after_private_owners_drop_and_rejects_repaired_splices -- --exact --ignored --test-threads=1 --nocapture
```

The library gate passed nine product-store cases, 98 runtime cases and four
compile-fail contracts. Two unrelated opt-in filesystem scenarios remained
ignored. The separate opt-in OS gate passed one complete scenario with one
actual daemon. The real encrypted computation uses the stored original rows and
hidden WHERE. Expected plaintext appears only in the test oracle.

After the private owners, proof producers and original input buffers dropped and
the daemon stopped, a reopened depot verified all 16 input proofs and 118 output
records against independently retained public pins. It reproduced the checked
ciphertext, encrypted response and complete graph identity. The 134 logical graph
nodes comprise 115 NTT, 17 arithmetic and two relinearization nodes; arithmetic
batching produces 118 physical output records. Input proofs are separate.

Negative challenges repaired catalog references while preserving valid grammar:
swapping two genuine Encoding children reached and failed actual input proof
verification; duplicating a genuine output record reached and failed the ordered
statement verifier. Foreign independent pins, omitted/trailing catalog entries,
an actually deleted claims blob and changed bytes on whole-root reopen also
rejected. Pre-cancelled recording performed no I/O or publication. Midstream
cancellation after CAS writes was not measured by this case.

All-target checking, strict Clippy, Core default checking and workspace formatting
passed. Two initial strict-Clippy attempts stopped on newly stabilized
`as_chunks` suggestions; both exact extent/count guards remain intact. The lock
file adds one local package and two existing-package dependency edges, without
changing external versions or checksums.

## Measured scope

| Observation | Value |
| --- | --- |
| Full OS command, including 44.09s compilation | 680.345s |
| Test runtime, including adversarial replays | 636.11s |
| Initial preparation plus stream/full verification | 535.465s |
| Preparation | 88.872s |
| Stream and full verification | 443.025s |
| Fresh keyless retained replay | 55.103s |
| Input frames / proofs | 15 / 16 |
| Input bytes | 264,176,639 |
| Sent / received application-frame bytes | 265,086,325 / 254,042,553 |
| Output ciphertext bytes | 446,494 |
| Catalog bytes | 6,372 |
| Logical retained bytes before corruption challenge | 508,766,228 |

The retained-byte observation includes namespace/profile files and extra repaired
challenge catalogs. It is neither clean product-only storage nor physical disk
allocation. Application-frame counters exclude TLS/TCP overhead. Different suite
boundaries and run conditions do not support a speedup comparison.

The Windows observer retained 7028 samples with nominal 100ms polling and a
maximum observed gap of 601.485ms. Per-process maxima were:

| Process | Sampled working set | Sampled private bytes | OS peak working set |
| --- | --- | --- | --- |
| Owner/test | 1,451,438,080 | 1,501,650,944 | 1,451,438,080 |
| Peer | 1,165,541,376 | 1,160,167,424 | 1,195,622,400 |
| Cargo | 80,519,168 | 67,735,552 | 80,519,168 |

These maxima occurred independently and must not be summed as simultaneous
usage. Neither the 1792MiB per-process soft fuse nor the 1800s runner budget
triggered. Sampling gaps and one fixed N4 operation do not certify the whole
system's memory target or concurrent-operation fit.

The frozen 1487-file source manifest SHA256 is
`DD4534BBD1C74DCC6FA24DB70A5E08AF80268960150E118AB03B2D660511098A`.
Every raw hash and the complete inventory matched after both native gates,
before this documentation update. Parent commit was
`e1cd9a5dacf29f9c38d08372b8dc54d16fd51afc`. Ignored OS receipts are in
`.local/private-peer-native-r1/retained-product-four-proof-os-r1/`; that historical
label does not imply four peers. Stdout SHA256 is
`E8789D13FFBD249E0B7EDC6BA51B06736AA18EFC78397AA8262782594325EFE6`;
stderr SHA256 is
`AEE6F91BFEAB580153E85084868927A7BAF7200B457B60DA951EA281B0132655`.
The separate library gate took 76.390s including compilation; its stdout SHA256
is `0051AD8FB5ED468C215B81FDE4E2EA9BE893FF1D93E6BF1DF25728D604FCFE05`
and stderr SHA256 is
`015D5F4DC25C2F903CC10B48979571913417DAB28B3944A727249A9C92A7907D`.
Generated ciphertexts, keys, witnesses and observation files are not committed.

This stage provides durable public mathematical evidence. It establishes no
fresh finalized head, SQL grant, writer authorization, FOR UPDATE/SKIP LOCKED
finality or interactive latency. Input individual128 and output SDK policies
remain separate; no whole128 composition or public same-secret relinearization-key
theorem is claimed. Closed joint application admission, owner recovery, general
SQL and verified history compaction remain separate unfinished work.
