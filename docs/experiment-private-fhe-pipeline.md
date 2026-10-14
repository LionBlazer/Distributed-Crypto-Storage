# Authenticated page retrieval to fresh FHE inputs

This separate experiment composes the measured native Spiral page retrieval with
real TFHE-rs encrypted execution. It is a known-row retrieval/query experiment;
private SQL index navigation and arbitrary SQL remain separate work. The original
[private-access probes](experiment-private-access.md) and their frozen source are
unchanged.

[Source](../experiments/private-access/spiral_fhe_probe.rs) and
[runner](../experiments/private-access/run-spiral-fhe.ps1) use the exact pinned
Blyss SDK revision fdb7206517c249603b0c91b65f1f29f95272107c and TFHE-rs 1.8.1.
The standalone generated manifest is under ignored .local/private-access and does
not change the root Cargo workspace.

## Ownership and measured operation

The same varied public fixture contains one million rows, three bytes each:
age:u8 and amount:u16. Existing compact-store pages hold 2048 rows, giving 489
real pages inside 512 fixed 8192-byte PIR slots. Canonical encrypted bytes and
Merkle proofs use the existing XChaCha20Poly1305/Merkle implementation.

For each query, the owner's application selects the known row, privately retrieves
its authenticated page or uses the separate visible-address control, verifies the
page against its independently retained local snapshot head and expected page
address, then decrypts its own page. Only afterward it freshly TFHE-encrypts the
selected age, amount and threshold. The evaluator runs age >= threshold, casts
the encrypted predicate into COUNT and conditionally selects amount or zero for
SUM. The owner decodes and decrypts the real encrypted answer. Neither answer is
substituted from plaintext; expected public-fixture answers are assertions after
the measured result is available.

The owner is online, reads selected plaintext and prepares FHE inputs for every
request. This does not provide autonomous execution with an offline owner, and
does not implement universal transciphering. Both privacy controls use the same
fresh-encryption path, keys, fixture and page geometry; order alternates between
rounds. Repeated values must produce different serialized FHE age ciphertexts.

The serialized evaluator ReadRequest contains only query_id, the query-wide
snapshot root and freshly encrypted age/amount/threshold. It contains no stored
page ciphertext, page nonce, page identifier or row ordinal. process_query for
Spiral receives only public PIR keys, encrypted PIR query and transformed encrypted
database; peer_read receives only the fresh FHE request and diagnostic counters.
Owner AEAD/PIR/FHE secrets are never arguments to either peer function. Both roles
still share one executable: no process isolation claim is made.

TFHE uses PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 unchanged. The experiment
needs neither a dedicated OPRF key nor encrypted mask regeneration. Spiral keeps
the previous native degree-2048/56-bit-modulus, Gaussian-width-6.4 configuration,
n=2, p=256, q2_bits=20 and the authored decomposition values, with nu1=7/nu2=2
for this 512-record database. The upstream circular-security/implementation-audit
limitations described in the preceding report still apply.

## Authentication, failures and update boundary

The owner checks the bounded recovered record, expected page, Merkle proof and
trusted snapshot before AEAD decryption or any FHE-input encryption. Altered
ciphertext, omitted records, wrong page and stale-head replay have explicit
rejection scenarios. PIR secret recovery necessarily happens before recovered-page
Merkle checking. The adapter checks native PIR wire lengths first, but native
decoding of arbitrary adversarial values and observable retry/error feedback are
not audited here.

FHE answer query_id/root checks happen before owner FHE decryption. These checks
match local message metadata; they are not cryptographic computation proofs.
A malicious evaluator can replace output ciphertexts and rewrite their metadata.
Authenticated input and successful decryption do not establish correct arithmetic
or query completeness. No proof is generated, verified or implied by fixture
assertions.

An additional real encrypted increment uses FheUint16::overflowing_add on encrypted
amount and delta. The owner decrypts the returned candidate and overflow flag.
65535+1 must reject without mutating canonical bytes or the trusted head.
An accepted 123+7 result is written back through Owner::replace_page; all embedded
Merkle proofs/NTT cache are rebuilt, then another private FHE read checks the new
amount. Assertions compare the public fixture; this is not a malicious-peer-safe
write authorization or computation-proof protocol. Writes remain observable.
INSERT/DELETE, concurrent publication, durable restart and repeated-update bounds
are outside this bounded probe.

## Measured composed results

Measured on 2026-10-15 Europe/Moscow (2026-10-14 UTC in the report name),
Windows x86_64, Rust 1.99, release build, eight Rayon workers, with other research
benchmarks stopped. The actual runner executed eight alternating visible/private
pairs on the same snapshot and same keys. All sixteen results matched, including
nonmatches, threshold-boundary matches, a matching maximum amount, the last row, middle rows and
repeated rows. Serialized fresh age ciphertexts differed on repeated values.

| Complete supported read | Samples | Minimum | Nearest-rank p50 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Private, first query after setup with evaluation-key restore | 1 | 279.9099 ms | 279.9099 ms | 279.9099 ms |
| Private, subsequent reads | 7 | 177.7870 ms | 183.7814 ms | 203.8771 ms |
| Visible control, already warm FHE key | 8 | 47.1591 ms | 49.3527 ms | 50.6753 ms |

These are actual composed request timers: retrieval/query generation, all
serialization/deserialization, page verification, AEAD decryption at the owner,
fresh field/threshold encryption, genuine encrypted peer predicate/COUNT/SUM and
owner answer decryption. They are not sums of independent experiments. The first
global query is private and includes 46.3197 ms restoring the serialized evaluation
key plus the first FHE execution. It does not include prior setup. Private and
visible modes alternate order after that; the visible control does not have an
independent cold-process sample. Seven/eight warm samples do not establish p95/p99
or a 500 ms production SLA.

The seven warm private reads spent 126.4698–134.2340 ms in the native PIR server
and 47.9787–69.6429 ms in real FHE evaluation. Owner fresh input encryption took
0.6135–0.8158 ms. The fresh direct FHE path avoids the separate compact-mask XOR
conversion stage because the owner has already decrypted its own verified page.
It does not make that owner work free or offer offline-owner execution.

Setup was measured separately: 4.7324 ms for sealing, 1.8747 ms for canonical
in-memory restore, 430.8225 ms for PIR keys/public serialization and restore,
0.6748 ms for padded proof records, 110.8076 ms for NTT preparation, 573.0293 ms
for FHE keys and 60.2221 ms for key serialization. Total setup, including the
public fixture/owner-key preparation, was 1183.9625 ms. Setup plus first query is
an arithmetic subtotal of 1463.8724 ms. There is no first-use 500 ms claim; disk,
network/key provisioning, queueing and consensus are not measured.

| Complete accounting on this fixture | Bytes |
| --- | ---: |
| Logical data | 3,000,000 |
| Canonical encrypted image | 3,023,584 (1.007861x) |
| Rebuildable Merkle hash index | 31,392 |
| SQL search index / persistent FHE row cache | 0 / 0 |
| Replica count | 1 |
| Sum of complete page+proof response records before padding | 3,172,128 |
| Temporary padded record buffer, dropped after preprocessing | 4,194,304 |
| Retained NTT RAM database / persisted NTT bytes | 33,554,432 / 0 |
| PIR public parameters, wire / expanded RAM payload | 6,029,344 / 23,855,104 |
| PIR owner base secret / retained derived secret matrix payloads | 49,152 / 131,072 |
| FHE owner key / peer evaluation key, serialized | 31,268 / 180,610,692 |
| Storage owner key / trusted manifest/head | 32 / 112 |
| Public fixture plaintext retained for assertions | 3,000,000 |
| Actual whole-process native peak, including PIR and FHE together | 438,153,216 (417.86 MiB) |

The PIR private-key payload figures come from source layout; no PIR secret-key
wire serializer is implemented. The known material subtotal, counting canonical
bytes, Merkle hashes, public PIR wire parameters, both serialized FHE keys,
storage-owner state and base PIR secret payload, is 189,775,576 bytes (63.2585x
this small logical fixture). It is not a complete durable owner-state format.
Fixed keys must not disappear from the joint ledger merely because canonical
encrypted data satisfies 2x. Derived matrices and allocator/temporary buffers
remain included in actual measured process memory.

The native peak includes both owner and peer roles, the actual PIR/TFHE keys,
key wire buffers, NTT cache, requests/responses, fixture assertions and update
temporaries. The paired visible control runs in this same process with the PIR
cache present, so this is a measured combined-process bound, not a separate
visible-only RAM measurement. There is no persistent expanded FHE data copy.
The owner retains diagnostic previous age ciphertexts only to assert fresh
encryption; they never supply query inputs or answers.

| Online read traffic | Request | Response |
| --- | ---: | ---: |
| Private page retrieval | 16,416 | 20,480 |
| Fresh FHE conditional COUNT/SUM | 263,536 | 197,656 |
| Total private read | 279,952 | 218,136 |
| Visible read, full page plus FHE | 263,544 | 204,152 |

A private read therefore has 498,088 bytes and two sequential round trips. The
short last visible page reduces its retrieval response from 6496 to 2080 bytes;
the private record/response remains padded. At symmetric 100 Mbit/s, serialization
of the private read needs at least 39.847 ms. With two 30 ms round trips, the warm
local observations imply a calculated 277.63–303.72 ms subtotal before queueing,
proofs or fresh-head confirmation. This is a network-budget calculation, not a
measured distributed result. Initial public PIR/FHE provisioning is another
186,640,036 upload bytes, also excluded from warm query traffic.

## Real encrypted increment and compact writeback

The 65535+1 query privately retrieved the authenticated maximum-amount row,
freshly encrypted amount/delta, evaluated overflowing_add at the peer and
decrypted the returned candidate/overflow flag at the owner. It took 211.4972 ms;
the overflow flag was true and the candidate wrapped to zero. The owner refused
writeback; canonical image bytes and trusted head were exactly unchanged.

The accepted 123+7 query returned encrypted candidate 130 with no overflow.
The owner then wrote that actual decrypted FHE result into the verified page,
called Owner::replace_page, discarded the old NTT database and rebuilt all
embedded proofs/NTT records before a new private FHE query verified COUNT=1,
SUM=130. The whole sequence was measured in one process:

| Accepted update phase | Actual time |
| --- | ---: |
| Private retrieval, fresh encrypted increment and owner decode | 224.0483 ms |
| Authenticated compact page writeback and stale-proof rejection | 0.0736 ms |
| All proof-record rebuild | 1.2002 ms |
| NTT rebuild | 154.9207 ms |
| Complete update through new cache readiness, including drops/overhead | 381.8077 ms |
| Additional private FHE read after update | 238.3480 ms |
| Complete update, rebuild and additional verification read | 620.8630 ms |

The last full cycle exceeds 500 ms. It must not be reported as a sub-500 ms
update/read lifecycle. Canonical bytes remain exactly 3,023,584. The measured
381.8077 ms update/cache-ready phase excludes network publication, consensus and
computation proofs. Both encrypted increment requests use 263,512 FHE request and
148,256 FHE response bytes, plus their private retrieval traffic.

Tampering, a wrong page, omission and an old proof against the new head are
rejected at owner page verification before fresh FHE preparation. The three
focused tests also cover wrong query identifier, wrong snapshot metadata and
matching metadata before owner FHE answer decryption. These tests do not add a
computation proof: maliciously replaced FHE outputs remain unverified.

## Reproduction and remaining work

The ignored raw report is
.local/private-access/spiral-fhe-1000000-8-t8-20261014-210918-259.jsonl.
The [separate dependency lock](../experiments/private-access/SpiralFhe.Cargo.lock)
pins 104 packages. The runner executed successfully with its actual environment
restoration, pinned clean SDK check, source copy, locked build and report capture.
It defaults to a project-local Cargo cache and restores process environment in
finally; Offline refuses to clone missing source. First online use may fetch
public source/dependencies. No keys or database images are written.

~~~powershell
./experiments/private-access/run-spiral-fhe.ps1 -Cargo E:/Users/white/.cargo/bin/cargo.exe -CargoHome E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home -TargetDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target -Rows 1000000 -Rounds 8 -Threads 8 -Offline
~~~

Focused release tests passed 3/3; release Clippy passed with --locked --offline
--no-deps and warnings denied for the authored harness. The unmodified upstream
Spiral crate still emits its existing compiler warnings. Source formatting and
runner syntax checks passed. The pinned source remains clean.

The next phase must measure a real private SQL-index/posting lookup before this
data-page retrieval. The current selector is a known row from the public fixture,
so the measurements hide only data-page choice within this one shard. PIR still
processes its encoded shard; peer/shard choice, request timing, routing identity,
result cardinality and writes need their own privacy policy and accounting.
Arbitrary SQL, indexed-field changes, INSERT/DELETE, malicious-output proofs,
consensus freshness and durable update/recovery remain unimplemented here.
The overall goal remains active.
