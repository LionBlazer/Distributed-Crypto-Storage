# Genuine private-access probes

The active goal remains at most 2x canonical encrypted storage and 500 ms for a
complete supported query. Neither visible access nor concealed access has been
selected. This experiment adds measured single-server PIR evidence; it does not
establish an indexed SQL query, malicious-peer computation proof, or the goal.

## Measured native DoublePIR primitive

[Source](../experiments/private-access/doublepir_probe.rs),
[headless runner](../experiments/private-access/run-doublepir.ps1) and
[dependency lock](../experiments/private-access/Cargo.lock) use the real Rust
DoublePIR implementation in [Blyss SDK revision
fdb7206517c249603b0c91b65f1f29f95272107c](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c/lib/doublepir).
The separate manifest and downloaded source live in ignored .local/private-access;
the root workspace and its dependencies are unchanged. No vendor source is
committed. The upstream SDK states that it has not been security reviewed.

The fixture is exactly the varied age:u8 / amount:u16 generator used by
compact_lookup: one million rows, 3,000,000 logical bytes. An ephemeral independent
AES-128-CTR key masks all row bytes before PIR encoding. The PIR server's data
matrix contains those ciphertext bytes. No AES key, plaintext row, or PIR client
secret is passed to answer. Both roles run in one process for measurement and
public-fixture assertions; this is not process-isolation evidence.

This raw AES fixture deliberately has no authentication or update protocol. It is
not the compact-store page format. A successful PIR response is compared against
the expected public fixture locally. That assertion is not a cryptographic check
of an untrusted peer.

The upstream high-level loader accepts only u8 values. The harness uses the
upstream public Db/Matrix and base_p encoder to encode each exact 24-bit row into
the same three base-p digits as the library's documented layout. It then invokes
unmodified init/setup/query/answer/recover primitives. All query randomness remains
enabled: Matrix::DETERMINISTIC is false. The harness changes no lattice parameter
and implements no replacement PIR scheme.

The implementation fixes LWE dimension n=1024, q=2^32 and error sigma=6.4. The
library table/picker selected p=512, l=48, m=65536, ne=x=3. Its parameter picker
maps the table's p=552 entry to 512 for rounding; this is upstream behavior,
not a smaller secret dimension. The Gaussian sampler uses a rounded floating
standard-normal sample and contains an upstream robustness TODO. Treat this as
research code, not a security audit or a production security claim. Relevant
primary code: [picker/setup/query/recover](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/doublepir/src/doublepir/doublepir.rs),
[parameter table](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/doublepir/src/params/params_store.rs),
[picker rounding](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/doublepir/src/params/params.rs)
and [sampler](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/doublepir/src/matrix/gaussian.rs).

Measured on 2026-10-14, Windows x86_64, Rust 1.99, release build, eight Rayon
workers, no concurrent research benchmark. The eight indices include the first
and last row, two repeated addresses (0 and 13), and varied middle addresses.
Every decoded ciphertext and decrypted three-byte row matched. Each row query
uses fresh PIR randomness. It is one serialized request/answer round trip; real
transport is excluded.

| Local phase | Eight-query observations |
| --- | ---: |
| Query generation, request encode/decode | 146.44–239.34 ms |
| Server answer, response encode/decode | 1.17–2.12 ms |
| Client recovery, ciphertext assertion and AES decrypt/assertion | 62.67–141.58 ms |
| Full measured primitive | 214.97–382.53 ms |
| First query, already initialized/preprocessed | 241.42 ms |
| Request / response | 262,248 / 98,380 bytes |
| Per-query secret state, serialized | 8,212 bytes |

Eight observations are not p95/p99 evidence. In particular, the fast server time
does not mean a 2 ms private lookup: owner computation dominates this implementation.
The first query is not a cold process or cold database query. Encoding took
42.01 ms, public shared-matrix generation 152.10 ms, and server preprocessing
1,371.85 ms before it. First-use hint transfer is another 50,331,660 bytes.
The captured ignored report is
.local/private-access/doublepir-1000000-8-t8-20261014-202917-654.jsonl.

| Accounted allocation/representation | Bytes |
| --- | ---: |
| Logical row bytes | 3,000,000 |
| Packed PIR database matrix | 4,194,432 |
| Serialized database matrix, including dimension header | 4,194,440 |
| Server preprocessing state, serialized | 368,660 |
| Client hint, serialized | 50,331,660 |
| Expanded shared public matrices | 268,500,992 |
| Seeds for those public matrices | 32 |
| Ephemeral owner AES key / public nonce | 16 / 16 |
| Fixture ciphertext buffer retained for assertions | 3,000,000 |
| Whole-process peak resident set | 614,686,720 |
| Resident set during measured queries | 383,823,872–384,040,960 |

The packed matrix is 1.398144x logical bytes; adding server state is about
1.52103x before metadata. If the canonical compact image is retained alongside
this matrix, both must be counted: this is not a free index. The 48 MiB hint is
additional client state, not canonical table storage. Two expanded copies of the
hint exist in this same-process harness, and recovery clones a hint; the OS peak
includes that, setup clones, query buffers and fixture checks. The shared matrices
are reused by both roles in this harness; separate processes would not share these
allocations automatically. Only their 32-byte seeds need be persistent, but this
implementation expands them in RAM. TFHE keys are not loaded: adding the existing
180,610,692-byte evaluation-key serialization gives an arithmetic subtotal of
795,297,412 bytes, not a measured combined-process peak.

These exact values support a narrow conclusion: private selection of a raw
three-byte ciphertext from a million rows can be measured without a
noncolluding-server assumption, within this local primitive's 500 ms budget.
They do not establish authenticated full-page retrieval within 500 ms.

## Why widening only the DoublePIR decoder is insufficient

The Rust DbInfo rejects records of 64 bits or more and recover returns u64.
An authenticated compact-store page with 256 rows already needs 816 bytes before
its Merkle path. Extending that byte interface would not fix the chosen geometry.
With the unchanged picker, p=512 and m>=64*n=65536, an 816-byte record needs
ne=ceil(816*8/9)=726 field elements. The standard x=ne setting makes l at least
726 even for only 3907 pages. The hint H2 has n*delta*x rows and n columns,
where delta=ceil(32/9)=4. Thus H2 alone would occupy
1024*4*726*1024*4 = 12,180,258,816 bytes, before metadata and any FHE key.
This is a source-derived allocation calculation, not an attempted 12 GB run.
It fails the 1–2 GB process budget before timing can matter.

The original [SimplePIR/DoublePIR paper](https://www.usenix.org/system/files/usenixsecurity23-henzinger.pdf)
also studies client hints and dynamic databases. Its LWE-based one-server model
does not depend on two honest noncolluding peers. Database-dependent hints must
remain synchronized with the database; this Rust snapshot API supplies no working
mutable-entry operation (Db::_set is todo). A safe current experiment must rebuild
preprocessing and replace the client's hint for a new snapshot. Incremental hint
maintenance, concurrent clients, crash recovery and durable updates are unmeasured.

## Full-request and privacy consequences

For k sequential private index/data fetches the latency ledger is
sum(PIR generation + server + recovery + transfer) + k*RTT, followed by fresh
FHE-input preparation, execution, response transfer and verification. The measured
3-byte primitive alone plus the separate 117–152 ms warm AES-radix FHE observations
would give an unmeasured arithmetic range of about 332–534 ms before network,
authentication, index navigation or proofs. Those probes use different formats
and cannot be added into a claimed implemented pipeline. A 2-level private index
would need at least three such fetches unless its top levels are owner-cached;
even three observed minima exceed 500 ms before FHE.

At 100 Mbit/s symmetric links, the measured 360,628 online bytes need at least
28.85 ms serialization time, plus RTT; the initial 48 MiB hint needs about 4.03 s.
These are bandwidth calculations, not network measurements. Padding result length,
hiding the selected peer/shard, and access timing require their own policy.
No storage-only PIR construction hides an address exposed later to an evaluator.

A concrete composition boundary is therefore: privately retrieve a fixed-size
authenticated encrypted page and its Merkle path; verify it at the owner's
application against an independently trusted snapshot head; freshly remask the
selected input for the evaluator, with a fresh encrypted mask token; send no
stored ciphertext, nonce, page identifier, row ordinal or page-specific root that
can identify the selection. Bind any eventual proof to a query and the trusted
snapshot without publishing the selected address. This is a proposed protocol
boundary, not implemented remasking or a proof system.

A malicious server can return arbitrary PIR bytes or selectively fail. Successful
decryption alone is not authenticity, and visible client retries or detailed error
feedback may reveal information. The raw probe supplies neither response
authentication nor such a feedback protocol. Merkle/AEAD page verification in the
next experiment can reject corruption and stale pages; it still cannot prove SQL
selection completeness or correct FHE arithmetic. The trusted version must come
from outside the answering peer.

## Measured authenticated full-page Spiral

[Spiral source](../experiments/private-access/spiral_page_probe.rs),
[headless runner](../experiments/private-access/run-spiral-page.ps1) and
[separate lock](../experiments/private-access/Spiral.Cargo.lock) now exercise the
complete native byte-record API in the same exact SDK revision. The harness
invokes unmodified load_db_from_seek, Client::generate_query, process_query and
Client::decode_response. The decoder returns a 32-byte scratch tail after the
useful record; the adapter takes exactly db_item_size useful bytes before bounded
compact-store decoding. It changes no PIR arithmetic.

The same one million varied three-byte rows are sealed with the actual
compact-store XChaCha20Poly1305 implementation. Each page contains 2048 rows:
489 real pages, padded to 512 PIR slots of 8192 bytes. A normal response record
contains a four-byte length, the complete page packet and its nine-hash Merkle
path; its unpadded LookupResponse is 6496 bytes (2080 for the short last page).
Page grouping differs from the earlier 256-row compact_lookup experiment. To
compare actual costs fairly, this harness measures a separate visible-address
control on these exact same 2048-row pages, same keys, fixture and response
verification. The direct control is not sent as part of the concealed protocol.

Only canonical compact bytes are retained as durable data. All 512 records are
generated uniformly before private reads; the peer does not build a selected
page's proof in response to its private query. The padded 4 MiB record buffer is
dropped after preprocessing. A 32 MiB expanded NTT database cache remains in RAM.
It is explicitly counted and never saved. Saving that expanded representation
would exceed 2x here. The local peer snapshot/tree is public encrypted data;
the owner's AEAD key and long-term PIR secret remain outside process_query inputs.
The roles still share a benchmark process, so this does not demonstrate process
isolation.

Cryptographic settings preserve the upstream CFG_20_256 ring, noise and
decomposition values: degree 2048, CRT moduli 268369921 and 249561089, n=2, p=256,
q2_bits=20, t_gsw=8, t_conv=4, t_exp_left=8 and t_exp_right=56. Only database
geometry changes to nu_1=7, nu_2=2 for the 512 records; it does not shrink the
million-row fixture or lattice dimension. The native Gaussian width is s=6.4 in
exp(-pi*x^2/s^2), giving standard deviation about 2.55323. The native sparse
ternary secret weight is 256. This is distinct from DoublePIR's normal sigma=6.4.

The [Spiral paper, sections 3 and 5.1](https://www.cs.utexas.edu/~dwu4/papers/Spiral.pdf)
targets 128-bit classical lattice security for its degree-2048, 56-bit-modulus
settings and explicitly assumes key-dependent-message/circular security for
key-switching components. The exact SDK variant and its correctness-error
probability have not been independently audited or re-estimated here. The
upstream SDK's unaudited status remains relevant; successful fixture tests are
not a cryptographic security estimate.

A new process on 2026-10-14, Rust 1.99, Windows x86_64, eight Rayon workers, no
concurrent research benchmark, retrieved pages 0, 488, 244 and 0 with fresh native
queries. The pinned Client::generate_query obtains fresh entropy for both its
private encryption randomness and public query seed each time. No deterministic
debug RNG is selected, and CLIENT_TEST is never populated with an owner key.

| Complete local retrieval | Observed time |
| --- | ---: |
| First cached full-page private read | 142.5008 ms |
| Subsequent three private reads | 133.7321–136.6521 ms |
| Query generation and query encode/decode | 1.0487–1.1669 ms |
| Server private answer | 132.1931–140.8622 ms |
| Native owner recovery | 0.4489–0.4786 ms |
| Merkle verification, AEAD decrypt and exact page assertion | 0.0148–0.0221 ms |
| Separate same-page visible read, encode/decode, verify and decrypt | 0.0075–0.0295 ms |

Every byte of every decrypted page matched the public fixture. The owner rejected
a modified recovered ciphertext byte, a valid response at a different expected
page index, an omitted/zero record, and an old valid proof against the new snapshot
head after replacement. These are page authentication tests; they do not audit
native decoding of arbitrary malicious PIR wire inputs or client retry/error
feedback. They establish neither SQL completeness nor FHE computation proofs.

Cold-cache construction costs 1.7882 ms to decode/rebuild the canonical snapshot
from an in-memory serialized image, 0.8860 ms to form padded response records and
123.1868 ms for NTT preprocessing. Their sum plus the first query is 268.3618 ms.
This excludes disk I/O. Fresh PIR key generation and public-parameter serialization/
restoration additionally cost 432.7446 ms: including those first-use setup stages
would be 701.1064 ms before network or FHE. No cold-first-use 500 ms claim is made.

| Full-page account | Bytes |
| --- | ---: |
| Logical rows | 3,000,000 |
| Canonical compact image, including manifest/nonces/tags | 3,023,584 (1.007861x) |
| Rebuildable compact Merkle hash payload | 31,392 |
| Sum of actual per-page LookupResponse payloads before PIR padding | 3,172,128 |
| Padded temporary PIR record buffer, then dropped | 4,194,304 |
| Retained RAM NTT database / persisted NTT bytes | 33,554,432 / 0 |
| Per-client public PIR parameters, serialized / expanded RAM payload | 6,029,344 / 23,855,104 |
| Database-dependent client PIR hint | 0 |
| Owner base secret polynomials / retained derived secret matrices, source payload sizes | 49,152 / 131,072 |
| Owner AEAD key / trusted head | 32 / 112 |
| Public fixture buffer retained for assertions | 3,000,000 |
| Online request / answer, exactly one round trip | 16,416 / 20,480 |
| Whole-process peak including replacement/rebuild | 114,388,992 |

The owner PIR key is not serialized by this API; the polynomial figures are
source-layout payload counts, not a measured owner-key wire format. The OS peak
includes both roles, public-parameter buffers, source fixtures, authentication
checks, the retained NTT database and query temporaries. It excludes TFHE keys:
adding the known 180,610,692-byte evaluation-key serialization gives only an
arithmetic subtotal of 294,999,684 bytes (about 281.3 MiB), not a measured composed
process. Including fixed TFHE/PIR keys in joint disk totals is far above 2x for
this tiny 3 MB fixture even though canonical data itself is 1.007861x. No
persistent expanded data copy is hidden under an index label.

The one real replacement flips a byte in page 0, calls Owner::replace_page with
the retained old head, drops the old NTT cache, rebuilds all response records and
the NTT cache, privately retrieves page 0 again and checks its new plaintext.
Canonical bytes remain exactly 3,023,584. Replacement/stale-proof rejection costs
0.0423 ms, response-record reconstruction 0.7962 ms, NTT reconstruction 114.0523 ms,
and the new authenticated private read 129.8828 ms: 244.9260 ms altogether.
Embedding paths in every record means a changed leaf affects other records'
Merkle paths, so this implementation really rebuilds the whole cache. It provides
no incremental-cache or database-dependent-client-hint update shortcut.
The PIR public keys remain usable across snapshots and no new hint is downloaded.

The captured ignored report is
.local/private-access/spiral-1000000-4-t8-20261014-204520-115.jsonl.
This is one replacement and canonical serialization/restore in memory, not 10000
writes, durable restart, INSERT/DELETE, concurrent version publication or hidden
writes. A peer can compare old/new ciphertext pages during updates.

## What this changes in the 500 ms budget

Authenticated full-page private retrieval is now an implemented measured
component on the million-row fixture. It does not make FHE input selection hidden
automatically. The next concrete adapter can authenticate/decrypt at the owner's
application and freshly TFHE-encrypt the selected fields and threshold; the
evaluator would receive fresh FHE inputs, no stored ciphertext/nonce/page address.
This uses the existing XChaCha page format and does not assume it is compatible
with the separate AES-mask conversion example. The owner is online for the read.
The proof-binding and authorized-client protocol remain unresolved.

One observed Spiral retrieval plus the separate warm 117.60–151.78 ms FHE phase
is an unmeasured arithmetic subtotal of about 251–294 ms. A second sequential
private index-node fetch raises that subtotal to about 385–437 ms, before input
preparation, traffic, RTT and proofs. At 30 ms RTT, two private fetches and one
FHE request need at least another 90 ms; even the high observed local subtotal
already exceeds 500 ms when combined with those round trips. Cached index levels,
a different query protocol, or a declared lower RTT would need actual tests.
This is not a measured composed-query result.

The full-page PIR's 36,896 online bytes need at least 2.952 ms of serialization
time at symmetric 100 Mbit/s, plus RTT. First-use public parameters need another
6,029,344 upload bytes (at least 482.35 ms on that link). These are calculations,
not transport measurements. Neither local timing nor throughput establishes
arbitrary SQL, a private index traversal, query load tails, or a malicious-peer
proof system. The goal remains active.

Other primary-source candidates checked: [Respire](https://github.com/AMACB/respire)
runs natively in Rust but documents around 17x preprocessing memory for single
queries and 49–57x for its batched configurations. [YPIR](https://github.com/menonsamir/ypir)
requires AVX-512/Ubuntu in its published runner; it was not installed. Basic
[Path ORAM](https://pages.cs.wisc.edu/~yxy/pubs/PathORam.pdf) uses dummy tree slots,
a position map and a stash; Z=4 tree padding exceeds this task's 2x canonical
budget before replication. These are candidate-specific limitations, not proof
that concealed access as a whole cannot meet the goal.

## Reproduction

Run serially with the other CPU probes stopped. Both runners clone only public
source into ignored storage, checks the exact revision and clean tracked source,
copies the committed dependency lock, builds and runs; it opens no GUI, launches
no service and writes no key/database images. First use may download Rust
dependencies into the selected project-local CARGO_HOME. It does not install a
toolchain or persist environment changes. Windows resident-memory accounting uses
GetProcessMemoryInfo; non-Windows runs currently report zero for that metric.

~~~powershell
./experiments/private-access/run-doublepir.ps1 -Cargo E:/Users/white/.cargo/bin/cargo.exe -CargoHome E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home -TargetDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target -Rows 1000000 -Rounds 8 -Threads 8 -Offline
~~~

The upstream library emits diagnostic text among JSON lines; select lines starting
with an opening brace to analyze the records. All generated reports stay ignored.

~~~powershell
./experiments/private-access/run-spiral-page.ps1 -Cargo E:/Users/white/.cargo/bin/cargo.exe -CargoHome E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home -TargetDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target -Rows 1000000 -Rounds 4 -Threads 8 -Offline
~~~

Both authored harnesses passed release Clippy with --locked --offline --no-deps
and warnings denied. The pinned upstream libraries still emit their existing
compiler warnings (including Spiral's dormant mutable CLIENT_TEST hook); no vendor
code was changed. Both PowerShell runners passed syntax parsing. The measured
programs were built/run with the same underlying locked Cargo commands; a fresh
network clone and whole runner invocation were not separately repeated.
