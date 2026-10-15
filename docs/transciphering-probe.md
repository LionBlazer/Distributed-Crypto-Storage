# Compact input to an addressed FHE aggregate

This opt-in experiment exercises a narrow query: select one public physical row
address, compare its encrypted age >= encrypted_threshold, and return exact
encrypted COUNT and SUM of its u16 amount. COUNT is 0 or 1; SUM is 0 or the stored
amount, so neither result can overflow its type. The first four public fixtures
cover nonmatch, equality, a matching maximum u16, and another nonmatch; remaining
rows vary deterministically.

The [example](../experiments/fhe-prototype/examples/transcipher_query.rs) uses pinned
TFHE-rs 1.8.1 with the existing PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
a dedicated OPRF key and an explicit Rayon budget (two threads by default). It does not change the prototype's
Owner/Evaluator APIs. It generates ephemeral keys and public synthetic fixtures
in memory and prints JSON lines; it writes no secret, data or result files.

## Four explicit modes

**owner-aes** creates compact AES-128-CTR page ciphertext with TFHE's native
AesPlainState. For a query, the owner authenticates the page against its locally
confirmed root, regenerates only the addressed row's three mask bytes, and FHE
encrypts those mask bits. The peer receives the compact ciphertext, encrypted mask
and encrypted threshold. TranscipherSession::one_time_pad converts the masked
age/amount to genuine FHE values before the comparison and conditional aggregate.
The owner decrypts only the returned FHE aggregate during the query.

**owner-aes-radix** uses the same AES-CTR page representation but encrypts its selected
mask as FheUint8/FheUint16 directly. The peer XORs public compact bytes with these
two FHE values, then executes the same encrypted conditional COUNT/SUM. This reduces
the request payload compared with the bit-pad API; scalar XOR still incurs measured
TFHE work. It requires the owner online to issue the fresh encrypted mask token.

The native one-time-pad API is a conversion primitive here; the persistent mask
stream is AES-CTR, not a retained table of independently random plaintext pads.
Repeated queries may encrypt the same mask for the same immutable ciphertext.
Rewriting plaintext requires a fresh page nonce and version; pad reuse across
different plaintext revisions would expose XOR relations. This experiment creates
one revision and supplies no durable nonce allocator or update protocol.

**native-oprf** uses the public native FheUint8/FheUint16 encrypted-PRF APIs.
At write time the owner decrypts each generated FHE mask once and XORs its three
bytes with the fixture. At query time the peer regenerates the same FHE mask from
the page nonce, version, row address and field domain, then XORs the public compact
bytes under FHE. No query mask token or persistent row pad is needed. This is a
raw performance and local correctness control; its storage security is unestablished.

**native-oprf-rerand** calls the separate official re-randomized PRF API and enables
DerivedCPKWithoutKeySwitch. It additionally re-randomizes every input to the
conditional aggregate, including the threshold, under a fresh invocation context.
Both key sizes and all added execution stages are counted. This mode does not
establish a production malicious-peer protocol by itself.

TFHE's [encrypted-PRF documentation](https://docs.zama.org/tfhe-rs/fhe-computation/advanced-features/encrypted-prf)
requires the re-randomized variants when the sIND-CPA^D model applies and promises
reproducibility with the same hardware, seed and server key.
Its [re-randomization guide](https://docs.zama.org/tfhe-rs/fhe-computation/advanced-features/rerand)
requires re-randomizing encrypted program inputs. These local tests do not establish
cross-hardware plaintext stability, a strong PRF suitable for arbitrary repeated
known-plaintext storage, or resistance to malicious decryption/error-oracle use.
The PRF construction is documented in
[Fast Homomorphic Evaluation of LWR-based PRFs](https://eprint.iacr.org/2024/665).
Supplement C of the
[author-hosted paper](https://marcjoye.github.io/papers/DJL_25homprf.pdf)
explicitly describes PRF-stream compact transciphering and recommends a 256-bit
public seed. The final experiment format uses a fresh 256-bit page seed, with
revision/address/field context supplied to the library's own seed API.
Those acceptance questions must be resolved before adopting native-OPRF masked
storage, even if measurements are promising.

## Role boundary and authentication

The peer_query function receives only compact bytes and the encrypted request.
Its TFHE context holds a server evaluation key; it receives neither the FHE ClientKey
nor the AES/MAC secret keys. The example executable contains both roles to assert
correctness against a deliberately public fixture; it does not demonstrate process
isolation.

A page has an explicit cipher mode, public page identifier, revision, row count,
fresh 256-bit page nonce/seed (AES-CTR uses its first 128 bits), compact payload and a 256-bit BLAKE3 keyed authentication tag.
AES and authentication keys are independently sampled. The owner checks the exact
page root it retained from a trusted local write, then checks the keyed tag using
BLAKE3's constant-time Hash comparison. BLAKE3 documents its
[keyed hash as a MAC](https://docs.rs/blake3/1.8.7/blake3/fn.keyed_hash.html).
This construction is an experiment, not a reviewed storage protocol or a selected
production AEAD.

Changed ciphertext, an invalid tag even with a supplied replacement hash, malformed
page length, and a valid old page against a new local root are rejected in focused
tests. The peer checks that request mode/address/root match the supplied page.
The answer carries the local request identifier and root. These checks bind local
messages; they do not prove the peer performed the requested FHE computation.

The root is local owner state, not a consensus-confirmed database head. No index
membership/completeness proof or FHE computation proof is generated or verified.
The bounded bincode round trips are for trusted benchmark objects and are not a
production hostile-ciphertext decoder.

## Storage accounting

Every row contains three logical bytes, independent of Rust struct padding. The
custom page wire format stores 72 header bytes, the exact 3 * rows compact bytes,
and a 32-byte tag: 3 * rows + 104 bytes. Reconstructing TFHE's public stream type
wrappers during an AES query avoids persisting their per-field serialization
metadata; it does not remove any encrypted input bytes.

The JSON setup record reports:

- Page payload, metadata/tag and actual serialized page length.
- Owner AES/MAC keys plus the one locally confirmed page root (80 bytes for AES;
  64 for the native modes).
- Actual serialized owner FHE key and peer evaluation key lengths. The owner key
  is counted through an in-memory counting writer; no key bytes are printed/saved.
- Zero persistent FHE row caches, row pads, indexes, replicas and query proofs.
- Both compact-data expansion and the joint total including owner state and keys.
- A clearly marked algebraic 1 GiB projection using the same page size and a
  retained owner root per page. It is not a measurement of a 1 GiB database.

A 1024-row page is 3176 bytes / 3072 = 1.03385x; including its 80 bytes of AES owner
state gives 1.05990x before FHE keys. Tiny fixtures do not meet a joint 2x bound
once fixed FHE key material is included. A favorable amortized projection does not
prove a repeated-update lifecycle or the storage cost of index/proof structures.

## Timing and memory

Each query includes owner page authentication, fresh mask/threshold encryption,
request serialization/deserialization, peer root check, mask regeneration or decode,
compact-to-FHE conversion, genuine encrypted predicate/COUNT/SUM, response
serialization/deserialization and owner decryption. The peer receives the entire
small page for this benchmark; reported page-transfer bytes are separate from
request/response bytes. There is no hidden persistent FHE input cache.

The first query includes restoring the serialized evaluation key from an in-memory
buffer. Later queries retain the evaluation key and convert their addressed row
again. Native-OPRF writes already execute FHE; therefore the first query is not
reported as a cold-process/first-bootstrap measurement. Key generation, key
serialization and compact write costs are reported separately.

No network delay, disk I/O, scheduling/consensus, remote root confirmation, proof
generation or proof verification is measured. Whole-process peak resident memory
includes both roles, key wire buffers and temporaries, and does not isolate peer
RAM. Four rounds are behavioral observations, not p95/p99 or a 500 ms SQL SLA.

## Initial four-query measurements

Measured serially on 2026-10-14 with Rust 1.99.0, Windows x86_64 and two Rayon
threads. Each mode starts a new process and fresh key set. The final 256-bit-seed
format was used for every row below; no concurrent research benchmark ran.

| Mode | Page rows | First local query including key restore | Later three queries | Request bytes | Whole-process peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| owner-aes | 1024 | 406.66 ms | 315.62-328.44 ms | 461086 | 351.18 |
| owner-aes-radix | 1024 | 395.75 ms | 294.32-300.32 ms | 263550 | 351.32 |
| native-oprf | 64 | 472.79 ms | 359.50-402.61 ms | 65934 | 351.74 |
| native-oprf-rerand | 64 | 531.61 ms | 439.94-591.67 ms | 65934 | 352.57 |

Every response is 197656 bytes. AES pages are 3176 bytes; native-mode pages in this
smaller write-time fixture are 296 bytes. Each mode's first query additionally
restores the evaluation key in 75.31-82.08 ms. Raw native write-time preparation
takes 5.61 seconds for 64 rows; re-randomized native preparation takes 5.88 seconds.
AES preparation takes approximately 0.2 ms for 1024 rows. These are separate setup
measurements, not free work hidden in a query cache.

The baseline FHE owner/evaluation keys serialize to 31268 / 180610692 bytes.
Re-randomization changes them to 31272 / 180643576 bytes. No TFHE compression key
is enabled because this compact-input experiment never persists FHE rows; the
security parameters for computation are unchanged. The 1024-row AES joint total
including all these keys is 180645216 bytes, far above 2x this tiny fixture.
Its explicitly unmeasured 1 GiB algebraic projection is 1.21251x, counting a retained
owner root per page. Native 64-row data plus owner state is 1.875x before FHE keys;
its corresponding 1 GiB algebraic projection is about 1.8766x.

All sixteen exact output assertions pass. The native re-randomized mode exceeds
500 ms in this final run. A previous 128-bit-seed prototype run observed
353.55-428.21 ms warm for that mode, and another raw-native first query took
504.04 ms. These variations preclude treating four observations as an SLA or
selecting only favorable runs. The final AES-radix trial is promising for a narrow
local point query, while network/proofs/updated compact persistence remain open.

## Twenty fresh-query CPU-budget comparison

A follow-up executes twenty addressed queries against the same 1024-row compact
page, with freshly encrypted request masks/thresholds and a fresh peer conversion
for every query. The first four cases are the explicit boundary fixtures; later
cases query varied ages/amounts. The algorithm, representation and security
parameters are unchanged between the two thread budgets.

| Rayon threads | First query with key restore | Key restore only | Warm minimum | Warm p50 | Warm p95 / p99 / maximum | Peak MiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 500.2801 ms | 117.4258 ms | 303.9476 ms | 358.8425 ms | 573.8835 ms | 351.22 |
| 8 | 239.5069 ms | 80.1508 ms | 108.4610 ms | 117.5992 ms | 151.7846 ms | 353.20 |

Warm statistics use the remaining nineteen queries and the nearest-rank rule
(sorted sample at ceil(n * q), one-based). At n=19, p95 and p99 both select the
sample maximum. They are descriptive sample statistics, not reliable production
tail estimates. Both runs pass all twenty public-fixture correctness assertions.
The two-thread run exceeds 500 ms and must not be described as meeting that bound.

Eight threads provide substantial margin for this local one-row query on the
research host, at a different CPU budget. They do not supply a distributed indexed
query SLA: the 263550-byte request, 197656-byte answer and 3176-byte fetched page
still need transmission; proof generation/verification, fresh-root confirmation
and the compact update/writeback lifecycle remain unimplemented.

The complete JSON records were captured in ignored .local/fhe-research as:

- transcipher-final-owner-aes-radix-20-20261014-201723-138.jsonl (two threads).
- transcipher-final-owner-aes-radix-20-t8-20261014-201855-393.jsonl (eight threads).

The source passes release Clippy with warnings denied and all four focused
authentication/format tests. No benchmark report is committed.

## Visible and hidden access composition

The physical page and row address are public in this probe. There is no SQL index
construction, million-row index traversal, range selection or arbitrary SQL.

A hidden-access alternative must conceal the whole execution transcript. PIR
retrieval alone is insufficient if the next FHE request contains the original
compact ciphertext, page nonce or row position that the executor can match to
stored data. Owner-side fresh remasking might separate retrieval from execution,
but needs an explicit client state, communication and proof-binding protocol.
It is a proposed composition, not implemented or measured here. Choosing between
visible and hidden access remains an unresolved user-level privacy decision.

## Reproduction

Run serially with other CPU benchmarks stopped:

~~~sh
cargo build --release --offline -p fhe-prototype --example transcipher_query
cargo test --release --locked --offline -p fhe-prototype --example transcipher_query
cargo run --release --locked --offline -p fhe-prototype --example transcipher_query -- owner-aes 1024 4
cargo run --release --locked --offline -p fhe-prototype --example transcipher_query -- owner-aes-radix 1024 4
cargo run --release --locked --offline -p fhe-prototype --example transcipher_query -- native-oprf 64 4
cargo run --release --locked --offline -p fhe-prototype --example transcipher_query -- native-oprf-rerand 64 4
cargo run --release --locked --offline -p fhe-prototype --example transcipher_query -- owner-aes-radix 1024 20 2
cargo run --release --locked --offline -p fhe-prototype --example transcipher_query -- owner-aes-radix 1024 20 8
cargo clippy --release --locked --offline -p fhe-prototype --example transcipher_query -- -D warnings
~~~

On the current Windows research checkout, Cargo is
E:/Users/white/.cargo/bin/cargo.exe; set CARGO_HOME to the main checkout's
.local/cargo-home and CARGO_TARGET_DIR to its target to reuse pinned
dependencies. Generated reports belong in ignored .local/fhe-research if captured.

The native TFHE implementation paths used here are
[HL transciphering](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/high_level_api/transciphering/mod.rs),
[AES-CTR plaintext stream](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/transciphering/ciphers/aes/plain.rs),
[native integer OPRF](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/high_level_api/integers/oprf.rs)
and [dedicated OPRF key configuration](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/high_level_api/keys/inner.rs).
