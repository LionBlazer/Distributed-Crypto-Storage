# Private PaddedV2 age index -> data PIR -> fresh FHE

Status: real 1M-row native Spiral + TFHE run completed; this remains an isolated
bounded experiment. The previously published known-row experiment remains separate
in [the known-row report](experiment-private-fhe-pipeline.md).

This isolated headless experiment owns an online-owner composition: the owner
privately reads an authenticated encrypted age index, decodes complete postings,
privately reads the authenticated data page, decrypts its own selected fields,
and freshly encrypts those fields for a peer's actual encrypted equality,
COUNT and SUM. The peer receives only public querywide roots/nonce and fresh
TFHE ciphertexts. This does not implement offline-owner execution, universal
transciphering, a SQL completeness proof, or a malicious-computation proof.

The public synthetic fixture is the compact-query benchmark fixture at commit
6763556: age 250 has one row (sum 100), age 251 four rows (sum 810), age 252
sixteen rows (sum 5000), and age 255 no rows. Other rows have ages below 200.
The fixture oracle is consulted only after the query to assert the result:
retrieval never selects addresses using fixture constants. Selected ordinals
must be decoded from authenticated private index responses.

## Responsibilities and entry points

| Source | Responsibility |
| --- | --- |
| [spiral_index_fhe_probe.rs](../experiments/private-access/spiral_index_fhe_probe.rs) | Native PIR transport, independently trusted heads, bounded selection, owner fresh encryption, encrypted-only evaluator, setup/accounting and paired measurements. |
| [padded_index_codec.rs](../experiments/private-access/padded_index_codec.rs) | PaddedV2 builder, binding/count/offset checks, canonical delta-varint selection through a PageSource callback, and cached metadata entry point. |
| [padded_index_codec_tests.rs](../experiments/private-access/padded_index_codec_tests.rs) | Adapted original codec contracts and callback/budget rejection cases. |
| [run-spiral-index-fhe.ps1](../experiments/private-access/run-spiral-index-fhe.ps1) | Fetch and verify the pinned SDK, prepare an ignored standalone Cargo package, build, run and save raw JSONL. |
| [SpiralIndexFhe.Cargo.lock](../experiments/private-access/SpiralIndexFhe.Cargo.lock) | Reproducible standalone dependency versions. |

The only direct project dependency is
[compact-store](../crates/compact-store/README.md), which owns canonical encrypted
snapshots, independent commitments, Merkle membership verification and owner AEAD
decryption. No compact-query secret-key export or production API change is needed.

The native SDK source is pinned to
[fdb7206517c249603b0c91b65f1f29f95272107c](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs).
The unchanged cryptographic configuration and security limitations are described
in [the private-access report](experiment-private-access.md). Only geometry
nu1=7 and nu2=2 is chosen for each 512-record database. Both index and data
records have fixed length 8192 bytes. Each contains a length-prefixed complete
LookupResponse with AEAD ciphertext and membership proof, followed by padding.
The temporary padded record buffer is discarded after NTT cache construction.
The two native NTT caches remain in RAM and are never persisted.

## Codec differences from the published implementation

The source originates from compact-query PaddedV2 at commit 6763556.
Its fixed-capacity formula, schema, header data-head binding, counts/offsets
checks, canonical varint rules, exact bucket boundary check, ordinal range check,
and duplicate rejection are retained. The following changes are explicit:

- Direct snapshot lookup is replaced with PageSource::lookup_wire; the existing
  codec authenticates and decrypts each returned page before consuming bytes.
- An IndexHeader may omit its decrypted first page when reconstructed from
  owner-cached counts/offsets. No postings or selected ordinals are cached.
- select_from_header accepts that already verified header. The online owner checks
  its exact data/index head bindings before invoking it.
- The probe accepts at most 16 selected rows and one posting page and one data
  page. Preflight rejects cross-page posting bytes or selected data rows. The
  underlying decoder's original cross-page behavior remains covered separately.
- Amount-only rebind is performed in the harness by replacing the current data
  commitment in index page zero, then rebuilding both native caches. The codec's
  original mutation helper is not copied.

The encoded index header is exactly 2164 bytes: the 112-byte data head plus
256 counts and 257 offsets, each u32. Cached owner metadata is exactly 2276
payload bytes: counts/offsets (2052) plus both 112-byte head bindings. Existing
independently trusted heads occupy another 224 bytes; that explicit duplication
is counted. This is not a claim of a 2048-byte complete cache.

## Compared profiles

AddressOnly conceals page addresses under native single-server PIR but exposes
the candidate count, request length, number of page reads, and RPC schedule.
This is an experimental comparison; approval of that leakage policy is unresolved.
It evaluates exactly the complete indexed candidate list, including an empty list.

Fixed16 uses one posting read, one data read and sixteen fresh encrypted rows
for all four fixture cases. Absent results still perform native encrypted dummy
PIR reads and authenticate both pages. Padding validity is a fresh encrypted
FheBool, never a public/trivial flag. The peer evaluates encrypted validity AND
encrypted equality before aggregation. This bounds cardinality hiding to the
declared one-page/16-row workload; it does not establish arbitrary-query hiding.

Both profiles compare Uncached (a real header PIR per query) and Cached
(version-bound owner metadata installed from a real verified private header
read). The latter's setup/refresh read and persistent owner state are reported.
The same shape and fresh-encryption/evaluator path are used by visible control.

For a nonempty query, Cached has posting, data, FHE: three sequential RPCs.
Uncached adds the header: four. AddressOnly absent can skip posting/data; its
shorter schedule is explicitly visible. The benchmark includes complete
serialization, local server work, owner recovery/authentication/decryption,
fresh encryption, real FHE evaluation and owner result decryption. It does not
measure network propagation, congestion, durable disk I/O or a remote process.
Timing differences are not a formal constant-time proof.

## Reproduction

Run from the repository root in PowerShell:

    ./experiments/private-access/run-spiral-index-fhe.ps1 -Rows 1000000 -Rounds 8 -Threads 8

The first run needs network access for the exact SDK revision and locked crates;
-Offline requires those caches to exist. CargoHome and TargetDirectory are
project-local by default and process environment is restored in finally.
The runner never writes owner secrets, plaintext participant data or generated
reports to tracked paths. Raw reports are ignored under .local/private-access.

Use -PrepareOnly to prepare the ignored standalone package before running these focused checks:

    cargo test --release --locked --offline --manifest-path .local/private-access/spiral-index-fhe-probe/Cargo.toml
    cargo clippy --release --locked --offline --no-deps --manifest-path .local/private-access/spiral-index-fhe-probe/Cargo.toml -- -D warnings

Round count applies to each of both profiles, both header policies and both
access policies: eight rounds produce 64 real complete query samples, with two
repetitions of each age. Rayon has eight workers by default; at most eight scoped
OS threads initiate row operations, sharing that Rayon pool.

## Failure model and open evidence

Before fresh FHE preparation, the owner rejects invalid/missing/tampered page
responses, wrong addresses, stale data/index proofs, stale cached metadata,
invalid data/index bindings and over-budget selections. Codec tests include
malformed/truncated/noncanonical varints, duplicate ordinals, exact bucket
boundaries, fixed-capacity padding and corrupt authenticated headers.

The canonical amount replacement changes the actual data snapshot, rebinds the
actual index head, invalidates old proofs/cache, rebuilds native caches, refreshes
the owner header by real PIR and performs a fresh indexed private FHE query.
Writes are visible and this is not a crash/durable commit protocol.

FHE output nonce/root checks reject accidental replay/version mismatch before
owner decryption. A malicious evaluator can forge those public metadata fields
or return incorrect ciphertexts. Input membership/AEAD checks do not authenticate
COUNT/SUM computation or prove index completeness against the logical table.
The native SDK and malicious-response/decryption-feedback composition remain
unaudited. Single-server PIR avoids a two-noncolluding-peer assumption but does
not itself provide malicious-server verifiable computation.

The measured limits and accounting below do not establish completion of the SQL goal.

## Measured result (one million rows)

The real run completed with exit status 0. All 64 complete queries returned the
expected COUNT/SUM, and every selected ordinal matched the complete decoded
posting list. Nineteen focused codec/pipeline/binding tests passed; authored
release Clippy with --no-deps -- -D warnings passed. The pinned SDK emits four
existing warnings and was not modified. Rust formatting, runner PowerShell AST,
new-file whitespace and document relative links were checked.

Raw ignored report:
.local/private-access/spiral-index-fhe-1000000-8-t8-20261014-213732-102.jsonl.
The measured main source SHA-256 is
76E31DEEBA2653590B06CD804E3CE8E046E7A32B2E7B91D78C248D5541B0D9E4.
No owner secret key was serialized to a file or supplied to the PIR/FHE peers.

Each table cell is the observed minimum–maximum full local latency in milliseconds,
with **two complete measurements for that exact age/profile/header/access case**.
These small samples do not establish a latency distribution or a 500 ms guarantee.

| Profile | Header | Matching rows | Visible ms | Private ms |
| --- | --- | ---: | ---: | ---: |
| AddressOnly | Cached | 1 | 62.785–76.697 | 312.547–337.744 |
| AddressOnly | Cached | 4 | 274.514–279.046 | 534.128–550.907 |
| AddressOnly | Cached | 16 | 805.291–884.614 | 1084.819–1095.492 |
| AddressOnly | Cached | 0 | 1.094–1.356 | 1.003–1.263 |
| AddressOnly | Uncached | 1 | 63.616–75.358 | 447.929–565.737* |
| AddressOnly | Uncached | 4 | 263.538–304.625 | 685.577–699.409 |
| AddressOnly | Uncached | 16 | 807.856–1019.363 | 1343.158–1515.777 |
| AddressOnly | Uncached | 0 | 1.136–1.482 | 127.561–132.248 |
| Fixed16 | Cached | 1 | 805.635–855.984 | 1114.965–1137.553 |
| Fixed16 | Cached | 4 | 827.946–874.167 | 1081.436–1222.381 |
| Fixed16 | Cached | 16 | 844.249–887.154 | 1059.404–1186.133 |
| Fixed16 | Cached | 0 | 804.610–808.898 | 1056.427–1082.530 |
| Fixed16 | Uncached | 1 | 859.137–902.760 | 1221.814–1293.730 |
| Fixed16 | Uncached | 4 | 814.678–881.711 | 1216.954–1235.357 |
| Fixed16 | Uncached | 16 | 818.563–859.510 | 1175.318–1226.266 |
| Fixed16 | Uncached | 0 | 852.767–865.743 | 1192.520–1215.849 |

*The first complete query was Private/AddressOnly/Uncached/one row, 565.7371 ms,
including 47.7814 ms restoring the serialized FHE evaluation key and first FHE
use. Its repeat was 447.9287 ms. No separate first-use sample was fabricated
for the other policies. Header-cache installation had already exercised PIR
during setup and is charged below.

The cached AddressOnly absent case performs no index-posting or data PIR read.
The authenticated cached counts establish the empty selection to the owner.
The peer returns the freshly encrypted zero identities supplied in the request;
there is no candidate FHE arithmetic/PBS. Its ~1 ms result is an explicit
absence-leaking fast path, not evidence for arbitrary private FHE queries.
Fixed16 absent executes the real sixteen-slot equality/validity/aggregation path.

For completeness, the following summaries pool four different cardinalities
(twice each), **n=8 per row**. Median is the average of the two middle values.
They should not be interpreted as per-query-type results.

| Profile | Header | Access | Minimum ms | Mixed-cardinality median ms | Maximum ms |
| --- | --- | --- | ---: | ---: | ---: |
| AddressOnly | Cached | Visible | 1.0943 | 175.6054 | 884.6142 |
| AddressOnly | Cached | Private | 1.0034 | 435.9358 | 1095.4917 |
| AddressOnly | Uncached | Visible | 1.1358 | 169.4479 | 1019.3625 |
| AddressOnly | Uncached | Private | 127.5610 | 625.6571 | 1515.7772 |
| Fixed16 | Cached | Visible | 804.6104 | 836.0971 | 887.1541 |
| Fixed16 | Cached | Private | 1056.4269 | 1098.7479 | 1222.3810 |
| Fixed16 | Uncached | Visible | 814.6778 | 859.3236 | 902.7595 |
| Fixed16 | Uncached | Private | 1175.3181 | 1219.3840 | 1293.7303 |

Native PIR server work across individual reads was 110.4734–151.7753 ms.
One cached private one-row operation therefore includes two real PIR reads
before its 65.75–67.36 ms peer FHE phase. Four-row private cached FHE took
275.95–309.07 ms; adding the two real reads made both complete queries exceed
500 ms. Sixteen-row FHE already exceeded 500 ms in the visible control.
No sum of independently benchmarked subsystems is substituted for these
complete-operation measurements.

## Public shape and wire audit

A post-run structural audit checked all 32 Fixed16 measurements: each has
16 serialized FHE rows, one posting read and one data read; Uncached has exactly
one additional header read. For each access/header mode, total serialized
request bytes, response bytes and RPC count were identical across all four ages
and both repetitions. The absent case used fresh encrypted false validity bits
and authenticated native dummy PIR reads.

| Fixed16 policy | Request bytes | Response bytes | Total bytes | Sequential RPCs |
| --- | ---: | ---: | ---: | ---: |
| Private Cached | 3,853,722 | 370,360 | 4,224,082 | 3 |
| Private Uncached | 3,870,171 | 390,840 | 4,261,011 | 4 |
| Visible Cached | 3,820,906 | 340,344 | 4,161,250 | 3 |
| Visible Uncached | 3,820,947 | 344,792 | 4,165,739 | 4 |

Each actual native query is 16,416 bytes plus the serialized public store id/root
(33 bytes), and each native response is 20,480 bytes. Visible requests serialize
the same store id/root plus the public u64 page (41 bytes total). A full data
LookupResponse is 6496 bytes; a full index response is 4448 bytes. Both include
the real membership path. Fixed16 FHE request/answer alone are 3,820,824/329,400
bytes. COUNT is FheUint8 (safe for the public maximum 16); SUM is FheUint32
(safe for sixteen u16 amounts).

AddressOnly Cached totals for 0/1/4/16 are respectively 724,688 / 1,012,642 /
1,654,930 / 4,224,082 bytes privately and 724,688 / 949,810 / 1,592,098 /
4,161,250 visibly. Uncached adds one header read: 36,929 private bytes or
4489 visible bytes. AddressOnly absent has one RPC Cached/two Uncached;
nonempty has three/four. That length/schedule leakage is material.

These equalities address public message shape on the accepted workload.
They do not prove constant execution time, resistance to an active malicious
PIR server or decryption-feedback security. The cache mode, database choice,
querywide head and query timing are visible. Queries exceeding the declared
budget are rejected and are not covered by a padded completion schedule.

## Storage, keys and actual memory

All expansion factors in the primary accounting use the same **3,000,000-byte
logical plaintext denominator** (one million public three-byte rows).

| Material | Bytes | Ownership / lifetime |
| --- | ---: | --- |
| Canonical encrypted data | 3,023,584 | Peer snapshot, 489 pages of at most 2048 rows. |
| Canonical encrypted PaddedV2 SQL index | 2,041,564 | Peer snapshot, 493 pages of at most 4096 bytes. Includes fixed-capacity padding. |
| Combined canonical snapshots | 5,065,148 | **1.6883827× logical plaintext**; one replica. |
| Data/index Merkle hash caches | 31,392 + 31,616 | Rebuildable RAM; not added to canonical snapshot disk bytes. |
| Data/index native NTT caches | 33,554,432 each | 67,108,864 total (64 MiB), RAM only; zero persisted bytes. |
| Temporary native input records | 4,194,304 | One database construction buffer at a time; dropped. |
| Shared Spiral public parameters, wire | 6,029,344 | One setup shared by the two PIR databases. |
| Shared Spiral expanded public matrix payload | 23,855,104 | Peer RAM, not another disk copy. |
| Spiral owner base / derived secret payload | 49,152 / 131,072 | Owner only; polynomial payload counts, not implemented secret-key wire format. |
| TFHE evaluation key, serialized | 180,610,692 | Public evaluator key; actual deserialized allocation included in process measurement. |
| TFHE owner key, serialized byte count | 31,268 | Owner only; counted with a sink, not saved or sent. |
| Compact-store owner key | 32 | One owner AEAD key shared by its data/index snapshots. |
| Independently trusted heads | 224 | Owner two complete commitments. |
| Cached header including duplicated bindings | 2276 | Owner metadata; exact count, no postings or ordinals. |
| Persistent FHE row cache | 0 | Fresh encrypted selected inputs per query. |

The known serialized material subtotal (combined canonical images + shared PIR
public wire + TFHE evaluation/owner key counts + AEAD key + trusted heads +
cached header) is **191,738,984 bytes = 63.9129947× logical plaintext**.
This subtotal omits an unavailable PIR owner-key serializer and is not a claim
of complete persistent-system storage. If fixed keys are persisted with this
small fixture, a whole-system <=2× claim fails. Adding NTT caches on disk would
also fail; the measured implementation keeps them in RAM.

The single native process's actual maximum working set was **471,756,800 bytes
(449.9023 MiB)**, including both PIR databases, key setup/serialization and TFHE.
Maximum sampled post-query resident memory was 323,174,400 bytes (308.2031 MiB).
These are one-process owner+peer measurements, not a sum of separate peak
benchmarks, a peer-only allocation trace or the memory requirement at larger
database geometry. Setup had a 7,000,000-byte public fixture capacity; that
buffer was dropped before queries. Runtime copies of fresh encrypted requests
and answers are included in the actual process peak. Allocator/container/stack
overhead is not inferred from payload counts.

## Setup and actual version transition

Full setup was 1475.3399 ms including fixture construction, both canonical images
and restore, both native caches, keys, key serialization/public PIR roundtrip and private owner
header-cache installation. Selected setup stages were:

| Stage | Measured ms |
| --- | ---: |
| Data seal / index build and seal | 5.0325 / 9.7818 |
| Canonical encode and decode, both | 4.3863 |
| Shared Spiral key setup/public roundtrip | 444.1017 |
| Data records / native NTT construction | 0.7260 / 116.0168 |
| Index records / native NTT construction | 0.5995 / 109.1877 |
| TFHE key generation / key serialization | 578.2917 / 63.5455 |
| Private header-cache installation | 140.5892 |

Setup plus the first complete query was 2041.0770 ms. This setup includes the
cached-header policy even though the first measured query used Uncached.
It is an in-memory experiment with serialized canonical/key roundtrips;
durable file reloads and network transfer time are unmeasured.

A real owner-authorized amount replacement changed ordinal zero from 100 to 101.
It replaced the canonical data page, replaced the data-head binding in canonical
index page zero, dropped both old native databases, rebuilt every affected
serialized proof record and both NTT caches, refreshed the owner header via
a real private read, then queried age 250 through fresh private index/data/FHE
operations. The result was COUNT=1/SUM=101.

| Update stage | Measured ms |
| --- | ---: |
| Canonical data replacement and index rebind, including rejection checks | 0.1052 |
| Data records / NTT rebuild | 0.9123 / 127.7926 |
| Index records / NTT rebuild | 0.7395 / 109.9642 |
| Private owner header refresh | 123.3095 |
| Update through caches/header ready | 365.8280 |
| Complete fresh indexed private read after update | 303.2019 |
| Entire replacement, rebuild, refresh and read | **669.0996** |

Old data proofs, old index proofs and the old cached header were rejected against
the new independently held heads before fresh FHE preparation. Tampered, omitted
and wrong-address index records were likewise rejected. Codec malformed/duplicate
cases were exercised in the focused contract suite. Neither update traffic nor
write addresses are concealed. One local successful transition is not durable
atomic publication, concurrent-write handling, consensus or recovery evidence.

The evidence supports a real bounded private age-index composition, with online
owner decryption and fresh FHE inputs. It does not satisfy the overall performance,
arbitrary SQL, malicious result proof or distribution requirements. On this
configuration only the one-row cached private queries met 500 ms among nonempty
private classes in both measured repetitions; the warm uncached one-row repeat
also did, while its first use did not. No privacy policy was newly approved.
