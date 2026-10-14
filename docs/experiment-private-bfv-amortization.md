# Twenty independent retained BFV/PIR tables

Status 2026-10-15: the actual retained run keeps twenty independent one-million-row
data/index snapshots and all forty native PIR caches live. All 192 full paired
EQ COUNT/SUM reads are exact; the slowest is 435.892 ms locally. For Fixed16
16-row queries, cached private reads are 298.346–310.172 ms across supplied
first/middle/last table IDs, and uncached reads are 409.882–428.769 ms.
Every per-table/profile/header/age/access cell has only two samples.

Actual native process peaks are 1,710,084,096 B working set and 1,717,149,696 B
private commit, below the decimal 2 GB guard. Primary canonical images plus
shared key/owner payload accounting are 1.93869635x, or 1.95969902x with retained
Merkle payload, against 60,000,000 B logical plaintext. These are NOT full-state
2x results: forty retained NTT overlays alone cost 1,342,177,280 B. Counting
canonical once plus known auxiliary representations gives 24.72990915x, before
unpartitioned BFV native key/container overhead and the resident canonical copy.
Actual disk-file bytes plus current process working set end at 1,790,645,970 B.
The expanded representations are explicit, not hidden as free overhead.

The [new standalone package](../experiments/private-bfv-amortization/README.md)
continues the [measured one-table composition](experiment-private-bfv-index.md)
without modifying any frozen prior source. It remains owner-online, EQ-only,
Rows16, one posting/data page per request, local warm-cache retrieval and
unverified BFV arithmetic. It adds no new crypto parameters, network bound,
hidden write, arbitrary SQL, production owner backup or computation proof.

## Actual lifecycle, sharing and independent tables

One shared BFV Rows16 Owner/public setup and one native Spiral owner/public
setup are generated, serialized and restored BEFORE the tables. Each table
then calls compact-store Owner::generate with its own distinct public database
identifier; all twenty AEAD keys and nonce domains are independently sampled.
Each actual data snapshot and full PaddedV2 index is sealed, serialized to its
own new ciphertext file, decoded, converted into two independent native NTT
allocations, and supplied an owner header installed by a real private query.

No table, database, cache or result is cloned, deduplicated or replaced by a
row-count projection. All twenty data roots and twenty index roots are distinct,
asserted in the executable and independently checked in the raw full 112-byte
head records. Every table stays in the retained vector throughout the query
matrix. Each table emits its actual full data/index heads, canonical lengths,
hash bytes, two cache sizes, represented proof-response payload and setup times.

The supplied query IDs are 0,9,19; the table identity, complete global heads,
versions and cache choice are public. PIR conceals the page address within
the selected table/store, not which table is selected.

| Table ID | Rare-group first ordinal /data page | Age250 SUM | Age251 SUM | Age252 SUM |
| --- | ---: | ---: | ---: | ---: |
| 0 | 59,392 /29 | 100 | 810 | 5000 |
| 9 | 741,376 /362 | 109 | 1206 | 7448 |
| 19 | 577,536 /282 | 119 | 1646 | 10168 |

Every fixture is explicitly public synthetic input and has complete age 250/
251/252/255 groups of 1/4/16/0 rows. Common-age distributions and all amounts
also vary by table. The owner oracle maps only compare returned complete
ordinals/aggregates after the whole timer; they never supply selected rows
to the query. Every operation obtains ordinals from the actual authenticated
encrypted index, retrieves/authenticates the actual selected data page,
freshly encrypts verified fields, runs real peer BFV predicate/COUNT/SUM and
decrypts the bounded unverified answer. This is not a sum of old timings.

Both Visible and Private execute the same BFV16 kernel. AddressOnly exposes
empty/nonempty via omitted posting/data calls; it does not serialize active
cardinality in BFV. Fixed16 uses real authenticated dummy posting/data reads
and fresh encrypted zero low/high/COUNT weights for inactive slots. Full
request/response lengths and RPC counts are asserted invariant across all four
cardinalities for every table/header/access mode. Visible exposes requested
page addresses and repetition. The comparison approves no leakage policy.

The public-only BFV evaluator receives no storage snapshot, original stored
ciphertext/nonce/ordinal/page, owner key or plaintext fields. Both complete
trusted heads and a fresh 128-bit query ID bind the pending/output context.
The harness prevents an in-flight snapshot/head replacement through immutable
borrows. A persistent concurrent head/replay ledger is not implemented.

## Recovery, unchanged parameters and source evidence

The [Spiral owner-state module](../experiments/spiral-owner-state/README.md)
provides an actual 336 B owner image: framing, exact profile/revision/RNG
contract, expected domain, original public-setup hash, secret seed and a
corruption checksum. It is secret trusted owner state and never written to
peer/canonical output. Its checksum is not malicious-backup authentication.
The module pins little-endian 64-bit native public wire and deterministic
secret shuffle to the exact SDK/rand versions, not arbitrary platforms/releases.

The original public wire must remain available: generate_keys_from_seed uses
the seed for secret matrices, then samples fresh public entropy. Restore uses
supported generate_secret_keys_from_seed with the original public wire.
The original Client and owner image are dropped before restoring the actual
live Client used by every full query. The final retained owner image is 336 B;
live base/full secret polynomial payloads 49,152/131,072 B are also reported
as RAM copies. A separately validated original-client-drop recovery experiment
passes seven contract tests and actual private PIR recovery; this composition
then exercises the restored client across twenty independent real databases.

Spiral is unchanged pinned fdb7206517c249603b0c91b65f1f29f95272107c, the same
512 fixed 8192-byte record profile as the one-table report. Core Rows16 uses
the same N=8192/t=114689/Q=218/CBD(20) variance 10 native/unfused/level 0 profile.
The main f46d0bb optimization constructs that exact official parameter entry
directly, with full public parameter-wire equality validation; it does not
change crypto constants. The runtime gate checks actual owner/peer parameters,
geometry and implementation flags; actual public/secret byte counts are logged.

| Source boundary | SHA256 |
| --- | --- |
| Measured composition src/main.rs | DCA845399F7AE41AB9E582DD2F80BBFCF84CF70B13396C6256475CE6AE6440F7 |
| Shared BFV core lib.rs | 83D3E4E23803F96544617E88AA6EF2B17DFEC274DCB962C168BDAFD7DBA82C7A |
| BFV kernel.rs, unchanged | 1D719AA6193470C6F3B8C7D28FBC56A87A90D4D14E152A9CE63E5FF47400AE54 |
| Owner-state lib.rs | 32CF886EEAD6D14CA887E13B8A595FFAA5049E3ACB17844919A5B31F4AE25E3B |
| PaddedV2 callback codec, unchanged | 05A3BAF2AD3AB697B3CC9AD8EEB1B392D1C5B34FDB06AD3DFE0101ABF89F44ED |
| Actual executable | 8DD3D6C766CDC540FA02F663A8D3A5E21FAB41477FEC42B177E8F6F97B6C5A35 |

BFV's upstream ABOUT128 label and worst-case noise remain independently
unvalidated; no >=128-bit independent security result is inferred. The owner
decodes unsigned limbs with COUNT<=active_rows<=16, limbs<=255*COUNT<=4080,
SUM<=65535*COUNT. Output remains ProofStatus::Unavailable; binding and bounds
cannot establish correct arithmetic against a malicious peer. Native PIR
active-response/decryption feedback and arbitrary SQL completeness remain open.

## Bounded admission, tests and actual run

A separate target/private-bfv-amortization and unique package ID avoid the
previous shared-artifact collision. Eighteen focused release tests and authored
strict Clippy pass. Tests cover the original codec failures plus varied
independent complete fixture groups, real distinct data pages and admission
reserve/native-peak/overflow rejection. The unchanged SDK emits its four
existing lifetime/static-mut warnings; CLIENT_TEST is untouched and receives
no owner key.

Before EVERY table and cache allocation, admission checks current native
working/private bytes plus an expected addition (80 MiB/table, 48 MiB/cache)
and a reserved 80 MiB against decimal 2,000,000,000 B. Known native peaks also
must be below the cap; the 25 ms native sampler is an additional backstop.
Failure emits completed=false and an actual partial-file/retained-state ledger
and returns before the next allocation. It does not force twenty tables.
All 62 table/cache/update admission checks in the actual run pass. The policy
does not constitute a formal bound on every allocator instruction; actual
native peak counters establish the completed run's measured bound.

The initial retained two-table smoke run passes 64 reads plus actual replacement/
fresh-read and all failure checks, native peaks 398,131,200/400,502,784 B.
The actual 20 run follows only after that success. One launch permission review
timed out before process creation, so that attempt generated no measurement.
The safe retry executes the existing identical validated binary from main's
writable checkout and writes only main/.local/private-bfv-amortization.
Its first provenance record is the exact source manifest from the successful
dry run. No failed sample is dropped, repeated or reclassified.

Actual20 setup takes 7610.570 ms, including independently building all forty
native caches and twenty actual private owner-header fills. Shared BFV
keygen 142.735 ms/public restore 156.491 ms and Spiral setup/recovery 414.580 ms
are actual stages, not an assertion that setup fits 500 ms. Queries read
already-retained memory caches, not disk. The workload is sequential, with
8 Rayon threads and at most 13 native threads observed; no other heavy team
build/benchmark overlaps the exclusive CPU lease.

## All paired full-operation measurements

Two samples of each table/profile/header/age/access cell give 192 complete
operations. Times below are minimum/median/maximum milliseconds; n=2 in every
Visible and every Private cell. No mixed-cardinality median or throughput
conversion replaces these full measurements.

| Table | Profile | Header | Age (rows) | Visible min/median/max ms | Private min/median/max ms |
| ---: | --- | --- | ---: | ---: | ---: |
| 0 | AddressOnly | Cached | 250 (1) | 77.913/81.242/84.572 | 306.203/306.323/306.443 |
| 0 | AddressOnly | Cached | 251 (4) | 79.077/79.644/80.211 | 300.522/303.208/305.894 |
| 0 | AddressOnly | Cached | 252 (16) | 79.210/79.503/79.796 | 302.491/303.704/304.918 |
| 0 | AddressOnly | Cached | 255 (0) | 78.204/80.066/81.927 | 77.990/79.246/80.501 |
| 0 | AddressOnly | Uncached | 250 (1) | 77.586/78.277/78.968 | 408.283/414.654/421.024 |
| 0 | AddressOnly | Uncached | 251 (4) | 77.633/79.183/80.734 | 408.456/412.660/416.863 |
| 0 | AddressOnly | Uncached | 252 (16) | 78.349/79.697/81.045 | 412.855/415.023/417.192 |
| 0 | AddressOnly | Uncached | 255 (0) | 78.077/79.508/80.940 | 191.756/193.978/196.200 |
| 0 | Fixed16 | Cached | 250 (1) | 80.078/85.476/90.875 | 301.125/307.157/313.188 |
| 0 | Fixed16 | Cached | 251 (4) | 78.219/78.531/78.843 | 300.276/303.772/307.268 |
| 0 | Fixed16 | Cached | 252 (16) | 79.532/80.693/81.854 | 303.451/306.811/310.172 |
| 0 | Fixed16 | Cached | 255 (0) | 78.083/79.355/80.627 | 302.090/311.607/321.124 |
| 0 | Fixed16 | Uncached | 250 (1) | 80.101/80.946/81.790 | 408.377/413.951/419.525 |
| 0 | Fixed16 | Uncached | 251 (4) | 78.734/78.854/78.974 | 415.971/416.365/416.759 |
| 0 | Fixed16 | Uncached | 252 (16) | 78.781/80.583/82.385 | 418.742/423.755/428.769 |
| 0 | Fixed16 | Uncached | 255 (0) | 77.349/80.678/84.007 | 415.016/421.345/427.675 |
| 9 | AddressOnly | Cached | 250 (1) | 78.840/81.645/84.451 | 307.449/314.119/320.790 |
| 9 | AddressOnly | Cached | 251 (4) | 77.884/78.775/79.665 | 300.158/303.421/306.683 |
| 9 | AddressOnly | Cached | 252 (16) | 77.735/78.273/78.811 | 299.715/307.602/315.489 |
| 9 | AddressOnly | Cached | 255 (0) | 77.798/78.185/78.573 | 78.976/79.222/79.468 |
| 9 | AddressOnly | Uncached | 250 (1) | 79.309/81.190/83.070 | 414.170/425.031/435.892 |
| 9 | AddressOnly | Uncached | 251 (4) | 77.784/78.519/79.254 | 418.612/419.195/419.777 |
| 9 | AddressOnly | Uncached | 252 (16) | 78.739/79.085/79.432 | 415.053/418.029/421.004 |
| 9 | AddressOnly | Uncached | 255 (0) | 77.365/78.331/79.297 | 189.032/189.723/190.414 |
| 9 | Fixed16 | Cached | 250 (1) | 79.287/80.871/82.455 | 302.791/308.359/313.927 |
| 9 | Fixed16 | Cached | 251 (4) | 79.408/81.253/83.098 | 303.721/305.764/307.806 |
| 9 | Fixed16 | Cached | 252 (16) | 79.496/80.369/81.242 | 298.346/303.906/309.467 |
| 9 | Fixed16 | Cached | 255 (0) | 76.754/76.825/76.897 | 301.621/301.643/301.665 |
| 9 | Fixed16 | Uncached | 250 (1) | 78.173/80.323/82.474 | 410.564/417.307/424.050 |
| 9 | Fixed16 | Uncached | 251 (4) | 77.934/78.644/79.353 | 414.433/417.166/419.900 |
| 9 | Fixed16 | Uncached | 252 (16) | 79.556/80.927/82.299 | 411.270/416.338/421.406 |
| 9 | Fixed16 | Uncached | 255 (0) | 77.259/78.457/79.656 | 411.767/413.771/415.775 |
| 19 | AddressOnly | Cached | 250 (1) | 77.921/78.051/78.181 | 299.551/299.729/299.907 |
| 19 | AddressOnly | Cached | 251 (4) | 77.234/77.489/77.745 | 306.287/308.054/309.822 |
| 19 | AddressOnly | Cached | 252 (16) | 77.080/77.172/77.265 | 300.874/302.777/304.681 |
| 19 | AddressOnly | Cached | 255 (0) | 76.430/78.291/80.152 | 77.229/78.367/79.505 |
| 19 | AddressOnly | Uncached | 250 (1) | 77.500/77.714/77.928 | 411.922/414.847/417.773 |
| 19 | AddressOnly | Uncached | 251 (4) | 78.502/79.615/80.729 | 409.523/412.642/415.760 |
| 19 | AddressOnly | Uncached | 252 (16) | 77.504/77.673/77.843 | 409.960/412.321/414.681 |
| 19 | AddressOnly | Uncached | 255 (0) | 76.768/77.006/77.244 | 186.220/188.048/189.876 |
| 19 | Fixed16 | Cached | 250 (1) | 77.722/78.050/78.378 | 299.517/301.142/302.767 |
| 19 | Fixed16 | Cached | 251 (4) | 76.771/77.459/78.147 | 297.461/300.425/303.388 |
| 19 | Fixed16 | Cached | 252 (16) | 78.897/79.183/79.470 | 298.747/298.897/299.047 |
| 19 | Fixed16 | Cached | 255 (0) | 77.249/78.081/78.914 | 299.085/302.472/305.860 |
| 19 | Fixed16 | Uncached | 250 (1) | 77.575/78.279/78.983 | 406.224/406.918/407.612 |
| 19 | Fixed16 | Uncached | 251 (4) | 79.136/80.148/81.159 | 406.730/409.281/411.831 |
| 19 | Fixed16 | Uncached | 252 (16) | 78.507/79.452/80.397 | 409.882/413.418/416.955 |
| 19 | Fixed16 | Uncached | 255 (0) | 77.058/78.547/80.037 | 408.617/408.822/409.028 |

All 192 queries return exact complete ordinals/COUNT/SUM. The largest observed
time 435.892 ms is table 9 AddressOnly/Uncached/age250; no observed query exceeds
500 ms. This is a small local warm-cache sample, not a remote deadline or tail
guarantee. The full timer includes header/posting/data fetch, authentication/
decryption/selection, fresh BFV preparation and serialization, actual peer
decode/evaluate/encode, owner output check/decrypt and ciphertext-only freshness
evidence. Stage subtotals overlap; do not add header/posting counters again to
index_verify_decrypt_select_ms.

The wire shape is unchanged by retaining more tables. BFV request/output are
670,134/446,764 B. Private nonempty and all Fixed16 operations transfer
1,190,756 B Cached with 3 sequential exchanges, or 1,227,685 B Uncached with 4.
AddressOnly/absent uses 1,116,898 B/1 exchange Cached and 1,153,827 B/2 Uncached.
Visible nonempty/Fixed16 use 1,127,924/1,132,413 B with 3/4 exchanges. No network
transport/envelope, disk query I/O or RTT is measured; table/root/version
identity stays public in both access controls.

## Actual primary bytes and every retained expanded representation

All factors below use 60,000,000 B logical plaintext: 20 actual 1M tables ×3 B/row.
The primary file counts are actual file lengths, not NTFS allocation/journal
sizes, and no fsync/crash-durability guarantee is claimed.

| Representation | Actual or explicitly counted bytes |
| --- | ---: |
| Twenty canonical data images | 60,471,680 |
| Twenty canonical full index images | 40,831,280 |
| Canonical primary images combined | 101,302,960 (1.68838267x) |
| Shared PIR public wire /BFV public wire | 6,029,344 /8,930,306 |
| Actual primary files: 40 table images +2 public setups | 116,262,610 |
| Shared owner PIR image /BFV secret serialized count | 336 /8195 |
| Twenty independent AEAD secret payloads | 640 |
| Independent trusted heads,40×112 | 4480 |
| Twenty cached headers, including duplicated heads | 45,520 |
| Primary image+sharedkeys+owner known subtotal | 116,321,781 (1.93869635x) |
| Retained data+index Merkle payload | 1,260,160 |
| Known subtotal plus retained hashes | 117,581,941 (1.95969902x) |
| ALL 40 retained NTT overlays | 1,342,177,280 |
| Retained raw proof-record overlays | 0 |
| Proof-response payload represented inside NTT | 107,269,040 (subset, not added twice) |
| Expanded shared PIR public polynomial RAM payload | 23,855,104 |
| Live PIR base/full secret polynomial RAM copies | 49,152 /131,072 |
| Canonical once +all known listed auxiliary representations | 1,483,794,549 (24.72990915x) |
| Final current process working/private bytes | 1,674,383,360 /1,681,408,000 |
| Native peak process working/private bytes | 1,710,084,096 /1,717,149,696 |
| Actual primary files +final current working/private process | 1,790,645,970 /1,797,670,610 |

Each NTT allocation is 33,554,432 B, with two actual allocations per table.
Raw fixed record buffers are 4,194,304 B per conversion and dropped, not
retained alongside NTT. The represented encrypted page/proof payload is
5,363,452 B per table; it is expanded into NTT, not an extra retained copy.
Neither raw proof records nor NTT are persisted; persistence would add their
actual bytes. Canonical decoded ciphertext snapshots also remain in process,
separately from disk files, and are not silently equated with zero RAM.

The 24.73x known-representation sum is still a lower accounting boundary, not
a complete serialized memory image: core-expanded BFV keys, parameter tables,
allocator/container metadata and resident canonical copies are not individually
partitioned by the unchanged public core API. Native whole-process current/
peak working/private counters include all these live allocations. The explicit
disk+process sums give the actual combined physical-file/process boundary,
including both resident and file copies, while excluding filesystem cache
outside the process. No auxiliary expanded copy is claimed to be free.

The 336 B image establishes pinned PIR owner recovery, but the BFV/compact
owner secret terms are byte counts and were not persisted/exported/restarted.
complete_portable_owner_state_established therefore remains false. Primary
images cannot independently restart the entire owner session. All secret
owner bytes stay owner-side; no secret seed/key is logged or sent to a peer.

## Real retained-state replacement and rejection

After 192 reads, table 19's owner changes actual amount 119->120 in its canonical
data page, rebinds its index header to the new data head, writes both primary
images, drops ONLY that table's old two NTT caches, rebuilds the real pair,
privately refreshes the owner header and runs a fresh full private Fixed16
query. All other nineteen table/cache pairs remain live, all their heads are
checked unchanged and final state again retains all forty caches.

| Actual replacement lifecycle | ms |
| --- | ---: |
| Canonical data replacement +index rebind | 0.036 |
| Through actual canonical file rewrite | 3.080 |
| Data records /NTT rebuild | 0.661 /108.650 |
| Index records /NTT rebuild | 0.529 /103.990 |
| Real private header refresh | 115.833 |
| Through cache/header ready | 335.693 |
| Full fresh private index->PIR->BFV read | 308.765 |
| Whole replacement+files+rebuild+refresh+read | 644.474 |

COUNT 1/SUM 120 is exact and canonical lengths do not grow. This is an
owner-authorized compact replacement, NOT FHE/BFV UPDATE. Writes and version
changes remain visible; std::fs::write does not implement atomic crash recovery,
durable commit, fsync, replication or a concealed write protocol.

The untrusted serialized LookupResponse boundary after a real PIR retrieval
injects a valid index page from another table,
a valid data page from another table and an omitted index response. All reject
before BFV preparation. After replacement, old owner header, old data response
and old index response also reject with preparation counter unchanged; the
old index page 0 is compared against current expected page 0, isolating freshness
rather than relying only on a wrong page number. All 193 successful preparations
are real full operations (192 matrix +1 fresh read). Public output bindings
do not prove arithmetic, SQL completeness or consistency of an equivocal owner.

## Reproduction and frozen evidence

Use the module runner's dedicated target and explicit source directories.
The actual run used the executable built/tested by the two-table stage and a
safe writable output directory; its source/core/owner hashes are identical.
Generated snapshots, public setup files and raw JSONL remain ignored.

Actual20 raw:
E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/private-bfv-amortization/amortization-20-s2-t8-20261014-230743-584.jsonl
SHA256 3EE6A90793431AD1506F8E8D5C61B457F39DBD274A86DCE7408061074A75C3B1.
Dry2 raw in this task WT:
.local/private-bfv-amortization/amortization-2-s1-t8-20261014-230439-567.jsonl.

The next resource question is removing or bounding the expanded PIR overlays
while preserving real private latency, plus independently validating BFV
security/noise. This experiment establishes the reported narrow retained
local execution, not the complete 2x/500ms arbitrary-SQL goal. Both visible
page access and real PIR remain explicit controls.