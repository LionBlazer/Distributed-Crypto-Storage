# Disk-only bulk + BFV: actual1000 tables

One fresh1000-table run completed **54/54 exact full operations**, local
**26.6722–30.3293ms**,0/54 above500ms. All2001 physical files plus observed process
native peak private were **5,346,678,644B /3GB logical =1.782226214667x**. This is an
actual bounded storage/query measurement, not a projected multiple of the tiny probe.
It transfers BOTH entire encrypted snapshots, **not PIR**; every query carries
**5,736,091 application bytes** across two sequential RPCs. No network was measured.
At100Mbps/10msRTT, the explicit serial MODEL is505.55948–509.21658ms, all54 above500ms.

The [new standalone package](../experiments/private-bfv-bulk-scale/README.md)
extends the [separate18-operation probe](experiment-private-bfv-bulk-disk.md).
One declared compact/BFV authority owns ONE database with1000 independently sealed
1M-row tables. It does not inherit earlier per-table-owner recovery/PIR-bundle
semantics, establish portable restart or change the GUI's visible-only adapter.

## Actual data, selection and trusted routing

All1000 tables were freshly generated, sealed and saved, not copies, hardlinks,
resident tables or projected files. Each has1,000,000 public synthetic3B age/u16
amount rows and2048 rows/data page. Ordinary ages0..199 have amount
`(ordinal*13 + tableID*641 +7) mod65536`. One age250 row at ordinal500000 has
amount4095+tableID. Age254 is absent. Age255 occupies exactly256 ordinals
`floor(i*999999/255)`, i=0..255, on256 distinct data pages; all amounts65535 give
exact unsigned SUM16,776,960. These are explicit public fixtures, not participant data.

A single same-DB compact/BFV owner independently seals each table, with fresh
encryption and globally distinct data/index roots. The database/key domain is
shared across all tables; the physical inventory confirms one such identity.
Owner memory retains all
1000 trusted descriptors, not decoded snapshots. Public catalogJSONL contains IDs,
both112B heads, exact lengths and basenames. It is not a restart authority or head
consensus mechanism.2000 distinct roots and ALL physical lengths/112B manifests
matched the independent live descriptors before and after the query series. Only
IDs0/499/999 were queried; file inventory covers all1000.

Synchronous dispatch starts its outer timer before descriptor lookup/clone and
public peer construction. It sets the single owner's trusted descriptor from its
live catalog; no pending operation crosses a descriptor switch. Public evaluator
clones share its two owning Arc fields; no per-query key generation/secret copy or
setup-wire roundtrip occurs. The temporary peer has only ciphertext paths, public
heads and public BFV material, and is dropped before the outer timer ends.

Unchanged frozen bulk roles exact-read BOTH held files EVERY operation.270B request/
response framing has tableID, fresh requestID, head pair and lengths, with no selected
address/predicate/count. Bounded exact framing/nonce/current-head/length gates precede
canonical decode. Owning restoration recomputes BOTH full ciphertext roots and
checks index AEAD/head binding; complete count/postings/canonical varints, duplicate/
row/256-selection limits and all selected page AEAD/age gates precede fresh encryption.
There is no one-/two-page limit, index prefix/truncation or plaintext answer fallback.
The current owning compact-query selection budget is256 complete matches; larger
groups reject before preparation. Retrieval moves O(table bytes), even for absence;
these timings do not describe index-only visible fetching or arbitrary full-scan SQL.

Real byte/COUNT weights execute eight BFV rotations/adds,0 products/depth. Empty
queries still transfer both images and evaluate encrypted zero weights. Owner
completion consumes its context/keyset/head-bound pending token and returns
**Unverified /ProofStatus::Unavailable**. Authentication does not prove arithmetic.
Profile remains N8192,Q218,t114689, coefficient moduli8796092858369,8796092792833,
17592186028033,17592185438209,17592184717313; CBD(20), variance10 secret/error,
native NTT/unfused, input/output level0. Full original keys remain retained.
Independent numeric security/noise/CCA and malicious-arithmetic-proof gates remain open.

## Validation and whole-operation observations

Nine owning release tests passed3.30s after a35.43s first dedicated build. Six bulk
tests are byte-identical to the measured baseline. Three new tests cover admission
count/budget/actual-free-space failures; one shared owner/three independently sealed
tables with9 genuine BFV dispatches; and swapped same-owner table files, misrouting
and unknown IDs rejected before fresh preparation. Retained tests include both-mode
0/1/sparse256 HE, framing/replay/heads/limits, actual ciphertext/extra-file corruption,
complete overbudget and foreign-owner absence. Strict authored Clippy (9.37s), silent
fmt check and release build (1.71s) passed first attempt. Four unchanged SDK warnings
remain; CLIENT_TEST is unused. No source fix, build retry or discarded runtime occurred.

The standalone lock stayed unchanged under --locked --offline, SHA256
A5C13AFCF41E643544056C32452B4E6E6187978038AB73B4A2AFE2946BC85109.
It differs from bulk18 only by the package name; no dependency version/checksum
changed. The full source/EXE was frozen and root/B independently reviewed the driver
before root explicitly authorized the sole actual1000 run.

54 operations =3 samples×3 EQ cases×3 supplied IDs×2 observations. Each observation
reopens and reads the complete files. There are NO application cache miss/hit labels;
OS filesystem cache is allowed. The whole outer interval includes descriptor dispatch,
Arc peer creation, native admission, nonce/request encode, disk/read/full response,
full canonical/root/index restore, complete selection/AEAD/age/fresh encryption,
BFV request decode/HE/output encoding, owner completion, diagnostic full-bodySHA256,
Table/query cleanup and peer drop. The nested frozen clock is reported separately,
not added to outer time. Public oracle/expected-page reconstruction and native
sampling happen after the outer timer. No key/table setup time is hidden in query time.

Each cell has6 observations; nearest-rank p50. Cell p95 equals its maximum at n6.

| EQ case / tableID | Min ms | p50 ms | Max ms | Count / SUM |
|---|---:|---:|---:|---:|
| absent /0 |26.7265|26.9689|27.7484|0 /0|
| absent /499 |26.6722|26.8582|27.3037|0 /0|
| absent /999 |26.7264|26.7426|27.1148|0 /0|
| point /0 |27.2721|27.3654|27.7526|1 /4095|
| point /499 |27.2290|27.3828|27.5492|1 /4594|
| point /999 |27.0412|27.3078|27.5342|1 /5094|
| sparse256 /0 |29.5762|29.7762|30.3293|256 /16776960|
| sparse256 /499 |29.8095|30.0020|30.0724|256 /16776960|
| sparse256 /999 |29.6817|29.7894|29.9319|256 /16776960|

Whole-series p50=27.4426,p95=30.0699,max30.3293ms. All54 observations are retained;
0 above500 locally. Every prepared selected count equals0/1/256 and all owner results
match the post-timer oracle. Fixture-expected page counts0/1/256 are not claimed as
new internal I/O instrumentation. Per-table bodySHA is constant across queries;
independent concatenated fileSHA matches raw for all three queried tables. Both
observations use actual full reads, not cached response/decoded Table reuse.

## Traffic and network MODEL

All54 use identical four-part lengths: bulk request270B, bulk response5,065,418B,
BFV request223,595B and response446,808B. Outgoing223,865B +incoming5,512,226B =
5,736,091B. Two sequential RPCs are required: fresh BFV cannot be prepared before
owner receives/authenticates/selects from bulk snapshots. Table IDs, current roots,
lengths, timing and failures remain public. Full transfer conceals selected addresses;
it is not a formal traffic-analysis proof, and failure shapes are not padded.

For measured local L, W=5,736,091B, bandwidth B Mbps and RTT R milliseconds:
`serial_model_ms = L + 8W/(1000B) + 2R`. No overlap is assumed. TCP/TLS/framing,
queueing/link variation and actual remote compute are excluded; this is arithmetic,
not a network measurement or WAN SLA.

| Model link / RTT | Transfer alone ms | Full modeled range ms |
|---|---:|---:|
|100Mbps /0ms|458.88728|485.55948–489.21658|
|100Mbps /10ms|458.88728|505.55948–509.21658|
|1000Mbps /0ms|45.888728|72.560928–76.218028|
|1000Mbps /10ms|45.888728|92.560928–96.218028|

Minimum zero-RTT bandwidth for500ms is96.9492–97.7040Mbps across the observations.
100Mbps permits only5.3917–7.2203ms RTT under this model. All54 exceed500ms when
modeled at100Mbps/10msRTT. No same-fixture256-page PIR comparison was measured;
there is no measured PIR speedup or break-even claim from unrelated old timings.

## Actual files, retained material and resource boundary

Preflight observed1,233,281,019,904B available disk, checked6,293,553,152B planned
canonical/catalog reserve plus64MiB free-space margin against declared6.5GB before
key generation/writes. Every public file used CreateNew/write_all/flush. No fsync,
crash-atomicity or rollback guarantee is claimed. Fresh actual dataset—not an estimate:

| Item | Bytes |
|---|---:|
| Logical1000-table payload |3000000000|
|1000 canonical data files (3023584 each) |3023584000|
|1000 padded index files (2041564 each) |2041564000|
| Public catalogJSONL |848148|
| All2001 actual files |5065996148|
| Native observed OS-peak working set |274644992|
| Native observed OS-peak private commit |280682496|
| Actual files +observed peak private |5346678644|

Canonical-only ratio is1.6883826667x; actual files+observed native peak private ratio
is1.782226214667x. The latter includes full retained original BFV/PIR setup/native
allocations, catalog, transient Table/root/query/oracle buffers and runtime heap.
It meets the<=2x scoped single-process/single-replica measurement here, not the entire
distributed/recovery/privacy/proof requirements. Native current/OS-peak RSS+private commit
were checked against decimal2GB before setup/queries and after each through the
completion record. These are observed in-process peaks, not a post-exit/machine-wide
memory measurement. OS filesystem cache/replicas/network are excluded.

No canonical snapshot, resident ciphertext response, owner response cache or NTT
database overlay survives query calls. Owner still retains all1000 trusted descriptors:
244,000B serialized payload overlaps296,000B live entry structs;318,780 path-string
OS units are reported separately, not called bytes or added twice. Full BFV public
setup is live via Arc; serialized count13,395,426B (parameters46,relin1,116,273,
rotation keys12,279,077 plus framing), transient flatwire only for count/fingerprint.
One compact owner key32B and BFV secret serialized COUNT8195B remain private/live.
Original UNUSED PIR owner (336B restorable-image count), client/private buffers, public wire6,029,344B,
expanded public matrix u64 payload23,855,104B and public seed32B remain live through
completion. Client stack struct264B excludes its private buffers, already included
in native totals. No keys/owner images/public-setup files are persisted. Do not add
these subpayloads on top of the native peak again or omit them because PIR is unused.

Setup31,161.4462ms is separate: PIR408.9829ms,BFV327.1758ms, independent canonical
seal/write30,348.1006ms plus ledger/overhead. No existing owner/fixture was regenerated
inside query clocks. ONE same-DB owner is an explicit new scope; this does not claim
portable checkpoint/restart compatibility with earlier independently owned tables.

## Frozen evidence and reproduction

WT .local/private-bfv-bulk-scale/ retains:

* Raw1057 records: bulk-scale-1000-20261015-021637-104.jsonl; SHA256
  F85473FA12903228302931FC6D7D62C3A5375806A7E31C6096DB7CE02F68D824.
* Pre-run frozen EXE: frozen-pre-run-20261015-021637-104/private-bfv-bulk-scale.exe;
  SHA256 EB8991144000DE126DCA28B5A93CDFF01FC26AD418BBE7B48D300488250BB9D7.
* Pre-run archive-manifest.json,63 files/EXE and original owning dependency sources;
  SHA256234AAD68D418819219A584E57F48B15EBD19A4C61DFCEB0FF6C1E7E220022368.
* source-ready-manifest.json16B8DCA5..., active-run.json/run-completion.json;
  exact02:17:41.7343087Z..02:18:14.6032955Z, wrapper32,864.9671ms, exit0/stderr0B.
* tests-release-1.log, clippy-release-1.log, build-release.log and checks-result.json.
  fmt was silent; no fmt-output file is claimed.
* audit-bulk-scale.ps1/result.json independently check54 unique cells/formulas/work/
  wire/model, all2000 actual heads/lengths/distinct roots, one databaseID, three full
  bodySHAs, all63 archive hashes and actual joint accounting. final handoff-manifest
  binds current source/docs and all evidence hashes.

See package README for locked/offline jobs2/Rayon8/testthreads1 reproduction. The
pre-run README/source-basis metadata describe their historical preparation stage;
current README/report describe actual completion. Measured Rust/frozen module copies
were not edited. No competing authorized heavy job ran. Only this one actual1000
launch occurred; no sweep, timing filter, repeat, GUI or network launch happened.
No main/frozen edit, commit or push was performed by this task.

This owner-online supplied-table read prototype does not establish general SQL or
global routing, malicious arithmetic verification, independent security/noise/CCA,
hidden writes, portable restart, backup availability, durable checkpoint, replication
or consensus. Independently trusted current heads remain an input. The observed
local latency/storage result must remain alongside its explicit bandwidth and proof
limits; it does not complete the overall database requirements.
