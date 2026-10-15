# Whole-table bulk disk → exact BFV aggregate

The subsequent [actual 1,000-table experiment](experiment-private-bfv-bulk-scale.md)
measures scale separately with a new disk-only dispatcher and one DB owner. The
measurements below remain the original single-table Disk/Resident control.

One fresh1,000,000-row public table completed **18/18 exact full operations** on
2026-10-15. Local time was **27.0733–31.5408ms**, with0/18 above500ms. The complete
serialized traffic was **5,736,091B per query**. This is an alternative full-snapshot
retrieval plan, **not PIR**; no network was measured. Under the stated serial model,
100Mbps and10ms RTT gives505.9606–510.4281ms, so the local result is not a WAN SLA.

The [standalone package](../experiments/private-bfv-bulk-disk/README.md) reuses the
owning compact-query/BFV/index/store implementation. No frozen probe, main source,
crypto profile or SDK was edited. No new crypto primitive or answer cache exists.

## Actual selection and roles

The fresh3MB logical table has2048 rows/data page. Ordinary ages are0..199.
Age255 occupies exactly256 ordinals `floor(i*999999/255)`, i=0..255, spanning
256 distinct data pages, all amount65535. Its exact SUM is16,776,960. Age250 has
one disjoint row at ordinal500000 with amount4095; age254 is absent. Public oracle
rows/ordinals are constructed after each whole timer and never feed preparation.
The measured operations are these three EQ selections, not arbitrary WHERE/range.

OwnerTable retains the sole compact/BFV secret authority and independently trusted
tableID/head-pair/length descriptor. DiskPeer owns ciphertext paths/optional serialized
ciphertext cache and shared public-only BFV evaluator. One270B request asks for BOTH
entire canonical encrypted snapshots; the270B response header precedes both full
bodies. Headers contain magic/version, tableID, fresh16B requestID, two112B heads and
two u64 lengths. No selected page, predicate or selected count occurs in this wire.
The peer validates its public descriptor and held-file sizes before response allocation.
The owner checks exact bounded framing/current descriptor/nonce before canonical decode;
8MiB per image is the fixed limit, with truncated/trailing/overlength inputs rejected.

Owning restoration recomputes both full ciphertext Merkle roots and verifies schema
and index AEAD/head binding. Complete index counts/postings/canonical varints, duplicate/
row/selection bounds and selected-page Merkle/AEAD checks remain. Every selected age
must match before fresh preparation. No one-/two-page selection limit is introduced:
the256-page sparse selection passes through the same owning API. Fresh encrypted byte
weights and COUNT ones run the real exact-index BFV eight-rotation/addition operation.
Owner completion consumes its pending context/keyset/head-bound token; result is
**Unverified / ProofStatus::Unavailable**, not a cryptographic arithmetic proof.

The unchanged profile is N8192,Q218,t114689; coefficient moduli
8796092858369,8796092792833,17592186028033,17592185438209,17592184717313;
CBD(20), variance10 for secret/error, native NTT/unfused, input/output level0.
The full original setup, including unused relinearization/rotation keys, is retained.
Independent numeric security/noise/CCA and malicious-result proof gates remain open.

## Timing, validation and complete observations

The whole OwnerTable.execute interval includes resource admission, nonce/request
encoding, held-file reads or resident copies/response construction, bounded full
root/index restoration, complete selection/selected AEAD/fresh encryption, request
decode/peer HE/output serialization, owner completion, diagnostic5MB body SHA256
and dropping Table/response/query buffers. Setup and post-timer oracle/native sampling
are separate. Disk mode opens/exact-reads both files each query; OS file cache is
allowed. Resident mode prefetched5,065,148B of peer ciphertext in1.1571ms outside
the query timer. There is no owner response/plaintext/FHE overlay cache.

Three observations per mode/case; p50 is nearest-rank. No case/outlier was omitted.

| Peer mode / EQ case | Min ms | p50 ms | Max ms | Count / SUM |
|---|---:|---:|---:|---:|
| Disk / absent |27.6893|28.0286|28.7335|0 /0|
| Disk / point |27.5969|28.3348|28.6310|1 /4095|
| Disk / sparse256 |30.6900|30.8331|31.4811|256 /16776960|
| Resident / absent |27.0733|27.5783|27.7660|0 /0|
| Resident / point |27.6397|27.7484|28.0557|1 /4095|
| Resident / sparse256 |29.9929|30.6111|31.5408|256 /16776960|

All18 had the same full ciphertext-body SHA256 and all four wire lengths; empty
cases still ran encrypted zeros with8 rotations,0 products/depth. Each prepared
selected count equaled0/1/256. Reported expected data-page counts0/1/256 are post-timer
fixture geometry, not new internal page-access instrumentation.

All six release tests passed in2.14s after a35.14s first dedicated build: framing
replay/version/table/head/truncate/trailing/oversize; sparse fixture; six genuine
both-mode BFV0/1/256 operations; actual data/index corruption and extra file bytes
before owner prepare; complete overbudget group before successful HE preparation;
foreign owner even for absence. Strict authored all-target Clippy (9.41s), fmt check
and release build (1.50s) passed first attempt. Unchanged SDK emits four existing
lifetime/static-reference warnings; CLIENT_TEST is unused. No source bug, failed
runtime launch or benchmark retry occurred. This is owning-boundary validation,
not a formal proof or broad fuzzing campaign.

Offline lock resolution selected112 packages,107 registry entries. Compared with
main Cargo.lock, common exact-version checksums match; only additional rand0.8.5
and rand_chacha0.3.1 are required by the existing pinned Spiral dependency. No main
lock changed. The new standalone lock SHA256 is
465E9279C04A4ADA5ECC96D7C72E540D39E6CD5D1B5E5853F513B46D0675135E.

## Actual bytes and explicit network model

| Serialized part | Bytes per query |
|---|---:|
| Bulk request |270|
| Bulk response: header +both full images |5065418|
| BFV exact request |223595|
| BFV response |446808|
| Outgoing total |223865|
| Incoming total |5512226|
| Both directions |5736091|

There are two sequential request/response steps: owner must authenticate/select
after bulk receipt before it can freshly prepare BFV. These are application bytes;
TCP/TLS/framing, queueing and link variability are excluded. For bytes W, measured
local L milliseconds, link B Mbps and RTT R milliseconds, the no-overlap model is
`L + 8W/(1000B) + 2R`. It is arithmetic, not measured remote execution.

| Model link / RTT | Transfer alone ms | Full modeled range ms |
|---|---:|---:|
|100Mbps /0ms|458.88728|485.96058–490.42808|
|100Mbps /10ms|458.88728|505.96058–510.42808|
|1000Mbps /0ms|45.888728|72.962028–77.429528|
|1000Mbps /10ms|45.888728|92.962028–97.429528|

Minimum bandwidth for500ms at zero RTT is97.0314–97.9567Mbps over these observations;
100Mbps permits only4.7860–7.0197ms RTT under this ideal model. Bulk-only framing
5,065,688B already costs405.25504ms at100Mbps. There is no measured same-fixture PIR
256-page run, so no PIR speedup or measured retrieval-plan break-even is claimed.
A future comparison must measure the same selection/fixture, not sum old timings.

## Retained keys, native memory and files

| Item | Bytes |
|---|---:|
| Logical payload |3000000|
| Canonical data file |3023584|
| Padded canonical index file |2041564|
| Public head/length anchor file |780|
| All three files |5065928|
| BFV full public serialized count (native setup retained via Arc) |13395426|
| BFV secret serialized COUNT only |8195|
| Compact owner key |32|
| Spiral owner restorable image count |336|
| Original Spiral public wire, retained |6029344|
| Full expanded Spiral public matrix u64 payload, retained |23855104|
| Spiral public seed |32|
| Client stack struct only; private buffers in native totals |264|
| Peer Resident ciphertext cache (Disk mode0) |5065148|
| Transient Table rebuildable Merkle payload |63008|
| Observed native OS-peak working set |273571840|
| Observed native OS-peak private commit |279662592|
| Actual files +observed native peak private |284728520|

Both BFV/PIR full setups remain live through the final operation; PIR is UNUSED for
retrieval, no NTT database overlay is created. Setup wire bytes are not falsely
substituted for resident allocations. BFV flat wire is transient for fingerprint/count
only; no public key file, secret file or owner image is written. Native peaks already
include retained keys, Client private buffers, Resident cache, temporary root/Table
buffers and runtime allocations: do not add listed subpayloads again. Native counters
are checked before setup/queries and after each operation through the final completion
record; they are observed process peaks, not post-exit OS sampling or machine-wide
memory. Current/OS-peak RSS and private counters all remained below decimal2GB.

Canonical data+index alone is1.6883826667x logical. Actual files +observed native peak
private is **94.9095067x at3MB logical**, so this probe does NOT meet combined2x.
Setup was813.5361ms total, including427.4639ms PIR and337.4392ms BFV setup and
16.0358ms public fixture seal/write. Setup precedes all query clocks. No pooled-disk
scale or1000-table claim follows; future scale requires fresh independent files and
a measured capacity-one loader, not multiplying a resident-table result.

## Frozen evidence and limits

Under WT .local/private-bfv-bulk-disk/:

* Raw22 records (setup+2 modes+18 operations+completion):
  bulk-18-20261015-015939-039.jsonl,
  SHA256 AB4B9933FF35EE122E8AE06A65FABA88FE5E63E58FC8EB4A5CB8D10C3ED47BF2.
* Pre-run EXE frozen-pre-run-20261015-015939-039/private-bfv-bulk-disk.exe,
  SHA256 F428FA0A8B7B0B1CD978C7C0C03F2F4104461C57E3096382A250EEABEAF94800.
* Pre-run archive-manifest.json SHA256
  10390F380C7F26F52CD7F1C8EB75F3FE58E76F5C42B64920976010786BF6B9FF;
  includes exact package and owning dependency source copies before measurement.
* active-run.json/run-completion.json bind args, paths and02:00:04.5546528Z..
  02:00:05.9886373Z successful process; wrapper wall1430.3671ms, stderr0B.
* lock-resolution.log, lock-comparison-main.json, tests-release-1.log,
  clippy-release-1.log, build-release.log and audit-summary.json retained. The fmt
  check succeeded silently; no separate fmt-check.log file was created.
* Final handoff-manifest.json binds current source/docs and raw/executable evidence.

The sole run used8 Rayon workers in the isolated dedicated target, with no authorized
concurrent heavy job. No GUI/network launch, main/frozen edit, commit or push occurred.
The later lock-copy preparation/README/report edits do not change measured Rust source.

Table identity, heads, sizes, timing, mode and failures remain public; no formal
traffic-analysis, arithmetic proof, CCA safety, general SQL, hidden writes, replication,
consensus, backup/restart or durable crash-atomicity claim is made. Full snapshot auth
requires independently trusted current heads; it does not choose those heads or
prove malicious peer arithmetic. This bounded alternative broadens authenticated
selected-page support and demonstrates its bandwidth cost, without closing those gates.
