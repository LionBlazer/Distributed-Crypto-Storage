# Actual1000-table owner-process restart

Using the SAME frozen executables as the [three-table probe](experiment-private-bfv-restart-disk.md),
a fresh1000-table writer exited and a separate reader restored the ORIGINAL
compact/BFV/PIR owners, original public setup and current updated files. All768
query results and nine restore rejection controls passed.

The SAME RUN measured all2005 dataset files plus the conservative sum of observed
parent/serial-child native private peaks at5,444,478,278B /3,000,000,000B =
1.8148260927×. All384 ExactIndex operations were below500ms (max320.6736ms).
FullPredicate had ONE retained overrun:520.2137ms. These results cover the bounded
complete exact-index groups below, not arbitrary SQL, a physical-cold/network
deployment or a completed durable recovery system.

## Reproduction identity and lifecycle

No runtime source change or rebuild occurred after tiny3. Before execution the
three frozen EXE hashes were rechecked and E: available free space measured
1,200,110,788,608B. The fresh public config was1000 independent1M-row tables,
IDs0/499/999, one sample, Rayon8, capacity1, canonical budget6,500,000,000B
(preflight1000×6MiB=6,291,456,000B), writer deadline300s and reader600s.

Broker PID277300 held a32B wrapping master in Zeroizing RAM and sent child copies
only through anonymous stdin. Writer PID297492 generated the ORIGINAL keys,
files and public setup, sealed generation0, then selected table999's actual
age250 index posting ordinal333824. Fresh BFV1099 + encrypted delta1 produced1100.
Owner-local arithmetic authorization preceded canonical data replacement and
index rebind; both revisions became1, canonical growth0. Generation1 was sealed
against those current heads. No native cache existed during the writer update.

Writer exited0/EOF after31,016.7110ms. Only THEN did reader PID290552 start,
restore the original owners/publics and run queries. Reader exited0/EOF after
141,192.4967ms. There was no owner-key or encrypted fixture generation in reader,
no old lost-key dataset reuse, and no process observation-timeout restart.
Public oracle rows were independently reconstructed only AFTER query timing.

This is an actual OWNER PROCESS restart while a separate trusted broker remains
alive. Full-machine restart/key custody and independently trusted current-anchor
persistence remain external. When this deliberately ephemeral broker exits, its
master is gone; the retained sealed files alone do not authorize another session.

## Complete measured query matrix

The original full BFV keyset/Owner serves FullPredicate and ExactIndex. Both
Visible/Private, cached/uncached header, AddressOnly/Fixed256, real table
miss/hit and all eight complete groups run on each of the three supplied IDs:
8×2×2×2×2×3×2=768 full operations. ExactIndex always performs eight encrypted
rotations/additions and zero products; FullPredicate performs its encrypted
predicate/products/relinearization. Actual index postings supply every selected
ordinal. No filtering/truncation, precomputed answer, permanent FHE cache or
plaintext peer aggregate substitutes for that work.

All entries are min/median/max milliseconds, n=12 EACH cell
(three IDs×two profiles×miss/hit). Each cardinality remains a separate row.
The256 fully separated kernel/case/profile/header/access/event groups, n=3 each,
are retained in the statistics artifact. Full timers include file read, full
trusted-root reconstruction, NTT construction, real retrieval/authentication,
fresh encrypted preparation, peer wire round trip and owner decryption.

| ExactIndex | Visible cached | Visible uncached | Private cached | Private uncached |
| --- | --- | --- | --- | --- |
| EQ0 |21.96/24.81/33.64|22.68/25.77/35.98|22.36/119.06/222.35|95.97/196.78/320.67|
| EQ1 |23.01/26.78/35.03|23.14/25.61/33.68|167.24/200.89/232.47|238.61/263.16/295.15|
| EQ16 |22.42/24.47/31.03|22.41/25.43/33.59|163.87/188.75/213.07|236.11/261.87/292.05|
| EQ64 |22.81/27.22/35.89|22.51/25.21/37.29|169.65/192.57/221.48|241.06/267.33/296.03|
| EQ256 |23.22/25.64/34.23|23.02/25.78/32.41|164.85/189.67/218.76|238.29/259.49/284.30|
| GE256 |22.70/26.86/36.90|23.13/25.77/35.47|168.36/194.99/224.38|247.07/275.53/306.97|
| range21 |22.41/25.28/36.43|22.65/25.48/34.79|168.12/193.59/221.28|238.68/265.53/291.18|
| range256 |22.58/25.61/36.55|23.33/26.14/36.32|171.95/220.44/279.09|247.42/272.47/315.32|

| FullPredicate | Visible cached | Visible uncached | Private cached | Private uncached |
| --- | --- | --- | --- | --- |
| EQ0 |84.21/89.43/96.52|84.57/89.55/97.07|87.94/186.92/293.79|157.59/257.70/371.37|
| EQ1 |86.83/92.96/99.00|84.65/90.20/95.51|230.16/256.56/284.49|301.09/325.69/370.65|
| EQ16 |84.37/87.26/92.15|84.32/88.10/96.25|227.03/251.07/279.74|303.60/340.05/383.63|
| EQ64 |85.06/89.27/95.94|84.46/90.00/96.23|229.01/253.04/314.40|302.74/332.82/374.21|
| EQ256 |84.21/91.29/96.26|86.95/90.57/97.30|228.07/255.11/276.38|297.68/323.97/359.30|
| GE256 |118.94/127.30/142.80|122.15/128.73/135.40|262.53/295.85/327.24|344.49/371.34/399.15|
| range21 |206.13/210.77/216.04|207.41/216.43/241.64|354.29/386.71/459.05|431.63/457.87/484.48|
| range256 |205.43/211.24/222.46|210.36/215.52/224.46|358.29/397.54/457.18|433.42/468.66/520.21|

The sole>500ms cell is table999/FullPredicate/range256/Fixed256/Private/uncached
MISS520.2137ms: load43.8658ms, nested query474.7704ms, native pair
build34.8149ms including32.8775ms NTT. Its peer used15 products/20 rotations,
request942,770B and response508,204B (four sequential logical RPCs). The whole
timer is retained; no stage is subtracted. ExactIndex's maximum320.6736ms was
an absent EQ0 query with actual Fixed256 dummy work.

## Initialization, update and restore failures

Whole writer initialization before its receipt was30,947.5089ms, including
canonical generation27,041.3794ms, PIR generation393.6152ms, BFV generation
212.0005ms, public serialization7.2996ms, original public peer setup140.6983ms,
previous export/seal178.4594ms and current export/seal182.7418ms.
Actual authenticated select→fresh BFV +1→authorized data/index write19.0314ms,
request446,884B/response446,808B; peer one encrypted add, zero products/rotations.
This owner locally verified its unverified UPDATE result before mutation.

Reader initialization2,047.2021ms separately reports original authenticated
secret restore253.3649ms, original public evaluator145.0467ms, authenticated
header bootstrap1,502.4987ms, public/cipher reads5.1341ms and nine negative
controls130.6094ms. These setup costs are excluded from query latency and exposed.

The SAME nine controls passed before query BFV preparation: wrong wrapping key,
tag corruption, truncation, oversize, wrong original BFV public bytes/profile
binding, wrong original PIR public bytes, wrong trusted catalog/table binding,
valid old checkpoint versus the independently held CURRENT anchor, and valid old
checkpoint/OLD anchor versus CURRENT physical heads. Restore checks every physical
head/length before secret decode; full snapshots still reconstruct Merkle roots
before NTT/page use. No valid-old checkpoint is silently treated as current.

## All files and all retained material

Logical denominator is3,000,000,000B (1000×1M×3B); these are actual files/objects,
not a projection or multiplication of the tiny-table resource result.

| Retained files | Count | Actual bytes |
| --- | ---: | ---: |
| Canonical encrypted data+index |2000|5,065,148,000|
| Original full BFV public setup |1|13,395,426|
| Original PIR public setup |1|6,029,344|
| Public catalog |1|700,670|
| Previous sealed checkpoint |1|371,699|
| CURRENT sealed checkpoint |1|371,699|
| ALL dataset files |2005|5,086,016,838|

Canonical expansion remains1.6883826667×. Both sealed backups and all original
public files are included, even the superseded generation. The BFV public setup
retains46B parameters,1,116,273B relinearization key and12,279,077B rotation keys
plus framing, shared by both kernels. Compact owner keys32,000B; BFV secret
serialization8,195B and owning image8,327B; Spiral owner image336B; external broker
wrapping master32B. Actual expanded private/public allocations are inside native
process peaks; serialized counts are not a substitute for process accounting.

The reader retains1000 authenticated cached headers2,276,000B including their
two full heads, separate trusted-head objects224,000B, one shared expanded Spiral
public payload23,855,104B and client secret/identity payload180,224B. Capacity is
one table: canonical snapshot5,065,148B, Merkle payload63,008B, native private
NTT pair67,108,864B; transient proof-record inputs8,388,608B are dropped after
construction. Unloaded snapshots/caches and persisted NTT overlays are0. Final
visible entry has no NTT; private samples actually retain the full64MiB pair.

| Native observation | Peak RSS | Peak private commit |
| --- | ---: | ---: |
| Broker, observed after both child exits |6,090,752|1,474,560|
| Writer, OS peaks read through held handle AFTER exit |343,953,408|356,986,880|
| Reader, OS peaks read through held handle AFTER exit |349,556,736|355,332,096|
| Sum of reported parent peak +serial active-child maximum |355,647,488|358,461,440|

Children do not overlap. The last row is a conservative sum-of-reported-peaks
bound, not synchronized aggregate sampling and not an externally sampled
broker-through-its-own-exit value. Current post-exit RSS is not used as a peak.
API failure, a zero child RSS peak, or regression of either peak below the earlier
child receipt rejects. All observed private peaks were also nonzero. All native
current/peak gates remained below decimal2GB with
80MiB admission reserve; max sampled child threads13/global Rayon8. Filesystem
cache and kernel pipe buffers outside process counters are not counted.

ALL files +the private bound =5,444,478,278B /3,000,000,000B=1.8148260927×
IN THIS SAME RUN. The RSS counterpart is5,441,664,326B (1.8138881087×).
The separate public broker result JSONL4,307,801B is an explicitly retained
measurement artifact, not hidden canonical/cache state.

## Audit, hashes and finite scope

An independent explicit-formula audit checked all768 ordinals/COUNT/SUM/low+high
limbs, including actual1099→1100 and maximum SUM16,776,960. All2000 physical112B
heads and exact file lengths matched the1000-entry catalog; database IDs, owner
domains, data roots and index roots were each1000 distinct. Both original public
file hashes matched the current anchor. All768 dimension cells were unique,
Fixed256 wire shapes remained invariant within their operation/header/access
shape, both load events were real, and nine rejects were retained.

The [tiny3 source report](experiment-private-bfv-restart-disk.md) records116
runtime tests +two doctests/strictClippy. No tests, build, source patch or extra
benchmark sweep was repeated here: the exact frozen binaries were reused.

Ignored main artifact root: .local/private-bfv-restart-disk/

- Public args/provenance: actual1000-20261015-015121-998.public-preflight.json
  SHA2565771ED222B569183FD867604AA35F85637DF4FEDDE258F7D5A1B17B93943439C.
- Raw dataset-1000-20261015-015121-998.broker-results.jsonl
  SHA25602750BE1BA23591D8AE4C387572C973E3879F3BC67D1D35D0760D9E2BED73419.
- Broker lifecycle actual1000-20261015-015121-998.log
  SHA256EFAC85E3124FBCC5E65852936C1B1E86702E93F0ECCAE02AE27F5D025EDC639C.
- All256 groups actual1000-statistics.json
  SHA2564C1D01B12C1C5E26362C6B73315EADE5F29E4865A85E7B31E091A5922278D182.
- Independent answers/physical/public identity audit actual1000-independent-audit.json
  SHA2562D16B061DBED3BEE921D539F4B40EBE2B128BEE190A64AC959D9DCA51F749472.
- Physical catalog SHA256C88650FDB2344FD90ECE77F356BA5221A0F181728BA218C20548684F92D2F4B2.
- CURRENT backup SHA256F7CC15B79522E061416C8A37FA45319184994B937BCC9C7757976E6A646D0C17.
- Previous backup SHA25686FF991F9CB13CD9BCE130B361C1D76902C47F43C44D94139E9035769217115A.

Frozen research-worktree EXEs remain under
.local/private-bfv-restart-disk/tiny3-budget-fix-artifacts-20261015-013627-170/.
Broker EBB6252CBE9F876819A2419346A775E38CE4EBBD22EE133727C5671D989CDC87;
writer06C9A0186F51624415F43A8A760C4BDD4F97AF10A43E6D44A45F18C3843CCADA;
reader19B797C3E889F3BE26186D31AE8B188177975133039E0A5CA336E2D785877A76.
Reproduction requires a separately authorized fresh output directory and the
retained PUBLIC config, then that broker EXE; there is no wrapping-key CLI/env/file
argument. The small-table run.ps1 intentionally defaults to three tables.

This remains online-owner, at most256 complete exact-selected rows within one
posting/data page. Private access hides pages within the public table/root;
AddressOnly cardinality/RPC leakage and Fixed256 dummy cost remain distinct.
Query restore/bootstrap is separate, OS-cold/network effects unmeasured, original
upstream BFV security/failure gates unresolved independently, malicious arithmetic
results explicitly Unverified. No private-write protocol, durable fsync/atomic
multi-file publication, external rollback authority, portable cross-version
backup, full-machine custody or arbitrary-SQL/proof completion is claimed.
