# Exact-index aggregation through real disk, index, PIR and BFV

The fresh 1,000-table paired run passed all 768 matrix queries, six additional
genuine BFV operations and 13 before-BFV rejections. ExactIndex completed all 384
matrix operations within 351.1100 ms. FullPredicate, under the SAME Owner/full
keyset/process and complete storage path, had nine operations above 500 ms,
maximum 562.2240 ms. Actual dataset files plus this process's native peak private
commit were 5,448,908,128 B / 3,000,000,000 logical B = **1.8163027093x**.
These jointly measured numbers apply to the bounded exact-index operation below,
not arbitrary SQL, malicious-peer arithmetic verification or production security.

## Operation and trust boundary

The [standalone package](../experiments/private-bfv-exact-disk/README.md) compares
FullPredicate (fresh encrypted age/threshold predicate and byte-limb COUNT/SUM)
with ExactIndex (a distinct aggregate requiring a complete exact owner-built
age-index selection). Both share ONE Rows256 BFV Owner/evaluator/full keyset
and ONE Spiral owner/client/public setup. Comparator/relinearization keys remain
generated, serialized, restored, retained and counted. There is no TFHE material,
precomputed answer or permanent FHE-row cache.

The PaddedV2 reader authenticates complete counts/postings, decodes bounded
varints, rejects duplicate/out-of-range ordinals and enforces complete count<=256
plus one-posting-page/one-data-page budgets without truncation. Actual ordinals
come from encrypted postings via real native Spiral queries. Selected compact
pages undergo Merkle/AEAD authentication against independent trusted full heads.

Before padding, preparation counter or encryption, ExactIndex checks EVERY
selected active age against the authorized EQ/GE/closed-range predicate.
Any mismatch rejects the complete selection without filtering. It then freshly
encrypts original low/high amount bytes and COUNT-one weights, with fresh
encrypted zeros for inactive slots. The peer performs eight rotations/additions,
zero ciphertext products and depth 0. No owner SUM/COUNT substitutes are used.
FullPredicate retains actual encrypted comparison. Exact completion compares
real decrypted COUNT against its pending active-row count, then checks unsigned
limb bounds; both outputs remain UnverifiedAggregate. In-bounds public wrong-SUM
transformations remain possible, so metadata/COUNT/bounds do not prove arithmetic.

Exactness also requires the owner-built index to describe the same actual data:
both snapshots are constructed from the same rows, and the normal measured
replacement changes amount only while rebinding the data head. An authenticated
index root is not a semantic completeness certificate. Checking selected ages
catches false positives, not omitted rows from an incorrect owner index.
This adapter accepts typed exact age-index queries only; coarse candidates,
extra nonindexed WHERE terms, unrelated columns and arbitrary SQL are unsupported.

No original compact ciphertext/nonce, page, ordinal, plaintext or owner secret
enters the BFV evaluator request. Pending tokens bind operation, queryID, both
current 112-byte heads, geometry and shared keyset identity. Live heads are checked
through completion. The owner is online and reads its selected authenticated
plaintext; this is not offline-owner autonomous execution.

Loader.execute starts the whole timer before admission, eviction/drop, held-file
reads, full snapshot decode/Merkle reconstruction and native cache construction.
Actual index/data retrieval, authentication, age gate, fresh encryption,
ciphertext-only freshness evidence, full serialization, peer evaluation and
owner decode/decrypt are included. QueryID randomness is drawn immediately
before the timer; the fixture oracle runs afterward. Nested stages overlap
and must not be summed. Setup/bootstrap is reported separately.

## Actual dataset and paired matrix

1,000 independent 1,000,000-row encrypted tables were generated with distinct
database IDs, owner domains, data/index roots and per-table owners. IDs 0/499/999
were queried, one sample each, alternating kernel order. Capacity is one:
unloaded tables retain no snapshots, proof records or NTT cache. Each mode
actually retrieves its own pages and freshly encrypts its own input.

| Case | Authorized predicate | Complete rows |
|---|---|---:|
| eq0 | age=253 | 0 |
| eq1 | age=250 | 1 |
| eq16 | age=252 | 16 |
| eq256 | age=255 | 256 |
| ge256 | age>=255 | 256 |
| range256 | age in [240,241] | 256 (64+192) |
| eq64 | age=240 | 64 |
| range21 | age in [250,252] | 21 (1+4+16) |

8 cases * 2 kernels * 2 profiles * 2 headers * 2 accesses * 2 miss/hit * 3 IDs=768 unique cells.
Both profiles use Rows256. AddressOnly reveals absence by skipping posting/data
requests; positive counts share the same BFV shape. Fixed256 absence performs
actual dummy posting/data fetches and encrypts fresh inactive zeros.

Visible access reveals page addresses/repetition; PIR conceals pages within the
selected public table. Table/head identities, operation, cache events, updates,
length/RPC counts and timing remain visible. FullPredicate wire identifies
predicate kind; ExactIndex BFV wire has no EQ/GE/range field. Synthetic harness
labels are not evidence of that field on ExactIndex wire. Structural Fixed256
checks are not a cardinality-hiding/constant-time/active-feedback proof. The
open leakage policy is not silently relaxed.

## Complete-operation latency

Each table cell below is min/median/max milliseconds across THREE DIFFERENT
table IDs, one fresh query each, not repeated-sample confidence intervals.
Miss includes actual file read, restoration and (Private) cache construction;
the OS file cache is uncontrolled, so physical-cold storage is not established.
The worst ExactIndex cell is eq16/AddressOnly/Private/Uncached miss, table 999,
351.1100 ms. Cached private maxima are 250.9708 ms miss /202.4163 ms hit;
uncached private hit max 281.4843 ms. These are measured whole operations,
not sums of independent microbenchmarks or throughput-derived latency.
### FullPredicate

| Case (rows) | Profile | Header | Visible miss | Visible hit | Private miss | Private hit |
|---|---|---|---:|---:|---:|---:|
| eq0 (0) | AddressOnly | Cached | 92.63/101.10/105.38 | 94.42/95.21/96.30 | 144.53/149.33/154.96 | 89.69/91.52/101.35 |
| eq0 (0) | AddressOnly | Uncached | 95.49/99.58/99.90 | 94.67/100.22/100.86 | 222.20/224.96/230.63 | 168.94/175.78/198.49 |
| eq0 (0) | Fixed256 | Cached | 91.44/94.47/100.49 | 95.19/95.82/97.49 | 303.91/305.28/305.69 | 248.67/252.30/254.92 |
| eq0 (0) | Fixed256 | Uncached | 94.15/95.88/96.07 | 93.33/94.33/103.82 | 368.78/374.28/378.72 | 324.16/324.22/331.13 |
| eq1 (1) | AddressOnly | Cached | 96.94/98.11/101.09 | 99.44/99.51/101.05 | 304.10/316.17/324.52 | 244.10/249.37/250.62 |
| eq1 (1) | AddressOnly | Uncached | 95.12/99.92/104.47 | 91.65/92.15/92.95 | 379.43/381.10/387.03 | 329.11/331.53/333.94 |
| eq1 (1) | Fixed256 | Cached | 97.30/97.65/100.12 | 94.77/96.53/97.48 | 299.42/299.89/317.29 | 247.26/256.16/260.90 |
| eq1 (1) | Fixed256 | Uncached | 91.40/95.31/96.85 | 93.39/94.21/95.27 | 373.34/382.85/383.25 | 330.84/333.43/335.60 |
| eq16 (16) | AddressOnly | Cached | 92.60/93.32/97.04 | 96.95/97.82/100.49 | 293.39/304.45/316.13 | 249.45/252.05/253.03 |
| eq16 (16) | AddressOnly | Uncached | 96.00/96.76/98.28 | 97.14/97.46/98.61 | 373.62/379.03/381.70 | 326.10/327.67/331.57 |
| eq16 (16) | Fixed256 | Cached | 93.91/94.86/104.69 | 93.83/95.31/98.13 | 300.12/307.27/311.50 | 245.42/247.45/262.85 |
| eq16 (16) | Fixed256 | Uncached | 94.46/97.76/99.29 | 96.55/99.69/103.16 | 374.43/374.97/375.14 | 323.13/327.95/332.78 |
| eq256 (256) | AddressOnly | Cached | 92.95/93.47/101.99 | 94.79/96.26/96.74 | 290.66/300.92/303.04 | 244.27/245.96/254.35 |
| eq256 (256) | AddressOnly | Uncached | 96.01/105.81/108.55 | 92.93/94.81/99.73 | 371.63/373.83/389.49 | 320.95/327.22/329.77 |
| eq256 (256) | Fixed256 | Cached | 90.23/96.04/99.78 | 90.29/92.10/94.84 | 298.21/302.68/311.25 | 246.06/248.67/250.14 |
| eq256 (256) | Fixed256 | Uncached | 98.06/98.77/101.58 | 89.77/92.54/94.25 | 375.58/381.29/384.36 | 324.56/327.26/331.01 |
| ge256 (256) | AddressOnly | Cached | 133.02/137.40/144.96 | 127.36/132.27/135.67 | 335.70/338.66/347.43 | 287.34/290.52/294.65 |
| ge256 (256) | AddressOnly | Uncached | 136.37/139.77/140.03 | 132.35/133.81/133.89 | 410.21/434.58/436.01 | 371.80/374.16/382.62 |
| ge256 (256) | Fixed256 | Cached | 133.27/134.52/137.38 | 125.56/127.23/129.59 | 334.72/337.24/348.25 | 285.60/288.84/289.99 |
| ge256 (256) | Fixed256 | Uncached | 132.27/135.25/135.80 | 127.30/128.40/132.37 | 411.18/424.45/456.17 | 366.22/368.72/370.73 |
| range256 (256) | AddressOnly | Cached | 228.00/238.86/242.48 | 221.46/224.90/228.68 | 427.40/429.79/430.60 | 382.74/383.86/390.39 |
| range256 (256) | AddressOnly | Uncached | 219.30/219.62/230.31 | 217.46/219.61/235.88 | 508.49/525.32/562.22 | 455.29/466.62/473.82 |
| range256 (256) | Fixed256 | Cached | 224.64/226.64/230.51 | 215.16/229.96/233.20 | 412.41/432.19/435.03 | 372.79/394.44/406.72 |
| range256 (256) | Fixed256 | Uncached | 218.72/233.11/235.84 | 222.01/222.12/225.74 | 499.60/501.54/509.03 | 457.83/467.58/472.13 |
| eq64 (64) | AddressOnly | Cached | 91.38/100.74/103.53 | 94.63/95.98/99.18 | 298.94/301.09/305.16 | 248.32/249.45/251.22 |
| eq64 (64) | AddressOnly | Uncached | 96.09/99.73/106.42 | 91.15/94.55/100.58 | 374.23/375.93/378.88 | 323.20/324.14/326.93 |
| eq64 (64) | Fixed256 | Cached | 93.54/93.97/99.09 | 95.06/95.39/98.11 | 300.03/303.63/306.59 | 247.71/252.62/254.86 |
| eq64 (64) | Fixed256 | Uncached | 97.96/100.48/102.56 | 95.12/99.62/100.33 | 375.62/376.20/392.81 | 319.86/329.75/331.39 |
| range21 (21) | AddressOnly | Cached | 226.82/233.98/236.78 | 223.53/236.10/239.12 | 426.79/429.76/435.18 | 388.83/392.51/407.73 |
| range21 (21) | AddressOnly | Uncached | 220.10/225.93/238.99 | 216.80/226.54/228.40 | 509.59/518.50/524.78 | 466.32/473.56/478.65 |
| range21 (21) | Fixed256 | Cached | 219.47/225.48/226.82 | 216.79/220.50/223.00 | 436.05/438.87/449.28 | 376.57/381.90/387.87 |
| range21 (21) | Fixed256 | Uncached | 221.09/222.67/230.41 | 216.23/217.49/223.16 | 490.50/499.51/513.56 | 461.14/467.79/476.27 |

### ExactIndex

| Case (rows) | Profile | Header | Visible miss | Visible hit | Private miss | Private hit |
|---|---|---|---:|---:|---:|---:|
| eq0 (0) | AddressOnly | Cached | 26.58/27.84/31.70 | 23.41/23.89/24.25 | 63.78/64.54/72.10 | 23.20/23.26/23.55 |
| eq0 (0) | AddressOnly | Uncached | 28.22/28.46/33.47 | 22.94/24.68/25.06 | 158.08/159.10/163.27 | 99.42/107.50/108.68 |
| eq0 (0) | Fixed256 | Cached | 27.37/27.42/33.86 | 23.28/23.69/23.86 | 232.70/240.50/243.12 | 183.45/185.41/202.42 |
| eq0 (0) | Fixed256 | Uncached | 27.18/27.72/34.54 | 23.38/23.47/23.67 | 311.44/312.16/318.72 | 262.10/266.64/272.18 |
| eq1 (1) | AddressOnly | Cached | 28.07/30.85/37.42 | 24.68/26.54/28.64 | 231.21/236.71/236.81 | 181.63/182.06/185.74 |
| eq1 (1) | AddressOnly | Uncached | 31.07/33.98/35.90 | 24.40/28.05/28.91 | 311.38/315.28/320.89 | 255.87/259.07/260.67 |
| eq1 (1) | Fixed256 | Cached | 32.30/35.35/36.08 | 24.58/27.46/29.68 | 230.82/233.56/240.88 | 184.34/187.69/191.92 |
| eq1 (1) | Fixed256 | Uncached | 28.24/30.35/37.46 | 23.88/24.20/29.00 | 316.04/317.70/328.37 | 256.29/257.80/261.09 |
| eq16 (16) | AddressOnly | Cached | 28.07/28.47/35.45 | 23.56/24.51/24.92 | 229.39/230.04/236.30 | 180.78/180.89/182.15 |
| eq16 (16) | AddressOnly | Uncached | 27.77/27.91/37.72 | 23.46/24.12/24.14 | 307.68/313.94/351.11 | 263.05/268.87/281.48 |
| eq16 (16) | Fixed256 | Cached | 27.25/27.45/33.82 | 23.50/23.96/24.18 | 232.20/232.94/248.96 | 179.33/185.60/187.75 |
| eq16 (16) | Fixed256 | Uncached | 27.86/28.27/36.28 | 24.13/24.44/25.40 | 314.27/316.94/323.76 | 256.67/258.31/263.93 |
| eq256 (256) | AddressOnly | Cached | 28.72/28.87/45.01 | 24.33/24.80/25.29 | 229.81/232.29/250.97 | 181.75/182.55/182.64 |
| eq256 (256) | AddressOnly | Uncached | 27.07/27.37/34.89 | 23.39/23.91/24.48 | 301.02/303.12/306.36 | 255.06/260.80/263.56 |
| eq256 (256) | Fixed256 | Cached | 28.25/29.10/36.81 | 24.06/24.30/24.39 | 228.83/235.61/236.51 | 180.86/182.40/184.24 |
| eq256 (256) | Fixed256 | Uncached | 33.12/35.74/39.34 | 28.24/29.14/30.16 | 312.01/314.07/326.60 | 251.00/251.54/252.93 |
| ge256 (256) | AddressOnly | Cached | 33.49/35.54/36.74 | 28.78/29.38/30.39 | 232.59/235.35/240.51 | 178.95/180.61/183.47 |
| ge256 (256) | AddressOnly | Uncached | 30.45/30.77/36.48 | 25.06/26.51/28.94 | 316.09/317.09/331.89 | 260.60/260.75/263.68 |
| ge256 (256) | Fixed256 | Cached | 27.74/28.17/33.96 | 23.29/24.30/24.52 | 230.93/241.57/243.32 | 182.14/186.25/187.21 |
| ge256 (256) | Fixed256 | Uncached | 32.78/33.03/40.45 | 27.41/28.24/30.07 | 312.86/316.60/317.25 | 257.25/257.80/267.61 |
| range256 (256) | AddressOnly | Cached | 31.78/32.77/36.43 | 26.30/27.65/28.15 | 226.54/231.95/239.37 | 181.33/182.63/184.26 |
| range256 (256) | AddressOnly | Uncached | 27.86/28.26/34.01 | 24.04/24.21/24.27 | 308.92/311.04/311.42 | 258.31/262.50/264.66 |
| range256 (256) | Fixed256 | Cached | 28.04/28.30/34.37 | 23.60/23.71/24.18 | 228.07/234.25/241.28 | 180.33/182.08/186.50 |
| range256 (256) | Fixed256 | Uncached | 27.17/30.13/41.52 | 23.16/23.24/27.70 | 308.49/315.57/319.73 | 260.71/263.65/265.68 |
| eq64 (64) | AddressOnly | Cached | 27.13/27.86/33.48 | 23.31/24.78/25.44 | 227.75/234.73/243.22 | 179.11/180.61/188.11 |
| eq64 (64) | AddressOnly | Uncached | 28.85/33.08/41.29 | 24.10/26.90/29.65 | 304.46/313.62/317.62 | 256.06/256.27/261.60 |
| eq64 (64) | Fixed256 | Cached | 27.71/29.06/40.42 | 23.66/23.92/26.69 | 226.86/241.95/243.30 | 178.96/183.63/184.75 |
| eq64 (64) | Fixed256 | Uncached | 27.93/28.31/34.32 | 23.69/24.00/24.12 | 310.57/311.77/321.30 | 257.35/263.15/266.40 |
| range21 (21) | AddressOnly | Cached | 29.15/29.58/34.73 | 23.90/27.29/30.03 | 225.51/225.85/229.80 | 180.12/182.19/184.22 |
| range21 (21) | AddressOnly | Uncached | 27.59/27.85/33.60 | 23.20/23.87/24.16 | 315.24/315.45/319.25 | 252.99/261.43/265.57 |
| range21 (21) | Fixed256 | Cached | 27.59/27.66/33.50 | 23.24/23.35/23.65 | 225.22/230.78/242.30 | 178.89/180.86/188.32 |
| range21 (21) | Fixed256 | Uncached | 32.78/33.08/38.15 | 27.18/28.24/28.77 | 306.03/306.84/307.56 | 253.11/259.52/261.58 |


## Every operation above 500 ms

All nine are FullPredicate, Private/Uncached application-cache misses. No
ExactIndex matrix operation or additional control exceeded 500 ms.

| Case | Profile | Table | Whole ms |
|---|---|---:|---:|
| range256 | AddressOnly | 0 | 508.4948 |
| range256 | AddressOnly | 499 | 525.3204 |
| range256 | AddressOnly | 999 | 562.2240 |
| range256 | Fixed256 | 499 | 509.0317 |
| range256 | Fixed256 | 999 | 501.5388 |
| range21 | AddressOnly | 0 | 509.5868 |
| range21 | AddressOnly | 499 | 524.7839 |
| range21 | AddressOnly | 999 | 518.4981 |
| range21 | Fixed256 | 999 | 513.5610 |

## Disk, material and native memory from THIS run

Every expansion factor uses 3,000,000,000 logical bytes (one billion three-byte
rows), not encrypted canonical data as a different denominator.

| Material | Actual bytes |
|---|---:|
| Canonical data, 1,000 independent files | 3,023,584,000 |
| Canonical PaddedV2 index, 1,000 independent files | 2,041,564,000 |
| Canonical combined | 5,065,148,000 (1.6883826667x) |
| Catalog file | 700,670 |
| Shared complete BFV public wire | 13,395,426 |
| Shared original PIR public wire | 6,029,344 |
| ALL 2,003 dataset files | 5,085,273,440 |
| Shared owner image/count subtotal | 8,531 (336 PIR +8,195 BFV) |
| Per-table owner AEAD key counts | 32,000 |
| Known files plus these secret image/counts | 5,085,313,971 |
| Owner key +two heads +cached-header payload | 2,532,000 |
| Catalog structs, overlapping inline payload above | 2,640,000 |
| Owner cached headers alone, included above | 2,276,000 |
| One loaded canonical pair in RAM | 5,065,148 |
| One loaded Merkle hash payload | 63,008 |
| One retained native NTT pair in RAM | 67,108,864 |
| Retained proof records /unloaded snapshots /unloaded NTT /persisted NTT | 0 |
| Temporary record-input pair, transient | 8,388,608 |
| Shared expanded PIR public polynomial RAM payload | 23,855,104 |
| Final process RSS /private commit | 330,035,200 /335,020,032 |
| Native peak RSS /private commit | 358,236,160 /363,634,688 |
| All files +native peak RSS | 5,443,509,600 (1.8145032000x) |
| All files +native peak private commit | 5,448,908,128 (1.8163027093x) |

Process RAM already includes actual native keys, owner/client state, canonical
snapshots, expanded public data, cache/proof payloads, transients, heap overhead
and retained freshness hashes. Do not add listed subpayloads to RAM again.
Native BFV keys are not individually partitioned. The PIR client's source-derived
secret/identity polynomial RAM payload is 180,224 B. The 336 B trusted recovery
envelope requires the ORIGINAL PIR public wire and pinned SDK/RNG/profile/LE64;
its checksum is not backup authentication. BFV's 8,195 B is a serialization count,
not an exported backup. Per-table AEAD keys and full owner restart material were
not persisted. Complete owner restart remains false.

Independent audit opened all 2,000 physical 112 B heads and checked exact lengths
against the catalog: 1,000 distinct DB IDs, owner domains and data/index roots.
Owner keys are generated by 1,000 independent Owner calls; their secret bytes or
uniqueness were not exported/directly inspected. OS/filesystem cache outside the
process, replication, build/raw-log artifacts and other processes are outside
this deployment ledger. RAM-only expansions remain in the measured joint ratio.
Actual file writes imply no fsync/atomic-commit/crash-durability guarantee.

Admission uses decimal 2,000,000,000 B, all four current/native-peak RSS/commit
fields, an 80 MiB reserve and checked arithmetic before table/cache allocation.
Old buffers drop before loading another table; failed loads/admission publish no
entry. Memory-only admission is inside timing (max summed admission stage
0.1358 ms); expensive thread enumeration stays outside query timing.
Rayon used eight workers and one query at a time. Observed process threads
peaked at 13, final 10; this is not concurrent throughput.

Setup took 31,430.7456 ms including table generation/writes and locally
owner-authenticated cached-header bootstrap: BFV keygen 228.4749 ms,
public restore/evaluator 224.3125 ms, PIR setup/restore 449.2520 ms.
No table NTT cache was prepared at setup. Owner header caches were bootstrapped
from authenticated new index plaintext, not privately filled through PIR.
Every private miss builds the real native pair inside its complete timer.

## Wire and unchanged security profile

| BFV operation | Request B | Response B | Products | Rotations | Depth |
|---|---:|---:|---:|---:|---:|
| ExactIndex, all supported queries | 223,595 | 446,808 | 0 | 8 | 0 |
| FullPredicate EQ | 670,134 | 446,764 | 5 | 11 | 5 |
| FullPredicate GE | 670,134 | 446,764 | 8 | 14 | 5 |
| FullPredicate closed range | 893,423 | 446,764 | 15 | 20 | 5 |

One actual PIR call is 16,449 B request /20,480 B response; visible index/header
fetch is 41/4,448 B and data fetch 41/6,496 B. Positive AddressOnly and every
Fixed256 query add posting+data calls; uncached adds one header call. Complete
ExactIndex traffic, including the genuine BFV RPC, is:

| Access/header | Request B | Response B | Total B | Sequential RPCs |
|---|---:|---:|---:|---:|
| Visible/Cached | 223,677 | 457,752 | 681,429 | 3 |
| Visible/Uncached | 223,718 | 462,200 | 685,918 | 4 |
| Private/Cached | 256,493 | 487,768 | 744,261 | 3 |
| Private/Uncached | 272,942 | 508,248 | 781,190 | 4 |
| AddressOnly absent, Cached, either access | 223,595 | 446,808 | 670,403 | 1 |
| AddressOnly absent, Visible/Uncached | 223,636 | 451,256 | 674,892 | 2 |
| AddressOnly absent, Private/Uncached | 240,044 | 467,288 | 707,332 | 2 |

These are actual locally serialized messages; network transport/RTT is unmeasured.
Full public setup is unchanged: parameters 46 B, relinearization 1,116,273 B,
rotation keys 12,279,077 B. The runtime BFV gate checks N8192, t114689 and
Q=[8796092858369,8796092792833,17592186028033,17592185438209,17592184717313]
(218 bits), unchanged CBD(20)/variance10 secret and error, native/unfused/additive/
level0. Upstream about 128 security is not independently validated; independent
parameter and failure-bound validation remain open. No parameter/key weakening
or smaller setup is used for ExactIndex.

Spiral uses the unmodified
[pinned Blyss SDK](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c)
512x8192 B profile: N2048, n2, CRT268369921/249561089, p256, q2bits20, width6.4,
nu1=7, nu2=2 and unchanged decompositions. Width 6.4 corresponds to standard
deviation about 2.553 under that Gaussian convention. The reviewed native
pair-cache and Combined trial/expansion helpers preserve full buffers/responses.
Single-server PIR needs no noncolluding-peer assumption, but semi-honest query
privacy is not an active selective-failure/feedback composition proof.
Authenticated retrieval is not an FHE computation proof.

## Failure and lifecycle evidence

All 13 rejects occur before BFV preparation: truncated data/index, same-length
tamper, wrong-table data/index, extra byte, old image at new head, stale catalog
head, stale owner header, and four Visible/Private x Cached/Uncached age mismatches.
For the latter the owner changes age 250 to 249, authenticates the new data and
header binding, but deliberately retains the old posting. ExactIndex rejects
specifically at the selected-age gate with prepare counter unchanged, without
filtering. FullPredicate actually executes encrypted comparison and returns
0/0 (251.3934 ms). This is an owner-maintenance fault fixture, not a completeness
proof or production rollback/index-update API.

Three real ExactIndex cache controls are visible miss 32.6216 ms, native upgrade
223.8518 ms and private hit 183.0049 ms. Normal owner compact amount replacement
on table 999 writes actual images/catalog, invalidates caches and reads freshly:
347.5868 ms total = write/catalog/invalidate 121.3646 ms plus fresh miss
226.2024 ms, returning COUNT 1/SUM 1100. Canonical/catalog lengths do not grow;
stale images/heads/header reject. A final restored miss takes 265.2781 ms.
This is explicitly NOT FHE UPDATE. Write locations/version activity are visible,
and writes are not crash durable. These six controls plus 768 matrix=774 BFV
operations; all outputs remain unverified.

## Preserved six-case dry and reproduction

The frozen dry3 ran 576 six-case cells +six controls and 13 rejects:
ExactIndex max 320.2934 ms, zero >500; FullPredicate three >500,
max 517.7424 ms. All three overruns were range256 Private/Uncached misses:
AddressOnly table2 506.0583 ms; Fixed256 table0 504.1942 ms and table2 517.7424 ms.
Its complete source/executable/raw were archived before adding eq64/range21.
The extension changes only CASES, derived counts and explicit cardinality/ID
test coverage; independent source review confirmed no algorithm change.
Both versions pass 31 release owning tests and strict authored Clippy.
Current authenticated callback/page-budget tests cover IDs 0,1,2,499,999, and
expected-array length checks prevent zip truncation.

~~~powershell
.\experiments\private-bfv-exact-disk\run.ps1 -PrepareOnly -Offline
$env:CARGO_HOME = Join-Path $PWD '.local/cargo-home'
$env:CARGO_TARGET_DIR = Join-Path $PWD 'target/private-bfv-exact-disk'
cargo test --release --locked --offline --manifest-path .local/private-bfv-exact-disk/package/Cargo.toml
cargo clippy --release --locked --offline --manifest-path .local/private-bfv-exact-disk/package/Cargo.toml --all-targets --no-deps -- -D warnings
.\experiments\private-bfv-exact-disk\run.ps1 -Tables 1000 -TableIds '0,499,999' -Samples 1 -Threads 8 -MaxCanonicalBytes 6500000000 -ServerSchedule combined -Offline
~~~

Runner overrides are Cargo/CargoHome/TargetDirectory/CoreDirectory/CorePackage/
PirOwnerStateDirectory/CacheCoreDirectory/CompactStoreDirectory. It copies/hashes
all core/store/helper modules, pins the SDK and uses unique package/target paths
with runtime profile/key-byte gates. The measured Cargo1.99/MSVC build selected
current main sources explicitly, then ran the same validated executable with
output redirected to the raw file. Source preparation alone performs no build,
keygen or dataset writes. Full execution creates a fresh CreateNew dataset; old
files cannot be silently reopened with new AEAD keys.

Artifacts under the research checkout's ignored .local/private-bfv-exact-disk:

| Artifact | SHA-256 |
|---|---|
| Actual raw disk-1000-v2-s1-t8-combined-20261015-002342-672.jsonl | E3C20B127435C03E1FE1B88D43A97D869714A900DF7AB6BBD28697AA3BEF2D28 |
| Actual executable | 5C4F7B0572C8A4D3F81B93A0BA8A2FFE98276628E36DA452219D5465194E10C0 |
| Runtime main.rs | D5D8F003BA3CB4606994237DFEEBAF5C2613F795BE33229C9519A5D3114BBC07 |
| Actual catalog | 8C0EFE96244305754006EE7D8C58CF8FA59DB1CEA5CB890C29962AE64D03B03A |
| Independent head/answer audit | 48A2CEFF40250E3D9AE6B1C50DD97F16A8CC4AABB948C553F5F7C322B7F9E3A8 |
| Full per-cell statistics JSON | 653018D50E69893C363813FE05CD674275C232E496445C60D4B1FD6D592D3BB4 |
| Six-case raw | 8DB098B3F2449EF3A202D08E2F2775BB744BB6430D75B13FDD6C2E2B64271695 |
| Six-case executable | 8BDBDF19839D8B8AEE9628B2490650FA12BD8A6B767ECB317608DFF879FE8399 |
| Six-case archive manifest | 3AFDF4EEE06C79899E2FAD248054B86508CCD09DBFF584F2603CF8A18BC5E417 |

Dataset: snapshots-1000-v2-20261015-002342-672. Frozen dry: six-case-baseline.
v2-ready-manifest.json, v2-source.log, v2-tests.log, v2-clippy.log and v2-build.log
retain measured source/validation provenance. Full raw and independent per-cell
statistics preserve every slow FullPredicate operation.

Merged core lib: F4EC7930D306AE933142AFE7455B500B61A23D53F3DBA69454E796F33EF88CCB.
Exact module: 36F534D4695CE29924631B647C327A2E4ABAE720E27925E6925381550D49BFE2.
Kernel: B36ED5A738B271D12EBEFD81A1BCDBFA6A6BE484362EB8EE0E17C89901E08FF0.
PIR owner: 32CF886EEAD6D14CA887E13B8A595FFAA5049E3ACB17844919A5B31F4AE25E3B.
Cache helper: 4DA15C08050DD6F55FA2B0811088513DF8A31540848A91B56F4E9B059A5E6DCE.
Trial module: F9B343135A377CF6559415C7C62584A66B823E007DA98DBF43B1EC88C861B3FC.
Combined: 931FD2B0775E10D83872F8E35D04D9C8CBBC055D373BBA221B6C097F01E78F98.
The raw source event records every core/store/owner/cache/compositor source hash.

The result covers online-owner exact indexed COUNT/SUM for complete <=256-row,
one-posting/one-data-page groups. General SQL, larger groups, private writes,
offline-owner execution, complete owner recovery, independent production security,
network/physical-cold storage, replication and verified malicious-peer computation
remain open. No overall-goal completion is claimed.