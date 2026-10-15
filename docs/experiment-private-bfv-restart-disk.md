# True owner-process restart disk probe

The subsequent [actual 1,000-table run](experiment-private-bfv-restart-disk-scale.md)
reuses these frozen binaries and separately validates scale. The measurements
below remain the original three-table run.

The three-table run succeeded after the writer ACTUALLY exited and a separate
reader restored the ORIGINAL compact-store, BFV and Spiral owners. All 768 full
queries were exact, including the committed amount update. ExactIndex's384
operations reached317.3461ms; FullPredicate's384 controls reached480.1963ms;
zero queries exceeded500ms. This is a THREE-table result, not a scaled
storage/latency claim.

## Process and ownership boundary

The new [package](../experiments/private-bfv-restart-disk/README.md) reuses the
validated [recovery candidate](proposal-owner-recovery-candidate.md) and the
frozen [eight-case disk pipeline](experiment-private-bfv-exact-disk.md). No
frozen predecessor source or dataset changed.

Broker PID271996 held one 32B wrapping master in Zeroizing RAM. Writer PID294996
received it only through anonymous stdin. Writer generated three independent
1M-row tables, one Rows256 BFV setup and one Spiral setup. It sealed generation0,
then selected the complete age250 group from the real authenticated index of
table2: ordinal151552. Fresh BFV amount102 + encrypted delta1 produced103.
The owner independently checked that unverified output before authorizing the
data replacement and index-header rebind. Both revisions became1 without byte
growth; generation1 was then sealed. No loaded PIR cache existed during the
writer update.

Only after writer EOF and successful exit did the broker launch reader PID231132.
Reader received the wrapping key plus a separately broker-held PUBLIC current
anchor through bounded stdin framing. It restored original secrets/public files,
without generating owners or encrypted fixtures, and bootstrapped authenticated
header caches. It dropped its wrapping-key copy before query work. The independent
public fixture oracle reconstructs synthetic plaintext rows AFTER query timers;
it never supplies selected addresses or BFV inputs.

This proves a separate OWNER PROCESS restart under a live external broker.
Full-machine restart, persistent wrapping-key custody and current-anchor authority
remain external. The broker's deliberately unpersisted master disappears when it
exits; retained ciphertext alone is not a subsequent runnable owner session.

## Operation and query matrix

The SAME restored BFV Owner and ORIGINAL full public setup serve both kernels.
Each full timer covers held exact canonical file reads on misses, full Merkle
reconstruction against trusted heads, eviction/cache construction, actual index
and data retrieval, AEAD/authentication, fresh encrypted BFV input, peer wire
decode/evaluation/encode, and owner decryption. ExactIndex additionally checks
every selected age before preparation and runs eight encrypted rotations/adds,
zero products. FullPredicate runs its original encrypted predicate/products,
relinearization and rotations using the restored original evaluation keys.

The complete groups are EQ0(age253), EQ1(age250), EQ16(age252), EQ64(age240),
EQ256(age255), GE256(age>=255), range21(age250..252), range256(age240..241).
Both AddressOnly/Fixed256 profiles, cached/uncached headers, Visible/Private
access and kernels cover IDs0/1/2, each with a genuine capacity-one miss and hit:
8×2×2×2×2×3×2=768 full operations. No group was truncated or discarded.
One posting page, one data page and at most256 selected rows remain explicit
limits. There is no permanent FHE row cache or plaintext aggregate substitution.

Nonce generation precedes timing; ciphertext-only freshness evidence is inside
the timer. Restore, negative controls, cached-header bootstrap and the post-timer
public oracle are separate. These are application misses following writer file
activity, not OS-cold physical disk or measured network latency.

All timings below are min/median/max milliseconds, n=12 EACH cell:
three tables×two profiles×miss/hit. Cardinalities stay separate by row. The256
fully separated kernel/case/profile/header/access/event groups (n=3 each) are
retained in the statistics artifact, so these summaries do not hide event shape.

| ExactIndex | Visible cached | Visible uncached | Private cached | Private uncached |
| --- | --- | --- | --- | --- |
| EQ0 |22.23/24.60/30.06|21.88/24.19/31.47|21.75/113.98/212.21|94.40/189.14/281.29|
| EQ1 |22.49/25.24/32.78|22.48/25.42/32.79|164.21/189.73/242.77|236.96/264.14/285.96|
| EQ16 |23.17/26.06/35.74|22.70/26.37/44.18|165.05/192.97/213.33|237.11/260.60/316.84|
| EQ64 |22.35/24.97/32.31|22.63/25.02/31.96|165.62/189.88/212.13|238.88/278.54/299.47|
| EQ256 |22.70/25.09/33.03|22.93/25.95/32.68|166.16/190.79/214.13|235.90/260.38/294.32|
| GE256 |22.41/25.14/31.86|22.60/25.33/33.48|165.19/189.01/212.55|238.36/267.42/317.35|
| range21 |22.45/25.30/33.70|22.75/25.01/31.37|166.37/191.60/212.79|239.83/262.15/282.82|
| range256 |22.45/25.02/33.67|22.57/25.50/33.08|163.85/189.36/219.91|236.38/259.18/286.18|

| FullPredicate | Visible cached | Visible uncached | Private cached | Private uncached |
| --- | --- | --- | --- | --- |
| EQ0 |83.15/86.83/92.42|84.18/88.76/94.90|84.07/180.89/278.17|158.97/256.85/359.71|
| EQ1 |83.54/87.60/93.23|83.92/87.19/92.29|227.21/252.37/280.94|301.70/324.82/349.60|
| EQ16 |83.78/89.84/95.82|84.08/89.86/95.74|229.45/251.23/276.49|301.34/324.08/357.20|
| EQ64 |85.03/90.88/100.63|84.33/88.93/104.96|226.19/251.10/275.09|298.19/325.55/347.26|
| EQ256 |84.25/89.06/96.68|83.90/89.40/96.69|226.42/251.43/275.65|300.02/322.38/350.12|
| GE256 |121.72/126.71/131.01|119.69/126.55/131.44|261.50/291.09/311.59|333.48/359.24/389.56|
| range21 |206.08/210.00/218.48|206.42/210.54/220.32|359.69/393.15/419.88|423.57/449.10/471.61|
| range256 |206.39/210.22/216.37|207.79/217.05/236.91|358.04/383.61/400.64|429.93/450.83/480.20|

Slowest: table1/FullPredicate/range256/Fixed256/Private/uncached MISS480.1963ms.
All samples/outliers are retained; there are no>500ms cells.

## Setup, update and rejection controls

Writer initialization before exit1,206.7644ms separately reports PIR generation
384.3144ms, BFV generation206.5632ms, public serialization8.0429ms, original
public peer setup139.2134ms, canonical generation48.4426ms, previous export/seal
166.4852ms and current export/seal165.0418ms. Stages are observations, not a sum
substituted for whole initialization.

Real authenticated selection→fresh BFV UPDATE→owner-authorized file replacement
took17.9130ms, including5.6589ms preparation. Peer performed one encrypted add,
zero products/rotations, request446,884B/response446,808B. The owner locally
authorized the returned bounded +1 before writing; this is NOT an arithmetic
proof or a broad UPDATE performance claim.

Reader initialization357.6519ms includes public/cipher reads4.1873ms,
negative controls25.4288ms, authenticated original secret restore170.6724ms,
original public evaluator143.8125ms and authenticated header bootstrap4.1532ms.
These setup costs are exposed and excluded from query latency.

All nine negative controls rejected before query BFV preparation:

1. Wrong wrapping key.
2. Corrupted sealed tag.
3. Truncated checkpoint.
4. Oversized backup before secret decode.
5. Wrong original BFV public/profile.
6. Wrong original PIR public.
7. Wrong trusted catalog/table binding.
8. Valid OLD backup versus CURRENT independent anchor.
9. Valid OLD backup/OLD anchor versus CURRENT nonzero physical heads.

Head/length checks precede secret decode; full-body Merkle reconstruction also
precedes NTT/page use. An authenticated old checkpoint is not automatically current.

## Complete files, key payloads and native memory

Logical plaintext denominator9,000,000B (three 1M×3B tables).

| Item | Actual bytes/count |
| --- | ---: |
| Six canonical data/index files |15,195,444B;1.6883826667×|
| Original BFV public file |13,395,426B|
| Original PIR public file |6,029,344B|
| Public catalog |2,085B|
| BOTH retained sealed checkpoints |9,996B each;19,992B total|
| ALL11 dataset files |34,642,291B|
| Compact owner keys / image |96B keys total;80B/image|
| BFV serialized secret / image |8,195B /8,327B|
| PIR original owner image |336B|
| Broker wrapping master |32B;not persisted|
| Cached headers including both heads |6,828B|
| PIR client secret/identity payload |180,224B|
| Expanded original PIR public payload |23,855,104B|
| Max retained loaded tables |1|
| Private native NTT pair |67,108,864B|
| Transient proof-record inputs |8,388,608B;dropped after NTT build|
| Loaded canonical/hash payload |5,065,148B /63,008B|
| Unloaded snapshots/NTT |0|

The shared BFV public file includes46B parameters,1,116,273B relinearization key
and12,279,077B rotation keys plus framing; ExactIndex retains this full keyset.
Secret images are Zeroizing owner memory or sealed ciphertext. A child receives
a wrapping-key copy; the reader's wrong-key negative fixture is Zeroizing and
dropped before queries. Kernel pipe-buffer zeroization, upstream protobuf
temporary-copy zeroization and SDK private-allocation zeroization are unproven.

Broker reads Windows native counters through each held Child handle AFTER actual
successful exit, requiring a nonzero RSS peak and rejecting either peak's regression below earlier
receipt peaks. Late child ledger/receipt work therefore remains in lifetime peaks;
post-exit current RSS is not a peak.

| Process | Native peak RSS | Native peak private commit |
| --- | ---: | ---: |
| Broker, observed through both child exits |6,787,072|1,712,128|
| Writer through exit |339,730,432|352,317,440|
| Reader through exit |346,755,072|352,104,448|
| Parent+serial active child conservative bound |353,542,144|354,029,568|

Last row is observed parent peak +max(writer peak,reader peak), because child lifetimes
do not overlap. It is a CONSERVATIVE SUM-OF-PEAKS BOUND, not synchronized
aggregate measurement. All native counters stayed below decimal2GB.
Max sampled child threads13, global Rayon8, Cargo jobs2, testthreads1.
Filesystem cache and kernel buffers outside process counters are not counted.

ALL dataset files +private bound =388,671,859B /9,000,000B=43.1857621111×.
The tiny run does NOT meet2× including fixed setup/RAM and makes no1000-table
projection. Separate public benchmark result JSONL is2,608,150B; it is an
explicit measurement artifact, not hidden data/cache state.

Cached metadata payload is2,276B/table including both112B heads. Fixed256
absent groups do actual dummy posting/data fetches and fresh encrypted zero
weights. AddressOnly permits cardinality/RPC distinctions. Table/root identity,
profiles, operation shape, cache events and updates remain public. PIR hides
selected pages within the chosen table; final leakage policy, active feedback,
malicious execution proofs and private writes remain open.

## Validation and immutable artifacts

116 runtime test executions +two compile-fail doctests passed:51 binary-owned,
39 BFV (explicit original-evaluation-key recovery included),23 compact-store,
3 bundle. Authored strict release Clippy passed for all four packages. The
unmodified pinned SDK retains four existing warnings.

First actual tiny attempt failed BEFORE BFV/update/current checkpoint; no reader
launched. One writer Source incorrectly shared a one-page header/posting budget.
A genuine authenticated regression reproduces that rejection and confirms the
separate-source fix. Its10 files34,632,295B and partial logs remain untouched.
The retry used FRESH files after the concrete fix. Earlier manifest/type/Clippy
failures/logs remain retained; observation timeouts never caused a restart.

Ignored main artifact root: .local/private-bfv-restart-disk/

- Raw dataset-3-budgetfix-20261015-013634-197.broker-results.jsonl:
  SHA2567E6DE0845181C0B12401F4ACB87B12592F876AFA2E53D9624207EC36C1B54BA5.
- Lifecycle tiny3-budgetfix-20261015-013634-197.log:
  SHA256D9AAB0E99D1E9BE188BF56C36ADACD74599BD73913E0115169785F2F3CD61C33.
- All256 separated groups tiny3-budgetfix-statistics.json:
  SHA256444F822307B05266987AEECD08ACD8ED8A926365F86759F82574FE9C9CF7C1D0.
- Independent768-answer/limb and six physical-head check:
  tiny3-budgetfix-independent-audit.json:
  SHA256C78403FD706DB928E42D981DC5ADE34E780DCA71490AFB886D45BC8EECFA4E13.

Immutable research-worktree source/executable archive:
.local/private-bfv-restart-disk/tiny3-budget-fix-artifacts-20261015-013627-170/
artifact-manifest.json SHA256D54443686C8AAF073D974942EFFF089E194386520A4E1BFD93B52B97E86E11DA.
Measured broker EBB6252CBE9F876819A2419346A775E38CE4EBBD22EE133727C5671D989CDC87;
writer06C9A0186F51624415F43A8A760C4BDD4F97AF10A43E6D44A45F18C3843CCADA;
reader19B797C3E889F3BE26186D31AE8B188177975133039E0A5CA336E2D785877A76.

## Reproduction and remaining scope

Source-only command (public paths only):

~~~powershell
./experiments/private-bfv-restart-disk/prepare.ps1 -SourceRepository E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage -PreparedOwnerDirectory <validated-owner-recovery-source>
~~~

Run using the printed source generation:

~~~powershell
./experiments/private-bfv-restart-disk/run.ps1 -PreparedDirectory <printed-source-generation> -ArtifactRoot <new-ignored-artifact-root> -TargetDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-process-restart-disk -CargoHome E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home
~~~

The new runner is deliberately three-table-only; it accepts no wrapping key.
The measured run used the same bounded binaries directly with a retained public
config. Pinned profile remains N8192/t114689/Q218/CBD(20) variance10,
native/unfused/additive/level0, upstream about128 security unresolved independently;
Spiral SDK fdb7206517c249603b0c91b65f1f29f95272107c and original public wire.
No parameter weakening, cross-version portability, crash-atomic publication,
private-write protocol, computation proof or general-SQL claim is established.
Actual1000-table restart needs separately authorized FRESH generation.
