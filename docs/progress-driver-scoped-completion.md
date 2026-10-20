# Progress v3 Driver validation and timing

On 2026-10-20, one actual four-validator/five-product workflow passed in
**5,845.27 seconds** (97.42 minutes). It exercised hidden-predicate FHE,
FOR UPDATE waiting, SKIP LOCKED, cold parked recovery, continuation and NOWAIT.
All five peer processes exited successfully and joined. This validates a bounded
fixed-source Driver composition, not full PostgreSQL or interactive latency.

## Change and ownership

The owner now consumes the original genuine input16/output118 verification
through a move-only evidence object inside the SAME synchronous Driver call.
After an independently verified current-context weighted certificate, it checks
the same store and all original bytes again, then checks Source/query/Core896,
Result160, the complete private bank/book and durable WAL fsync. No second native
product verification is required in this one call. Cancellation, error or a
public Pending return drops this object. It cannot be serialized or reconstructed
from a catalog/success flag. The closed Driver retains no scoped frame across
public calls, and cold/recovery APIs accept no such frame.

All validators, signer/import/floor paths, public cold completion, duplicates
and recovery still perform the full original native proof verification. This
different composition has a distinct v3 application contract and new App/G/
Rules/Binding identities; old v2 state is rejected without migration. Individual
math/Core profiles, wire grammar, proof checks and production budgets are unchanged.

The upload scheduler gives each configured endpoint one joined worker. Three
FIFO slots bound concurrent public blob ownership to at most 3 x 32 MiB. A slot
covers only read/PUT; Submit and checkpoint waits do not hold it. One valid exact
QC triggers cancellation, joining and draining of every worker. Actually returned
foreign-current certificates and local errors remain hard failures, including
errors that race cancellation. Three stalled PUTs can still occupy all blob slots;
this is not a proof of liveness against arbitrarily many malicious routes.

## Executed workflow

The public nonsecret fixture is `[(0,65535), (1,0), (128,255), (255,65534)]`.
N4 denotes four rows, T2 two transactions, and D2 savepoint depth two. This
workflow does not cover every D2 scenario. Four independent OS validators and a
separate OS FHE producer use the installed fixed-weight fixture and real TLS RPCs.
No certificate or answer is manufactured by the test.

| QC slot | Actual operation and checked behavior |
| --- | --- |
| 1 | Bootstrap and empty private owner |
| 2, 3 | Begin A and B through the real Driver |
| 4 | A locks row3 (age255); actual encrypted product returns Done |
| 5 | B `>=0 LIMIT3 OFFSET1` locks rows0/1/2, selects1/2 and parks at row3 |
| -- | All owner, depot and ingress handles drop; full cold proof/QC/WAL replay preserves B's parked statement |
| 6 | A `>=0 LIMIT2 OFFSET1 SKIP LOCKED` skips B's conflicts before OFFSET; its own row3 consumes OFFSET, yielding Done EMPTY |
| 7 | Ordinary A End releases row3; B's stable ID survives transaction compaction |
| 8 | B resumes its original call without replacement SQL, with fresh q/nonce/Copen; rows1/2/3 return without applying OFFSET twice |
| 9 | New A begins with no prior held locks |
| 10 | A NOWAIT obtains actual Error and a failed transaction bank; B retains all four locks |
| 11 | A COMMIT obtains actual Aborted |

Exactly five Work starts, five successful Work ends, five distinct accepted
catalogs and five `original_native_scoped` completions were observed. Genuine
scoped-frame substitutions were rejected with the owner unchanged. Final parent
slot11/context12, exactly 40 WAL records and an empty global flight were asserted.
All children joined before removal of the owned temporary root. Capture was
disabled; the separate [public replay profile](progress-validator-profile.md)
keeps its own narrower evidence scope.

## Timing

Seconds below come from monotonic phase receipts in the uncapped test log.
Prepare and Work precede the upload round. Upload and first QC are measured from
that round's start; they overlap and must not be added together. Work includes
remote FHE, proof production and local streaming verification/recording. QC
waiting includes application checks, queueing, transport and consensus.

| Product | Prepare | Work/stream | All four uploads | First valid QC | QC to joined workers | Private completion/fsync | Full Driver call |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A acquire | 103.636 | 409.352 | 12.489 | 386.349 | 0.556 | 3.544 | 904.149 |
| B parked | 105.957 | 407.708 | 13.208 | 643.892 | 1.788 | 3.757 | 1163.868 |
| A SKIP LOCKED | 95.876 | 397.203 | 16.209 | 393.984 | 0.265 | 4.377 | 892.451 |
| B resume | 118.814 | 443.303 | 14.541 | 281.604 | 40.357 | 3.733 | 888.676 |
| A NOWAIT | 109.581 | 471.872 | 12.440 | 316.623 | 0.187 | 3.899 | 902.946 |

Full parked owner recovery took 89.824 seconds. The five control calls took
19.302, 18.963, 454.341, 46.977 and 436.053 seconds. The two long End calls spent
442.031 and 425.977 seconds respectively reaching the first QC despite small
control payloads. A 40.357-second post-QC join tail also remains unexplained.
Neither delay is established as unavoidable cryptographic cost.

The optional per-validator finality/actor diagnostics exhausted their 4096-line
caps before slot 4; later fine-grained attribution is unavailable in this run.
The independent uncapped Driver markers still cover every operation. The
separate cold replay identifies repeated application checks and actor queueing
as costs worth investigating. Upload measurements from different fixtures or
schedulers are not a controlled full-query speedup. Five FHE jobs and recovery
also cannot be compared directly with older one-job or four-job test durations.

## Narrow owning checks and resources

Serial release checks passed before this full run:

| Check | Selected result | Test body | Complete command |
| --- | --- | ---: | ---: |
| Evidence `scoped_recording_tests::` | 2 passed | 0.03 s | 4.67 s |
| Joint `v3_handoff_contract_rejects_v2_descriptor_manifest_request_and_genesis` | 1 passed | 6.72 s | 13.82 s |
| storage-client owning `host::network::` filter | 17 passed, 1 ignored | 0.02 s | 37.90 s |
| storage-client strict all-target Clippy | passed | -- | 3.26 s |
| dcs-peer release build | passed | -- | 11.39 s |
| std-only repository requirements mirror | passed | <0.01 s | 0.32 s |

Commands use `--release --offline --locked`; storage-client also uses
`--features private-input-proofs`. The full prebuilt release harness ran only:

```text
private_predicate::source::locking::joint::progress::host::network::process_tests::actual_four_validators_wait_park_reopen_skip_locked_end_resume_then_nowait_abort --ignored --exact --nocapture --test-threads=1
```

The observer held actual process identities through exit, including creation
times. The complete-test fuse remained 7200 seconds; production operation 1800
and I/O 180 seconds, Rayon 2, two build jobs and the 1,792-MiB per-process fuse were
unchanged. No memory setting, affinity, deadline or unrelated process changed.
There was no monitor fault, observed fuse, OOM, forced cleanup or unknown child.

| Role | OS lifetime peak working set, bytes | Sampled peak private bytes |
| --- | ---: | ---: |
| Owner/test | 1469042688 | 1629597696 |
| FHE producer | 1221394432 | 1314656256 |
| Four validators, individual range | 644726784--652455936 | 677888000--703000576 |

The maximum sampling gap was 1.032 seconds; sampled private peaks can miss
transients. These measurements are not a formal whole-process resource bound.
Final accounted owner storage was 2699945515 bytes in 713 files, including
2699799163 depot bytes and 146352 control bytes, below its 10-GB quota. This does
not establish the target 1--2x storage ratio for general data.

## Provenance and remaining work

The run used an unpublished implementation snapshot on top of
`62d3d98e0a9fe37cf846ad86859a2b84ccff68c6`. All 1,705 tracked/nonignored source
images matched before and after the run. The source map uses sorted-key compact
UTF-8 JSON of repository paths to uppercase RAW SHA-256 values. Subsequent
documentation updates are outside that exact native snapshot.

| Retained local identity | SHA-256 |
| --- | --- |
| Source map | `6A904AB69CD8406A676D2D3ECC02AD160F7441E6DE20DCD60BA403BF345B897A` |
| Test binary | `00A733C843DECB20410E95C56CF288319751FBD70BA787F3D1F5657FECA73783` |
| dcs-peer binary | `E74116DF704E4370617BC6DB4DF0F92635005479994ED9E178EB935DD95D05FC` |
| Observer source | `832BC81724776FAD0112993445A8A7E206E75F34149427B9B46EEE22D8C8DFAC` |
| Observer result | `445B912B7FAC145F2BDD6F26DE5B0208509431094CC2F933BAF9674612741732` |
| Complete timing extraction | `9E896113A0713EDA85E8EBEBA053687F71DB3F990EBC572F225566D47BD768E8` |
| Uncapped stderr | `046ADBFF6A426B51D185BD3E1513F52AEB7B9D699CE64CD3A28A1A55BB0BE74F` |

The result was `PASS_COMBINED5_V3_ONE_RUST_TEST`; external observation took
5845.625 seconds. Generated logs, data, keys and public archives are not committed.

General SQL/schema/DML/MVCC, parked cancellation/RollbackTo, deadlock handling,
mutable-row EPQ, a Session/PGwire/GUI bridge, delegated rights, permissionless
confirmed-weight admission and a general latest-head/lease policy remain open.
Existing capability guards stay closed. This fixed-source pass does not validate
unexecuted later application profiles or independently settle production crypto
choices. The [fast-test rule](../AGENTS.md#verification-and-completion) requires
narrow checks for ordinary changes and another expensive run only for an affected
boundary, a failure or a concrete unresolved concern.
