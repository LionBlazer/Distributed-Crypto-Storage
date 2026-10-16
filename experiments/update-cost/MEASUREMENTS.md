# Readiness listener: full proved SQL observations, 2026-10-16

These small Windows x64 loopback observations compare the original nonblocking
listener's 10-ms polling with the reviewed readiness-driven peer candidate. They
support the measured scenarios only. They do not establish a general 500-ms SQL
guarantee, production consensus security, WAN latency or a 1–2-GiB RAM bound.

## Acceptance and comparison scope

The unchanged `proved_sql` executable launched independently running peers with
fresh in-memory test credentials and ignored durable state. Every accepted result
retained genuine BFV/STARK verification, complete authenticated selection, final
confirmed freshness, authorization and exact changed-row assertions. INSERT and
UPDATE included durable transition publication and its descendant confirmation.
The test uses an explicitly easy internal work target and one confirmation; this
is a protocol fixture, not a production attack budget. No prover-status acceptance,
preprocessing-cache experiment or parallel journal-verifier experiment was used.

The mutation scenario starts with four public rows, two logical shards and two
peer processes, inserts a fifth row, then updates three rows across both shards.
It also deliberately kills a peer and restarts persisted state. The separate
aggregate scenario has 512 asymmetric rows: even rows have age 18 and amount 65535,
odd rows age 7 and amount 1, split round-robin across the two shards. It checks
COUNT/SUM, filtered selection and empty COUNT/SQL NULL SUM.

The owner was built with `-C target-cpu=native`, Cargo jobs 2, Windows MSVC, Rust
1.99.0. The machine reported `AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD`.
Owner and each peer used exactly eight Rayon threads; the selected peer backend
was AVX-512. Profile v3, N8192/Q218, all 81,920 residues, FRI blowup 8, 192 queries,
extension degree 5 and the 128-bit security floor remained unchanged. Peer heavy
proof admission and connection/resource limits were preserved. Other development
builds and proof tests were paused during the latency windows; there was no RSS
monitor in any latency sample. Each sample was a fresh whole scenario; compilation
and database setup were outside individual `accepted_sql_ms` query timers.

The test/source base was `d3e07ca2687eeb794a2207fb2ae82f7d59564fc3`, with the
opt-in recorder from `67991378b91adb9f12cea21796d10dbfbd4c82fb`. Only the baked
peer executable was replaced between the matched observations. The same test
executable, fixture assertions and profile-v3 kernels were retained. The after
peer was built from the reviewed readiness implementation subsequently committed as
`25a445194f3a26b42d7d7ddd1f6345fcb8062f4f`, with no source changes between build
and commit. The actual compared executable hashes below identify those artifacts;
a later rebuild is not assumed to be byte-identical.

| Artifact | SHA256 |
| --- | --- |
| Unchanged `proved_sql-0ddecf929fe1a8e4.exe` | `88ECA07198F891B65ACF7DA6A1145F62697762B39019052B0704BB59681058A5` |
| Before `dcs-peer.exe` | `9355EA28222C06B5BCF20E3CF5E50905ECAD1758E61014E64553F0ADC58B8E26` |
| After `dcs-peer.exe` | `018DD2138B441401F8FF46F599E68CF1072D8AEEC39940DFE4C553C45CA23418` |
| Unchanged `dcs-proof-avx512.dll` | `6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975` |
| Unchanged `dcs-proof-avx2.dll` | `EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C` |

## Matched UPDATE observations

Three metadata-gated full scenarios before and after each passed. Every UPDATE
recorded exactly 30 completed RPCs, 90 events, zero failures and no truncation.
The bounded analyzer validated all successful frame pairs, their order and Trace
byte counts. Times below are milliseconds, in run order.

| UPDATE observation | Before samples | After samples |
| --- | --- | --- |
| Complete accepted UPDATE envelope | 601.070 / 557.539 / 612.988 | 399.466 / 420.317 / 441.746 |
| Complete envelope median | 601.070 | 420.317 |
| Union of RPC intervals | 516.960 / 489.591 / 545.163 | 316.115 / 338.084 / 356.646 |
| Wall time without an owner RPC in flight | 84.110 / 67.948 / 67.825 | 83.351 / 82.233 / 85.101 |
| Ten journal-sync calls, elapsed sum | 72.965 / 63.449 / 92.328 | 6.682 / 7.148 / 7.279 |
| Four Store calls, elapsed sum | 42.634 / 25.256 / 43.566 | 9.107 / 17.953 / 18.708 |
| Four Fetch calls, elapsed sum | 41.340 / 33.930 / 32.994 | 3.879 / 3.022 / 3.204 |
| Two Mine calls, elapsed sum | 112.275 / 123.949 / 107.768 | 105.485 / 100.006 / 114.818 |
| Four Publish calls, elapsed sum | 170.437 / 146.654 / 165.872 | 130.665 / 151.448 / 148.730 |
| Two overlapping Prove calls, interval union | 57.418 / 76.364 / 65.390 | 57.506 / 54.777 / 60.880 |

RPC sums overlap and must not be added as exclusive critical-path costs. Public
callbacks group encode/connect/TLS/write together and peer/wire/read together;
they cannot isolate peer proof generation or durable fsync. The old trace showed
substantial pre-send time even on small RPCs; the readiness candidate reduced
small sync/fetch call costs while retaining the genuine proof/publication spans.
Local gaps still include owner proof verification, compact completion, staging
and request construction. These measurements locate combined phases, not a claim
that every saved millisecond belongs to listener polling alone.

The six logs and generated JSON remained under ignored
`.local/update-cost-observation/`: baseline prefixes `20261016-030556-133`,
`20261016-030604-006`, `20261016-030611-675`; after prefixes
`20261016-031239-118`, `20261016-031246-305`, `20261016-031253-379`.

## Separate ordinary latency samples

Three additional after scenarios ran with `DCS_TEST_RPC_PROFILE` unset and no
memory monitor. Every existing acceptance assertion passed. There is no matched
unprofiled-before set at this exact base, so the following table is an after
observation rather than an additional before/after estimate. Units are ms.

| Complete operation | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| `SELECT * FROM records` | 188.157 | 190.040 | 254.852 |
| `SELECT amount, age FROM records WHERE age >= 18 LIMIT 1` | 187.120 | 192.603 | 208.859 |
| `INSERT INTO records VALUES (21, 255)` | 257.643 | 266.429 | 268.714 |
| `UPDATE records SET amount = amount + 1 WHERE age >= 18` | 413.826 | 416.809 | 428.950 |
| `SELECT * FROM records WHERE age >= 18`, after writes | 233.457 | 240.006 | 240.048 |
| `SELECT age FROM records WHERE age > 255`, after restart | 250.891 | 255.608 | 291.684 |
| 512 rows: `SELECT COUNT(*), SUM(amount) FROM records` | 189.859 | 197.410 | 197.914 |
| 512 rows: `SELECT COUNT(*) FROM records WHERE age >= 18` | 191.872 | 193.472 | 197.854 |
| 512 rows: `SELECT SUM(amount) FROM records WHERE age = 7` | 195.679 | 196.402 | 202.349 |
| 512 rows: `SELECT COUNT(*) FROM records WHERE age > 255` | 193.716 | 198.404 | 202.791 |
| 512 rows: `SELECT SUM(amount) FROM records WHERE age < 7` | 198.219 | 198.559 | 201.870 |

The intentional process-loss query `SELECT amount FROM records WHERE age = 21`
included dead-endpoint detection: 2313.313 / 2319.969 / 2324.933 ms. It is a failure
recovery observation, separate from ordinary no-failure latency. The samples do
not estimate tails or larger typed tables. Raw logs and `measurements.json` are
under ignored `.local/readiness-runs/20261016-031300-584-after/`.

## Combined atomic-INSERT contract recheck

After integrating atomic literal INSERT batches, the complete new application was
measured again at `0619807a01df1dfe2a6dfc427762d5a9bf010ff8`. This uses INSERT wire
version 3 and proved-job application commitment version 2; those changes reject
the previous application's journal policy. Both owner and peer were rebuilt from
the combined source. This is a new full-scenario observation, not another matched
listener-only comparison. The fixture still times a single-row INSERT; its timing
does not measure a 256-row batch.

The same native owner, two actual peer processes, eight threads per process,
unchanged profile-v3 SIMD kernels, test work/confirmation policy and fixtures above
were used. Three fresh mutation scenarios and three 512-row aggregate scenarios
all passed. Builds and database setup were outside the query timers. No RPC or
memory monitor, other build or proof test ran in this timing window. The separately
packaged portable application and both actual-peer script scenarios also passed;
portable execution was not the source of these native timings.

| Complete operation | Minimum ms | Median ms | Maximum ms |
| --- | ---: | ---: | ---: |
| `SELECT * FROM records` | 190.118 | 190.184 | 197.155 |
| `SELECT amount, age FROM records WHERE age >= 18 LIMIT 1` | 187.542 | 194.435 | 205.417 |
| `INSERT INTO records VALUES (21, 255)` | 253.950 | 266.008 | 270.928 |
| `UPDATE records SET amount = amount + 1 WHERE age >= 18` | 410.977 | 420.161 | 421.218 |
| `SELECT * FROM records WHERE age >= 18`, after writes | 229.572 | 244.558 | 253.346 |
| `SELECT age FROM records WHERE age > 255`, after restart | 250.007 | 253.715 | 254.377 |
| 512 rows: `SELECT COUNT(*), SUM(amount) FROM records` | 190.186 | 192.062 | 200.803 |
| 512 rows: `SELECT COUNT(*) FROM records WHERE age >= 18` | 192.491 | 193.331 | 198.927 |
| 512 rows: `SELECT SUM(amount) FROM records WHERE age = 7` | 186.925 | 192.976 | 198.668 |
| 512 rows: `SELECT COUNT(*) FROM records WHERE age > 255` | 190.370 | 196.566 | 201.586 |
| 512 rows: `SELECT SUM(amount) FROM records WHERE age < 7` | 188.396 | 190.349 | 196.042 |

The deliberate stopped-peer read remained 2306.290 / 2308.083 / 2308.288 ms. These
observations establish neither a 500-ms failure-recovery bound nor a tail, WAN,
larger-table or complete PostgreSQL latency guarantee. They include real proof
verification, authorization, freshness and durable mutation confirmation.

The native test executable `proved_sql-007699ff40f823e7.exe` had SHA256
`F3DD883134E8146F0AEF54DA40803439C0E35967B4FAC82F87BE7E0AE5A55F3B`;
`dcs-peer.exe` had SHA256
`42C318A4E4A61BF7043844B7D7407587992106E6919F0F5A55082CE1068AC7DF`.
Both kernel hashes equal the unchanged hashes in the artifact table above.
The six unprofiled logs, all 36 individual query timers and artifact identities
remain in ignored `.local/combined-sql-runs/20261016-033710-864/measurements.json`
and adjacent logs. Reproduction uses the same two exact test names and environment
below, with this rebuilt matching owner/peer pair and `DCS_TEST_RPC_PROFILE` unset.

## Separate, incomplete memory observation

One additional full mutation/failure/restart scenario passed under concurrent
development load, with the RPC recorder disabled. The monitor owned the test
process handle and discovered only its newly created direct child PIDs through
CIM `ParentProcessId` plus creation-time checks. It queried OS working-set/peak
counters through retained handles; no unrelated processes were inspected or
terminated. Requested discovery/sample periods were 500/100 ms, but blocking CIM
calls caused a 2573-ms maximum gap: only six RSS samples and one discovery race
were recorded. The initial peer that was deliberately killed had already begun
exiting before a useful sample; its roughly 8-MiB report is not a valid lifetime
peak and is excluded from resource conclusions.

Observed OS peaks were 204.17 MiB for the owner, 174.60 MiB for the other initial
peer and 172.65 MiB for the restarted peer. The observed simultaneous working-set
sum reached 248.44 MiB. That sampled sum is incomplete, may miss the real peak and
is not the sum of the independent OS peaks. This run cannot establish an all-peer
peak, an adversarial-concurrency bound or compliance with the process RAM target.
It is excluded from latency samples. The unchanged test executable has no PID
notification hook; no production or fixture behavior was modified for monitoring.
The raw limitations and counters are in ignored
`.local/update-cost-observation/20261016-031734-773-memory/memory.json`.

## Million-row UPDATE diagnostic

A separate 2026-10-16 diagnostic used application source `771d1a5bac5968c94821ff615171c445ec20b76c`
plus the opt-in recorder extension in this change. The same million-row real-daemon
scenario and profile-v3 AVX-512 peer from the [combined record](../combined-sql/README.md)
passed its exact changed-row, agreed-head, image-size and subsequent SELECT assertions.
Owner and peer each used eight Rayon threads. PID/memory hooks were disabled.
Other development builds/tests were active: this is one instrumented execution,
not a quiet latency sample or a before/after speed claim.

The complete UPDATE envelope was 1483.769 ms with 14 completed RPCs, 42 frame/Trace
events, zero failed RPCs and no truncation. The analyzer validated every callback's
phase, ordering, byte count and envelope. The owner sent 41,200,034 application
bytes and received 77,908,880, including runtime framing and journal evidence.

| Operation | RPCs | RPC elapsed sum ms | Request bytes | Response bytes |
| --- | ---: | ---: | ---: | ---: |
| Store | 1 | 356.185 | 37,604,542 | 91 |
| Journal collect | 1 | 244.298 | 46 | 18 |
| Fetch version | 1 | 217.537 | 254 | 37,604,546 |
| Fetch | 1 | 213.458 | 46 | 37,604,546 |
| FHE proof | 1 | 168.851 | 446,974 | 1,125,626 |
| Journal mine | 2 | 60.308 | 1,573,575 | 1,573,823 |
| Journal publish | 2 | 17.758 | 1,573,879 | 100 |
| Journal sync | 5 | 5.813 | 718 | 130 |

The RPC interval union was 1284.207 ms; 199.562 ms had no owner RPC in flight.
These local gaps include original-input preparation, proof checks, compact staging
and request construction. RPC phases combine client codec/TLS and server work;
they cannot individually measure disk audit, FSYNC, proving or listener waiting.
The journal collector currently reads and validates complete stored images to
identify obsolete objects. This observation motivates examining that ownership
boundary, without skipping integrity validation before Fetch, Prove or page replies.
Moving work out of the envelope or dropping durable publication would not prove
the requested improvement.

Ignored raw log, validated trace and analysis are in
`.local/update-cost-million/20261016-043448-244/`. SHA256 identities:

- Test owner `proved_sql-43b267abd6ab93e6.exe`: `89CEB45E56345198C55B00820421C4CAA9B2CD9BFC82EBADBC71D5D00FC8468C`.
- Peer `dcs-peer.exe`: `42C318A4E4A61BF7043844B7D7407587992106E6919F0F5A55082CE1068AC7DF`.

The peer binary, full proof profile and both SIMD kernel hashes are unchanged from
the combined record. This diagnostic retains one descendant confirmation and
the deliberately easy test work contract; it establishes no production attack,
recovery, throughput or tail-latency bound.

## Reproduction

Build the owned process fixture outside the timing window, following the
[dcs-peer](../../apps/dcs-peer/README.md) and
[proof-kernel](../../apps/proof-kernel/README.md) instructions. Set native
`RUSTFLAGS`, use a distinct ignored `CARGO_TARGET_DIR`, and package trusted
unchanged profile-v3 SIMD kernels beside the peer executable. Build the two peer
revisions in separate targets. Preserve the original peer and test executable;
verify hashes before replacing only the peer at the test's baked
`CARGO_BIN_EXE_dcs-peer` path. Rebuilding the fixture during comparison would no
longer hold its binary identity constant. Never mix a different proof profile.

Run the preserved test executable directly, with no build or monitor in the loop:

```powershell
$env:RAYON_NUM_THREADS = '8'
$env:DCS_TEST_PEER_THREADS = '8'
$env:DCS_TEST_RPC_PROFILE = '1'
$fixture = '.local/target-update-cost-observation/release/deps/proved_sql-0ddecf929fe1a8e4.exe'
& $fixture proved_select_insert_update_survive_a_process_loss_and_journal_restart --exact --nocapture --test-threads=1 > .local/update-before.log 2>&1
python -B experiments/update-cost/analyze.py .local/update-before.log
```

Repeat three fresh scenarios per peer binary in a quiet window, with separate
log paths. Verify analyzer success and all test assertions before comparing phase
unions. For ordinary latency, remove `Env:DCS_TEST_RPC_PROFILE` and run the same
scenario three times, then three
`real_peers_prove_count_sum_and_empty_sql_null_over_complete_shards` scenarios.
Retain every `accepted_sql_ms` line, including intentional recovery. Run memory
monitoring separately and report actual discovery/sample gaps and missed
lifetimes. Keep generated logs, ciphertexts and binaries under ignored `.local/`.
