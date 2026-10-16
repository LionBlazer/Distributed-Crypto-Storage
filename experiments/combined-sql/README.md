# Combined SQL, private identities and resource observations

These 2026-10-16 observations measure the combined application at
`5caa85db410111b68e1d3d368300d338bcba9ce9`, including atomic INSERT, readiness
listeners, PostgreSQL text/NULL ordering, bounded owned jobs, parallel typed
projection and encrypted stable row identities. They do not establish complete
PostgreSQL, SQL row locks, production consensus, a general 500-ms bound or a
whole-process resource guarantee.

The [latest combined recheck](#q2-page-custody-and-collection-recheck) below pins
the later Q2/page-custody/collection integration separately from this original record.

## Full accepted operations

The Windows x64 host reports `AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD`.
Rust 1.99.0/MSVC release builds used `-C target-cpu=native`, build jobs 2, and
eight Rayon threads in the owner and every peer. Peers selected AVX-512. The
unchanged proof profile v3 covers all 81,920 residues, N8192/Q218, FRI blowup 8,
192 queries, extension degree 5 and the 128-bit security floor. INSERT wire v3,
application commitment v2, fixed private index v3 and typed index v2 were used.
No preprocessing-cache experiment was included.

Four existing real-daemon scenarios ran three fresh times each. All exact rows,
genuine proof checks, authorization, confirmed freshness and durable mutation
assertions passed. The fixture's deliberately easy work target and one descendant
confirmation do not represent a production attack budget. Startup, keys and table
creation are outside each query timer; query preparation, actual I/O, proof
verification, completion and final freshness are inside it. Writes include durable
publication and confirmation. No other build, proof test, PID/RPC hook or memory
monitor ran during these latency samples.

The small mutation scenario starts with four rows on two shards/two peers, inserts
a fifth and updates three across both shards. The typed scenario returns all 300
rows with text and binary columns through four actual proofs on two peers. The
512-row aggregate scenario has asymmetric extreme amounts across two peers. The
million-row scenario uses one actual peer, 999,999 age-7 rows and one age-42 row;
it updates and then reads that final row. Table size below is the initial size.

| Initial rows | Complete SQL operation | Minimum ms | Median ms | Maximum ms |
| ---: | --- | ---: | ---: | ---: |
| 4 | `SELECT * FROM records` | 193.716 | 197.909 | 198.084 |
| 4 | `SELECT amount, age FROM records WHERE age >= 18 LIMIT 1` | 193.656 | 196.506 | 202.749 |
| 4 | `INSERT INTO records VALUES (21, 255)` | 277.135 | 280.109 | 287.988 |
| 4 | `UPDATE records SET amount = amount + 1 WHERE age >= 18` | 414.090 | 425.759 | 466.094 |
| 4 | `SELECT * FROM records WHERE age >= 18`, after writes | 229.027 | 230.631 | 235.988 |
| 4 | `SELECT age FROM records WHERE age > 255`, after restart | 250.893 | 253.686 | 260.952 |
| 300 | `SELECT label, id, payload FROM typed_rows ORDER BY id DESC` | 387.373 | 389.962 | 392.415 |
| 512 | `SELECT COUNT(*), SUM(amount) FROM records` | 197.215 | 198.507 | 198.752 |
| 512 | `SELECT COUNT(*) FROM records WHERE age >= 18` | 194.988 | 195.055 | 200.170 |
| 512 | `SELECT SUM(amount) FROM records WHERE age = 7` | 191.206 | 193.796 | 204.123 |
| 512 | `SELECT COUNT(*) FROM records WHERE age > 255` | 190.587 | 192.880 | 200.613 |
| 512 | `SELECT SUM(amount) FROM records WHERE age < 7` | 197.311 | 198.135 | 198.564 |
| 1,000,000 | `SELECT * FROM records WHERE age = 42` | 486.708 | 487.940 | 490.931 |
| 1,000,000 | `UPDATE records SET amount = amount + 1 WHERE age = 42` | 1363.324 | 1385.483 | 1394.065 |

The deliberately stopped-peer read `SELECT amount FROM records WHERE age = 21`
took 2307.564 / 2310.894 / 2321.482 ms. The million-row UPDATE exceeds 500 ms;
the ordinary no-failure samples cannot establish a recovery bound or tail SLA.
The current path transfers complete encrypted images and fully checks server
custody. The million-row data/index images total 37,604,272 bytes before bundle/RPC
wrappers. Sparse network retrieval and delta publication remain separate work;
their time benefit must be measured without omitting integrity checks.

All 45 individual timers, 12 logs and artifact identities remain under ignored
`.local/combined-final-runs/20261016-041415-242/`. Actual SHA256 values:

| Artifact | SHA256 |
| --- | --- |
| Native owner/test `proved_sql-43b267abd6ab93e6.exe` | `727F17C02BDD3F24FD7410081A73E4018C65FB3F239F3045D8730DE93020823A` |
| Native `dcs-peer.exe` | `42C318A4E4A61BF7043844B7D7407587992106E6919F0F5A55082CE1068AC7DF` |
| AVX-512 kernel | `6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975` |
| AVX2 kernel | `EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C` |

The earlier [matched listener comparison](../update-cost/MEASUREMENTS.md) and
[matched typed-worker comparison](../typed-select/README.md) preserve their own
source/artifact identities. These combined rechecks are not additional matched
estimates of either individual optimization.

## Separate million-row lifecycle memory observation

One additional complete million-row scenario passed with `DCS_TEST_FIXED_PIDS=1`.
A Windows PSAPI monitor started the exact owner, retained its handle and the one
directly owned peer handle before table creation, and observed both lifetimes
without CIM discovery. This includes allocation, encrypted creation, actual
Store/Fetch, genuine UPDATE, agreed restore, SELECT and cleanup. It is separate
from all latency samples. Concurrent development load was uncontrolled.

Fifteen samples requested 100-ms intervals; the actual maximum gap was 259 ms,
with zero missed lifetimes. Independent OS peak working sets were 199,352,320
bytes for the owner and 227,446,784 for the peer; `PeakWorkingSet64` agreed.
The corresponding peak pagefile/commit counters were 219,422,720 and 261,877,760
bytes. The maximum sampled simultaneous working-set sum was 386,179,072 bytes;
it is not the sum of independent peaks or a continuous whole-system peak.
Raw counters and logs remain in ignored
`.local/fixed-index-runs/20261016-041701-942-memory/`.

This selected one-peer fixture is not an adversarial-concurrency, larger-catalog
or 1–2-GiB process bound. The new million-row index is exactly 34,416,624 encoded
bytes across 8,306 pages; data is 3,187,648 bytes. The owning tests check actual
custody geometry and sparse owner ID authentication. Network fetch still uses
full images; sparse local decryption alone does not establish sparse disk/network I/O.

## Reproduction and validation

Build the real [dcs-peer fixture](../../apps/dcs-peer/README.md) outside the timing
window with the native configuration above and trusted unchanged profile-v3
kernels beside its peer. Run the compiled test executable directly with
`RAYON_NUM_THREADS=8`, `DCS_TEST_PEER_THREADS=8`, `--exact --nocapture
--test-threads=1`. Clear `DCS_TEST_RPC_PROFILE`, `DCS_TEST_TYPED_PIDS` and
`DCS_TEST_FIXED_PIDS` for latency. Repeat each exact name three times:

- `proved_select_insert_update_survive_a_process_loss_and_journal_restart`
- `typed_sql::typed_300_row_select_accepts_complete_ordered_proved_bytes`
- `real_peers_prove_count_sum_and_empty_sql_null_over_complete_shards`
- `million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`

For memory, run only the last scenario with its PID hook and an independent
retained-handle monitor; report actual gaps and missed lifetimes. Keep generated
logs, ciphertext and binaries ignored.

The combined native owning suite passed 115 tests, including genuine proof
tampering, atomic batch rejection/retry, exact head/owner checks, actual process
failure, one-million-row layout, stable identities and both worker cancellation
boundaries. Strict Clippy and formatting passed. Portable GUI all-target tests,
architecture/requirements mirror and packaging passed. Its two opt-in SQL script
scenarios and the actual three-daemon Northwind import/typed-read scenario passed
separately. The latter's single validation run returned all 2,155 order-detail
rows through 14 proofs in 1.438 s; it is not a three-sample latency estimate and
does not meet 500 ms. Unsupported full PostgreSQL and live row locking still reject.

## Q2, page custody and collection recheck

Source `94191fa58f208e30c6b26a59c659acf36b24dfbf` combines Q2 ten-band aggregation,
bounded page custody, one physical-custody audit/hash per read, validated-membership
collection and PostgreSQL matched UPDATE counts. Live SQL still fetches full images;
the raw page RPC does not approve exposing query-dependent page addresses. The
[PostgreSQL contract](../../docs/postgresql-contract.md) records that privacy boundary.
FHE/STARK profile v3, all 81,920 residues and kernel ABI are unchanged; the semantic
application anchor is v3 and old Q1/R1/application-v2 journals reject.

Three fresh complete scenarios per fixture ran with owner/peers each using eight
Rayon threads, native Rust 1.99/MSVC and the same AVX-512 kernels as the original
record. All exact outputs, genuine proofs, source heads and confirmed freshness
assertions passed. Writes include durable publication and synchronous collection.
Other development builds/proof tests were held. No RPC, PID or memory hook ran.
Startup/table creation remains outside each SQL timer. These six scenarios produced
36 individual SQL timers; they are not matched estimates of individual changes.

| Source rows | Complete SQL operation | Minimum ms | Median ms | Maximum ms |
| ---: | --- | ---: | ---: | ---: |
| 1,000,000 | `UPDATE records SET amount = amount + 1 WHERE age = 42` | 960.821 | 1025.948 | 1083.130 |
| 1,000,000 | `SELECT * FROM records WHERE age = 42` | 452.721 | 453.185 | 474.222 |
| 5,119 | `SELECT COUNT(*), SUM(amount) FROM records` | 195.988 | 198.536 | 199.302 |
| 5,119 | `SELECT COUNT(*) FROM records WHERE age = 18` | 191.774 | 196.221 | 201.643 |
| 5,119 | `SELECT SUM(amount) FROM records WHERE age = 7` | 192.393 | 197.998 | 198.606 |
| 5,119 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42` | 191.184 | 199.204 | 207.709 |
| 5,119 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255` | 193.440 | 197.679 | 199.678 |
| 5,120 | `SELECT COUNT(*), SUM(amount) FROM records` | 194.533 | 194.935 | 195.016 |
| 5,120 | `SELECT COUNT(*) FROM records WHERE age = 18` | 195.550 | 196.009 | 197.412 |
| 5,120 | `SELECT SUM(amount) FROM records WHERE age = 7` | 191.843 | 193.845 | 194.956 |
| 5,120 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42` | 228.557 | 231.247 | 251.090 |
| 5,120 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255` | 250.499 | 266.520 | 266.936 |

The million-row fixture has one peer, 999,999 age-7 rows and one age-42 row.
The [Q2 fixture](../../docs/proved-aggregate-bands.md) has two peers and asymmetric
2560/2559 or 2560/2560 shards, distinct amount bands, one nonempty zero SUM and
empty-shard/empty-relation cases. Its output and boundary assertions are unchanged.
The separate [matched collection comparison](../update-cost/MEASUREMENTS.md#matched-collection-change-on-one-million-rows)
isolates only collection. Do not attribute this later recheck's difference to one
patch or compare Q1/Q2 capacities as the same workload.

The million-row UPDATE remains above 500 ms. These three samples per case do not
establish a tail, throughput, recovery, whole-process RAM or production-consensus
bound. Memory was not remeasured in this window. Full PostgreSQL, typed aggregates,
transactions and live row locks remain incomplete.

Raw six logs and all timers are in ignored
`.local/combined-q2-gc-runs/20261016-045752-059/`. SHA256 identities:

| Artifact | SHA256 |
| --- | --- |
| Owner/test `proved_sql-43b267abd6ab93e6.exe` | `3435F65582699697CCE209FD59BA1298C9F0BE971B4C993C030ED61D11B45210` |
| Peer `dcs-peer.exe` | `B51BA46381B37C69E1161622DC32F6A8D8344B908AC1999F60191A179632F399` |

Both unchanged kernel hashes remain the AVX2/AVX-512 values in the original table.
Reproduce with the earlier native configuration and exact test names
`million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`
and `q2_real_peers_aggregate_5119_and_5120_asymmetric_rows_with_partial_and_empty_bands`.
Run each compiled scenario three fresh times; do not build during timing.

All owning BFV-core, compact-query, runtime, storage-client and real-daemon suites
passed on this combined source, including malformed Q2 bands, old-policy rejection,
genuine proof tampering, 5121-row capacity rejection, page-RPC corruption and both
collection failure cases. Four compile-fail contracts, strict native/GUI Clippy,
formatting, requirement mirroring and document links passed. Portable GUI all-target
tests and packaging passed; its two opt-in real-process SQL-script scenarios passed
with the newly packaged peers. The historical Northwind validation above was not
repeated for this recheck.
