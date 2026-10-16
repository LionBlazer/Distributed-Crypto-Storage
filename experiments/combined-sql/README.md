# Combined SQL, private identities and resource observations

These 2026-10-16 observations measure the combined application at
`5caa85db410111b68e1d3d368300d338bcba9ce9`, including atomic INSERT, readiness
listeners, PostgreSQL text/NULL ordering, bounded owned jobs, parallel typed
projection and encrypted stable row identities. They do not establish complete
PostgreSQL, SQL row locks, production consensus, a general 500-ms bound or a
whole-process resource guarantee.

The [Q2 combined recheck](#q2-page-custody-and-collection-recheck),
[matched static-read comparison](#matched-static-select-read-images) and
[padded UPDATE comparison](#padded-update-writeback-comparison) below pin their
source and artifact identities separately from this original record.
The later [complete LIMIT measurement](LIMIT-MEASUREMENTS.md) covers a million
matching rows with a bounded proved prefix on the combined PostgreSQL/Delta source.
The [authenticated-candidate comparison](CANDIDATE-MEASUREMENTS.md) measures the
subsequent writeback refactor without changing custody, wire or proof checks.
The [shared-packet record](SHARED-PACKETS-MEASUREMENTS.md) retains both ownership
experiments, including the regression, final timings and separate memory observations.
The [static aggregate comparison](AGGREGATE-MEASUREMENTS.md) measures complete
COUNT/SUM over the same million-row source before and after fixed ReadImage preparation.
The [object-profile comparison](CUSTODY-PROFILE-MEASUREMENTS.md) separates corrected
clean timings from the first instrumented window. The subsequent
[static UPDATE comparison](STATIC-UPDATE-MEASUREMENTS.md) records full mutation
latency while retaining complete final custody verification.
The [borrowed-validation comparison](BORROWED-VALIDATION-MEASUREMENTS.md) retains
the following refactor's non-improving timings and its narrower allocation claim.
The [bulk serialization comparison](BULK-SERIALIZATION-MEASUREMENTS.md) measures
byte-identical custody encoding while retaining the original decoder and audits.
The [bounded bulk decoding comparison](BULK-DECODING-MEASUREMENTS.md) measures the
subsequent slice decoder while retaining complete custody and SQL acceptance checks.

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

## Matched static SELECT read images

The before source is `4ff5d30505b78de3a7816ce5d24090fe9def5949`; the after source
is `6c960a63695e0d2ba560cb874b02c8b688bff407`. The latter integrates static
authenticated read images into fixed-schema SELECT, shared canonical index
parsing, and proof/freshness completion boundaries. Both include the earlier Q2,
collection and pagination changes. This compares the complete integrated SELECT
path, not an isolated network microbenchmark.

On the same Windows host, both sources used Rust 1.99.0/MSVC release,
`-C target-cpu=native`, eight owner and eight peer Rayon threads, and the unchanged
AVX-512 proof kernel. Profile v3 still covers all 81,920 residues; application v3,
fixed private index v3 and the FHE/kernel ABI are unchanged. Other builds and proof
jobs were held during both timing windows. No RPC/PID hook or memory monitor ran.
Startup, keys and table creation are outside the SQL timers; complete
`Session::execute` preparation, real peer I/O, genuine proof verification, encrypted
result completion and final freshness checks are inside. Writes include Store,
fsync, agreed publication, confirmation and synchronous collection.

Each of the following unchanged real-daemon fixtures ran three fresh times per
source: `million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`
and `proved_select_insert_update_survive_a_process_loss_and_journal_restart`.
All twelve scenarios and 54 individual SQL timers passed their exact output,
proof, head, durability and recovery assertions. The million-row fixture has one
peer, 999,999 age-7 rows and one age-42 row whose amount changes from 1 to 2 before
SELECT. The small fixture has four initial rows, two shards and two peers, followed
by one inserted row and three updated rows. Its failure read deliberately stops
the first holder; its final empty read follows journal restart.

Each cell below is minimum / median / maximum milliseconds over three samples.

| Initial rows | Complete SQL operation | Before ms | After ms |
| ---: | --- | ---: | ---: |
| 1,000,000 | `SELECT * FROM records WHERE age = 42` | 451.701 / 455.573 / 476.499 | 337.816 / 350.141 / 352.530 |
| 1,000,000 | `UPDATE records SET amount = amount + 1 WHERE age = 42` | 980.912 / 1065.072 / 1093.189 | 1030.326 / 1075.575 / 1085.137 |
| 4 | `SELECT * FROM records` | 198.845 / 200.241 / 203.812 | 199.393 / 199.644 / 208.639 |
| 4 | `SELECT amount, age FROM records WHERE age >= 18 LIMIT 1` | 198.985 / 202.107 / 204.403 | 196.916 / 204.154 / 205.969 |
| 4 | `INSERT INTO records VALUES (21, 255)` | 252.800 / 265.378 / 266.614 | 253.504 / 256.486 / 264.261 |
| 4 | `UPDATE records SET amount = amount + 1 WHERE age >= 18` | 403.527 / 416.530 / 428.871 | 407.338 / 409.023 / 417.837 |
| 4 | `SELECT * FROM records WHERE age >= 18`, after writes | 231.429 / 235.398 / 238.624 | 241.320 / 242.982 / 252.538 |
| 4 | `SELECT amount FROM records WHERE age = 21`, after holder loss | 2319.676 / 2320.025 / 2328.732 | 2311.490 / 2335.784 / 2336.006 |
| 4 | `SELECT age FROM records WHERE age > 255`, after restart | 268.461 / 270.561 / 283.281 | 257.451 / 263.453 / 263.745 |

The million-row SELECT median falls by 105.432 ms, or 23.1%. Its encoded response
shrinks from the full bundle's 37,604,546 bytes to 5,461,664 bytes: all encrypted
data and the fixed 493-page posting prefix, with actual Merkle proofs. The omitted
private row-identity tail is not needed for SELECT. Selection depends only on
committed public geometry; predicates, projections, empty results and LIMIT do not
change that footprint. The server still audits the entire physical bundle and both
snapshots, including the omitted tail. Malformed or missing omitted pages reject.
See the [compact-query boundary](../../crates/compact-query/README.md) and
[privacy contract](../../docs/postgresql-contract.md) for the exact scope.

UPDATE still uses full-image reads and publication and its median remains about
1.08 seconds. The stopped-holder SELECT remains about 2.34 seconds; the current
connection attempt to the unavailable endpoint has a two-second budget. This
comparison does not isolate that phase. Three samples do not establish a tail SLA,
throughput, WAN behavior or a general 500-ms bound. RAM was not remeasured. Adaptive
page access, padded UPDATE deltas, complete PostgreSQL and live locks are not part
of either measured source. The unchanged fixture work target and confirmation
policy do not establish production consensus security.

The ignored raw directories each retain the manifest, six logs, all 27 timers and
copies of the exact owner, peer and kernels:

- `.local/static-read-image-runs/20261016-052408-014-before/`
- `.local/static-read-image-runs/20261016-054415-241-after/`

| Artifact | Before SHA256 | After SHA256 |
| --- | --- | --- |
| Owner/test | `7018BAB56A81177C65BFE13DEE779BD335C03AFA9BD0EC5F19D0A378E4EAD8D1` | `8A4BF94410F4CAB5DACA8BDDCCE46A68954CC6A0FC4058C6B85E847CC456DAC8` |
| Peer `dcs-peer.exe` | `581EADECC4CA1AFC2A255FB90C1FAC8E10FC5722ED98485AA94194FA253A81A2` | `871DC11DFE50D0F9578DBB4562063184ACC6FEDA7C4897B646F5FDFB2ABEAABE` |

Both kernel hashes are the unchanged values in the first artifact table. The
before owner is `proved_sql-43b267abd6ab93e6.exe`; the after owner is
`proved_sql-b77c1dcb3169d113.exe`. Reproduce by building each pinned source with the
native configuration above, then running these two exact fixture names three times
with `--exact --nocapture --test-threads=1` and both thread variables set to 8.
The test executable embeds its build-time `CARGO_BIN_EXE_dcs-peer` path; copying it
alone does not redirect peer lookup. At execution that path must contain the
matching preserved or freshly built peer and kernels. Do not run a before owner
against the after peer or build during timing.

On the after source, the native owning suites passed 146 behavioral tests and one
compile-fail contract. Strict native Clippy and formatting passed. Portable GUI
all-target tests passed 193 tests with 10 opt-in tests ignored; architecture,
requirement mirroring and strict Clippy passed. Fresh packaging and both opt-in
real-process SQL-script scenarios passed separately. These checks cover actual
read-image frame bounds, source/head rebinding, malformed omitted pages, genuine
proof rejection, cancellation before RPC and after proof, and mandatory final
freshness. The historical Northwind scenario and memory observation were not rerun
in this matched comparison.

## Padded UPDATE writeback comparison

Source `0b92c939ddd913b4cb5b1edb243eea1ff84a4b02` adds
[padded verified replacement uploads](../../docs/padded-update-delta.md) to the
static-read source `6c960a63695e0d2ba560cb874b02c8b688bff407`. Existing holders
receive a geometry-fixed delta only when it is smaller than Full Store; new
replicas retain their preplanned Full Store role. The million-row complete request
falls from 37,604,542 to 1,188,143 bytes. A four-row image still chooses Full Store.
The base and reconstructed target are fully audited, quota charges the full new
object, and ordinary fsync, publication, confirmation and collection remain.
This wire reduction does **not** establish a latency improvement.

The same two real-daemon fixture functions, assertions and timed operation
boundaries as the static-read comparison were unchanged. Owner and peers used
eight Rayon threads, native Rust 1.99.0/MSVC release and the exact preserved
AVX2/AVX-512 libraries identified above. Application v3, proof profile v3, all
81,920 residues and kernel ABI are unchanged. All agents finished heavy commands
before timing and held further builds/proof jobs. No RPC/PID/memory hook ran.
Each fixture ran three fresh times, producing these 27 accepted SQL timers:

| Initial rows | Complete SQL operation | Minimum ms | Median ms | Maximum ms |
| ---: | --- | ---: | ---: | ---: |
| 1,000,000 | `UPDATE records SET amount = amount + 1 WHERE age = 42` | 1127.306 | 1141.710 | 1157.888 |
| 1,000,000 | `SELECT * FROM records WHERE age = 42` | 354.410 | 354.861 | 356.922 |
| 4 | `SELECT * FROM records` | 196.267 | 199.427 | 202.411 |
| 4 | `SELECT amount, age FROM records WHERE age >= 18 LIMIT 1` | 198.463 | 198.764 | 205.678 |
| 4 | `INSERT INTO records VALUES (21, 255)` | 249.274 | 314.714 | 317.884 |
| 4 | `UPDATE records SET amount = amount + 1 WHERE age >= 18` | 412.225 | 444.273 | 452.387 |
| 4 | `SELECT * FROM records WHERE age >= 18`, after writes | 235.812 | 241.874 | 245.794 |
| 4 | `SELECT amount FROM records WHERE age = 21`, after holder loss | 2317.041 | 2322.797 | 2326.987 |
| 4 | `SELECT age FROM records WHERE age > 255`, after restart | 255.762 | 262.333 | 271.130 |

The million-row UPDATE median exceeds the earlier source's 1075.575 ms. To check
this concern against adjacent runs, one additional window alternated before then
after for each of three fresh million-row pairs. Both variants used their exact
preserved owner and matching baked peer, with the same preserved kernels. No build
or other heavy job resumed between these six scenarios. All twelve additional
timers passed the same exact result/proof/head assertions; neither series was
discarded. Cells show minimum / median / maximum milliseconds:

| Complete SQL operation | Before, `6c960a6` | After, `0b92c93` |
| --- | ---: | ---: |
| `UPDATE records SET amount = amount + 1 WHERE age = 42` | 1126.187 / 1139.967 / 1156.295 | 1159.141 / 1164.171 / 1167.407 |
| `SELECT * FROM records WHERE age = 42` | 340.532 / 346.132 / 350.482 | 353.436 / 372.698 / 403.649 |

The adjacent UPDATE median increases by 24.204 ms, or 2.1%; the new path did not
improve complete-operation latency on this loopback fixture. The later baseline
also differs from the earlier window, and SELECT has visible spread. Three samples
cannot isolate causation or establish a tail SLA. Delta adds a full base audit and
reconstruction while retaining target validation; phase costs were not measured
here. A smaller upload must not be presented as a measured WAN speedup. UPDATE
still exceeds 500 ms, as does the stopped-holder read. RAM and throughput were not
remeasured. Complete PostgreSQL, transactions and live row locks remain incomplete.

Ignored raw records, exact artifact copies and manifests are retained in:

- `.local/padded-delta-runs/20261016-060812-435-after/` (six logs, 27 timers).
- `.local/padded-delta-runs/20261016-061001-083-adjacent-pairs/` (six logs, 12 timers).

| After artifact | SHA256 |
| --- | --- |
| Owner/test `proved_sql-b77c1dcb3169d113.exe` | `613F570290C5515EE979091247E0CB773E50FAE81489C95C8A53A55F753AE127` |
| Peer `dcs-peer.exe` | `60F4529B2B5BAF4870A6E3D32F31CADB6D2F5DD4FC8548AC8A1CF4626974ABCB` |

Before owner/peer hashes are `8A4BF944...456DAC8` / `871DC11D...ABEAABE`, with full
hashes and preserved files in the static-read table above. Both variants used the
same full kernel hashes in the original artifact table. The after test executable
embeds `.local/target-padded-update-delta/release/dcs-peer.exe`; the before embeds
`.local/target-bfv-query-proof-native/release/dcs-peer.exe`. Reproduce using the
earlier native configuration and two exact fixture names. A copied owner still
launches its baked peer path: install matching preserved files there outside the
timer. For the adjacent window, the unused before path's original peer and kernels
were backed up, restored in `finally` and hash-checked after all pairs. Never mix
source variants or overwrite another running consumer's artifacts.

The combined source passed 159 native behavioral tests and one compile-fail
contract, strict native Clippy and formatting. Portable GUI passed 193 tests with
10 opt-in tests ignored, strict Clippy, architecture and requirements mirroring;
both opt-in real-process SQL-script scenarios passed separately. After freezing
the native artifacts, the million-row, small mutation/failover and Q2 aggregate
fixtures also passed with the exact preserved SIMD libraries used for timing.
Independent source review covered full-root reconstruction, malformed padding,
corrupt overwritten/omitted base pages, duplicate replay after restart/base GC,
TLS upload authority, lost ACK and preplanned recipient roles. The alias regression
rejects distinct routing IDs for one TLS identity or socket before proof/upload;
the quota regression rejects same-holder Full fallback without advancing state.
Requirements and production-finality limitations are unchanged.
