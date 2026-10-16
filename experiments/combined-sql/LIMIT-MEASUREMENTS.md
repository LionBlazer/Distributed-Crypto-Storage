# Complete LIMIT on one million matching rows

Source `97bba1cf15ea0cd1d7e645fa21142ea0a95d886f` combines exact PostgreSQL
identifier/catalog binding, typed index v3, static fixed-schema ReadImage, padded
UPDATE writeback and complete bounded LIMIT selection. This record measures the
last feature through real owner/client and peer processes. It is a newly supported
workload: earlier sources rejected the million-row matching set before applying
LIMIT, so there is no accepted before latency or percentage speedup estimate.

## Operation and conditions

The public synthetic fixture has one million rows on one actual peer, alternating
ages 42 and 18, with amount `ordinal % 65536`. Every row matches `age >= 18`.
The first query must return exactly amounts 0 through 99 in original order; the
second returns no rows. All three fresh scenarios checked these exact results,
genuine full-residue proof acceptance, unchanged confirmed version, one actual
ReadImage and one proof per successful query. They also checked identical source
request/response byte counts for both queries, no whole-bundle/adaptive-page fallback,
and explicit pre-proof rejection of the unbounded and LIMIT257 cases.

The Windows x64 host is the same AMD host as the [combined record](README.md).
Rust 1.99.0/MSVC release used `-C target-cpu=native`, with eight Rayon threads in
the owner and peer. The actual peer reported AVX-512. FHE/STARK profile v3, all
81,920 residues, application v3 and kernel ABI are unchanged. All agents had
finished their heavy commands before timing; no build or proof job ran alongside
the samples. RPC/PID environment hooks and memory monitoring were disabled.
The fixture's bounded metadata-only frame recorder remained enabled and its
callback cost is included. It records actual completed I/O, never payloads or keys.

Timers wrap the complete `Session::execute`: preparation, all matching-posting and
candidate-age validation, actual peer RPC, FHE projection, genuine proof checking,
final journal freshness and result completion. Startup, keys, table creation and
post-query fixture assertions are outside. No candidate validation stops at LIMIT,
including LIMIT0. A zeroizing bitmap is bounded at 125,000 bytes per million-row
shard; one decrypted data page is retained at a time. Returned cells come only from
the checked encrypted result. The [owning API](../../crates/compact-query/README.md)
and [client boundary](../../crates/storage-client/README.md) describe the contract.

| Complete SQL operation | Minimum ms | Median ms | Maximum ms |
| --- | ---: | ---: | ---: |
| `SELECT amount FROM records WHERE age >= 18 LIMIT 100` | 375.218 | 379.181 | 384.812 |
| `SELECT age, amount FROM records WHERE age >= 18 LIMIT 0` | 372.198 | 373.234 | 388.556 |

These six full-operation samples meet 500 ms for these exact queries and fixture.
Three samples do not establish tail latency, throughput, WAN behavior or a general
SQL bound. Source validation remains O(matches), plus bitmap traversal; this is
not early-stop index retrieval. The retained per-shard prefix must fit 256 FHE
slots. Larger results, ordered expressions and general streaming require further
work. UPDATE and the stopped-holder read in the combined record still exceed
500 ms. RAM was not measured in this window.

The current owner-online source/index conversion and confirmed-known-head model
remain as documented in the [PostgreSQL contract](../../docs/postgresql-contract.md).
Arithmetic proof timing does not establish the missing public source/completeness
relation or production finality. Complete PostgreSQL and live row locks remain open.

## Reproduction and verification

Ignored `.local/complete-limit-runs/20261016-063436-278/` contains three logs, all
six timers, the manifest and exact owner/peer/kernel copies. SHA256 identities:

| Artifact | SHA256 |
| --- | --- |
| Owner/test `proved_sql-b77c1dcb3169d113.exe` | `3D6C85EC774879446CF47E54A053255B98A25467E7648B688AC9128829E5B8A8` |
| Peer `dcs-peer.exe` | `CAC96AB37DE9669CABFFE5EF7862C36DD3247993D9666FECA91CFA2C2FB67073` |
| AVX2 kernel | `EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C` |
| AVX-512 kernel | `6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975` |

Build the pinned source outside timing. Run
`million_matching_rows_with_explicit_limit_use_real_proofs_and_the_same_static_source_frames`
three fresh times through the compiled test executable with `--exact --nocapture
--test-threads=1`, `RAYON_NUM_THREADS=8` and `DCS_TEST_PEER_THREADS=8`.
Clear `DCS_TEST_RPC_PROFILE`, `DCS_TEST_TYPED_PIDS` and `DCS_TEST_FIXED_PIDS`.
The owner embeds `.local/target-bfv-query-proof-native/release/dcs-peer.exe` as its
peer path; a copied owner still launches that path. Install the matching peer and
kernels there outside the timer and preserve other consumers' artifacts.

The combined integration passed 166 native behavioral tests, one compile-fail
contract and strict native Clippy. Portable GUI passed 194 tests, with 10 opt-in
tests ignored, plus strict Clippy, architecture and requirement mirroring. Fresh
packaging, both real-process SQL-script scenarios and the opt-in complete Northwind
scenario passed separately. Northwind preserved 13 tables and 3,308 rows and returned
all 2,155 order-detail rows through 14 genuine proofs. That functional run used two
owner threads outside a controlled latency window and took about 4.06 s for the final query;
it is not another controlled timing estimate or a 500-ms result. Types, launcher,
formatting, document links and requirements consistency also passed.
