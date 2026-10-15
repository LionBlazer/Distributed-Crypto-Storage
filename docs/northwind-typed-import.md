# Typed Northwind import and proved SELECT

The official [Microsoft Northwind script](https://github.com/microsoft/sql-server-samples/tree/master/samples/databases/northwind-pubs)
was downloaded on demand from `instnwnd.sql`, not bundled in the repository.
The checked UTF-8 file is 1,049,720 bytes, SHA-256
`3cc62b3fca6d244a47dbde698b809331e4f85988a0685b2b370717d431e94871`.

The complete imported catalog contains:

| Table | Rows |
| --- | ---: |
| Employees | 9 |
| Categories | 8 |
| Customers | 91 |
| Shippers | 3 |
| Suppliers | 29 |
| Orders | 830 |
| Products | 77 |
| Order Details | 2,155 |
| CustomerCustomerDemo | 0 |
| CustomerDemographics | 0 |
| Region | 4 |
| Territories | 53 |
| EmployeeTerritories | 49 |

All 13 base tables and 3,308 rows are retained. Primary/unique/foreign/CHECK
constraints are validated on owner input before any peer state is written.
Views and procedures remain authenticated catalog source metadata; they are not
implemented executable views/programs. Installation/session directives are parsed
as import-format metadata and never executed by the host. Text comparison uses the
documented ordinal policy, not an assumed SQL Server default collation.

## Security path

`relational-types` owns schema/import/plans and no network or peer evaluation.
`storage-client::relational::RelationalSession` stores each bounded relation and
its complete private per-column postings as compact AEAD pages on actual peers.
It retains keys and trusted schema/heads, not an imported plaintext answer cache.
Owner-private index lookup determines complete candidate ordinals; source pages
are authenticated against exact agreed heads. Every original cell of those rows
is BFV encrypted before the peer homomorphically zeroes unprojected columns.

Each streamed block requires the existing genuine full-residue public-polynomial
STARK. The pending request binds schema, salted SQL identity, table, complete
selection, projection, queried confirmed head and exact block position/count.
Proof verification precedes output decryption. Empty selections also receive real
encrypted arithmetic evidence. Initial and final work-journal checks reject stale
or changed state. The returned version is exactly the head used for preparation.

This retains the explicit owner-online indexed model. Private index authentication
is separate from public FHE arithmetic evidence; no independently public SQL/AEAD
link proof is claimed. Table/page accesses, selected sizes, mask/cell-length
patterns and timing remain observable. No ORAM or concealed-index promise is added.
The local work profile is deliberately easy and does not establish a production
adversarial work budget or independent failure domains.

Imported catalogs are currently immutable. Generic mutation transitions, joins,
aggregates, transactions and stored programs reject until their own execution and
proof contracts exist. The earlier two-column writable Session remains isolated.
The new path has explicit 8 MiB per-table encoded data/index budgets, network table
admission, one million result cells and 32 MiB projected output. The 8,191-byte FHE
block capacity is independent of row count; neither import nor SELECT truncates at
128 rows. An explicit TOP/LIMIT retains its ordinary query meaning.

## Reproduction and observed performance

Build the real daemon, download the public script outside version control, then:

```powershell
$env:DCS_PEER_BIN = '<absolute path to dcs-peer.exe>'
$env:DCS_NORTHWIND_SQL = '<absolute path to instnwnd.sql>'
$env:RAYON_NUM_THREADS = '2'
cargo test --release --locked -p fhe-playground --bin fhe-playground official_northwind_import_and_typed_select_use_independent_peer_processes -- --ignored --test-threads=1 --nocapture
```

One local Windows run on 2026-10-16 with Rust 1.99, two Rayon threads and the
portable compiled proof engine measured:

| Complete operation | Elapsed | Evidence/result |
| --- | ---: | --- |
| Encrypt, store/replicate and confirm the complete import | 1.641 s | 13 tables / 3,308 rows / three distinct child PIDs |
| Customers in Germany, two-column projection/order | 2.243 s | 11 exact rows / 1 proved block |
| Full SELECT from Order Details | 29.203 s | 2,155 exact rows / 14 proved blocks |

The test compares the full Order Details result against the independently parsed
public input, checks known German customers and a decimal-price Product query,
asserts distinct peer processes, and rejects a typed UPDATE. These are single-run
functional timings, not latency distributions, resource guarantees or 50–100 ms
results. Memory and storage expansion for this typed path have not been measured.
No source, ciphertext, keys or generated measurement outputs are committed.

The same test was also run with the normally packaged peer and proof kernels.
Both client verification and peers selected AVX-512 once at startup, using the
same cryptographic parameters and wire proofs. This run measured 2.048 s for the
complete import, 935 ms for the German-customer query and 12.711 s for all 2,155
order details (the same 14 proof blocks). Acceleration helps, but the complete
operation remains well above the 50–100 ms target. To select the same trusted
installation for this opt-in test, set `DCS_TEST_PROOF_KERNEL_DIR` to the absolute
packaged `proof-kernels` directory and point `DCS_PEER_BIN` at its sibling peer.

Hermetic tests additionally cover 300 rows across multiple genuine proof blocks,
two tables, Unicode/text/decimal/binary values, SQL three-valued NULL logic,
replica corruption/failover, missing evidence, request/output tampering,
read-as-mutation rejection and malformed owner input before any RPC. The graph
and importer UI are checked headlessly; these tests never open a native window.
