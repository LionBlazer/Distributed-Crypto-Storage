# Relational types

Owner-side typed schemas, lossless table-dump import, canonical row encoding and
schema-bound SELECT planning. The library has no peer evaluator, secret keys,
network transport or GUI dependency. Its direct dependencies are Serde and Serde JSON;
consumers supply encryption, indexing, proofs and version agreement.

`import_database_dump(sql, ImportLimits)` reads SQL Server base-table dumps into
`ImportedDatabase`. It preserves every base table, column and row, including NULL,
Unicode text, signed integers, exact decimals/money, IEEE real values, timestamps
and binary images. Limits are explicit byte/row/table resource budgets; there is no
128-row limit. `validate_database` also validates manually constructed owner input.
Declared primary, unique, foreign and CHECK constraints are checked against the
complete imported data, including references to tables declared later.

SQL Server `GO`, session formatting, explicit identity values, filegroup placement,
conditional installation cleanup and temporarily disabled checks are interpreted
as dump-format directives, with notices in the catalogue. Nothing in the dump is
executed as an administrative command. Views and stored procedures are preserved
as source catalogue objects; they do not become executable query plans. CHECK
expressions use the supported typed predicate grammar; `GETDATE()` is resolved on
the owner at import validation. Unsupported statements and expressions fail the
import before publication instead of silently dropping data or constraints.

`plan_select_schemas` and `plan_select` bind single-table projections, comparisons,
AND/OR/NOT, IN, BETWEEN, IS NULL, ORDER BY and TOP/LIMIT to actual column indices.
ORDER BY resolves PostgreSQL's default NULL placement (ASC NULLS LAST and DESC
NULLS FIRST) and explicit NULLS FIRST/LAST separately for every ordering column.
They produce an AST, never an answer. Joins, aggregates, stored programs, row locks
and mutation plans are rejected here until their separate execution/proof paths
exist. Text comparisons use case-sensitive Unicode ordinal ordering and ignore
trailing spaces; they do not assume SQL Server's unspecified server collation.

`encode_row_with_ranges` returns canonical bytes and the original byte range of
each field, so a consumer can construct homomorphic projection masks without
precomputing query answers. `encode_value`, `decode_value` and `decode_row` retain
type distinctions and reject malformed/trailing encodings. These codecs are not
encryption or proof systems.

Planning rejects SQL over 64 KiB, predicates over 128 nodes, and comments or
parentheses deeper than 128 levels. The codec bounds each field to 8 MiB and each
encoded row to 16 MiB. Schema validation runs even for empty tables and rejects
invalid widths, precision, ranges and constraint indices before data access.

Run hermetic examples with `cargo test --release -p relational-types`. The opt-in
official Northwind test reads `DCS_NORTHWIND_SQL` and verifies all 13 base tables
and 3,308 rows, including binary photos and declared constraints. Download the
public Microsoft script yourself; no database dump is vendored in this crate:

```powershell
$env:DCS_NORTHWIND_SQL = '<path to downloaded instnwnd.sql>'
cargo test --release -p relational-types official_northwind -- --ignored
```
