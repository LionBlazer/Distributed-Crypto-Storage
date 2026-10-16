# Relational types

Owner-side typed schemas, lossless table-dump import, canonical row encoding and
schema-bound SELECT planning. The library has no peer evaluator, secret keys,
network transport or GUI dependency;
consumers supply encryption, indexing, proofs and version agreement.
Serde is the runtime dependency; Serde JSON is used by contract tests.

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

Canonical catalog strings are exact object names: `foo` and `Foo`, or columns
`id` and `ID`, may coexist. `TableSchema::column_index`, `ImportedDatabase::table`
and generic catalog/FK validation compare these names exactly. The SQL Server
source adapter separately checks ASCII-case-insensitive uniqueness and binds its
source column/FK references. FK metadata records resolved exact target names;
actual table/column names are never folded or renamed.

`TableSchema::checks` contains explicit `CheckConstraint` variants with a flat
`{dialect, source}` representation. `PostgreSql18Utf8` uses PostgreSQL name binding;
`SqlServerDumpAsciiCi` preserves the source adapter's declared name rules. An
unknown/missing language or the former string representation rejects, without
fallback. Import retains the original CHECK source span, including identifier
quoting, comments and literal spellings. One private bounded predicate parser binds
temporary column indices under the declared policy; no bound AST is serialized.
GETDATE is an import-only operand resolved once per validation, without rewriting
the source expression. These are the existing supported typed predicate grammar
and comparisons, not complete PostgreSQL/SQL Server expression engines.

Live SELECT uses PostgreSQL 18 UTF-8 identifier rules: unquoted ASCII letters fold
to lowercase, quoted names stay exact, doubled double quotes escape a quote, and
identifier tokens clip to 63 decoded bytes at a UTF-8 boundary. High-bit UTF-8 bytes
are not Unicode-case-folded or normalized. Empty/NUL names, SQL Server brackets and
unimplemented U&/UESCAPE identifiers reject. The current flat catalog occupies only
`public`; qualified `dbo` and other live namespaces reject. An alias hides the
original qualifier and is bound by the same exact rules. Initial names/aliases use
PG ColId categories; dotted components use ColLabel, including reserved words.
`validate_postgresql_catalog` rejects source metadata names longer than 63 bytes
before live key creation or I/O instead of silently renaming imported objects.
Lossless source import may still retain such names for owner inspection.

Private `names` owns these binding/admission rules, `predicate` owns shared typed
expression construction, and `pg_keywords` owns only fixed keyword classification.
Its 494 entries and [public upstream fixture](tests/fixtures/pg18-kwlist.h) come
from PostgreSQL 18.0 commit `3d6a828938a5fa0444275d3d2f67b64ec3199eb7`;
source SHA256 is `fdcdf3694513cba63b4016f63032472b686e381bb35f17c5d645bc2f6f1dac16`.
Offline parity tests compare every entry/category, plus actual lexical/binding
examples. The full [PostgreSQL permission notice](POSTGRESQL-LICENSE) accompanies
the derived classifications and packaged applications; no PostgreSQL parser is
vendored. Relevant primary contracts are [identifier syntax](https://www.postgresql.org/docs/18/sql-syntax-lexical.html)
and the pinned [scanner support](https://raw.githubusercontent.com/postgres/postgres/3d6a828938a5fa0444275d3d2f67b64ec3199eb7/src/backend/parser/scansup.c).

`plan_select_schemas` and `plan_select` bind single-table projections, comparisons,
AND/OR/NOT, IN, BETWEEN, IS NULL and ORDER BY to actual column indices.
ORDER BY resolves PostgreSQL's default NULL placement (ASC NULLS LAST and DESC
NULLS FIRST) and explicit NULLS FIRST/LAST separately for every ordering column.
`SelectPlan::window` describes pagination after filtering and ordering: OFFSET,
LIMIT (including ALL/NULL) and FETCH FIRST/NEXT ... ROW/ROWS ONLY or WITH TIES.
OFFSET and LIMIT/FETCH may appear in either order; a NULL offset is zero and an
omitted FETCH count is one. WITH TIES requires ORDER BY, extends the last selected
row's complete ordering-key peer group and never restores skipped rows. Row counts
are nonnegative SQL bigint literals fitting the host's usize; arbitrary expressions
and parameters are not implemented. Parenthesized literals are accepted. Existing
SQL Server TOP input remains a limit spelling and cannot combine with LIMIT/FETCH.
They produce an AST, never an answer. Joins, aggregates, stored programs, row locks
and mutation plans are rejected here until their separate execution/proof paths
exist. `compare_values` uses case-sensitive Unicode ordinal text ordering, preserving
spaces. `compare_typed_values` applies the declared column type: variable
VARCHAR/NVARCHAR/text preserves trailing spaces, while fixed CHAR/NCHAR ignores
trailing U+0020. Complete-index sorting, predicates and import key/CHECK validation
use that same distinction. There is no implicit server-default collation or locale.
These are comparison rules; imported variable spaces and existing fixed-field
padding remain in the encoded values.
Text comparison literals keep their own length and bytes instead of inheriting
the column's storage width or padding; import/storage validation still enforces
declared widths. Numeric coercions and general SQL casts remain separate work.

`encode_row_with_ranges` returns canonical bytes and the original byte range of
each field, so a consumer can construct homomorphic projection masks without
precomputing query answers. `encode_value`, `decode_value` and `decode_row` retain
type distinctions and reject malformed/trailing encodings. These codecs are not
encryption or proof systems.

Planning rejects SQL over 64 KiB, predicates over 128 nodes, and comments or
parentheses deeper than 128 levels. The codec bounds each field to 8 MiB and each
encoded row to 16 MiB. Schema validation runs even for empty tables and rejects
invalid widths, precision, ranges and constraint indices before data access.
Redundant later ORDER BY columns are validated and eliminated: they cannot break
ties on the same earlier column. Executor sort keys therefore never exceed the
validated schema's column count, regardless of repeated SQL syntax.

Run hermetic examples with `cargo test --release -p relational-types`. The opt-in
official Northwind test reads `DCS_NORTHWIND_SQL` and verifies all 13 base tables
and 3,308 rows, including binary photos and declared constraints. Download the
public Microsoft script yourself; no database dump is vendored in this crate:

```powershell
$env:DCS_NORTHWIND_SQL = '<path to downloaded instnwnd.sql>'
cargo test --release -p relational-types official_northwind -- --ignored
```
