# SQL plan

Backend-independent parsing and typed plans for the supported `records(age: u8,
amount: u16)` schema. This is an implemented SQL subset, not a general SQL engine.
It has no project or third-party dependencies.

`parse_sql` consumes the entire statement and returns `QueryPlan` or `Error`.
Plans cover SELECT projections, COUNT/SUM, typed INSERT tuple lists and additive
UPDATE. Each `QueryPlan::Insert { rows }` owns the nonempty literal batch from one
statement, preserving tuple order. Opaque `Predicate::age_mask` returns the final
SQL TRUE set over nonnullable age values: bit `age % 8` of byte `age / 8`. The
canonical 32-byte value is an owner-side compilation boundary, not a peer request
or a query answer. `RowValues` represents statement input supplied by the client. No plan executes SQL, decrypts data or validates a
computation proof.

The parser limits each complete statement to 4096 bytes, rejects malformed later
tuples and unsupported clauses, and preserves projection order. Fixed row SELECT
accepts LIMIT integer/ALL/NULL and OFFSET integer/NULL in either order, once each.
ALL or a NULL limit means unbounded; a NULL offset means zero. Integer literals
may have a sign, must be nonnegative and fit both i64 and usize; arithmetic
expressions, FETCH and aggregate pagination remain unsupported.

`QueryPlan::Select::window` is an owner-side `RowWindow { offset, limit }`, with
no serialized peer representation. `prefix_limit` returns checked OFFSET + LIMIT
for shard preparation, or zero for LIMIT0 regardless of OFFSET. Unbounded windows
still require the executor's complete matching set. Storage, selection and FHE
budgets belong to that executor rather than a GUI row cap; a small final window
does not make an oversized prefix admissible.

The [playground](../../playground/README.md) is one consumer. Encrypted execution
uses [compact-query](../compact-query/README.md) through the application's explicit
adapter; this library has no dependency on that backend.

Run `cargo test --release --locked -p sql-plan` from the repository root.

WHERE supports AND/OR/NOT, parentheses, age comparisons (=, <>, !=, <, <=, >, >=),
[NOT] BETWEEN, [NOT] IN, age IS [NOT] NULL, and boolean TRUE/FALSE/NULL atoms.
The private compiler retains both TRUE and FALSE sets until WHERE completion;
UNKNOWN belongs to neither. NOT swaps those sets; BETWEEN and IN compose ordinary
three-valued comparisons. For example, `NOT(age BETWEEN NULL AND 10)` selects ages
above 10, while `age NOT IN(7,NULL)` selects none. The fixed age column itself is
not nullable. The planning budget is 128 expression/operator/list elements, also
bounding nested NOT and parentheses, within the existing statement-byte limit.

Comparison bounds accept signed i64 (including its minimum) and may lie outside
0..=255; comparison uses their mathematical value without narrowing. Larger
integer literals reject explicitly; this is not PostgreSQL's general numeric
coercion/type system. INSERT ages/amounts and UPDATE deltas retain their u8/u16
storage bounds. Unsupported expressions, columns and clauses reject as a whole.

The [fixed-record pagination validation](../../docs/fixed-select-pagination.md)
records the implemented row window, actual proof tests and remaining boundaries.

## Typed row-locking SELECT plans

A single `FOR UPDATE`, `FOR NO KEY UPDATE`, `FOR SHARE` or `FOR KEY SHARE`
produces the distinct `QueryPlan::LockingSelect` variant, never an ordinary
SELECT. `LockingClause` retains its `LockStrength` and `LockWait`: omitted option
means Wait; NOWAIT and SKIP LOCKED are explicit alternatives. Predicate truth,
ordered projection and the original row window remain in the plan. No parser
chooses an actor, key, table identity, control root or agreed version.

The locking clause can precede or follow the entire LIMIT/OFFSET group. Splitting
that group, duplicate options/clauses, OF lists, joins, aggregates, ORDER BY, FETCH
and literal WAIT remain whole-statement errors in this fixed-record stage.
PostgreSQL itself supports a broader grammar; this is not full PostgreSQL support.
Sources: [PG18 SELECT locking](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE)
and its [pinned grammar](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/parser/gram.y)
(`select_no_parens`, `for_locking_item`, `select_limit`).

The [private locking experiment](../../experiments/hiding-fri-sha256-gate/src/opening/locking/README.md)
consumes actual compiled plans when constructing independently expected C_plan.
Storage-client Session/scripts and the historical lab reject locking plans before
query I/O. Parsing is not a lock grant, transaction, computation proof or authorization.
The [SQL locking-plan validation](../../experiments/hiding-fri-sha256-gate/SQL-LOCK-PLANS-VALIDATION.md)
records 24 parser PASS cases, six focused experimental cases and both parsed-query
CLI gates. All 195 names were discovered; the old 189 were not rerun. Parsing still
confers no live grant or source/control authority.
