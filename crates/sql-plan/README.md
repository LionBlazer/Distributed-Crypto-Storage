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

## Top-level transaction statement plans

`parse_statement` returns `StatementPlan::Query(QueryPlan)` for the same query
grammar, or a distinct `Begin`, `Commit` or `Rollback` plan. It shares the one
private tokenizer, query parser and complete-input check with `parse_sql`.
The existing `parse_sql` remains the query-only API and rejects transaction
commands. Neither entry point changes a session or executes data operations.

The transaction syntax accepts `BEGIN [WORK | TRANSACTION]` or `START TRANSACTION`,
followed by PostgreSQL transaction modes. `TransactionMode` retains each requested
isolation level, read/write mode and deferrability option in its original order.
Commas between modes are optional. Repeated and conflicting items remain in the
list rather than being overwritten; validating their effective semantics and
rejecting unsupported settings belongs to the eventual executor. An empty list
leaves defaults unspecified. In particular, `ReadUncommitted` is preserved as its
own requested level, with no backend-specific normalization.

`COMMIT`/`END` and `ROLLBACK`/`ABORT` accept optional `WORK` or `TRANSACTION` and
`AND [NO] CHAIN`. `TransactionChain::{Unspecified, Chain, NoChain}` distinguishes
omission from both explicit options. Equivalent command aliases and the optional
`WORK`/`TRANSACTION` spelling are normalized; the AST is not a lossless SQL text
codec. No parser inherits settings or starts a chained transaction.

The same 4096-byte whole-input cap and optional single trailing semicolon apply.
Malformed options, multiple statements, comments, SET TRANSACTION and two-phase
transaction commands reject explicitly. Named controls use the shared typed lexer
and the identifier rules below; query identifiers retain their existing subset.
These plans do not implement isolation, transaction execution, lock ownership,
freshness, proof verification or a network SQL acceptance path.

Primary syntax references: [PG18 BEGIN](https://www.postgresql.org/docs/18/sql-begin.html),
[START TRANSACTION](https://www.postgresql.org/docs/18/sql-start-transaction.html),
[COMMIT](https://www.postgresql.org/docs/18/sql-commit.html),
[ROLLBACK](https://www.postgresql.org/docs/18/sql-rollback.html), and the
[REL_18_0 grammar](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/parser/gram.y)
(`TransactionStmt`, `TransactionStmtLegacy`, `transaction_mode_list`,
`opt_transaction_chain`).

Native release validation on 2026-10-20 passed all 35 API cases: the 24 existing
cases and 11 new `tests/statements.rs` cases. The whole test command took 2.374
seconds including compilation and startup. Strict all-target Clippy, the default
core check and workspace format check also passed. The frozen 1,585-file source
receipt has SHA-256
`882FC07B4CC92F6A5F472286BAF29EDF1A3610B2CD26257986B2D5B11D04E2E7`;
the unchanged-source/log after receipt has SHA-256
`69F0AA1ED6A85518561E5BA237DDB6D74FD33B5AD47D327DD035432CED4F1212`.
Only this validation paragraph changed after that batch. The historical parser
validation above keeps its separate source and execution scope.

```powershell
cargo test --release --offline --locked -p sql-plan
cargo clippy --release --offline --locked -p sql-plan --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

These are pure parser/core checks, not SQL execution or distributed-lock tests.


## Named transaction syntax

`parse_statement` also returns distinct `Savepoint { name }`, `Release { name }`
and `RollbackTo { name }` plans for `SAVEPOINT name`, `RELEASE [SAVEPOINT] name`
and `ROLLBACK [WORK | TRANSACTION] TO [SAVEPOINT] name`. `ABORT TO` is not an
alias. Extra clauses, CHAIN on a named command and a second statement reject.
`SavepointName` has a private representation and a borrowed `as_str` accessor.
It supplies no savepoint existence, lock ownership or accepted state.

Names follow PostgreSQL 18's UTF8 `ColId` categories: ordinary identifiers,
unreserved keywords and column-name keywords are allowed; reserved and
function/type-only keywords require double quotes. Unquoted ASCII letters fold
to lowercase. Quoting preserves case and decodes doubled double quotes. Both
forms clip the decoded name to 63 UTF8 bytes without splitting a character;
Unicode normalization and non-ASCII case folding are not performed. This fixes
the usual 63-byte identifier limit, without PostgreSQL build-time customization.
The 4096-byte budget applies to the complete original input before clipping.

`SAVEPOINT` itself is an unreserved name. Thus `RELEASE SAVEPOINT` names
`savepoint`, while `RELEASE SAVEPOINT other` names `other`; ROLLBACK TO has the
same distinction. The pinned grammar has separate alternatives, not a greedy
optional-keyword production. Empty/NUL/unterminated quoted names reject.
Comments, Unicode `U&`/UESCAPE identifiers, strings and dollar quoting remain
unsupported. Backslashes in ordinary double-quoted names are literal.

One private lexer distinguishes words, quoted identifiers, integers and symbols.
Quoted query identifiers remain unsupported and never become keywords, columns,
operators or numeric literals. The query-only `parse_sql` still rejects named
controls. Parsing does not execute transaction/savepoint state changes; duplicate
names, unknown names, failed-transaction rules, rollback/release effects and their
proof/owner/network integration remain separate work. New named-syntax tests in
`tests/savepoints.rs` are source-only and unexecuted in this packet; the 35-case
native evidence above applies to its earlier parser revision.

Primary references: [PG18 SAVEPOINT](https://www.postgresql.org/docs/18/sql-savepoint.html),
[RELEASE](https://www.postgresql.org/docs/18/sql-release-savepoint.html),
[ROLLBACK TO](https://www.postgresql.org/docs/18/sql-rollback-to.html),
[lexical rules](https://www.postgresql.org/docs/18/sql-syntax-lexical.html),
[pinned grammar](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/parser/gram.y)
(`TransactionStmt`, `ColId`, conflict expectation),
[keyword categories](https://github.com/postgres/postgres/blob/REL_18_0/src/include/parser/kwlist.h),
and [UTF8 folding/clipping](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/parser/scansup.c).
