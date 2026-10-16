# SQL plan

Backend-independent parsing and typed plans for the supported `records(age: u8,
amount: u16)` schema. This is an implemented SQL subset, not a general SQL engine.
It has no project or third-party dependencies.

`parse_sql` consumes the entire statement and returns `QueryPlan` or `Error`.
Plans cover SELECT projections, COUNT/SUM, typed INSERT tuple lists and additive
UPDATE. Each `QueryPlan::Insert { rows }` owns the nonempty literal batch from one
statement, preserving tuple order. `Predicate::age_range` normalizes public
conditions without reading stored rows. `RowValues` represents statement input
supplied by the client. No plan executes SQL, decrypts data or validates a
computation proof.

The parser limits each complete statement to 4096 bytes, rejects malformed later
tuples and unsupported clauses, and preserves projection order. LIMIT must fit
`usize`; batch capacity, storage, selection and FHE budgets belong to the executor
rather than a GUI row cap.

The [playground](../../playground/README.md) is one consumer. Encrypted execution
uses [compact-query](../compact-query/README.md) through the application's explicit
adapter; this library has no dependency on that backend.

Run `cargo test --release --locked -p sql-plan` from the repository root.
