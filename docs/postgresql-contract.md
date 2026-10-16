# PostgreSQL implementation contract and open work

The user selected PostgreSQL semantics on 2026-10-16 and requested complete SQL,
including `FOR UPDATE` and `SKIP LOCKED`, with ordinary queries at most 500 ms.
[REQUIREMENTS.md](../REQUIREMENTS.md) remains the unchanged implementation contract.
This document records design work and blockers, not implemented SQL support.
The [combined measurements](../experiments/combined-sql/README.md) include actual
small fixed queries, typed 300-row projection, million-row point operations and a
separate whole-lifecycle resource observation. Million-row UPDATE and the measured
2,155-row typed output still exceed 500 ms.
The [measured network path](proved-sql-network.md) identifies the current workloads,
CPU budgets, proof boundary and remaining latency failures. A representative
larger workload and tail-latency contract remain to be established.

## Current execution boundary

The fixed-schema `storage-client::Session` accepts genuine proved row SELECT,
COUNT/SUM, atomic literal INSERT batches and additive amount UPDATE. INSERT admits
1..=256 incoming rows and a maximum 256-row completed relation per target shard.
One statement prepares every target proof and compact image before any Store or
authorization, then publishes one signed transition and retains one retry identity.
It preflights shard capacity and immutable protocol frame/update budgets; this
statement atomicity does not provide general transactions. Aggregates perform an
encrypted coefficient convolution under the existing full-residue product proof,
with checked client-side limb/shard completion and SQL NULL for empty SUM.
They currently admit at most 2560 matching rows per shard using ten 256-row bands
and the unchanged 256-term public kernel; row and mutation limits remain 256.
Excess rejects without a partial result. Q2/R2 requires application domain v3 and
rejects old journals/wires without migration; the arithmetic profile is unchanged.
The [Q2 process record](proved-aggregate-bands.md) reports 5119/5120-row full-query
samples; general typed aggregation remains open. Typed imported catalogs provide
immutable single-table SELECT with authenticated owner-private indices and proved
BFV byte projection. Unsupported operators reject before execution. Neither path
implements general transactions, DELETE, JOIN or SQL row locks.
Parsing syntax or preserving imported stored programs does not execute them.
Typed SELECT ordering follows PostgreSQL's ASC NULLS LAST / DESC NULLS FIRST
defaults and explicit NULLS FIRST/LAST per key, before applying LIMIT. See
[sorting rows](https://www.postgresql.org/docs/18/queries-order.html).
Typed SELECT also implements OFFSET and LIMIT ALL/NULL, plus FETCH FIRST/NEXT
... ROW/ROWS ONLY or WITH TIES using nonnegative bigint literal counts.
Pagination applies after complete authenticated filtering/ordering. WITH TIES
extends the last selected row's complete ordering-key peer group, including NULLs;
it requires ORDER BY and never restores rows removed by OFFSET. Empty windows
still require a genuine encrypted-result proof and final freshness check. General
count expressions/parameters and live locks remain unsupported. See the
[LIMIT/FETCH contract](https://www.postgresql.org/docs/18/sql-select.html#SQL-LIMIT).

Typed comparison preserves trailing spaces for variable VARCHAR/NVARCHAR/text and
ignores only trailing U+0020 for fixed CHAR/NCHAR. Predicates, ordering before LIMIT,
and imported unique/foreign/CHECK validation use the column's comparison rules.
Projection preserves the imported encoded field bytes, including existing fixed
padding. This change does not implement type casts or locale collations. See
[character types](https://www.postgresql.org/docs/18/datatype-character.html).
Text predicate literals retain their own bytes and may exceed the column's storage
width; comparison does not store or truncate them. Import field-width validation
remains mandatory. General numeric coercions and SQL casts remain unimplemented.
The typed encrypted private-index format/schema is version 2; an older comparator
ordering is rejected instead of being searched with incompatible partition rules.

Other inherited SQL Server adapter semantics still differ from PostgreSQL. Typed
imported queries currently lose quoted-identifier case and bind identifiers without
case sensitivity; PostgreSQL preserves quoted names and folds unquoted names to
lowercase. See [identifier rules](https://www.postgresql.org/docs/18/sql-syntax-lexical.html).
The fixed UPDATE outcome reports `affected_rows`, including matched rows whose values
remain unchanged, as required by PostgreSQL's command tag. Zero-delta and empty
selections still complete real peer arithmetic proofs and fresh-version checks;
unchanged compact images need no new data transition. This implements the count
for the supported additive operation, without triggers or live SQL locks. See
[UPDATE output](https://www.postgresql.org/docs/18/sql-update.html#SQL-UPDATE-OUTPUTS).
These existing boundaries do not establish full PostgreSQL compatibility.

Current public proofs attest full BFV addition and public-polynomial products.
Private AEAD/index-to-FHE preparation remains the designated owner's responsibility.
Adding plaintext owner execution of a missing operator would not implement its
required peer-side encrypted computation and proof of correct, complete results.

## Transaction and lock protocol work

[transaction-state](../crates/transaction-state/README.md) now implements the bounded
public control state: four lock modes, atomic acquisition, WAIT/NOWAIT outcomes,
SKIP LOCKED selection with LIMIT/OFFSET, savepoint upgrades/rollback/release,
non-reused transaction IDs and revision/sequence replay guards. Its metadata-only
journal adapter verifies real controller signatures and exact old-state witnesses,
while the journal verifies owner authorization, work and ancestry. Twenty-three
owning tests exercise these rules, actual journal publication, durable reopen,
forged control/data transitions and reorganization. Live SQL locking remains
unimplemented; metadata outcomes are not encrypted SQL results or final lock grants.

The remaining integration boundaries are:

1. The fixed table now has encrypted stable logical TableId/RowId metadata in
   compact-query private index v3, preserved by genuine amount UPDATE, atomic
   INSERT staging, restore and exact pending retry. Owner-issued references bind
   both exact heads and physical ordinal, with at most 256 sparse ID lookups.
   Existing network fetch still transfers the full encrypted image. These private
   references provide no public row-existence/completeness or lock proof. Typed
   imported tables, checked movement/compaction and a cross-data/lock proof
   relation remain open. Define transaction/statement identities, authorization,
   isolation, sequence, read/write sets and resource bounds.
2. Commit transaction and lock registries to agreed state. A separately typed
   metadata shard and its canonical witnesses are implemented independently;
   the live data application still needs a composite verifier and synchronization.
   Metadata heads must not masquerade as encrypted table commitments.
3. Validate ordered proof jobs and intermediate encrypted heads before one atomic
   multi-shard COMMIT. Preserve read-your-writes, rollback, savepoints and durable
   owner recovery of ambiguous publication without applying a mutation twice.
4. Bind complete ordered candidate rows, projection, selected identities, skip
   reasons, lock strength, wait policy and LIMIT to data and lock-state versions.
   Every UPDATE/DELETE/COMMIT must enforce ownership. Lock RPCs alone cannot protect
   rows against writes that ignore them.
5. Connect reservation evidence to encrypted-result proofs and recheck its required
   ancestry and ownership before result acceptance. Ordinary reads should depend
   on their actual data heads rather than rejecting every unrelated metadata change.

For the semantic reference, PostgreSQL 18 documents that conflicting `FOR UPDATE`
operations wait, while ordinary readers continue; locks normally last until the
transaction ends. Rollback to a savepoint releases later acquired locks.
See [explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html).
`SKIP LOCKED` continues past conflicting rows to satisfy LIMIT. Accepted skip
evidence must distinguish real conflicts from malicious omission. See the
[locking SELECT clause](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE).
Rechecking predicates after a wait and rejecting incompatible snapshots depends
on the selected [transaction isolation level](https://www.postgresql.org/docs/18/transaction-iso.html).

## Consensus and failure blocker

The current cumulative-work journal permits competing branches and later
reorganizations. Exact-parent/old-head checks can validate a reservation on one
branch, but two competing branches can each temporarily confirm incompatible
reservations. Detecting a later reorganization cannot undo an external queue job
already performed. Such branch-conditional reservations do not establish full
PostgreSQL mutual exclusion. This is an architectural consequence of the current
protocol, not a claim about PostgreSQL's behavior.

A compliant finality/failure model and abort/recovery protocol must be established
before claiming these SQL guarantees. A peer-local mutex, owner-only lock manager,
transport acknowledgement or unconfirmed lease would change required guarantees.
Local TCP disconnect also cannot establish global client death during a partition.
No such substitution is authorized by this implementation contract.

## Selective retrieval and the unresolved access policy

The bounded `FetchPages` custody RPC is implemented, but live SQL still uses full
encrypted-image Fetch. For the fixed schema, that Fetch does not disclose which
private index/data pages the owner subsequently examines. A direct selective SQL
adapter would disclose page addresses to its peers and change traffic-size metadata.
The requirements leave permitted access leakage unresolved; the raw custody API
does not approve such a policy for SQL. Preserve the current live path until an
explicitly selected leakage profile or private retrieval establishes that boundary.
PIR candidates and their active-response, setup, memory and full-query costs require
separate validation. A smaller reply alone does not justify a confidentiality change.

## Remaining SQL operators

Typed DML/DDL and constraints require authenticated catalog changes and actual
computation/transition circuits. General typed aggregation, joins, grouping, expressions, SQL
NULL semantics, set operations, subqueries, CTEs, windows and stored programs need
their own typed plans, encrypted execution and completeness relations. Extend
execution and its adversarial boundary tests together; unsupported syntax remains
fail-closed until the complete operator path exists.
