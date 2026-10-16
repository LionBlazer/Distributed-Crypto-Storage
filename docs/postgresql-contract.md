# PostgreSQL implementation contract and open work

The user selected PostgreSQL semantics on 2026-10-16 and requested complete SQL,
including `FOR UPDATE` and `SKIP LOCKED`, with ordinary queries at most 500 ms.
[REQUIREMENTS.md](../REQUIREMENTS.md) remains the unchanged implementation contract.
This document records design work and blockers, not implemented SQL support.
The [measured network path](proved-sql-network.md) identifies the current workloads,
CPU budgets, proof boundary and remaining latency failures. A representative
larger workload and tail-latency contract remain to be established.

## Current execution boundary

The fixed-schema `storage-client::Session` accepts genuine proved row SELECT,
COUNT/SUM, one-row INSERT and additive amount UPDATE. Aggregates perform an
encrypted coefficient convolution under the existing full-residue product proof,
with checked client-side limb/shard completion and SQL NULL for empty SUM.
They currently admit at most 256 matching rows per shard and reject excess;
general typed aggregation remains open. Typed imported catalogs provide
immutable single-table SELECT with authenticated owner-private indices and proved
BFV byte projection. Unsupported operators reject before execution. Neither path
implements general transactions, DELETE, JOIN or SQL row locks.
Parsing syntax or preserving imported stored programs does not execute them.

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

1. Give rows stable opaque identities independent of shard, physical ordinal,
   primary-key edits and page compaction. Define transaction/statement identities,
   authorization, isolation, sequence, read/write sets and resource bounds.
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

## Remaining SQL operators

Typed DML/DDL and constraints require authenticated catalog changes and actual
computation/transition circuits. General typed aggregation, joins, grouping, expressions, SQL
NULL semantics, set operations, subqueries, CTEs, windows and stored programs need
their own typed plans, encrypted execution and completeness relations. Extend
execution and its adversarial boundary tests together; unsupported syntax remains
fail-closed until the complete operator path exists.
