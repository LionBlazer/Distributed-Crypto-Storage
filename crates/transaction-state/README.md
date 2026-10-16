# Transaction control state

Deterministic public protocol state for transactions and PostgreSQL row-lock
ownership. It is a reusable foundation for the requested SQL transactions, not
an implemented SQL engine or live `FOR UPDATE`/`SKIP LOCKED` endpoint. There is no
thread, clock, local lock manager, transport, GUI or row-value execution here.

| Direct project dependency | Responsibility |
| --- | --- |
| [version-journal](../version-journal/README.md) | Exact-parent atomic publication, owner authorization, work, confirmations and ancestry |

SHA-256 commits canonical public state. Ed25519 verifies controller intent;
secret signing keys remain with callers. These primitives authenticate control
metadata and its transition rules, never replace a genuine FHE SQL proof.

## State and command contract

`Context::new(network, database, profile)` pins an independently chosen network ID,
database and explicit admission limits. `State::new(context)` creates the empty
control image. Its initial root does not depend on the eventual genesis hash:
genesis includes that root and application commitment; subsequent intents bind
the resulting exact genesis and parent block separately.

`State::transition(authenticated_actor, command)` returns a new state and outcome.
Its input is immutable. The pure state API relies on the caller's authenticated,
authorized actor; the journal adapter checks signed controller intent and the
journal independently checks owner permission. Errors, `Blocked` and NOWAIT
conflicts produce no partial state, lock upgrade, revision or sequence change.
This low-level error contract never automatically classifies a SQL statement as
failed. `FailCurrent` is a separate authenticated control intent, not evidence of
a SQL error, an encrypted data rollback or a published lock grant.

Commands provide BEGIN, lock acquisition, frame failure, SAVEPOINT, ROLLBACK TO,
RELEASE and control END with commit/abort intent. END releases ownership; it does
not publish or roll back encrypted data. Active transaction IDs come from a
committed monotonic high-water counter and are never reused after END. No growing
tombstone set is required. Every successful command consumes its exact revision and transaction
sequence, including reentrant acquisition and savepoint rollback. Counters use
checked arithmetic and exhaustion rejects explicitly.

`RowKey { table, row }` contains stable opaque identities. Callers must establish
row existence and preserve identity across physical movement, compaction and key
edits. Nothing here derives identities from current physical ordinals.

Four modes implement the documented other-owner conflicts:

| Requested / held | KEY SHARE | SHARE | NO KEY UPDATE | UPDATE |
| --- | --- | --- | --- | --- |
| KEY SHARE | | | | conflict |
| SHARE | | | conflict | conflict |
| NO KEY UPDATE | | conflict | conflict | conflict |
| UPDATE | conflict | conflict | conflict | conflict |

Own locks do not conflict or downgrade. Per-transaction acquisition/upgrade history
and savepoint cuts restore previous strengths without erasing other owners' locks.
ROLLBACK TO retains the target and removes younger points; RELEASE removes the
target and younger points while retaining acquired locks. Repeated names shadow
older points until the newer one is released.

`TransactionInfo::status` is `Active` or `Failed`. `FailCurrent` immediately
truncates only this transaction's lock history to the newest savepoint cut, or to
zero when there is no savepoint, then marks the current frame Failed. Pre-frame
lock strengths and other owners are preserved. A released child has already
joined its parent frame, so parent failure also releases that child's acquisitions.
The failed control record remains until recovery or END; `active_transactions()`
counts all unfinished records, including failed ones.

| Current status | Permitted work |
| --- | --- |
| Active | Existing commands and `FailCurrent` |
| Failed | `RollbackTo` or `End` only |

A successful `RollbackTo` restores Active, retains its target and removes younger
points; a failed rollback leaves the state unchanged. Repeated failure intent,
new acquisition, SAVEPOINT and RELEASE reject with `TransactionFailed` while
failed. END with Commit intent in a failed frame returns the actual outcome
`Ended(Abort)`, never `Ended(Commit)`. Normal API errors, WAIT `Blocked` and NOWAIT
conflicts still leave the original state unchanged; a future SQL owner must
classify a statement error separately before submitting authenticated failure.
Transport cancellation alone is not proof that a remote mutation rolled back.

These control rules follow the pinned PostgreSQL 18
[savepoint rollback](https://www.postgresql.org/docs/18/sql-rollback-to.html),
[failed-frame RELEASE restriction](https://www.postgresql.org/docs/18/sql-release-savepoint.html)
and [transaction state machine](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/access/transam/xact.c).
They do not implement MVCC, encrypted read-your-writes or SQL error execution.

An acquisition receives ordered row references from the separate SQL/completeness
layer. SKIP LOCKED skips only actual conflicts before LIMIT; selection preserves
input positions. OFFSET references acquire locks, while references after LIMIT
remain untouched. Repeated references may be selected repeatedly but create no
duplicate ownership. Skip receipts store positions, not a repeated holder list.
Other-owner conflict status is computed once per distinct row per command, avoiding
memory and work multiplication from repeated blocked references. NOWAIT returns
`LockUnavailable`; WAIT returns `Blocked` with exact owners. Runtime waiting,
cancellation, deadlocks, fairness and global abort recovery remain caller work.

The semantic references are PostgreSQL 18 [row locking](https://www.postgresql.org/docs/18/explicit-locking.html),
[SELECT locking](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE),
[ROLLBACK TO](https://www.postgresql.org/docs/18/sql-rollback-to.html) and
[RELEASE](https://www.postgresql.org/docs/18/sql-release-savepoint.html).

## Canonical witnesses and journal integration

`State::encode/decode` has a versioned bounded binary format: network/database/profile,
revision, transaction high-water mark and strictly ordered transaction entries.
Each entry contains controller, next sequence, opaque snapshot binding, savepoint
cuts and acquisition events. Lengths are checked against both profile limits and
remaining bytes before allocation. Unknown tags, invalid lock histories, conflicting
owners, duplicate/out-of-order transaction IDs and trailing bytes reject.

`SignedIntent` binds the complete canonical command, controller, original statement
identity, network/database/profile and exact genesis/parent. Sign the digest from
`Intent::signing_message(context)` externally; `verify(context)` checks the real
Ed25519 signature. Decoding alone establishes no authorization.

`MetadataVerifier` supplies an independent metadata-only application commitment.
`heads(state)` produces two distinct 112-byte manifests for transaction and effective
ownership roots. Their v2 schema is `magic[8], database[16], component[1], zero[7],
revision:u64, root[32], count:u64, profile[32]`. Integers are little-endian. The
transaction root commits the complete state image and monotonic allocator; the
ownership root commits sorted row/transaction holdings and modes; the transaction
root separately binds each transaction to its controller.

State, signed intent and head namespaces are `DCSTXS02`, `DCSTXI02` and
`DCSTXH02`. Profile, state/lock roots, controller authorization, verified-request
and metadata-application hash domains are v2. A transaction encodes status as one
byte after its snapshot (`0 = Active`, `1 = Failed`); other values reject. A Failed
state with events beyond its current frame cut is invalid. v1 encodings are
rejected; there is no decoder fallback, conversion or automatic migration.

`prepare(previous, signed_intent)` returns the exact request, full old-state witness,
old/new metadata heads, next state and control outcome. The owner signs the enclosing
`AuthorizedTransition` separately. `verify_control`/`TransitionVerifier` authenticate
the old image against the parent's exact metadata root, validate signed command
semantics, derive the new roots and require every other shard to remain unchanged.
A valid metadata witness cannot authorize any encrypted data update. Verification
is linear in bounded public state plus ordered candidates, with tree lookups; it
is not a succinct proof of SQL computation or SQL candidate completeness.

`VerifiedControl` is bound to the exact parent, genesis and complete signed request.
`matches_request(bytes)` checks the pending request identity, including the original
statement binding; matching state/outcome alone cannot substitute for that check.
It is not a confirmed grant: the caller must independently check journal work, owner authorization,
confirmation and current ancestry. Competing branches and reorganization remain
possible; a detached receipt confers no authority on the surviving branch.

## Resources, privacy and remaining integration

Profiles explicitly bound active transactions, effective holders, acquisition events,
savepoints, candidates and encoded state/command bytes. Direct commands and wire
commands share byte-budget checks. Resource failure rejects the whole command,
never adds an implicit row LIMIT. Frame failure truncates history without adding
holder/savepoint capacity. END removes unfinished ownership without needing
additional holder/history capacity. There is no local-time lease or disconnect
heuristic releasing agreed locks.

Control witnesses reveal opaque stable row references, controllers and access
relationships. No primary keys, row plaintext or plaintext predicates belong in
them. The live application's privacy policy for this metadata is still unresolved.
Full witnesses, publication overhead, large metadata and whole-process RAM have
not been benchmarked; no 500-ms or 1–2-GB production bound is established here.

Live SQL still rejects locking syntax. Integration requires authenticated stable
row IDs, MVCC/isolation and SQL statement-error classification, atomic encrypted
data/control rollback, proved complete SQL candidate selection,
encrypted read-your-writes, ordered multi-job commit proofs, composite data/control
validation, durable owner recovery and a compliant finality/failure model. See the
[PostgreSQL contract](../../docs/postgresql-contract.md). No data verifier accepts
metadata hashes, signatures or a replayed public control transition as its FHE proof.

## Verification

```sh
cargo test --release --locked --offline -p transaction-state -- --test-threads=1
cargo clippy --release --locked --offline -p transaction-state --all-targets -- -D warnings
```

The owning tests cover the full mode matrix, atomic conflicts, skip/order/LIMIT/
OFFSET, repeated references, resource caps, savepoint upgrades and names, replay
and controller checks, real signed journal transitions, cross-shard proof rejection,
confirmation/reorganization and durable reopen without an accepting SQL stub.

The Active/Failed extension passed all 37 owning tests, including fourteen new
failure/recovery cases, and strict Clippy with warnings denied. The
[validation record](../../docs/transaction-failure.md) describes the actual
signed/durable cases, version boundary and remaining live SQL integration.
